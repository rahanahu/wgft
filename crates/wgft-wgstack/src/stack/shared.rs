//! 接続の枠の外の、核の共有の状態 (Go の `stack` の欄のうち接続の枠を除くもの)。
//!
//! 接続の処理は、自分の枠の欄とこの値を同時に `&mut` で借ります。接続の枠の配列はこの値に入れないので、
//! 借用が重なりません。数えと 1 分に 1 回の門の状態もここにあり、segment ごとに触る接続の欄とは別の行に
//! あります。

use crate::budget::Budget;
use crate::buf::RECV_FLOOR;
use crate::buf::chunk::ChunkPool;
use crate::config::Config;
use crate::event::{Bits, EventList};
use crate::fixed_vec::FixedVec;
use crate::frag;
use crate::icmp::Pings;
use crate::index::Index;
use crate::output::{CtlRing, Dlist, NIL};
use crate::rng::ChaCha8;
use crate::seq;
use crate::siphash::SipKey;
use crate::tcp::conn::QLink;
use crate::tcp::listen::{Listener, PortTable};
use crate::tcp::syn::SynTable;
use crate::tcp::timewait::TwTable;
use crate::tcp::{FLOW_ACK_INTERVAL, IP_TCP_HEADERS, TS_OPTION_LEN};
use crate::udp::Udp;
use crate::wheel::Wheel;
use crate::wire::{self, FLAG_ACK, FLAG_RST, OptWriter, Segment, TcpHeader, Tuple};

/// 出力の組です。接続の枠の segment、握手の途中の行と TIME_WAIT の行の segment、UDP の datagram、制御の輪の
/// 順で、Go と同じ番号です。
pub(crate) const CLASS_CONN: usize = 0;
pub(crate) const CLASS_ROW: usize = 1;
pub(crate) const CLASS_UDP: usize = 2;
pub(crate) const CLASS_CTL: usize = 3;
pub(crate) const NUM_CLASSES: usize = 4;

/// 接続の知らせの印です。
pub(crate) const EV_READ: Bits = 1;
pub(crate) const EV_WRITE: Bits = 2;
pub(crate) const EV_CLOSED: Bits = 4;
/// ポートの知らせの印です。TCP の待ち受けと UDP の endpoint は同じポートの対象を分け合います。
pub(crate) const EV_ACCEPT: Bits = 1;
pub(crate) const EV_UDP_READ: Bits = 2;
pub(crate) const EV_UDP_WRITE: Bits = 4;
/// ping の endpoint の知らせの印です。
pub(crate) const EV_PING: Bits = 1;

/// 出力の組の状態です (Go の `output`)。
#[derive(Debug)]
pub(crate) struct Output {
    /// 送るもののある接続の枠です。
    pub(crate) conns: Dlist,
    /// 送るもののある行です。握手の途中の行は 0 から、TIME_WAIT の行は握手の途中の表の大きさから数えます。
    pub(crate) rows: Dlist,
    pub(crate) ctl: CtlRing,
    /// UDP の送信の FIFO にある datagram の数です。
    pub(crate) udp_queued: usize,
    pub(crate) cur: usize,
    pub(crate) deficit: [i64; NUM_CLASSES],
    /// 送信の番を持つ接続の枠です。番が無ければ [`NIL`] です。番を持つ接続は、いつも `conns` の先頭にあります
    /// (wgstack-rs.md の「送信の番」)。
    pub(crate) turn: u32,
    /// 番を持つ接続がこの番で作った packet の byte の和です。
    pub(crate) turn_bytes: u32,
    /// 番の長さの byte (N × MTU) です。0 は送信の番を使わないことを表し、`turn` はいつも [`NIL`] です。
    pub(crate) turn_limit: u32,
}

impl Output {
    fn class_empty(&self, c: usize) -> bool {
        match c {
            CLASS_CONN => self.conns.is_empty(),
            CLASS_ROW => self.rows.is_empty(),
            CLASS_CTL => self.ctl.len() == 0,
            CLASS_UDP => self.udp_queued == 0,
            _ => true,
        }
    }

    /// deficit round robin で次の組を選びます。どの組も空なら `None` です。
    pub(crate) fn pick(&mut self, quantum: i64) -> Option<usize> {
        for _ in 0..NUM_CLASSES {
            let c = self.cur;
            if self.class_empty(c) {
                self.deficit[c] = 0;
                self.cur = (c + 1) % NUM_CLASSES;
                continue;
            }
            if self.deficit[c] <= 0 {
                self.deficit[c] += quantum;
            }
            return Some(c);
        }
        None
    }

    /// 接続の組の先頭から取り出した枠 `id` が `n` byte の packet を作った後に、送信の番を進めます。番を使わない
    /// 時は何もしないので、出力は番の無い時と同じです。`id` が番を持っていなければ、ここで新しい番を始めます。
    /// 番の byte が長さに届かず、接続がまだ送るものを持って list に入れ直した時は、末尾から先頭に戻して番を
    /// 続けます。何も作らなかった時、送るものが無くなった時、長さに届いた時は番を終え、接続は末尾に残ります。
    pub(crate) fn turn_after(&mut self, id: u32, n: usize) {
        if self.turn_limit == 0 {
            return;
        }
        if self.turn != id {
            // 番を持つ接続はいつも list の先頭にあり、先頭から取り出した枠だけがここに来るので、ほかの枠の番は
            // 残っていません。
            debug_assert_eq!(self.turn, NIL, "a send turn was left on another slot");
            self.turn = id;
            self.turn_bytes = 0;
        }
        self.turn_bytes = self
            .turn_bytes
            .saturating_add(u32::try_from(n).unwrap_or(u32::MAX));
        if n > 0 && self.turn_bytes < self.turn_limit && self.conns.contains(id) {
            self.conns.move_to_front(id);
        } else {
            self.end_turn();
        }
    }

    /// 送信の番を終えます。
    pub(crate) fn end_turn(&mut self) {
        self.turn = NIL;
        self.turn_bytes = 0;
    }

    /// 送信の番の状態が list と合うことを確かめます。番を持つ接続は list の先頭にあり、番の byte は長さより
    /// 小さく、番を使わない時は番がありません。
    pub(crate) fn check_turn(&self) -> Result<(), &'static str> {
        if self.turn == NIL {
            return if self.turn_bytes == 0 {
                Ok(())
            } else {
                Err("send turn bytes are left without a turn")
            };
        }
        if self.turn_limit == 0 {
            return Err("a send turn is held while send turns are off");
        }
        if self.conns.front() != Some(self.turn) {
            return Err("the send turn holder is not at the head of the connection list");
        }
        if self.turn_bytes == 0 || self.turn_bytes >= self.turn_limit {
            return Err("the send turn bytes are out of range");
        }
        Ok(())
    }

    /// 組 `cls` が `n` byte の packet を作った後の deficit を進めます。
    pub(crate) fn spent(&mut self, cls: usize, n: usize) {
        self.deficit[cls] -= i64::try_from(n).unwrap_or(i64::MAX);
        if self.deficit[cls] <= 0 || self.class_empty(cls) {
            self.cur = (cls + 1) % NUM_CLASSES;
        }
    }
}

/// Counts of rejections and events by kind. The amount of held memory is in [`crate::Held`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Stats {
    pub mss_floor_drops: u64,
    /// SYNs that announced a window scale above 14. The handshake goes on with 14 (RFC 7323 2.3).
    pub wscale_clamped: u64,
    /// SYNs dropped because the half-open table was full. SYNs answered with a cookie are not counted.
    pub syn_table_full: u64,
    /// SYNs dropped because the accept queue or the connection slots were full while SYN cookies were in use.
    pub syn_accept_full: u64,
    /// SYNs answered with a cookie, without creating a row, because the half-open table was full.
    pub syn_cookies_sent: u64,
    /// ACKs that passed the cookie check and created a connection.
    pub syn_cookies_accepted: u64,
    /// ACKs that arrived within two periods after a cookie was sent and failed the cookie check. An ACK that hits a
    /// half-open row, and an ACK carrying neither payload nor FIN, is answered with an RST; the others are dropped.
    pub syn_cookies_rejected: u64,
    /// ACKs that passed the cookie check but found the accept queue or the connection slots full, and were turned into
    /// half-open rows built from the cookie value.
    pub syn_cookies_deferred: u64,
    /// ACKs that passed the cookie check but could neither create a connection nor a row and were reset with RST, plus
    /// rows built from a cookie value that used up their SYN-ACK retransmissions and were reset with RST.
    pub syn_cookies_reset: u64,
    pub accept_overflow: u64,
    pub tw_evicted: u64,
    /// The total of packets dropped because the control output ring was full. It is the sum of the next three.
    pub ctl_dropped: u64,
    /// TCP control segments dropped because the control output ring was full. These are RSTs and cookie SYN-ACKs.
    pub ctl_dropped_tcp: u64,
    /// ICMP errors dropped because the control output ring was full.
    pub ctl_dropped_icmp_error: u64,
    /// Echo replies dropped whole because the control output ring was full.
    pub ctl_dropped_echo: u64,
    pub ooo_dropped: u64,
    pub recv_trimmed: u64,
    pub recv_no_memory: u64,
    /// ACKs not sent because of the per-connection or per-row rate limit: challenge ACKs (RFC 5961) and ACKs to
    /// unacceptable segments. On connections only segments without payload count as unacceptable here; on rows,
    /// segments with payload count too.
    pub challenge_limited: u64,
    /// Fragments that the reassembly table held or dropped. Fragments that completed a datagram are not counted.
    pub fragments_dropped: u64,
    /// Incomplete datagrams removed to make room for other datagrams because the reassembly table was full. Their
    /// fragments are already counted in `fragments_dropped`.
    pub fragments_evicted: u64,
    /// UDP datagrams dropped. This includes datagrams refused by a budget, malformed datagrams and datagrams that
    /// arrived after an accounting inconsistency.
    pub udp_dropped: u64,
    /// Received datagrams refused by the per-endpoint limit.
    pub udp_endpoint_full: u64,
    /// Received datagrams refused by the stack-wide budget.
    pub udp_stack_full: u64,
    /// Older send datagrams dropped to make room for a new datagram when the send budget was exhausted.
    pub udp_send_evicted: u64,
    /// Send datagrams dropped before sending started because they exceeded the longest time they may wait.
    pub udp_send_expired: u64,
    pub icmp_dropped: u64,
    /// ICMP errors not sent because of rate limiting.
    pub icmp_limited: u64,
    pub malformed: u64,
    pub bad_checksum: u64,
    pub not_local: u64,
    /// Datagrams dropped because the source address is in 0/8, 127/8, 224/4 or 240/4 (RFC 1122 3.2.1.3).
    pub bad_source: u64,
    pub retransmit_aborts: u64,
    pub probe_aborts: u64,
    /// Times data was retransmitted because the retransmission timer expired. Window probes are not counted.
    pub rtos: u64,
    /// RTOs that followed another RTO before the cumulative acknowledgment advanced.
    pub rtos_backed_off: u64,
    /// RTOs outside recovery after one or two duplicate ACKs had been received.
    pub rtos_short_of_dup_thresh: u64,
    pub fast_recoveries: u64,
    pub partial_acks: u64,
    /// Retransmitted segments by cause. The indices are fast retransmit, partial acknowledgment, RTO, PMTU and TLP.
    pub retrans: [u64; 5],
    pub dup_acks_in: u64,
    pub acks_delayed: u64,
    pub acks_immediate: u64,
    pub accounting_faults: u64,
    /// Times HyStart++ entered Conservative Slow Start.
    pub hystart_css: u64,
    /// Times HyStart++ ended slow start after CSS.
    pub hystart_exits: u64,
    /// Times the congestion window was restored after a retransmission turned out to be unnecessary.
    pub spurious_undos: u64,
    /// Times recovery after an RTO found that the RTO had been unnecessary.
    pub spurious_rtos: u64,
    /// Times the peer was taken to have discarded data it had SACKed, and the SACK marks were cleared.
    pub sack_reneging: u64,
    /// Records that RACK marked as lost.
    pub rack_lost: u64,
    /// Times the RACK reordering timer expired.
    pub reorder_timeouts: u64,
    /// TLP probes sent.
    pub tlp_probes: u64,
    /// Times a TLP probe was taken to have repaired a loss and the congestion window was reduced.
    pub tlp_recoveries: u64,
    /// D-SACKs that raised the multiplier of the reordering window.
    pub dsacks_in: u64,
    /// Times a boost was obtained.
    pub boost_granted: u64,
    /// Times a holder without demand was returned to its floor.
    pub boost_reclaimed: u64,
    /// Out-of-order bytes cancelled when returning to the floor.
    pub boost_reneged_bytes: u64,
}

/// 制御の輪に積む packet の種類です。捨てた数を種類ごとに数えます。
#[derive(Clone, Copy)]
pub(crate) enum CtlKind {
    Tcp,
    IcmpError,
    Echo,
}

/// The kinds of log entry, each passed through a gate that allows at most one per minute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LogKind {
    /// A SYN announcing an MSS below the lower limit was dropped.
    MssFloor,
    /// A SYN announced a window scale above 14; the stack used 14 and went on with the handshake.
    WscaleClamped,
    /// A SYN was dropped because the half-open table was full.
    SynFull,
    /// SYNs were answered with a cookie because the half-open table was full. `count` is the number answered.
    SynCookies,
    /// A SYN was dropped because the accept queue or the connection slots were full while SYN cookies were in use.
    SynAcceptFull,
    /// The final ACK of a handshake was dropped because the accept queue or the connection table was full.
    AcceptOverflow,
    /// The oldest row was removed because the TIME_WAIT table was full.
    TwEvicted,
    /// A control packet was dropped because the control output ring was full.
    CtlDropped,
    /// A segment was dropped because of the limit on out-of-order intervals.
    OooDropped,
    /// A connection was closed because of an accounting inconsistency.
    AccountingFault,
    /// Datagrams were dropped by the UDP budget because the receiving socket was not read. `count` is the number
    /// refused by the budget.
    UdpDropped,
    /// Outgoing UDP datagrams were dropped because the send budget was exhausted or they waited too long. `count` is
    /// the sum of the dropped datagrams.
    UdpSendDropped,
    /// UDP accounting found an invariant violation and stopped all UDP in the stack. Emitted only once. The violation
    /// itself is returned by [`crate::Stack::udp_receive_fault`].
    UdpFault,
}

/// 門を通るログの種類です。`UdpFault` は 1 回だけ出すので門を持ちません。
const LOG_KINDS: [LogKind; 12] = [
    LogKind::MssFloor,
    LogKind::WscaleClamped,
    LogKind::SynFull,
    LogKind::SynCookies,
    LogKind::SynAcceptFull,
    LogKind::AcceptOverflow,
    LogKind::TwEvicted,
    LogKind::CtlDropped,
    LogKind::OooDropped,
    LogKind::AccountingFault,
    LogKind::UdpDropped,
    LogKind::UdpSendDropped,
];

/// The material for one log entry that passed the gate. `count` is the number since the stack was created. The caller
/// writes the message text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogLine {
    pub kind: LogKind,
    pub count: u64,
}

/// 1 分に 1 回までの門です (Go の `gate`)。核の時刻で判定します。
#[derive(Clone, Copy, Debug, Default)]
struct Gate {
    next: i64,
    used: bool,
    /// 門を通った時の数で、`poll_log` が取り出すまで持ちます。
    pending: Option<u64>,
}

/// 種類ごとの門です。
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Gates {
    gates: [Gate; LOG_KINDS.len()],
}

impl Gates {
    pub(crate) fn allow(&mut self, kind: LogKind, now: i64, count: u64) {
        let Some(i) = LOG_KINDS.iter().position(|&k| k == kind) else {
            return;
        };
        let g = &mut self.gates[i];
        if g.used && now < g.next {
            return;
        }
        g.used = true;
        g.next = now.saturating_add(60_000_000_000);
        g.pending = Some(count);
    }

    pub(crate) fn pop(&mut self) -> Option<LogLine> {
        for (g, &kind) in self.gates.iter_mut().zip(LOG_KINDS.iter()) {
            if let Some(count) = g.pending.take() {
                return Some(LogLine { kind, count });
            }
        }
        None
    }
}

/// 接続の枠の外の核の状態です。
#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) config: Config,
    /// 受け付ける宛先のアドレスです。
    pub(crate) addr: u32,
    /// 最後に受けた時刻 (ns) です。
    pub(crate) now: i64,
    pub(crate) isn_key: SipKey,
    pub(crate) ts_key: SipKey,
    /// SYN cookie の MAC の鍵です。
    pub(crate) cookie_key: SipKey,
    /// 最後に cookie の SYN-ACK を積んだ時刻 (ns) です。
    pub(crate) cookie_sent: Option<i64>,
    pub(crate) ip_id: u32,
    /// DF を下ろした datagram (UDP と echo の応答) の ID の数えです。DF を立てた packet は進めません (RFC 6864 4.3)。
    pub(crate) ip_id_open: u16,
    pub(crate) rng: ChaCha8,
    /// 空きの接続の枠です。
    pub(crate) conn_free: FixedVec<u32>,
    /// accept の待ち行列の節です。接続の枠の番号で引きます。
    pub(crate) qlinks: FixedVec<QLink>,
    pub(crate) conn_idx: Index,
    pub(crate) syn: SynTable,
    pub(crate) tw: TwTable,
    pub(crate) listeners: PortTable<Listener>,
    /// accept の待ち行列の全体の数です。
    pub(crate) queued: usize,
    pub(crate) out: Output,
    pub(crate) events: EventList,
    pub(crate) wheel: Wheel,
    pub(crate) fired: FixedVec<u32>,
    pub(crate) chunks: ChunkPool,
    pub(crate) frag: frag::Table,
    /// 再組み立ての表を次に掃除する時刻 (ns) です。
    pub(crate) frag_next_sweep: i64,
    pub(crate) udp: Udp,
    pub(crate) pings: Pings,
    /// ICMP の誤りの速さの制限の秒と、その秒に残る数です。
    pub(crate) icmp_sec: i64,
    pub(crate) icmp_count: i64,
    pub(crate) budget: Budget,
    pub(crate) stats: Stats,
    pub(crate) gates: Gates,
}

impl Shared {
    /// 拒否を数え、1 分に 1 回までログの材料にします (Go の `refused`)。
    pub(crate) fn refused(&mut self, kind: LogKind, now: i64) {
        let st = &mut self.stats;
        let c = match kind {
            LogKind::MssFloor => &mut st.mss_floor_drops,
            LogKind::WscaleClamped => &mut st.wscale_clamped,
            LogKind::SynFull => &mut st.syn_table_full,
            LogKind::SynAcceptFull => &mut st.syn_accept_full,
            LogKind::AcceptOverflow => &mut st.accept_overflow,
            LogKind::TwEvicted => &mut st.tw_evicted,
            LogKind::CtlDropped => &mut st.ctl_dropped,
            LogKind::OooDropped => &mut st.ooo_dropped,
            LogKind::AccountingFault => &mut st.accounting_faults,
            // UDP の数は入口が数え、cookie の数は送った所が数えます。
            LogKind::UdpDropped
            | LogKind::UdpSendDropped
            | LogKind::UdpFault
            | LogKind::SynCookies => return,
        };
        *c += 1;
        let n = *c;
        self.gates.allow(kind, now, n);
    }

    /// 制御の輪に積めずに捨てたことを、種類ごとと合計に数えます。
    pub(crate) fn ctl_refused(&mut self, kind: CtlKind, now: i64) {
        match kind {
            CtlKind::Tcp => self.stats.ctl_dropped_tcp += 1,
            CtlKind::IcmpError => self.stats.ctl_dropped_icmp_error += 1,
            CtlKind::Echo => self.stats.ctl_dropped_echo += 1,
        }
        self.refused(LogKind::CtlDropped, now);
    }

    /// 14 を超える窓の scale の SYN を数え、1 分に 1 回までログの材料にします (RFC 7323 2.3)。
    pub(crate) fn note_wscale_clamped(&mut self, now: i64) {
        self.refused(LogKind::WscaleClamped, now);
    }

    /// MSS の下限で SYN を捨てたことを数えます。
    pub(crate) fn drop_mss(&mut self, now: i64) {
        self.refused(LogKind::MssFloor, now);
    }

    /// DF を立てた packet (TCP と ICMP の誤り) の次の IP の ID です。
    #[expect(
        clippy::cast_possible_truncation,
        reason = "Go keeps the low 16 bits of the counter"
    )]
    pub(crate) fn next_id(&mut self) -> u16 {
        self.ip_id = self.ip_id.wrapping_add(1);
        self.ip_id as u16
    }

    /// DF を下ろした datagram の次の IP の ID です。0 は飛ばします。DF を立てた packet とは別の数えから取ります
    /// (RFC 6864 4.3 は、非 atomic の datagram の ID が重ならない間隔を保つことを求めます)。
    pub(crate) fn next_open_id(&mut self) -> u16 {
        #[cfg(feature = "harness")]
        if crate::stack::go_compat_shared_id() {
            return self.next_id(); // 凍結した Go の記録との照合用: 1 つの数えを共有する
        }
        self.ip_id_open = self.ip_id_open.wrapping_add(1);
        if self.ip_id_open == 0 {
            self.ip_id_open = 1;
        }
        self.ip_id_open
    }

    /// `[0, n)` の乱数です (Go の `randomU64N`)。
    pub(crate) fn random_below(&mut self, n: u64) -> u64 {
        self.rng.below(n)
    }

    /// RFC 6528 の鍵付きの hash で ISN を作ります。M は 4 µs ごとに進む時計です。`reuse` は TIME_WAIT の 4 つ組を
    /// 新しい SYN が使い直すときの前の接続の SND.NXT で、ISN をその 65537 先より前に置きません。
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "Go keeps the low 32 bits of the clock and the hash"
    )]
    pub(crate) fn isn(&self, t: Tuple, now: i64, reuse: Option<u32>) -> u32 {
        let mut iss = ((now / 4000) as u32).wrapping_add(self.isn_key.hash_tuple(t) as u32);
        if let Some(snd_nxt) = reuse {
            let floor = snd_nxt.wrapping_add(65537);
            if seq::lt(iss, floor) {
                iss = floor;
            }
        }
        iss
    }

    /// timestamp の値に足す offset です。アドレスの組の鍵付きの hash から作ります。
    #[expect(
        clippy::cast_possible_truncation,
        reason = "Go keeps the low 32 bits of the hash"
    )]
    pub(crate) fn ts_offset(&self, t: Tuple) -> u32 {
        self.ts_key
            .sum(u64::from(t.laddr) | u64::from(t.raddr) << 32, 0) as u32
    }

    /// 接続か行の速さを抑えた ACK を 1 つ許すかを決めます。`until` はその接続か行が次の ACK を許す時刻 (ns) で、
    /// 許したら次の時刻を返し、許さなければ数えて `None` を返します。間隔は固定で、接続か行の外の状態 (他の接続の
    /// ACK、窓、接続と行の数) を読まないので、他の接続の状態は許すかどうかに現れません。
    pub(crate) fn flow_ack(&mut self, until: i64, now: i64) -> Option<i64> {
        if now < until {
            self.stats.challenge_limited += 1;
            return None;
        }
        Some(now.saturating_add(FLOW_ACK_INTERVAL))
    }

    /// 自分が示す MSS です。MTU から IPv4 と TCP の header を引いた値です。
    pub(crate) fn our_mss(&self) -> u32 {
        u32::try_from(self.config.mtu).unwrap_or(0) - IP_TCP_HEADERS
    }

    /// SYN-ACK で広告する窓です。65535 と受信の floor の小さい方を、中身の大きさの倍数に切り下げます。
    pub(crate) fn initial_window(&self, ts: bool) -> u32 {
        let mut mss = self.our_mss();
        if ts {
            mss -= TS_OPTION_LEN;
        }
        let w = u32::try_from(RECV_FLOOR.min(65535)).unwrap_or(65535);
        w / mss * mss
    }

    pub(crate) fn queue_conn(&mut self, id: u32) {
        self.out.conns.push_back(id);
    }

    /// 接続を組の list から外します。番を持つ接続なら番も終えます。外れた枠を番が指したまま残さないためです。
    pub(crate) fn unqueue_conn(&mut self, id: u32) {
        self.out.conns.remove(id);
        if self.out.turn == id {
            self.out.end_turn();
        }
    }

    pub(crate) fn queue_row(&mut self, id: u32) {
        self.out.rows.push_back(id);
    }

    pub(crate) fn unqueue_row(&mut self, id: u32) {
        self.out.rows.remove(id);
    }

    /// 接続 `id` に知らせの印を付けます。
    pub(crate) fn signal(&mut self, id: u32, bit: Bits) {
        self.events.raise(id, bit);
    }

    /// 待ち受けのポート `port` に accept できる知らせを付けます。
    pub(crate) fn signal_listener(&mut self, port: u16) {
        let t = self.listener_target(port);
        self.events.raise(t, EV_ACCEPT);
    }

    /// 待ち受けのポート `port` の知らせの対象の番号です。接続の枠の後ろに並べます。接続の枠の数は accept の
    /// 待ち行列の節の配列の長さと同じです。
    pub(crate) fn listener_target(&self, port: u16) -> u32 {
        u32::try_from(self.qlinks.len()).unwrap_or(0) + u32::from(port)
    }

    /// option の無い segment を制御の輪に積みます。輪が満杯なら捨てて数えます。
    pub(crate) fn send_ctl(&mut self, h: TcpHeader) {
        self.send_ctl_with(h, None);
    }

    /// segment を制御の輪に積み、積んだかを返します。輪が満杯なら捨てて数えます。
    pub(crate) fn send_ctl_with(&mut self, h: TcpHeader, o: Option<&mut OptWriter>) -> bool {
        let id = self.next_id();
        let Some(b) = self.out.ctl.slot() else {
            let now = self.now;
            self.ctl_refused(CtlKind::Tcp, now);
            return false;
        };
        wire::write_tcp(b, id, &h, o, 0);
        let n = wire::finish_tcp(b);
        self.out.ctl.commit(n);
        true
    }

    /// どの接続にも行にも当たらない segment に RST を返します (RFC 9293 3.10.7.1)。RST には返しません。
    pub(crate) fn reply_rst(&mut self, seg: &Segment<'_>) {
        if seg.has(FLAG_RST) {
            return;
        }
        let mut h = TcpHeader {
            tup: seg.tup,
            flags: FLAG_RST,
            ..TcpHeader::default()
        };
        if seg.has(FLAG_ACK) {
            h.seq = seg.ack;
        } else {
            h.ack = seg.seq.wrapping_add(seg.seq_len());
            h.flags |= FLAG_ACK;
        }
        self.send_ctl(h);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gates_pass_once_a_minute_and_keep_the_count() {
        let mut g = Gates::default();
        g.allow(LogKind::SynFull, 5, 1);
        g.allow(LogKind::SynFull, 6, 2);
        assert_eq!(
            g.pop(),
            Some(LogLine {
                kind: LogKind::SynFull,
                count: 1
            })
        );
        assert_eq!(g.pop(), None);
        g.allow(LogKind::SynFull, 60_000_000_005, 3);
        assert_eq!(g.pop().map(|l| l.count), Some(3));
    }

    #[test]
    fn output_rotates_by_deficit() {
        let mut o = Output {
            conns: Dlist::new(2).unwrap(),
            rows: Dlist::new(2).unwrap(),
            ctl: CtlRing::new(2, 64).unwrap(),
            udp_queued: 0,
            cur: 0,
            deficit: [0; NUM_CLASSES],
            turn: NIL,
            turn_bytes: 0,
            turn_limit: 0,
        };
        assert_eq!(o.pick(100), None);
        o.conns.push_back(0);
        o.rows.push_back(1);
        assert_eq!(o.pick(100), Some(CLASS_CONN));
        o.spent(CLASS_CONN, 60);
        assert_eq!(o.pick(100), Some(CLASS_CONN), "the deficit allows more");
        o.spent(CLASS_CONN, 60);
        assert_eq!(o.pick(100), Some(CLASS_ROW));
    }
}
