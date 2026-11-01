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
use crate::output::{CtlRing, Dlist};
use crate::rng::ChaCha8;
use crate::seq;
use crate::siphash::SipKey;
use crate::tcp::conn::QLink;
use crate::tcp::listen::{Listener, PortTable};
use crate::tcp::syn::SynTable;
use crate::tcp::timewait::TwTable;
use crate::tcp::{IP_TCP_HEADERS, TS_OPTION_LEN};
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

    /// 組 `cls` が `n` byte の packet を作った後の deficit を進めます。
    pub(crate) fn spent(&mut self, cls: usize, n: usize) {
        self.deficit[cls] -= i64::try_from(n).unwrap_or(i64::MAX);
        if self.deficit[cls] <= 0 || self.class_empty(cls) {
            self.cur = (cls + 1) % NUM_CLASSES;
        }
    }
}

/// 種類ごとの拒否と事象の数です (Go の `Stats` の数の欄)。保持の量は [`crate::Held`] が持ちます。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Stats {
    pub mss_floor_drops: u64,
    /// 握手の途中の表が満杯で捨てた SYN です。cookie で応えた SYN は数えません。
    pub syn_table_full: u64,
    /// 握手の途中の表が満杯で、行を作らずに cookie で応えた SYN です。
    pub syn_cookies_sent: u64,
    /// cookie が通り、接続を作った ACK です。
    pub syn_cookies_accepted: u64,
    /// cookie を送ってから 2 周期の内に届き、cookie が通らなかった ACK です。どの行にも当たらない segment と
    /// して RST を返します。
    pub syn_cookies_rejected: u64,
    pub accept_overflow: u64,
    pub tw_evicted: u64,
    pub ctl_dropped: u64,
    pub ooo_dropped: u64,
    pub recv_trimmed: u64,
    pub recv_no_memory: u64,
    pub challenge_limited: u64,
    /// 再組み立ての表が保持したか捨てた断片です。datagram を完成させた断片は数えません (Go の
    /// `FragmentsDropped` と同じ数え方です)。
    pub fragments_dropped: u64,
    /// 捨てた UDP の datagram です。予算で断ったものと、壊れたものと、会計の不整合の後に届いたものを含みます。
    pub udp_dropped: u64,
    /// endpoint 1 つの上限で断った受信の datagram です。
    pub udp_endpoint_full: u64,
    /// 核の全体の予算で断った受信の datagram です。
    pub udp_tunnel_full: u64,
    pub icmp_dropped: u64,
    /// 速さの制限で送らなかった ICMP の誤りです。
    pub icmp_limited: u64,
    pub malformed: u64,
    pub bad_checksum: u64,
    pub not_local: u64,
    pub retransmit_aborts: u64,
    pub probe_aborts: u64,
    /// 再送のタイマーの期限で送り直した回数です。窓の probe は数えません。
    pub rtos: u64,
    /// 累積の確認が進む前に続いた RTO です。
    pub rtos_backed_off: u64,
    /// 回復の外で、重複した ACK を 1 つか 2 つ受けた後の RTO です。
    pub rtos_short_of_dup_thresh: u64,
    pub fast_recoveries: u64,
    pub partial_acks: u64,
    /// 原因ごとの再送の segment です。添字は高速の再送、部分の確認、RTO、PMTU、TLP です。
    pub retrans: [u64; 5],
    pub dup_acks_in: u64,
    pub acks_delayed: u64,
    pub acks_immediate: u64,
    pub accounting_faults: u64,
    /// HyStart++ が Conservative Slow Start に入った回数です。
    pub hystart_css: u64,
    /// HyStart++ が CSS の後に slow start を終えた回数です。
    pub hystart_exits: u64,
    /// 再送が不要だったと分かり輻輳の窓を戻した回数です。
    pub spurious_undos: u64,
    /// RTO の後の回復で、RTO が不要だったと分かった回数です。
    pub spurious_rtos: u64,
    /// 相手が SACK 済みのデータを捨てたとみなし、SACK の印を消した回数です。
    pub sack_reneging: u64,
    /// RACK が失われたとみなした記録の数です。
    pub rack_lost: u64,
    /// RACK の並べ替えの期限が来た回数です。
    pub reorder_timeouts: u64,
    /// 送った TLP の probe の数です。
    pub tlp_probes: u64,
    /// TLP の probe が損失を直したとみなして輻輳の窓を下げた回数です。
    pub tlp_recoveries: u64,
    /// 並べ替えの窓の倍率を上げた D-SACK の数です。
    pub dsacks_in: u64,
    /// boost を得た回数です。
    pub boost_granted: u64,
    /// 需要の無い保有者を floor に戻した回数です。
    pub boost_reclaimed: u64,
    /// floor に戻す時に取り消した順序外の byte の数です。
    pub boost_reneged_bytes: u64,
}

/// 1 分に 1 回までの門を通るログの種類です。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LogKind {
    /// MSS の下限より小さな MSS を示す SYN を捨てました。
    MssFloor,
    /// 握手の途中の表が満杯で SYN を捨てました。
    SynFull,
    /// 握手の途中の表が満杯で、SYN に cookie で応えました。`count` は応えた数です。
    SynCookies,
    /// accept の待ち行列か接続の表が満杯で、握手の最後の ACK を捨てました。
    AcceptOverflow,
    /// TIME_WAIT の表が満杯で最も古い行を外しました。
    TwEvicted,
    /// 制御の輪が満杯で制御の packet を捨てました。
    CtlDropped,
    /// 順序外の区間の数の上限で segment を捨てました。
    OooDropped,
    /// 会計の不整合で接続を閉じました。
    AccountingFault,
    /// 受信の socket が読まれず、UDP の予算で datagram を捨てました。`count` は予算で断った数です。
    UdpDropped,
    /// UDP の会計が不変条件の違反を見つけ、核の UDP をすべて止めました。1 回だけ出します。違反の中身は
    /// [`crate::Stack::udp_receive_fault`] が返します。
    UdpFault,
}

/// 門を通るログの種類です。`UdpFault` は 1 回だけ出すので門を持ちません。
const LOG_KINDS: [LogKind; 9] = [
    LogKind::MssFloor,
    LogKind::SynFull,
    LogKind::SynCookies,
    LogKind::AcceptOverflow,
    LogKind::TwEvicted,
    LogKind::CtlDropped,
    LogKind::OooDropped,
    LogKind::AccountingFault,
    LogKind::UdpDropped,
];

/// 門を通った 1 行の材料です。`count` は核を作ってからの数です。英語の文面は駆動の層 (`wgft-netstack`) が書きます。
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
    /// challenge ACK の token bucket です。
    pub(crate) ch_sec: i64,
    pub(crate) ch_count: i64,
    pub(crate) stats: Stats,
    pub(crate) gates: Gates,
}

impl Shared {
    /// 拒否を数え、1 分に 1 回までログの材料にします (Go の `refused`)。
    pub(crate) fn refused(&mut self, kind: LogKind, now: i64) {
        let st = &mut self.stats;
        let c = match kind {
            LogKind::MssFloor => &mut st.mss_floor_drops,
            LogKind::SynFull => &mut st.syn_table_full,
            LogKind::AcceptOverflow => &mut st.accept_overflow,
            LogKind::TwEvicted => &mut st.tw_evicted,
            LogKind::CtlDropped => &mut st.ctl_dropped,
            LogKind::OooDropped => &mut st.ooo_dropped,
            LogKind::AccountingFault => &mut st.accounting_faults,
            // UDP の数は入口が数え、cookie の数は送った所が数えます。
            LogKind::UdpDropped | LogKind::UdpFault | LogKind::SynCookies => return,
        };
        *c += 1;
        let n = *c;
        self.gates.allow(kind, now, n);
    }

    /// MSS の下限で SYN を捨てたことを数えます。
    pub(crate) fn drop_mss(&mut self, now: i64) {
        self.refused(LogKind::MssFloor, now);
    }

    /// 次の IP の ID です。
    #[expect(
        clippy::cast_possible_truncation,
        reason = "Go keeps the low 16 bits of the counter"
    )]
    pub(crate) fn next_id(&mut self) -> u16 {
        self.ip_id = self.ip_id.wrapping_add(1);
        self.ip_id as u16
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

    /// 核の全体の challenge ACK の token bucket から 1 つ取れたかを返します。1 秒ごとに limit/2 から 3*limit/2
    /// の間の乱数の数を補います。
    pub(crate) fn challenge_allowed(&mut self, now: i64) -> bool {
        const LIMIT: u64 = 1000;
        let sec = now / 1_000_000_000;
        if sec != self.ch_sec || self.ch_count < 0 {
            self.ch_sec = sec;
            self.ch_count = i64::try_from(LIMIT / 2 + self.random_below(LIMIT)).unwrap_or(0);
        }
        let ok = self.ch_count > 0;
        if ok {
            self.ch_count -= 1;
        } else {
            self.stats.challenge_limited += 1;
        }
        ok
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

    pub(crate) fn unqueue_conn(&mut self, id: u32) {
        self.out.conns.remove(id);
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
            self.refused(LogKind::CtlDropped, now);
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
