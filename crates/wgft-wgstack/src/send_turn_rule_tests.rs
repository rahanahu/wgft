//! 送信の番の規則の試験 (wgstack-rs.md の「送信の番」の「番の規則」と「送信の番の試験」)。
//!
//! 書き手の分離に従い、実装の担当とは別の担当が規則から書きました。どの試験も手で進める時計の核だけで動き、
//! 乱数の種も決まっているので、同じ入力に同じ答えを返します。
//!
//! 送るものが尽きない接続を作るため、試験の相手は核が送った中身つきの segment を 1 つずつすぐに確認し、
//! アプリケーションは確認のたびに送信の輪を書き足します。こうすると輻輳の窓と相手の窓は接続を止めず、接続は
//! いつも接続の組の list にいます。番の規則だけが接続の間の順を決めるので、番の長さ、公平、組の間の位置を
//! そのまま比べられます。packet の長さはどれも MTU で、番は N × MTU byte のちょうど N segment です。

#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "test helpers"
)]
#![expect(clippy::cast_possible_truncation, reason = "small test sizes")]

use core::net::SocketAddrV4;
use core::time::Duration;

use crate::output::NIL;
use crate::tcp::conn::{ConnId, State};
use crate::testnet_tests::{
    DUT, Out, PEER, PeerConn, TEST_MTU, TSeg, TestNet, parse_out, small_limits,
};
use crate::wire::{self, FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN};
use crate::{ListenerId, UdpId};

thread_local! {
    /// この試験の thread が確かめる番の長さ N (segment) です。どの試験も `for_each_n` が N を 2、4、8 に
    /// して流します (N の候補を比べる実験のためです)。
    static TURN_N: core::cell::Cell<u8> = const { core::cell::Cell::new(8) };
}

/// 番の長さ N (segment) です。
fn n() -> usize {
    usize::from(TURN_N.get())
}

/// 番の途中で止める packet の数です。3 packet で、N が小さければ N - 1 packet です。
fn mid() -> usize {
    3.min(n() - 1)
}

/// 番の長さの byte (N × MTU) です。
fn turn() -> usize {
    n() * TEST_MTU
}
/// 待ち受けのポートです。
const LISTEN: u16 = 80;
/// 相手の接続の最初のポートです。
const FIRST: u16 = 40000;
/// 相手の UDP の口です。
const PEER_UDP: SocketAddrV4 = SocketAddrV4::new(PEER, 5000);
/// 相手の ISN です。
const ISS: u32 = 1000;

static DATA: [u8; 65536] = [0x5a; 65536];

/// segment の (番号, 確認番号, flag, 窓, 中身の長さ) です。
type SegShape = (u32, u32, u8, u16, usize);

/// 核が出した packet の種類です。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Label {
    /// 接続の組の packet。値は相手のポートです。
    Conn(u16),
    /// UDP の datagram です。
    Udp,
    /// 制御の輪の RST です。
    Ctl,
    /// 握手の途中の行の SYN-ACK です。
    Row,
}

/// 核が出した packet です。
#[derive(Clone, Debug)]
struct Sent {
    label: Label,
    len: usize,
    out: Option<Out>,
}

/// 相手の側の 1 つの接続と、核の側の handle です。
struct Flow {
    c: ConnId,
    p: PeerConn,
    /// 確認のたびに送信の輪を書き足すか。
    feed: bool,
    /// 相手が確認を返すか (破棄した接続は返しません)。
    live: bool,
    /// 核の FIN を受けたら相手も FIN を返すか。
    fin_back: bool,
}

/// 送るものが尽きない接続を持つ核と、出した packet の記録です。
struct Bench {
    n: TestNet,
    l: ListenerId,
    u: UdpId,
    flows: Vec<Flow>,
    buf: Vec<u8>,
    sent: Vec<Sent>,
}

impl Bench {
    /// 番を `on` で選んだ核で、ポート `FIRST` から `k` 個の接続を開き、どれにも送るものを書きます。list の順は
    /// 開いた順です。
    fn new(on: bool, k: usize) -> Self {
        Self::with_mss(on, &vec![1380; k])
    }

    /// 相手の MSS を接続ごとに `mss` で選んで開き、どれにも送るものを書きます。
    fn with_mss(on: bool, mss: &[u16]) -> Self {
        let mut b = Self::opened(on, mss);
        for i in 0..b.flows.len() {
            b.feed(i);
        }
        b
    }

    /// 相手の MSS を接続ごとに `mss` で選んで開きます。まだ何も書きません。
    fn opened(on: bool, mss: &[u16]) -> Self {
        let mut n = if on {
            TestNet::with_send_turn_segments(small_limits(), TURN_N.get())
        } else {
            TestNet::new(small_limits())
        };
        let l = n.listen(LISTEN);
        let u = n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
        let mut b = Self {
            n,
            l,
            u,
            flows: Vec::new(),
            buf: vec![0; 65536],
            sent: Vec::new(),
        };
        for (i, &m) in mss.iter().enumerate() {
            b.open(FIRST + i as u16, m);
        }
        b.sent.clear();
        b
    }

    /// 相手のポート `port` から MSS `mss` で接続を開いて受け取ります。握手の間も、ほかの接続の出力を
    /// 1 つずつ進めます。接続の番号を返します。
    fn open(&mut self, port: u16, mss: u16) -> usize {
        self.n.inject(&TSeg {
            sport: port,
            dport: LISTEN,
            seq: ISS,
            flags: FLAG_SYN,
            wnd: 65535,
            mss,
            ws: Some(7),
            ts: Some((5000, 0)),
            ..TSeg::default()
        });
        let sa = (0..10_000)
            .find_map(|_| {
                let s = self.step().expect("the core answers the SYN");
                (s.label == Label::Row)
                    .then_some(s.out)
                    .flatten()
                    .filter(|o| o.rport == port)
            })
            .expect("a SYN-ACK");
        let mut p = PeerConn {
            sport: port,
            dport: LISTEN,
            iss: ISS,
            snd: ISS + 1,
            rcv: sa.seq.wrapping_add(1),
            dut_iss: sa.seq,
            ts: true,
            ts_val: 5000,
            dut_ts: sa.ts.map_or(0, |(v, _)| v),
            wnd: 65535,
        };
        self.n.peer_ack(&mut p, &[]);
        let c = self.n.accept(self.l);
        self.flows.push(Flow {
            c,
            p,
            feed: true,
            live: true,
            fin_back: false,
        });
        self.flows.len() - 1
    }

    /// 接続 `i` の送信の輪を書き足します。
    fn feed(&mut self, i: usize) {
        let f = &self.flows[i];
        if f.feed {
            let _ = self.n.s.write(self.n.now, f.c, &DATA);
        }
    }

    /// 核の packet を 1 つ読みます。接続の中身つきの segment と FIN は相手がすぐに確認し、送信の輪を書き足します。
    fn step(&mut self) -> Option<Sent> {
        let k = self.n.s.poll_transmit(self.n.now, &mut self.buf)?;
        assert!(k <= TEST_MTU, "packet of {k} bytes exceeds the MTU");
        let pkt = self.buf[..k].to_vec();
        let ip = wire::parse_ipv4(&pkt).expect("the core sent a bad IPv4 packet");
        let s = if ip.proto == wire::PROTO_UDP {
            Sent {
                label: Label::Udp,
                len: k,
                out: None,
            }
        } else {
            let o = parse_out(&pkt);
            let label = if o.has(FLAG_RST) {
                Label::Ctl
            } else if o.has(FLAG_SYN) {
                Label::Row
            } else {
                Label::Conn(o.rport)
            };
            Sent {
                label,
                len: k,
                out: Some(o),
            }
        };
        self.sent.push(s.clone());
        if let (Label::Conn(port), Some(o)) = (s.label, &s.out)
            && (!o.payload.is_empty() || o.has(FLAG_FIN))
            && let Some(i) = self.flows.iter().position(|f| f.p.sport == port)
            && self.flows[i].live
        {
            let f = &mut self.flows[i];
            f.p.absorb(core::slice::from_ref(o));
            self.n.peer_ack(&mut f.p, &[]);
            if o.has(FLAG_FIN) && f.fin_back {
                self.n.peer_fin(&mut f.p);
            }
            self.feed(i);
        }
        Some(s)
    }

    /// 核の packet を `k` 個読みます。
    fn run(&mut self, k: usize) {
        for _ in 0..k {
            self.step().expect("the core has something to send");
        }
    }

    /// 番の状態 (番を持つ枠、番の byte) です。
    fn turn(&self) -> (u32, u32) {
        (self.n.s.s.out.turn, self.n.s.s.out.turn_bytes)
    }

    /// 接続 `i` の枠です。
    fn slot(&self, i: usize) -> u32 {
        self.flows[i].c.slot
    }
}

/// 接続の組の中身つきの segment の (相手のポート, packet の長さ) の列です。
fn conn_data(sent: &[Sent]) -> Vec<(u16, usize)> {
    sent.iter()
        .filter_map(|s| match (s.label, &s.out) {
            (Label::Conn(p), Some(o)) if !o.payload.is_empty() => Some((p, s.len)),
            _ => None,
        })
        .collect()
}

/// 同じ接続が続く区間の (相手のポート, segment の数, byte) の列です。
fn runs(data: &[(u16, usize)]) -> Vec<(u16, usize, usize)> {
    data.chunk_by(|a, b| a.0 == b.0)
        .map(|r| (r[0].0, r.len(), r.iter().map(|x| x.1).sum()))
        .collect()
}

/// 組の位置の列です。接続の組の packet は接続を区別しません。
fn positions(sent: &[Sent]) -> String {
    sent.iter()
        .map(|s| match s.label {
            Label::Conn(_) => 'T',
            Label::Udp => 'U',
            Label::Ctl => 'C',
            Label::Row => 'R',
        })
        .collect()
}

/// 番の状態が規則と合うことを外から確かめます。番を持つ枠は list の先頭にあり、使っている接続の枠です。
fn assert_turn_sane(b: &Bench) {
    let (t, bytes) = b.turn();
    if t == NIL {
        assert_eq!(bytes, 0, "bytes without a turn");
        return;
    }
    assert_eq!(
        b.n.s.s.out.conns.front(),
        Some(t),
        "the holder leads the list"
    );
    assert!(
        !matches!(b.n.s.conns.tcb(t).state, State::Free | State::Closed),
        "the turn points at a slot that is {:?}",
        b.n.s.conns.tcb(t).state
    );
    assert!(bytes > 0 && (bytes as usize) < turn(), "turn bytes {bytes}");
}

// 無効の時

/// 無効の時は、送るものがある接続を 1 segment ずつ list の順に回し、番を持ちません。
fn off_rotates_one_segment_per_connection() {
    let mut b = Bench::new(false, 3);
    b.run(120);
    let data = conn_data(&b.sent);
    assert!(data.len() >= 100);
    for (i, &(port, len)) in data.iter().enumerate() {
        assert_eq!(port, FIRST + (i % 3) as u16, "segment {i}");
        assert_eq!(len, TEST_MTU);
    }
    assert_eq!(b.turn(), (NIL, 0));
}

// 番の長さ

/// 有効の時、3 つの接続がどれも送るものを持てば、list の順にちょうど N segment ずつ続けて送ります。N を
/// 超えて続かず、番の byte は N × MTU に届いた所で終わります。
fn on_runs_each_connection_for_n_segments_in_list_order() {
    let mut b = Bench::new(true, 3);
    for _ in 0..240 {
        b.step().unwrap();
        assert_turn_sane(&b);
    }
    let r = runs(&conn_data(&b.sent));
    assert!(r.len() >= 20, "{r:?}");
    let (last, done) = r.split_last().unwrap();
    for (i, &(port, segs, bytes)) in done.iter().enumerate() {
        assert_eq!(port, FIRST + (i % 3) as u16, "run {i} of {r:?}");
        assert_eq!((segs, bytes), (n(), turn()), "run {i} of {r:?}");
    }
    assert!(last.1 <= n(), "{r:?}");
}

/// 番の長さは segment の数ではなく、番を持つ接続が作った packet の byte で数えます。小さな segment の接続は
/// N を超える segment を続けて送り、byte が N × MTU に届いた packet で番を終えます。
fn a_turn_counts_bytes_of_the_packets_made() {
    let mut b = Bench::with_mss(true, &[536, 1380]);
    b.run(200);
    let r = runs(&conn_data(&b.sent));
    let small = conn_data(&b.sent).iter().find(|x| x.0 == FIRST).unwrap().1;
    assert!(small < TEST_MTU / 2, "{small}");
    let (_, done) = r.split_last().unwrap();
    assert!(done.len() >= 6, "{r:?}");
    for &(port, segs, bytes) in done {
        if port == FIRST {
            assert!(segs > n(), "{r:?}");
            assert!(bytes >= turn() && bytes - small < turn(), "{r:?}");
        } else {
            assert_eq!((segs, bytes), (n(), turn()), "{r:?}");
        }
    }
}

/// 番の途中で送るものが尽きた接続は、その時点で番を終え、次の接続がすぐに自分の番を始めます。残りは
/// 持ち越さず、後で送るものができた接続は、list の末尾から新しい番を得て N segment を送ります。
fn a_turn_ends_when_the_connection_runs_out() {
    let mut b = Bench::opened(true, &[1380; 3]);
    b.flows[0].feed = false;
    let a = b.flows[0].c;
    let few = mid() * (TEST_MTU - 52);
    assert_eq!(b.n.s.write(b.n.now, a, &DATA[..few]), Ok(few));
    b.feed(1);
    b.feed(2);
    b.run(mid());
    assert_eq!(conn_data(&b.sent), vec![(FIRST, TEST_MTU); mid()]);
    assert_eq!(b.turn(), (NIL, 0), "running out ends the turn");
    b.run(1);
    assert_eq!(
        b.turn(),
        (b.slot(1), TEST_MTU as u32),
        "the next connection starts at once"
    );
    b.flows[0].feed = true;
    b.feed(0);
    b.run(60);
    let r = runs(&conn_data(&b.sent));
    assert_eq!(
        r[..5],
        [
            (FIRST, mid(), mid() * TEST_MTU),
            (FIRST + 1, n(), turn()),
            (FIRST + 2, n(), turn()),
            (FIRST, n(), turn()),
            (FIRST + 1, n(), turn()),
        ],
        "{r:?}"
    );
}

// 公平

/// 長い転送で、接続ごとの送った byte の差はどの時点でも 1 回の番と 1 packet の内にあり、どの接続も、次に
/// 送るまでにほかの接続の (接続の数 - 1) × N segment より長く待ちません。
fn fairness_over_a_long_transfer() {
    const K: usize = 4;
    let mut b = Bench::new(true, K);
    b.run(2000);
    let data = conn_data(&b.sent);
    assert!(data.len() >= 1900);
    let mut bytes = [0usize; K];
    let mut last: [Option<usize>; K] = [None; K];
    for (i, &(port, len)) in data.iter().enumerate() {
        let j = usize::from(port - FIRST);
        let waited = i - last[j].map_or(0, |l| l + 1);
        assert!(
            waited <= (K - 1) * n(),
            "connection {j} waited {waited} segments before segment {i}"
        );
        last[j] = Some(i);
        bytes[j] += len;
        let spread = bytes.iter().max().unwrap() - bytes.iter().min().unwrap();
        assert!(
            spread <= turn() + TEST_MTU,
            "after segment {i} the bytes per connection are {bytes:?}"
        );
    }
}

// 組の間の位置

/// 2 つの接続が送り続ける間に、UDP の datagram (`'U'`)、制御の輪の RST と UDP の datagram (`'C'`)、
/// 握手の途中の行の SYN-ACK (`'R'`) を作らせ、核の packet の列を返します。`at` は作らせる packet の番号と種類
/// です。`at` が空なら、有効の核で `TARGETS` の各番号より後の、番の途中にある最初の番号を選んで `at` に入れます。
fn mixed(on: bool, at: &mut Vec<(usize, char)>) -> Vec<Sent> {
    const TARGETS: [(usize, char); 8] = [
        (3, 'U'),
        (12, 'C'),
        (20, 'R'),
        (30, 'U'),
        (45, 'C'),
        (58, 'R'),
        (70, 'U'),
        (80, 'U'),
    ];
    let choose = at.is_empty();
    let mut next = 0;
    let mut b = Bench::new(on, 2);
    for i in 0..100 {
        let kind = if choose {
            let (t, bytes) = b.turn();
            match TARGETS.get(next) {
                Some(&(target, kind)) if i >= target && t != NIL && bytes > 0 => {
                    next += 1;
                    at.push((i, kind));
                    Some(kind)
                }
                _ => None,
            }
        } else {
            at.iter().find(|x| x.0 == i).map(|x| x.1)
        };
        let now = b.n.now;
        let port = 50000 + i as u16;
        match kind {
            Some('U') => {
                for size in [100, 700, 1300] {
                    b.n.s.send_to(now, b.u, &DATA[..size], PEER_UDP).unwrap();
                }
            }
            Some('C') => {
                // 待ち受けの無いポートへの SYN は制御の輪の RST になります。
                b.n.inject(&TSeg {
                    sport: port,
                    dport: 81,
                    seq: ISS,
                    flags: FLAG_SYN,
                    wnd: 65535,
                    ..TSeg::default()
                });
                b.n.s.send_to(now, b.u, &DATA[..200], PEER_UDP).unwrap();
            }
            Some(_) => b.n.inject(&TSeg {
                sport: port,
                dport: LISTEN,
                seq: ISS,
                flags: FLAG_SYN,
                wnd: 65535,
                mss: 1380,
                ..TSeg::default()
            }),
            None => {}
        }
        b.step().unwrap();
    }
    if choose {
        assert_eq!(
            at.len(),
            TARGETS.len(),
            "every injection found a turn: {at:?}"
        );
    }
    b.sent
}

/// 番の途中でも、UDP の datagram、制御の packet、行の packet は番の無い時と同じ位置で出ます。組の間の
/// deficit round robin は TCP の packet 1 つごとに回ります。有効の核で番の途中に当たる時に作らせ、無効の核
/// では同じ番号の時に作らせて比べます。
fn udp_control_and_rows_keep_their_positions_mid_turn() {
    let mut at = Vec::new();
    let on = mixed(true, &mut at);
    let off = mixed(false, &mut at);
    let (p_off, p_on) = (positions(&off), positions(&on));
    for c in ['U', 'C', 'R'] {
        assert!(p_off.contains(c), "{p_off}");
    }
    assert_eq!(
        p_on, p_off,
        "on and off put the other classes at the same places"
    );
    // 試験が番を見ていることの確かめ:有効の時は N segment ずつ続き、無効の時は 1 つずつ入れ替わります。
    let longest = |s: &[Sent]| runs(&conn_data(s)).iter().map(|r| r.1).max();
    assert_eq!(longest(&off), Some(1));
    assert_eq!(longest(&on), Some(n()));
}

/// 番は接続の間の packet の順だけを変え、接続ごとの segment の作り方と順は変えません。
fn each_connection_sends_the_same_segments_on_and_off() {
    let per_conn = |on: bool| {
        let mut b = Bench::new(on, 3);
        b.run(300);
        let mut v: [Vec<SegShape>; 3] = Default::default();
        for s in &b.sent {
            if let (Label::Conn(p), Some(o)) = (s.label, &s.out) {
                v[usize::from(p - FIRST)].push((o.seq, o.ack, o.flags, o.wnd, o.payload.len()));
            }
        }
        v
    };
    let (off, on) = (per_conn(false), per_conn(true));
    for j in 0..3 {
        let k = off[j].len().min(on[j].len());
        assert!(k >= 90, "{k}");
        assert_eq!(off[j][..k], on[j][..k], "connection {j}");
    }
}

// 呼び出しの境目とバッチの境目

/// 番の状態は核の中にあり、`poll_transmit` の呼び出しの境目を越えて続きます。呼び手のバッチの間に入る入力
/// (時刻の進み、ほかの接続の書き込みと相手のデータ、UDP の受信、番を持つ接続への確認) も番を終えません。
fn a_turn_carries_across_calls_and_batches() {
    let mut b = Bench::new(true, 2);
    b.run(mid());
    let held = b.turn();
    assert_eq!(held, (b.slot(0), (mid() * TEST_MTU) as u32));
    // バッチの境目に入る入力
    b.n.advance(Duration::from_millis(1));
    b.feed(1);
    let p = &mut b.flows[1].p;
    b.n.peer_ack(p, &[7; 100]);
    let pkt = crate::testnet_tests::build_udp(PEER_UDP, 53, &[1; 50]);
    b.n.write(&pkt);
    let p = &mut b.flows[0].p;
    b.n.peer_ack(p, &[]);
    assert_eq!(b.turn(), held, "input between batches keeps the turn");
    // 3 つずつのバッチで引き、バッチの間で時刻を進めます。
    for _ in 0..30 {
        b.run(3);
        assert_turn_sane(&b);
        b.n.advance(Duration::from_micros(100));
    }
    let r = runs(&conn_data(&b.sent));
    let (_, done) = r.split_last().unwrap();
    assert!(done.len() >= 8, "{r:?}");
    for (i, &(port, segs, _)) in done.iter().enumerate() {
        assert_eq!(
            (port, segs),
            (FIRST + (i % 2) as u16, n()),
            "run {i} of {r:?}"
        );
    }
}

// 外れる枠

/// 番を持つ接続を破棄すると、その場で番が終わります。次の接続は持ち越しの無い新しい番で N segment を送ります。
fn aborting_the_holder_ends_its_turn() {
    let mut b = Bench::new(true, 3);
    b.run(mid());
    assert_eq!(b.turn().0, b.slot(0));
    b.flows[0].live = false;
    b.flows[0].feed = false;
    let a = b.flows[0].c;
    b.n.s.abort(b.n.now, a);
    assert_eq!(b.turn(), (NIL, 0), "an aborted holder leaves no turn");
    b.n.check();
    b.sent.clear();
    for _ in 0..60 {
        b.step().unwrap();
        assert_turn_sane(&b);
    }
    assert!(
        b.sent.iter().any(|s| s.label == Label::Ctl),
        "abort sends a RST"
    );
    let r = runs(&conn_data(&b.sent));
    let (_, done) = r.split_last().unwrap();
    for (i, &(port, segs, _)) in done.iter().enumerate() {
        assert_eq!((port, segs), (FIRST + 1 + (i % 2) as u16, n()), "{r:?}");
    }
}

/// 番を持つ接続が相手の RST で閉じると、その場で番が終わります。
fn a_peer_reset_of_the_holder_ends_its_turn() {
    let mut b = Bench::new(true, 3);
    b.run(mid());
    assert_eq!(b.turn().0, b.slot(0));
    b.flows[0].live = false;
    b.flows[0].feed = false;
    let rst = b.flows[0].p.seg(FLAG_RST | FLAG_ACK, &[]);
    b.n.s
        .handle_packet(b.n.now, &crate::testnet_tests::build_peer(&rst));
    assert_eq!(b.n.s.conns.tcb(b.slot(0)).state, State::Closed);
    assert_eq!(b.turn(), (NIL, 0), "a reset holder leaves no turn");
    b.n.check();
    b.sent.clear();
    for _ in 0..60 {
        b.step().unwrap();
        assert_turn_sane(&b);
    }
    let r = runs(&conn_data(&b.sent));
    assert_eq!(r[0], (FIRST + 1, n(), turn()), "{r:?}");
    assert!(r.iter().all(|x| x.0 != FIRST), "{r:?}");
}

/// 番を持つ接続を破棄し、その枠を新しい接続が使い直しても、番は古い枠を指しません。新しい接続は list の
/// 末尾から自分の番を得ます。
fn a_reused_slot_does_not_inherit_the_turn() {
    let mut b = Bench::new(true, 3);
    b.run(mid());
    let old = b.flows[0].c;
    assert_eq!(b.turn().0, old.slot);
    b.flows[0].live = false;
    b.flows[0].feed = false;
    b.n.s.abort(b.n.now, old);
    let d = b.open(FIRST + 10, 1380);
    let new = b.flows[d].c;
    assert_eq!(new.slot, old.slot, "the freed slot is used first");
    assert_ne!(new.generation, old.generation);
    assert_ne!(
        b.turn().0,
        new.slot,
        "the new connection has sent nothing yet"
    );
    b.n.check();
    b.feed(d);
    b.sent.clear();
    for _ in 0..80 {
        b.step().unwrap();
        assert_turn_sane(&b);
    }
    let r = runs(&conn_data(&b.sent));
    let (_, done) = r.split_last().unwrap();
    let first_new = done
        .iter()
        .position(|x| x.0 == FIRST + 10)
        .expect("the new connection sends");
    assert_eq!(done[first_new], (FIRST + 10, n(), turn()), "{r:?}");
    assert!(done.iter().all(|x| x.1 == n()), "{r:?}");
}

/// 番を持つ接続をアプリケーションが閉じると、送り残しを送る間は番を使い、送り終えて TIME_WAIT の行に移り
/// 枠を返した後も、番は返した枠を指しません。
fn closing_the_holder_leaves_no_stale_turn() {
    let mut b = Bench::new(true, 3);
    b.run(mid());
    let a = b.flows[0].c;
    assert_eq!(b.turn().0, a.slot);
    b.flows[0].feed = false;
    b.flows[0].fin_back = true;
    b.n.s.close_conn(b.n.now, a);
    b.n.check();
    assert_eq!(b.turn().0, a.slot, "the holder still has data to send");
    let mut steps = 0;
    while b.n.s.conns.tcb(a.slot).state != State::Free {
        steps += 1;
        assert!(steps < 5000, "{:?}", b.n.s.conns.tcb(a.slot).state);
        b.step().unwrap();
        assert_turn_sane(&b);
    }
    for _ in 0..40 {
        b.step().unwrap();
        assert_turn_sane(&b);
    }
    assert_eq!(
        b.n.s.conns.tcb(a.slot).state,
        State::Free,
        "the closed connection moved to a row and returned its slot"
    );
    assert!(b.sent.iter().any(|s| {
        s.out
            .as_ref()
            .is_some_and(|o| o.rport == FIRST && o.has(FLAG_FIN))
    }));
    let r = runs(&conn_data(&b.sent));
    assert!(r.iter().all(|x| x.1 <= n()), "{r:?}");
}

/// 不変条件の検査は、古い番 (list の先頭に無い枠、list から外れた枠、長さに届いた byte、無効の核の番) を
/// 見つけます。
fn check_invariants_catches_a_stale_turn() {
    let mut b = Bench::new(true, 2);
    b.run(mid());
    let (t, bytes) = b.turn();
    assert_eq!(t, b.slot(0));
    let caught = |b: &mut Bench| {
        let full = b.n.s.check_invariants();
        let part =
            b.n.s
                .check_invariants_touched(&mut crate::TouchedCheck::new());
        assert!(full.is_err() && part.is_err(), "{full:?} {part:?}");
    };
    // 番が list の先頭に無い接続を指します。
    b.n.s.s.out.turn = b.slot(1);
    caught(&mut b);
    b.n.s.s.out.turn = t;
    // 番が list から外れた枠を指します。
    b.n.s.s.out.conns.remove(t);
    caught(&mut b);
    b.n.s.s.out.conns.push_back(t);
    b.n.s.s.out.conns.move_to_front(t);
    // 番の byte が長さに届いています。
    b.n.s.s.out.turn_bytes = b.n.s.s.out.turn_limit;
    caught(&mut b);
    b.n.s.s.out.turn_bytes = bytes;
    b.n.s.check_invariants().unwrap();
    // 無効の核が番を持ちます。
    let mut off = Bench::new(false, 2);
    off.run(1);
    off.n.s.s.out.turn = off.n.s.s.out.conns.front().unwrap();
    off.n.s.s.out.turn_bytes = 1;
    caught(&mut off);
}

/// 試験 `t` を番の長さ `n` で流します。
fn with_n(n: u8, t: fn()) {
    TURN_N.set(n);
    t();
}

/// 番の長さ `$n` で、同じ規則の試験を module `$m` として流します。
macro_rules! rules_at {
    ($m:ident, $n:expr; $($t:ident),* $(,)?) => {
        mod $m {
            $(
                #[test]
                fn $t() {
                    super::with_n($n, super::$t);
                }
            )*
        }
    };
}

macro_rules! rules_at_each_n {
    ($($t:ident),* $(,)?) => {
        rules_at!(n2, 2; $($t),*);
        rules_at!(n4, 4; $($t),*);
        rules_at!(n8, 8; $($t),*);
    };
}

rules_at_each_n!(
    off_rotates_one_segment_per_connection,
    on_runs_each_connection_for_n_segments_in_list_order,
    a_turn_counts_bytes_of_the_packets_made,
    a_turn_ends_when_the_connection_runs_out,
    fairness_over_a_long_transfer,
    udp_control_and_rows_keep_their_positions_mid_turn,
    each_connection_sends_the_same_segments_on_and_off,
    a_turn_carries_across_calls_and_batches,
    aborting_the_holder_ends_its_turn,
    a_peer_reset_of_the_holder_ends_its_turn,
    a_reused_slot_does_not_inherit_the_turn,
    closing_the_holder_leaves_no_stale_turn,
    check_invariants_catches_a_stale_turn
);
