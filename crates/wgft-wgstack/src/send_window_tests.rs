//! 相手の窓 (SND.WND) の更新の規則の試験です (RFC 9293 3.10.7.4 の SND.WL1 と SND.WL2、wgstack-rs.md の
//! 「相手の窓の更新」)。
//!
//! 核は SND.UNA を進める ACK の窓を、SEG.SEQ が SND.WL1 より前でも使い、SEG.ACK が SND.UNA より前の segment の
//! 窓は使いません。並べ替えで遅れた古い segment が窓を戻さないこと、SND.WL1 が前の番号に戻ること、窓が 0 の時と
//! 窓の probe、窓の scale の端、番号の 1 周をまたぐ所、核の RTO の後と相手の FIN の後も確かめます。

#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "test helpers"
)]
#![expect(
    clippy::cast_possible_truncation,
    clippy::many_single_char_names,
    reason = "test helpers"
)]

use crate::seq;
use crate::tcp::conn::ConnId;
use crate::testnet_tests::{Out, PeerConn, TSeg, TestNet, show, small_limits};
use crate::wire::{FLAG_ACK, FLAG_FIN, FLAG_SYN};
use core::time::Duration;

/// 相手の SYN が示す条件です。
#[derive(Clone, Copy)]
struct Open {
    /// 相手の ISN です。
    peer_iss: u32,
    /// 核の ISN をこの値にします。`None` なら時刻 0 の ISN のままです。
    dut_iss: Option<u32>,
    ts: bool,
    /// 相手が示す窓の scale です。
    ws: Option<u8>,
}

const PLAIN: Open = Open {
    peer_iss: 1000,
    dut_iss: None,
    ts: false,
    ws: Some(7),
};

/// 時刻 `now` に相手の SYN を送り、握手を済ませた接続を返します。
fn open_at(o: Open, now: Duration) -> (TestNet, ConnId, PeerConn) {
    let mut n = TestNet::new(small_limits());
    if !now.is_zero() {
        n.advance(now);
    }
    let l = n.listen(80);
    n.inject(&TSeg {
        sport: 40000,
        dport: 80,
        seq: o.peer_iss,
        flags: FLAG_SYN,
        wnd: 65535,
        mss: 1380,
        ws: o.ws,
        ts: o.ts.then_some((5000, 0)),
        ..TSeg::default()
    });
    let outs = n.drain();
    assert!(
        outs.len() == 1 && outs[0].flags == FLAG_SYN | FLAG_ACK,
        "expected one SYN-ACK, got {}",
        show(&outs)
    );
    let sa = &outs[0];
    let mut p = PeerConn {
        sport: 40000,
        dport: 80,
        iss: o.peer_iss,
        snd: o.peer_iss.wrapping_add(1),
        rcv: sa.seq.wrapping_add(1),
        dut_iss: sa.seq,
        ts: o.ts,
        ts_val: 5000,
        dut_ts: sa.ts.map_or(0, |(v, _)| v),
        wnd: 65535,
    };
    n.peer_ack(&mut p, &[]);
    let c = n.accept(l);
    n.drain();
    (n, c, p)
}

/// `o` の条件で握手を済ませます。`o.dut_iss` があれば、核の ISN がその値になる時刻に SYN を送ります。核の ISN は
/// 「時刻の 4 µs ごとに 1 進む値」と 4 つ組の hash の和なので、時刻 0 の ISN から時刻を求めます。
fn open(o: Open) -> (TestNet, ConnId, PeerConn) {
    let Some(target) = o.dut_iss else {
        return open_at(o, Duration::ZERO);
    };
    let (_, _, probe) = open_at(o, Duration::ZERO);
    let ticks = target.wrapping_sub(probe.dut_iss);
    let r = open_at(o, Duration::from_micros(u64::from(ticks) * 4));
    assert_eq!(r.2.dut_iss, target, "the ISS model changed");
    r
}

fn scale(o: Open) -> u32 {
    u32::from(o.ws.map_or(0, |s| s.min(14)))
}

/// 中身の終わりが `edge` より先の segment を示します。
fn sent_past(outs: &[Out], edge: u32) -> Vec<String> {
    outs.iter()
        .filter(|o| {
            let end = o.seq.wrapping_add(o.payload.len() as u32);
            !o.payload.is_empty() && seq::gt(end, edge)
        })
        .map(ToString::to_string)
        .collect()
}

fn snd_wnd(n: &mut TestNet, c: ConnId) -> u32 {
    n.s.conn(c.slot).t.snd_wnd
}

/// 相手の窓を `w0` (窓の欄の値) にし、核に `total` byte を書かせて最初に送った量を返します。続けて相手のデータ
/// A と B を作り、B だけを核に届けます (A は失われました)。B が SND.WL1 を B の番号に進めます。
fn lose_a_deliver_b(
    n: &mut TestNet,
    c: ConnId,
    p: &mut PeerConn,
    w0: u16,
    total: usize,
) -> (u32, TSeg) {
    p.wnd = w0;
    n.peer_ack(p, &[]);
    n.drain();
    n.s.write(n.now, c, &vec![b'z'; total]).unwrap();
    let first = n.drain();
    let sent: u32 = first.iter().map(|o| o.payload.len() as u32).sum();
    assert!(sent > 0, "{}", show(&first));
    let a = p.seg(FLAG_ACK, &[b'a'; 100]);
    p.snd = p.snd.wrapping_add(100);
    let b = p.seg(FLAG_ACK, &[b'b'; 100]);
    p.snd = p.snd.wrapping_add(100);
    n.inject(&b);
    n.drain();
    (sent, a)
}

/// 相手が自分のデータの再送 (SEG.SEQ < SND.WL1) に新しい累積の確認と小さめの窓を載せたとき、核はその segment の
/// 窓を使い、相手が広告した右端の先へ新しいデータを送りません。SEG.SEQ だけで新しさを決める RFC 9293 3.10.7.4 の
/// SND.WL1 の規則では、核はこの窓を使わず、前の窓を新しい SND.UNA から測って右端の先へ送ります。
#[test]
fn ack_on_a_peer_retransmission_does_not_extend_the_send_window() {
    let mut n = TestNet::new(small_limits());
    let (c, mut p) = n.accepted(false);
    // 窓を 2816 byte に絞ります (窓の scale は 7)。
    p.wnd = 22;
    n.peer_ack(&mut p, &[]);
    n.drain();
    n.s.write(n.now, c, &vec![b'z'; 20_000]).unwrap();
    let first = n.drain();
    let sent: u32 = first.iter().map(|o| o.payload.len() as u32).sum();
    assert_eq!(sent, 2760, "{}", show(&first));
    // 相手のデータ A と B のうち、B だけが届きます (A は失われました)。
    let a = p.seg(FLAG_ACK, &[b'a'; 100]);
    p.snd = p.snd.wrapping_add(100);
    let b = p.seg(FLAG_ACK, &[b'b'; 100]);
    p.snd = p.snd.wrapping_add(100);
    n.inject(&b);
    n.drain();
    // 相手は A を再送し、その segment で核の 2760 byte を確認して窓を 1024 byte にします。広告する右端は
    // 前の右端 (確認の前の SND.UNA + 2816) より 968 byte 先へ進み、戻っていません。
    let mut a2 = a.clone();
    a2.ack = p.rcv.wrapping_add(sent);
    a2.wnd = 8;
    let edge = a2.ack.wrapping_add(8 << 7);
    n.inject(&a2);
    let outs = n.drain();
    let beyond = sent_past(&outs, edge);
    assert!(
        beyond.is_empty(),
        "the core sent past the advertised right edge {edge}: {beyond:?}"
    );
    assert!(
        outs.iter().any(|o| !o.payload.is_empty()),
        "the core sent nothing into the window up to {edge}: {}",
        show(&outs)
    );
}

/// 上の形を、窓の scale の無い相手、scale 0 の相手、相手と核の番号が 1 周をまたぐ所で確かめます。核は再送の
/// segment に載った窓をそのまま使い (SND.WND がその窓になり)、その右端の先へ送りません。
#[test]
fn ack_on_a_peer_retransmission_takes_its_window_across_scales_and_the_wrap() {
    let cases = [
        // 窓の scale を交渉しない相手。窓の欄は byte です。
        (Open { ws: None, ..PLAIN }, 2816, 1024),
        // scale 0 を示す相手。
        (
            Open {
                ws: Some(0),
                ..PLAIN
            },
            2816,
            1024,
        ),
        // 相手の番号が B の中で 2^32 をまたぎ (A は 2^32 - 150 から、B は 2^32 - 50 から 50 まで)、核の確認
        // (SND.UNA) も 2^32 をまたぎます。
        (
            Open {
                peer_iss: u32::MAX - 150,
                dut_iss: Some(u32::MAX - 1000),
                ts: true,
                ws: Some(7),
            },
            22,
            8,
        ),
        // 相手の番号が A の中で 2^32 をまたぎ、核の番号が 2^31 の境をまたぎます。
        (
            Open {
                peer_iss: u32::MAX - 50,
                dut_iss: Some((1 << 31) - 1500),
                ts: true,
                ws: Some(7),
            },
            22,
            8,
        ),
    ];
    for (o, w0, w1) in cases {
        let (mut n, c, mut p) = open(o);
        let (sent, a) = lose_a_deliver_b(&mut n, c, &mut p, w0, 20_000);
        let mut a2 = a.clone();
        a2.ack = p.rcv.wrapping_add(sent);
        a2.wnd = w1;
        let w = u32::from(w1) << scale(o);
        let edge = a2.ack.wrapping_add(w);
        n.inject(&a2);
        let outs = n.drain();
        let beyond = sent_past(&outs, edge);
        assert!(
            beyond.is_empty(),
            "peer iss {} dut iss {:?} ws {:?}: the core sent past the advertised right edge {edge}: {beyond:?}",
            o.peer_iss,
            o.dut_iss,
            o.ws
        );
        assert_eq!(
            snd_wnd(&mut n, c),
            w,
            "peer iss {} ws {:?}",
            o.peer_iss,
            o.ws
        );
        // 続く相手の ACK で窓が開けば、核はその右端まで送ります。
        p.rcv = a2.ack;
        p.wnd = w0;
        n.peer_ack(&mut p, &[]);
        let outs = n.drain();
        let edge = p.rcv.wrapping_add(u32::from(w0) << scale(o));
        assert!(sent_past(&outs, edge).is_empty(), "{}", show(&outs));
        assert!(
            outs.iter().any(|o| !o.payload.is_empty()),
            "the core did not send into the reopened window: {}",
            show(&outs)
        );
    }
}

/// 相手が再送の segment に載せた確認で窓を 0 にしたとき、核はその 0 を使い、新しいデータを送らずに窓の probe に
/// 移ります。窓の scale が最大の 14 (窓の欄の 1 が 16 KiB) の相手で確かめます。窓が開けば probe を止めて送ります。
#[test]
fn zero_window_on_a_peer_retransmission_starts_the_persist_timer() {
    let o = Open {
        ts: true,
        ws: Some(14),
        ..PLAIN
    };
    let (mut n, c, mut p) = open(o);
    let (sent, a) = lose_a_deliver_b(&mut n, c, &mut p, 1, 40_000);
    assert!(sent <= 1 << 14, "{sent}");
    let mut a2 = a.clone();
    a2.ack = p.rcv.wrapping_add(sent);
    a2.wnd = 0;
    n.inject(&a2);
    let outs = n.drain();
    let beyond = sent_past(&outs, a2.ack);
    assert!(
        beyond.is_empty(),
        "the core sent into a zero window: {beyond:?}"
    );
    assert_eq!(snd_wnd(&mut n, c), 0);
    assert!(n.s.conn(c.slot).t.persist, "the core did not start probing");
    p.rcv = a2.ack;
    p.wnd = 0;
    // 窓の probe (SND.UNA - 1 の番号の中身の無い segment) に窓 0 のまま応えます。その間に中身は送りません。
    let mut probes = 0;
    for _ in 0..40 {
        n.advance(Duration::from_millis(100));
        let outs = n.drain();
        assert!(outs.iter().all(|o| o.payload.is_empty()), "{}", show(&outs));
        if outs.iter().any(|o| o.seq == p.rcv.wrapping_sub(1)) {
            probes += 1;
            n.peer_ack(&mut p, &[]);
            n.drain();
        }
    }
    assert!(probes >= 2, "{probes}");
    assert!(n.s.conn(c.slot).t.persist);
    // 窓を開くと、核は probe を止めて右端まで送ります。
    p.wnd = 1;
    n.peer_ack(&mut p, &[]);
    let outs = n.drain();
    assert!(!n.s.conn(c.slot).t.persist);
    assert!(
        sent_past(&outs, p.rcv.wrapping_add(1 << 14)).is_empty(),
        "{}",
        show(&outs)
    );
    assert!(
        outs.iter().any(|o| !o.payload.is_empty()),
        "{}",
        show(&outs)
    );
}

/// 窓を開く ACK の後に、並べ替えで遅れた古い ACK (SEG.ACK < SND.UNA) が大きな窓を運んで届いても、核は窓を
/// 変えません。相手の再送の segment が SND.WL1 を戻した後に、それより先の番号の古い segment が届く場合も
/// 同じです (RFC 9293 3.10.7.4 は SND.UNA =< SEG.ACK の時だけ窓を更新します)。
#[test]
fn old_ack_after_a_newer_one_does_not_change_the_window() {
    // 相手は A、B の後に C (中身か中身の無い ACK) を古い確認と大きな窓で送り、その後に A を新しい確認で再送します。
    // C は遅れて、再送の A の後に届きます。C の番号は A より先なので、A が戻した SND.WL1 の規則だけでは断れません。
    for len in [100, 0] {
        let (mut n, c, mut p) = open(PLAIN);
        let (sent, a) = lose_a_deliver_b(&mut n, c, &mut p, 22, 20_000);
        p.wnd = 200;
        let c_late = p.seg(FLAG_ACK, &vec![b'c'; len]);
        p.snd = p.snd.wrapping_add(len as u32);
        assert_eq!(c_late.ack, a.ack);
        let mut a2 = a.clone();
        a2.ack = p.rcv.wrapping_add(sent);
        a2.wnd = 8;
        let edge = a2.ack.wrapping_add(8 << 7);
        n.inject(&a2);
        n.drain();
        assert_eq!(snd_wnd(&mut n, c), 8 << 7);
        n.inject(&c_late);
        let outs = n.drain();
        assert_eq!(
            snd_wnd(&mut n, c),
            8 << 7,
            "len {len}: an old ACK changed the window"
        );
        let beyond = sent_past(&outs, edge);
        assert!(
            beyond.is_empty(),
            "len {len}: the core sent past {edge}: {beyond:?}"
        );
        // C の中身は受け入れます (窓を使わないだけです)。
        assert_eq!(n.read_all(c).len(), 200 + len);
    }

    // 相手のデータを挟まない中身の無い ACK の並べ替え:新しい確認と小さな窓の後に、古い確認と大きな窓が届きます。
    let (mut n, c, mut p) = open(PLAIN);
    p.wnd = 22;
    n.peer_ack(&mut p, &[]);
    n.drain();
    n.s.write(n.now, c, &vec![b'z'; 20_000]).unwrap();
    let first = n.drain();
    let una0 = p.rcv;
    p.rcv = una0.wrapping_add(first[0].payload.len() as u32);
    p.wnd = 200;
    let older = p.seg(FLAG_ACK, &[]);
    p.rcv = una0.wrapping_add(first.iter().map(|o| o.payload.len() as u32).sum());
    p.wnd = 4;
    let newer = p.seg(FLAG_ACK, &[]);
    n.inject(&newer);
    n.drain();
    n.inject(&older);
    let outs = n.drain();
    assert_eq!(snd_wnd(&mut n, c), 4 << 7, "an old ACK changed the window");
    let beyond = sent_past(&outs, newer.ack.wrapping_add(4 << 7));
    assert!(beyond.is_empty(), "{beyond:?}");
}

/// SND.UNA を進めない segment では RFC 9293 の SND.WL1 の規則がそのまま効きます。同じ確認を持つ相手のデータの
/// うち、後の B が先に届いて窓を決めた後に、遅れた A (SEG.SEQ < SND.WL1) が別の窓を運んでも、核は窓を変え
/// ません。同じ番号と同じ確認の segment (窓の更新) は、窓を縮めるものも 0 にするものも使います。
#[test]
fn reordered_segment_with_the_same_ack_follows_wl1() {
    let (mut n, c, mut p) = open(PLAIN);
    p.wnd = 22;
    n.peer_ack(&mut p, &[]);
    n.drain();
    // 確認は同じ (核はまだ何も送っていません) で、A は窓 30、B は窓 20 を運びます。
    p.wnd = 30;
    let a = p.seg(FLAG_ACK, &[b'a'; 100]);
    p.snd = p.snd.wrapping_add(100);
    p.wnd = 20;
    let b = p.seg(FLAG_ACK, &[b'b'; 100]);
    p.snd = p.snd.wrapping_add(100);
    n.inject(&b);
    n.drain();
    assert_eq!(snd_wnd(&mut n, c), 20 << 7);
    n.inject(&a);
    n.drain();
    assert_eq!(
        snd_wnd(&mut n, c),
        20 << 7,
        "an older segment with the same ACK changed the window"
    );
    // 窓の更新:同じ番号と同じ確認で窓を縮め、次に 0 にします。
    p.wnd = 10;
    n.peer_ack(&mut p, &[]);
    n.drain();
    assert_eq!(snd_wnd(&mut n, c), 10 << 7);
    p.wnd = 0;
    n.peer_ack(&mut p, &[]);
    n.drain();
    assert_eq!(snd_wnd(&mut n, c), 0);
    // 窓が 0 の間に書いたデータは送らず、probe を待ちます。
    n.s.write(n.now, c, &[b'w'; 500]).unwrap();
    let outs = n.drain();
    assert!(outs.iter().all(|o| o.payload.is_empty()), "{}", show(&outs));
    assert!(n.s.conn(c.slot).t.persist);
}

/// 窓を更新した segment の番号が SND.WL1 になるので、SND.WL1 は前の番号に戻ります。相手のデータ A と B が
/// 失われて C だけが届き (SND.WL1 は C の番号)、相手が A を新しい確認と窓 0 で再送すると、SND.WL1 は A の番号に
/// 戻ります。その後に相手が送る窓の更新は、同じ確認と B の番号 (A の再送の後の相手の SND.NXT で、C より前) を
/// 持ちます。核はこの窓を使って送ります。SND.WL1 を C の番号に残すと、この更新を古い segment とみなして断り、
/// 窓 0 のまま止まります。
#[test]
fn window_update_after_wl1_moved_back_is_taken() {
    let (mut n, c, mut p) = open(PLAIN);
    p.wnd = 22;
    n.peer_ack(&mut p, &[]);
    n.drain();
    n.s.write(n.now, c, &vec![b'z'; 20_000]).unwrap();
    let first = n.drain();
    let sent: u32 = first.iter().map(|o| o.payload.len() as u32).sum();
    let a = p.seg(FLAG_ACK, &[b'a'; 100]);
    p.snd = p.snd.wrapping_add(100);
    let b_seq = p.snd;
    p.snd = p.snd.wrapping_add(100); // B は失われました
    let c_seg = p.seg(FLAG_ACK, &[b'c'; 100]);
    p.snd = p.snd.wrapping_add(100);
    n.inject(&c_seg);
    n.drain();
    assert_eq!(n.s.conn(c.slot).t.snd_wl1, c_seg.seq);
    let mut a2 = a.clone();
    a2.ack = p.rcv.wrapping_add(sent);
    a2.wnd = 0;
    n.inject(&a2);
    n.drain();
    assert_eq!(snd_wnd(&mut n, c), 0);
    assert_eq!(
        n.s.conn(c.slot).t.snd_wl1,
        a.seq,
        "SND.WL1 did not move back"
    );
    p.rcv = a2.ack;
    p.snd = b_seq;
    p.wnd = 22;
    n.peer_ack(&mut p, &[]);
    let outs = n.drain();
    assert_eq!(snd_wnd(&mut n, c), 22 << 7, "{}", show(&outs));
    assert!(
        sent_past(&outs, p.rcv.wrapping_add(22 << 7)).is_empty(),
        "{}",
        show(&outs)
    );
    assert!(
        outs.iter().any(|o| !o.payload.is_empty()),
        "the core did not send into the reopened window: {}",
        show(&outs)
    );
}

/// 核の RTO の後でも、相手の再送の segment に載った SND.UNA を進める ACK の窓を使います。核が先頭を再送した後に、
/// 相手が A を再送して送ったものをすべて確認し、窓を 1024 byte にします。
#[test]
fn ack_on_a_peer_retransmission_after_the_cores_rto() {
    let (mut n, c, mut p) = open(PLAIN);
    let (sent, a) = lose_a_deliver_b(&mut n, c, &mut p, 22, 20_000);
    let mut rtx = Vec::new();
    for _ in 0..30 {
        n.advance(Duration::from_millis(100));
        rtx.extend(n.drain());
        if !rtx.is_empty() {
            break;
        }
    }
    assert!(
        rtx.iter().any(|o| o.seq == p.rcv && !o.payload.is_empty()),
        "the core did not retransmit after its RTO: {}",
        show(&rtx)
    );
    let mut a2 = a.clone();
    a2.ack = p.rcv.wrapping_add(sent);
    a2.wnd = 8;
    let edge = a2.ack.wrapping_add(8 << 7);
    n.inject(&a2);
    let outs = n.drain();
    assert_eq!(snd_wnd(&mut n, c), 8 << 7);
    let beyond = sent_past(&outs, edge);
    assert!(beyond.is_empty(), "the core sent past {edge}: {beyond:?}");
}

/// 相手の FIN が順番の外で先に届いた後も同じです。B が FIN を運び、失われた A の再送が新しい確認と小さめの窓を
/// 運びます。核は窓を使い、A と B の中身と FIN を受け取ります。
#[test]
fn ack_on_a_peer_retransmission_after_its_fin() {
    let (mut n, c, mut p) = open(PLAIN);
    p.wnd = 22;
    n.peer_ack(&mut p, &[]);
    n.drain();
    n.s.write(n.now, c, &vec![b'z'; 20_000]).unwrap();
    let first = n.drain();
    let sent: u32 = first.iter().map(|o| o.payload.len() as u32).sum();
    let a = p.seg(FLAG_ACK, &[b'a'; 100]);
    p.snd = p.snd.wrapping_add(100);
    let b = p.seg(FLAG_ACK | FLAG_FIN, &[b'b'; 100]);
    p.snd = p.snd.wrapping_add(101);
    n.inject(&b);
    n.drain();
    let mut a2 = a.clone();
    a2.ack = p.rcv.wrapping_add(sent);
    a2.wnd = 8;
    let edge = a2.ack.wrapping_add(8 << 7);
    n.inject(&a2);
    let outs = n.drain();
    assert_eq!(snd_wnd(&mut n, c), 8 << 7);
    let beyond = sent_past(&outs, edge);
    assert!(beyond.is_empty(), "the core sent past {edge}: {beyond:?}");
    assert!(
        outs.iter().any(|o| o.ack == p.snd),
        "the core did not acknowledge the FIN: {}",
        show(&outs)
    );
    assert_eq!(n.read_all(c).len(), 200);
}
