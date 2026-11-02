//! TCP の正しさの監査で足した決定的な試験です。RFC との一致と、境目の条件の挙動を固定します。

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
use crate::testnet_tests::{Out, PeerConn, TestNet, show, small_limits};
use crate::wire::FLAG_ACK;
use core::time::Duration;

fn right_edge(o: &Out) -> u32 {
    o.ack.wrapping_add(u32::from(o.wnd) << 7)
}

/// 相手から 2^scale の倍数でない長さの segment を受け、核の ACK が広告する右端 (SEG.ACK + SEG.WND << scale) を
/// 集めます。`(最も先の右端, 最も先の右端より手前に見えた量の最大)` を返します。
fn advertised_edges(n: &mut TestNet, c: crate::ConnId, p: &mut PeerConn) -> (u32, u32) {
    let mut max_edge: Option<u32> = None;
    let mut worst = 0;
    for i in 0..400 {
        n.peer_ack(p, &[b'x'; 100]);
        n.advance(Duration::from_millis(50)); // 遅延 ACK を出させます
        for o in n.drain().iter().filter(|o| o.has(FLAG_ACK)) {
            let r = right_edge(o);
            if let Some(m) = max_edge
                && seq::lt(r, m)
            {
                worst = worst.max(m.wrapping_sub(r));
            }
            max_edge = Some(max_edge.map_or(r, |m| seq::max(m, r)));
        }
        if i % 7 == 0 {
            n.read_all(c);
        }
    }
    (max_edge.expect("the core sent ACKs"), worst)
}

/// 窓の欄は右端までの byte を scale で割って切り下げるので、相手から見える右端は前に見えた右端より最大
/// 2^scale - 1 byte 手前になります (wgstack.md の RFC 7323 の項が受け入れた性質。RFC 9293 の SHLD-14 と、切り上げる
/// Linux の tcp_select_window とは違います)。戻りがこの幅に収まり、核が前に広告した最も先の右端までのデータを
/// 受け入れることを確かめます。
#[test]
fn receded_edge_is_bounded_and_earlier_edge_data_is_accepted() {
    let mut n = TestNet::new(small_limits());
    let (c, mut p) = n.accepted(true);
    let (max_edge, worst) = advertised_edges(&mut n, c, &mut p);
    assert!(worst > 0, "the setup no longer shows the rounding");
    assert!(worst < 1 << 7, "the edge receded by {worst} bytes");
    n.read_all(c);
    // 読まずに、最も先に広告した右端までを segment の列で埋めます。
    let mut outs = Vec::new();
    while p.snd != max_edge {
        let k = (max_edge.wrapping_sub(p.snd) as usize).min(1300);
        n.peer_ack(&mut p, &vec![b'y'; k]);
        outs = n.drain();
    }
    n.advance(Duration::from_millis(50));
    outs.extend(n.drain());
    assert!(
        outs.iter().any(|o| o.ack == max_edge),
        "the core did not take the data up to its earlier edge {max_edge}: {}",
        show(&outs)
    );
    assert_eq!(n.s.stats().recv_trimmed, 0);
}

/// 送ったデータが飛んでいる間に相手が窓を 0 に縮め、その後は再送のたびに窓が 0 の ACK を返し続けます。相手は
/// 応えているので、接続を打ち切りません (RFC 9293 3.8.6.1 の MUST-36。Linux の tcp_retransmit_timer も、窓が 0
/// の相手が RTO_MAX の内に応える間は打ち切りません)。
#[test]
fn shrunk_zero_window_with_data_in_flight_is_not_aborted_while_the_peer_answers() {
    let mut n = TestNet::new(small_limits());
    let (c, mut p) = n.accepted(true);
    let data = vec![b'd'; 3000];
    n.s.write(n.now, c, &data).unwrap();
    let outs = n.drain();
    assert!(outs.len() >= 2, "{}", show(&outs));
    // 最初の segment だけを確認し、窓を 0 に縮めます。
    p.rcv = outs[0].seq.wrapping_add(outs[0].payload.len() as u32);
    p.wnd = 0;
    n.peer_ack(&mut p, &[]);
    n.drain();
    let mut el = Duration::ZERO;
    let mut answers = 0;
    while el < Duration::from_mins(25) {
        n.advance(Duration::from_millis(100));
        el += Duration::from_millis(100);
        let outs = n.drain();
        assert!(
            !outs.iter().any(|o| o.has(crate::wire::FLAG_RST)),
            "the core aborted after {el:?} although the peer answered {answers} probes: stats {:?}",
            n.s.stats()
        );
        if !outs.is_empty() {
            n.peer_ack(&mut p, &[]); // 窓は 0 のまま応えます
            answers += 1;
            n.drain();
        }
    }
    assert!(answers >= 10, "{answers}");
}

/// 相手が自分のデータの再送 (SEG.SEQ < SND.WL1) に新しい累積の確認と小さめの窓を載せたとき、核はその segment の
/// 窓を使わず (RFC 9293 3.10.7.4 の SND.WL1 の規則)、前の窓を新しい SND.UNA から測ります。相手が広告した右端は
/// 戻っていないのに、核はその右端の先へ新しいデータを送ります。Linux の tcp_may_update_window は SND.UNA を
/// 進める ACK の窓を常に使うので、この形では右端の先へ送りません。
#[test]
#[ignore = "audit finding: the core sends new data past the advertised right edge (see the audit report)"]
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
    let beyond: Vec<String> = outs
        .iter()
        .filter(|o| {
            let end = o.seq.wrapping_add(o.payload.len() as u32);
            !o.payload.is_empty() && seq::gt(end, edge)
        })
        .map(ToString::to_string)
        .collect();
    assert!(
        beyond.is_empty(),
        "the core sent past the advertised right edge {edge}: {beyond:?}"
    );
}

/// 相手の ISN を `iss` にして握手を済ませ、accept した接続と相手の側を返します (相手は SACK と timestamp と窓の
/// scale を示します)。
fn accepted_with_peer_iss(n: &mut TestNet, iss: u32) -> (crate::ConnId, PeerConn) {
    use crate::testnet_tests::TSeg;
    use crate::wire::FLAG_SYN;
    let l = n.listen(80);
    n.inject(&TSeg {
        sport: 40000,
        dport: 80,
        seq: iss,
        flags: FLAG_SYN,
        wnd: 65535,
        mss: 1380,
        ws: Some(7),
        sack_ok: true,
        ts: Some((5000, 0)),
        ..TSeg::default()
    });
    let outs = n.drain();
    assert_eq!(outs.len(), 1, "{}", show(&outs));
    let sa = &outs[0];
    let mut p = PeerConn {
        sport: 40000,
        dport: 80,
        iss,
        snd: iss.wrapping_add(1),
        rcv: sa.seq.wrapping_add(1),
        dut_iss: sa.seq,
        ts: true,
        ts_val: 5000,
        dut_ts: sa.ts.map_or(0, |(v, _)| v),
        wnd: 65535,
    };
    n.peer_ack(&mut p, &[]);
    let c = n.accept(l);
    n.drain();
    (c, p)
}

/// 穴の後ろに届いた FIN (順序外の FIN) は、穴が埋まった時に受け入れます。穴が埋まる前は EOF を返さず、ACK は穴の
/// 手前に留まり、SACK は FIN の前のデータを知らせます。番号の 1 周をまたぐ所と、FIN がちょうど 2^32 - 1 に
/// 載る所で確かめます (RFC 9293 3.10.7.4 の FIN の処理)。
#[test]
fn out_of_order_fin_is_taken_when_the_hole_fills_across_the_wrap() {
    use crate::Error;
    use crate::wire::FLAG_FIN;
    // 1 つ目:データが 2^32 をまたぎます。2 つ目:FIN の番号が u32::MAX です。
    for iss in [u32::MAX - 150, u32::MAX - 201] {
        let mut n = TestNet::new(small_limits());
        let (c, mut p) = accepted_with_peer_iss(&mut n, iss);
        let a = p.seg(FLAG_ACK, &[b'a'; 100]);
        p.snd = p.snd.wrapping_add(100);
        let b = p.seg(FLAG_ACK | FLAG_FIN, &[b'b'; 100]);
        let fin_seq = p.snd.wrapping_add(100);
        p.snd = p.snd.wrapping_add(101);
        n.inject(&b);
        let outs = n.drain();
        let last = outs.last().expect("an ACK for the out-of-order segment");
        assert_eq!(last.ack, a.seq, "{}", show(&outs));
        assert_eq!(
            last.sack.first().map(|s| (s.left, s.right)),
            Some((b.seq, fin_seq))
        );
        assert_eq!(n.read_all(c), b"");
        let mut buf = [0u8; 16];
        assert_eq!(n.s.read(n.now, c, &mut buf), Err(Error::WouldBlock));
        n.inject(&a);
        let outs = n.drain();
        assert!(
            outs.iter().any(|o| o.ack == p.snd && o.sack.is_empty()),
            "iss {iss}: the FIN was not acknowledged: {}",
            show(&outs)
        );
        let got = n.read_all(c);
        assert_eq!(got.len(), 200);
        assert!(got[..100].iter().all(|&x| x == b'a') && got[100..].iter().all(|&x| x == b'b'));
        assert_eq!(n.s.read(n.now, c, &mut buf), Ok(0), "EOF after the data");
        // 重複した FIN には ACK を返し、状態を変えません。
        n.inject(&b);
        let outs = n.drain();
        assert!(outs.iter().any(|o| o.ack == p.snd), "{}", show(&outs));
        // 閉じると LAST-ACK を経て枠を返します。
        n.s.close_conn(n.now, c);
        let outs = n.drain();
        let fin = outs.iter().find(|o| o.has(FLAG_FIN)).expect("our FIN");
        p.rcv = fin.seq.wrapping_add(1);
        n.peer_ack(&mut p, &[]);
        n.drain();
        assert_eq!(n.s.conns.in_use().count(), 0);
    }
}
