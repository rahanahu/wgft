//! 送信の番の状態の扱いの試験 (wgstack-rs.md の「送信の番」)。
//!
//! 番の規則 (長さ、公平、UDP と制御の位置、呼び出しを越えて続くこと) の試験は、書き手の分離に従って別の担当が
//! 書きます。ここは実装の担当が、番の状態が list と合い、無効の時に番を持たないことを確かめる試験だけを持ちます。

#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "test helpers"
)]

use crate::output::NIL;
use crate::tcp::conn::ConnId;
use crate::testnet_tests::{Out, PeerConn, TestNet, small_limits};

static DATA: [u8; 20_000] = [0x5a; 20_000];

/// 80 番で待ち受け、相手の 2 つのポートから接続を開き、どちらの接続にも `DATA` を書きます。
fn two_writers(n: &mut TestNet) -> [(ConnId, PeerConn); 2] {
    let l = n.listen(80);
    let pa = n.handshake(40000, 80, true, true);
    let ca = n.accept(l);
    let pb = n.handshake(40001, 80, true, true);
    let cb = n.accept(l);
    n.drain();
    for c in [ca, cb] {
        assert!(n.s.write(n.now, c, &DATA).unwrap() > 0);
    }
    [(ca, pa), (cb, pb)]
}

/// 中身を持つ segment の宛先のポートの列です。
fn data_ports(outs: &[Out]) -> Vec<u16> {
    outs.iter()
        .filter(|o| !o.payload.is_empty())
        .map(|o| o.rport)
        .collect()
}

/// 同じ宛先が続く長さの最大です。
fn longest_run(ports: &[u16]) -> usize {
    ports
        .chunk_by(|a, b| a == b)
        .map(<[u16]>::len)
        .max()
        .unwrap_or(0)
}

#[test]
fn off_holds_no_turn_and_alternates() {
    let mut n = TestNet::new(small_limits());
    two_writers(&mut n);
    let outs = n.drain();
    let ports = data_ports(&outs);
    assert!(ports.len() > 2, "{}", crate::testnet_tests::show(&outs));
    assert_eq!(longest_run(&ports), 1, "off keeps one segment per pick");
    assert_eq!(
        (n.s.s.out.turn, n.s.s.out.turn_bytes, n.s.s.out.turn_limit),
        (NIL, 0, 0)
    );
}

#[test]
fn on_keeps_the_head_connection_and_tracks_the_state() {
    let mut n = TestNet::with_send_turn(small_limits());
    two_writers(&mut n);
    let mut buf = vec![0u8; 2048];
    // 1 つ目の packet の後、番は先頭の接続にあり、list の先頭に残ります。
    let k = n.s.poll_transmit(n.now, &mut buf).unwrap();
    n.check();
    let holder = n.s.s.out.turn;
    assert_ne!(holder, NIL);
    assert_eq!(n.s.s.out.conns.front(), Some(holder));
    assert_eq!(n.s.s.out.turn_bytes as usize, k);
    let rest = n.drain();
    assert!(
        longest_run(&data_ports(&rest)) > 1,
        "the turn keeps a connection"
    );
    assert_eq!(n.s.s.out.turn, NIL, "nothing left to send ends the turn");
}

#[test]
fn closing_the_holder_ends_the_turn() {
    let mut n = TestNet::with_send_turn(small_limits());
    let [(ca, _), (cb, _)] = two_writers(&mut n);
    let mut buf = vec![0u8; 2048];
    n.s.poll_transmit(n.now, &mut buf).unwrap();
    n.check();
    let holder = n.s.s.out.turn;
    let c = if holder == ca.slot { ca } else { cb };
    assert_eq!(holder, c.slot);
    n.s.abort(n.now, c);
    n.check();
    assert_eq!(n.s.s.out.turn, NIL, "an aborted holder leaves no turn");
    // 残りの接続の出力は続き、番の状態は list と合ったままです。
    let outs = n.drain();
    assert_ne!(data_ports(&outs), [] as [u16; 0]);
}
