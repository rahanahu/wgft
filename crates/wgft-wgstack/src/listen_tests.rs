//! 待ち受けの守りの試験 (wgstack-rs.md の「待ち受けの守り」):待ち受けへの SYN と FIN の組です。
//!
//! 凍結した Go の wgstack と意図して違う所なので、Go の試験の写しではありません。

use crate::testnet_tests::{TSeg, TestNet, show, small_limits};
use crate::wire::{FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN};

#[test]
fn listener_drops_syn_fin() {
    let mut n = TestNet::new(small_limits());
    let _l = n.listen(80);
    n.inject(&TSeg {
        sport: 40000,
        dport: 80,
        seq: 1,
        flags: FLAG_SYN | FLAG_FIN,
        wnd: 1000,
        mss: 1380,
        ..TSeg::default()
    });
    let outs = n.drain();
    assert!(outs.is_empty(), "{}", show(&outs));
    assert_eq!(n.s.held().syn_rows, 0);
    // 閉じたポートへの SYN と FIN の組には、今までどおり RST を返します。
    n.inject(&TSeg {
        sport: 40000,
        dport: 81,
        seq: 1,
        flags: FLAG_SYN | FLAG_FIN,
        wnd: 1000,
        ..TSeg::default()
    });
    let outs = n.drain();
    assert!(outs.len() == 1 && outs[0].has(FLAG_RST), "{}", show(&outs));
}

#[test]
fn syn_fin_does_not_reuse_a_time_wait_row() {
    let mut n = TestNet::new(small_limits());
    let l = n.listen(80);
    let mut p = n.handshake(40000, 80, false, false);
    let c = n.accept(l);
    n.s.close_conn(n.now, c);
    let outs = n.drain();
    p.absorb(&outs);
    n.peer_ack(&mut p, &[]);
    n.peer_fin(&mut p);
    n.drain();
    assert_eq!(n.s.held().tw_rows, 1);
    n.inject(&TSeg {
        sport: 40000,
        dport: 80,
        seq: p.snd.wrapping_add(100_000),
        flags: FLAG_SYN | FLAG_FIN,
        wnd: 1000,
        mss: 1380,
        ..TSeg::default()
    });
    let outs = n.drain();
    assert!(outs.iter().all(|o| o.flags == FLAG_ACK), "{}", show(&outs));
    assert_eq!((n.s.held().tw_rows, n.s.held().syn_rows), (1, 0));
}
