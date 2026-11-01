//! 書き換えた接続の枠だけの確かめの試験です (wgstack-rs.md の「書き換えた所だけの確かめ」)。
//!
//! 2 つの確かめが同じ答えを返すことは、白箱の試験の道具 (`TestNet::check`) が各段で並べて確かめます。ここでは
//! 書き換えの口が枠に印を付けること、誤りを入れた時の答え、最初の呼び出しの数え直しを確かめます。

#![expect(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "test helpers"
)]

use crate::stack::TouchedCheck;
use crate::testnet_tests::{TestNet, small_limits};

/// 2 本の接続を持つ核です。接続の枠 0 と 1 を使います。
fn two_conns() -> TestNet {
    let mut n = TestNet::new(small_limits());
    let l = n.listen(80);
    let mut p = n.handshake(40000, 80, true, true);
    n.handshake(40001, 80, true, true);
    n.accept(l);
    n.accept(l);
    n.peer_ack(&mut p, &[1; 3000]);
    n.drain();
    n
}

/// 印の付いた枠の番号です。印を外します。
fn touched(n: &mut TestNet) -> Vec<u32> {
    let mut out = Vec::new();
    n.s.conns.take_touched(|i| out.push(i));
    out
}

/// 枠の配列を書き換える口はどれも、その枠に印を付けます。
#[test]
fn write_accessors_mark_the_slot() {
    let mut n = two_conns();
    touched(&mut n);
    n.s.conns.tcb_mut(1);
    assert_eq!(touched(&mut n), [1]);
    n.s.conns.bufs_mut(0);
    n.s.conns.parts_mut(1);
    assert_eq!(touched(&mut n), [0, 1]);
    assert_eq!(touched(&mut n), Vec::<u32>::new());
    // 読むだけの口は印を付けません。
    let _ = n.s.conns.tcb(0);
    let _ = n.s.conns.bufs(1);
    assert_eq!(touched(&mut n), Vec::<u32>::new());
}

/// 書き換えた枠の誤りを、書き換えた枠だけの確かめは全体の確かめと同じ文で捉えます。
#[test]
fn touched_check_reports_a_fault_in_a_touched_slot() {
    let mut n = two_conns();
    let mut c = TouchedCheck::new();
    n.s.check_invariants_touched(&mut c).unwrap();
    n.s.conns.tcb_mut(1).snd_cap = 1;
    let full = n.s.check_invariants();
    assert_eq!(
        full.unwrap_err().what(),
        "a connection's reservation disagrees with its rings"
    );
    assert_eq!(n.s.check_invariants_touched(&mut c), full);
    // 誤りを返した後の呼び出しはすべての枠を数え直すので、印が無くても同じ誤りを捉えます。
    assert_eq!(n.s.check_invariants_touched(&mut c), full);
}

/// 最初の呼び出しは印に関係なくすべての枠を確かめます。
#[test]
fn touched_check_counts_every_slot_on_its_first_call() {
    let mut n = two_conns();
    n.s.conns.tcb_mut(0).snd_cap = 1;
    touched(&mut n);
    let full = n.s.check_invariants();
    assert!(full.is_err());
    assert_eq!(n.s.check_invariants_touched(&mut TouchedCheck::new()), full);
}

/// 送り手の scoreboard の数えのずれも、書き換えた枠で捉えます (`rtx_bytes_drift` の故障の形)。
#[test]
fn touched_check_reports_scoreboard_drift() {
    let mut n = two_conns();
    let mut c = TouchedCheck::new();
    n.s.check_invariants_touched(&mut c).unwrap();
    let id = n.s.conns.id(0);
    n.s.write(n.now, id, &[2; 4000]).unwrap();
    n.drain();
    n.s.conns.tcb_mut(id.slot).rtx_bytes += 1;
    let full = n.s.check_invariants();
    assert!(full.is_err());
    assert_eq!(n.s.check_invariants_touched(&mut c), full);
}
