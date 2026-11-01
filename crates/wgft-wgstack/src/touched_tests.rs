//! 書き換えた接続の枠だけの確かめの試験です (wgstack-rs.md の「書き換えた所だけの確かめ」)。
//!
//! 2 つの確かめが同じ答えを返すことは、白箱の試験の道具 (`TestNet::check`) が各段で並べて確かめます。ここでは
//! 書き換えの口が枠に印を付けること、誤りを入れた時の答え、最初の呼び出しの数え直しを確かめます。

#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "test helpers"
)]

use crate::budget::Budget;
use crate::config::Config;
use crate::stack::{Spare, Stack, TouchedCheck};
use crate::testnet_tests::{
    DUT, PEER, TEST_MTU, TestHook, TestNet, build_icmp, build_udp, small_limits,
};
use crate::time::Time;
use core::net::SocketAddrV4;
use core::time::Duration;

fn config() -> Config {
    Config {
        limits: small_limits(),
        ..Config::new(DUT, TEST_MTU)
    }
}

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

/// 待ち受け、接続、UDP、ping、知らせを使い、ほかのポートを開いて閉じる台本です。出力と知らせを文字列にして
/// 返します。
fn scenario(n: &mut TestNet) -> String {
    let mut log = Vec::new();
    let l80 = n.listen(80);
    let l81 = n.listen(81);
    let mut p = n.handshake(40000, 80, true, true);
    let c = n.accept(l80);
    n.peer_ack(&mut p, &[1; 2000]);
    n.s.write(n.now, c, &[2; 5000]).unwrap();
    let u = n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 5353)).unwrap();
    n.write(&build_udp(SocketAddrV4::new(PEER, 9), 5353, &[3; 100]));
    n.s.send_to(n.now, u, &[4; 300], SocketAddrV4::new(PEER, 9))
        .unwrap();
    let ping = n.s.open_ping(n.now, PEER).unwrap();
    let mut echo = [5u8; 32];
    echo[0] = 8;
    n.s.send_ping(n.now, ping, &echo).unwrap();
    for pkt in n.drain_raw() {
        log.push(format!("{pkt:?}\n"));
        if pkt[9] == crate::wire::PROTO_ICMP {
            // 相手は echo の message を echo reply にして返します。
            let mut reply = pkt[crate::wire::IP_HEADER_LEN..].to_vec();
            reply[0] = 0;
            n.write(&build_icmp(PEER, &reply));
        }
    }
    n.s.close_listener(n.now, l81);
    n.s.close_udp(n.now, u);
    let u2 = n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 5353)).unwrap();
    log.push(format!("{l80:?} {l81:?} {u:?} {u2:?} {ping:?}\n"));
    for pkt in n.drain_raw() {
        log.push(format!("{pkt:?}\n"));
    }
    n.advance(Duration::from_millis(300));
    for pkt in n.drain_raw() {
        log.push(format!("{pkt:?}\n"));
    }
    log.push(format!("{:?}\n{:?}\n", n.events(), n.read_all(c)));
    log.push(format!("{:?}\n{:?}\n", n.s.stats(), n.s.held()));
    log.concat()
}

/// 閉じた核の表を作成の時の値に戻して使い回した核は、新しく作った核と同じ表を持ち、同じ台本に同じ出力を返します。
#[test]
fn a_reused_stack_matches_a_new_one() {
    let mut fresh = TestNet::new(small_limits());
    let want = scenario(&mut fresh);
    let bound = fresh.s.bound();
    let (closed, spare) = fresh.s.close_keeping(Time::from_nanos(1 << 40));
    assert!(closed.held.is_zero());
    assert_eq!(
        spare.kept(),
        3,
        "every table goes back to its value when made"
    );
    assert!(spare.is_fresh());
    let s = Stack::new_reusing(
        config(),
        closed.budget,
        spare,
        &[7; 64],
        TestHook::default(),
    )
    .unwrap();
    assert_eq!(s.bound(), bound);
    let mut reused = TestNet::from_stack(s);
    assert_eq!(scenario(&mut reused), want);
}

/// 設定が違う核は、大きさの合わない知らせの list を使い回さず作り直します。
#[test]
fn new_reusing_remakes_a_table_of_another_size() {
    let mut n = TestNet::new(small_limits());
    scenario(&mut n);
    let (closed, spare) = n.s.close_keeping(n.now);
    let other = Config {
        limits: crate::config::Limits {
            max_flows: 4,
            ..small_limits()
        },
        ..Config::new(DUT, TEST_MTU)
    };
    let s = Stack::new_reusing(other, closed.budget, spare, &[7; 64], TestHook::default()).unwrap();
    let mut n = TestNet::from_stack(s);
    scenario(&mut n);
    let fresh = Stack::new(other, Budget::new().unwrap(), &[7; 64], TestHook::default()).unwrap();
    assert_eq!(n.s.bound(), fresh.bound());
    assert_eq!(Spare::new().kept(), 0);
}
