//! Hash S の区画の核の試験 (試作、所有者の決定 2026-11-06 の役割を分けた形)。
//!
//! - 区画の核は鍵 (ISN、timestamp、cookie) を共有し、IP の ID を重ならない範囲で数える。区画 0 (front) は全部の空間
//! - boost の枠は区画に割り当てた枠の中だけで貸し、区画をまたいで回収しない。区画の `Budget` を戻すと 1 つの核の
//!   `Budget` に戻る
//! - 区画を持たない核は今と同じに動く (既存の試験のすべて)

#![expect(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    reason = "tests collect connections"
)]

use crate::boost_tests::{DEMAND_BYTES, boosted, read_n, send_bulk, wide_limits};
use crate::budget::Budget;
use crate::config::{Config, Limits, Partition};
use crate::stack::Stack;
use crate::testnet_tests::{DUT, TEST_MTU, TestHook, TestNet};

const SHARED: [u8; 64] = [9; 64];

fn part_config(index: u16, count: u16, limits: Limits) -> Config {
    Config {
        limits,
        partition: Some(Partition {
            index,
            count,
            shared_seed: SHARED,
        }),
        ..Config::new(DUT, TEST_MTU)
    }
}

/// 区画 `index` の核。種 `own` は区画ごとの値。
fn part(index: u16, count: u16, own: u8, budget: Budget) -> TestNet {
    let s = Stack::new(
        part_config(index, count, wide_limits()),
        budget,
        &[own; 64],
        TestHook::default(),
    )
    .unwrap();
    TestNet::from_stack(s)
}

#[test]
fn partitions_share_the_keys_and_split_the_ip_ids() {
    let mut a = part(1, 4, 1, Budget::empty().unwrap());
    let mut b = part(2, 4, 2, Budget::empty().unwrap());
    a.listen(80);
    b.listen(80);
    let pa = a.syn_sack(40000, 80, true, false, true);
    let pb = b.syn_sack(40000, 80, true, false, true);
    assert_eq!(pa.dut_iss, pb.dut_iss, "the same 4-tuple gets the same ISN");
    assert_eq!(pa.dut_ts, pb.dut_ts, "and the same timestamp offset");
    // 区画 2 of 4 の ID は [32768, 49152) の中
    for _ in 0..70_000 {
        let id = b.s.s.next_id();
        assert!((32768..49152).contains(&id), "id {id}");
    }
    // 区画 0 (front) は全部の空間
    let mut f = part(0, 4, 3, Budget::empty().unwrap());
    let (mut low, mut high) = (false, false);
    for _ in 0..70_000 {
        let id = f.s.s.next_id();
        low |= id < 16384;
        high |= id >= 49152;
    }
    assert!(low && high, "partition 0 keeps the full space");
}

#[test]
fn a_core_without_a_partition_keeps_its_own_keys() {
    let c = Config::new(DUT, TEST_MTU);
    assert_eq!(c.partition, None);
    let mut x = TestNet::with_seed(wide_limits(), [3; 64]);
    let mut y = TestNet::with_seed(wide_limits(), [3; 64]);
    x.listen(80);
    y.listen(80);
    let px = x.syn_sack(40000, 80, true, false, true);
    let py = y.syn_sack(40000, 80, true, false, true);
    assert_eq!(px.dut_iss, py.dut_iss);
}

/// 区画の枠は割り当てた枠だけ:P = 3 (TCP の区画 2 つ) では区画 1 つあたり 8 枠。9 本目の需要は、同じ区画の需要の
/// 無い保有者が無ければ boost を得ない。ほかの区画の枠は使わない。
#[test]
fn a_partition_lends_only_its_own_slots() {
    let mut whole = Budget::new().unwrap();
    let b1 = whole.take_part(0, 2).unwrap();
    let b2 = whole.take_part(1, 2).unwrap();
    assert!(!whole.is_whole());
    let mut a = part(1, 3, 1, b1);
    let la = a.listen(80);
    let mut held = Vec::new();
    for i in 0..9 {
        let mut p = a.handshake_sack(41000 + i, 80, true, false, true);
        let c = a.accept(la);
        send_bulk(&mut a, &mut p, DEMAND_BYTES);
        read_n(&mut a, c, DEMAND_BYTES);
        a.drain();
        held.push((c, boosted(&mut a, c)));
    }
    let n = held.iter().filter(|(_, b)| *b).count();
    assert_eq!(n, 8, "half of the 16 slots");
    assert_eq!(a.s.s.budget.lent(), 8);
    a.check();
    // 閉じて戻すと 1 つの核の Budget に戻る
    let ca = a.s.close(a.now);
    whole.give_back(ca.budget);
    whole.give_back(b2);
    assert!(whole.is_whole());
    assert!(whole.check().is_ok());
}

#[test]
fn a_lost_partition_budget_leaves_the_whole_incomplete() {
    let mut whole = Budget::new().unwrap();
    let b1 = whole.take_part(0, 2).unwrap();
    let _lost = whole.take_part(1, 2).unwrap();
    whole.give_back(b1);
    assert!(!whole.is_whole(), "the next generation makes a new budget");
}
