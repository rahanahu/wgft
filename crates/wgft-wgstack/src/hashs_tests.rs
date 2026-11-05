//! Hash S の区画の核の試験 (試作、notes の independent-exploration.md の 6.8 節)。
//!
//! - 区画の核は鍵 (ISN、timestamp、cookie) を共有し、IP の ID を重ならない範囲で数える
//! - boost の枠の集まりを分け合う区画で、ほかの区画の需要の無い保有者がすべての枠を持つ時に、新しい大きな流れが
//!   「枠が欲しい」で決まった時間の内に枠を得る (飢えの試験、6.8.5 節)
//! - 区画を持たない核は今と同じに動く (既存の試験のすべて)
#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "tests collect segments and share the pool"
)]

use std::sync::Arc;

use crate::boost_tests::{DEMAND_BYTES, boosted, read_n, send_bulk, wide_limits};
use crate::budget::{BoostPool, Budget};
use crate::config::{Config, Limits, Partition};
use crate::stack::Stack;
use crate::testnet_tests::{DUT, TEST_MTU, TestHook, TestNet};
use core::time::Duration;

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

/// 集まり `pool` を分け合う区画 `index` の核。種 `own` は区画ごとの値。
fn part(index: u16, count: u16, own: u8, pool: &Arc<BoostPool>) -> TestNet {
    let s = Stack::new(
        part_config(index, count, wide_limits()),
        pool.view().unwrap(),
        &[own; 64],
        TestHook {
            pool: Some(Arc::clone(pool)),
            ..TestHook::default()
        },
    )
    .unwrap();
    TestNet::from_stack(s)
}

#[test]
fn partitions_share_the_keys_and_split_the_ip_ids() {
    let pool = Arc::new(BoostPool::new(Budget::new().unwrap()).unwrap());
    let mut a = part(0, 4, 1, &pool);
    let mut b = part(2, 4, 2, &pool);
    a.listen(80);
    b.listen(80);
    let pa = a.syn_sack(40000, 80, true, false, true);
    let pb = b.syn_sack(40000, 80, true, false, true);
    assert_eq!(pa.dut_iss, pb.dut_iss, "the same 4-tuple gets the same ISN");
    assert_eq!(pa.dut_ts, pb.dut_ts, "and the same timestamp offset");
    // 区画 2 of 4 の ID は [32768, 49152) の中、区画 0 は全部の空間
    for _ in 0..70_000 {
        let id = b.s.s.next_id();
        assert!((32768..49152).contains(&id), "id {id}");
    }
    let mut seen_low = false;
    let mut seen_high = false;
    for _ in 0..70_000 {
        let id = a.s.s.next_id();
        seen_low |= id < 16384;
        seen_high |= id >= 49152;
    }
    assert!(seen_low && seen_high, "partition 0 keeps the full space");
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

/// 飢えの試験:区画 A の需要の無い 16 本がすべての枠を持つ時、区画 B の新しい大きな流れは「枠が欲しい」を立て、
/// A が次の起床で枠を返し、B は次の需要の区間で枠を得る。
#[test]
fn a_new_flow_in_another_partition_gets_a_slot_from_idle_holders() {
    let pool = Arc::new(BoostPool::new(Budget::new().unwrap()).unwrap());
    let mut a = part(0, 2, 1, &pool);
    let mut b = part(1, 2, 2, &pool);
    let la = a.listen(80);
    let mut holders = Vec::new();
    for i in 0..16 {
        let mut p = a.handshake_sack(41000 + i, 80, true, false, true);
        let c = a.accept(la);
        send_bulk(&mut a, &mut p, DEMAND_BYTES);
        read_n(&mut a, c, DEMAND_BYTES);
        a.drain();
        assert!(boosted(&mut a, c), "holder {i} not boosted");
        holders.push(c);
    }
    assert_eq!(pool.taken(), 16);
    a.s.sync_boost();
    assert_eq!(pool.taken(), 16, "lent slots stay taken");
    // A の保有者は 1 秒より長く需要が無い
    a.advance(Duration::from_millis(1100));
    assert_eq!(a.s.release_wanted(a.now), 0, "nobody wants a slot yet");
    assert_eq!(pool.taken(), 16);

    // B の新しい大きな流れ:空きが無く、自分の区画に降ろせる保有者もいないので「枠が欲しい」を立てる
    let lb = b.listen(80);
    let mut p = b.handshake_sack(42000, 80, true, false, true);
    let c = b.accept(lb);
    send_bulk(&mut b, &mut p, DEMAND_BYTES);
    read_n(&mut b, c, DEMAND_BYTES);
    b.drain();
    assert!(!boosted(&mut b, c));
    assert!(pool.wanted(), "B raised slot-wanted");
    assert!(b.s.take_boost_wanted(), "B's driver wakes the others");

    // A の次の起床:需要の無い保有者を floor に戻し、枠を集まりに返して印を外す
    let freed = a.s.release_wanted(a.now);
    assert!(freed > 0, "A returned slots");
    assert!(!pool.wanted());
    assert!(pool.taken() < 16);
    a.check();

    // B の次の需要の区間で枠を得る
    b.advance(Duration::from_millis(300));
    send_bulk(&mut b, &mut p, DEMAND_BYTES);
    read_n(&mut b, c, DEMAND_BYTES);
    b.drain();
    assert!(boosted(&mut b, c), "B's flow got a slot within one demand window");
    b.check();

    // 閉じた後、区画の Budget を集まりに返すと 1 つの Budget に戻る
    let ca = a.s.close(a.now);
    let cb = b.s.close(b.now);
    drop((a, b));
    pool.put_back(ca.budget);
    pool.put_back(cb.budget);
    let pool = Arc::try_unwrap(pool).unwrap();
    let budget = pool.into_budget().expect("all slots came back");
    assert_eq!(budget.slots(), 16);
    assert!(budget.check().is_ok());
}

#[test]
fn a_partition_reuses_a_slot_it_freed_before_returning_it() {
    let pool = Arc::new(BoostPool::new(Budget::new().unwrap()).unwrap());
    let mut a = part(1, 2, 1, &pool);
    let la = a.listen(80);
    let mut p = a.handshake_sack(41000, 80, true, false, true);
    let c = a.accept(la);
    send_bulk(&mut a, &mut p, DEMAND_BYTES);
    read_n(&mut a, c, DEMAND_BYTES);
    a.drain();
    assert!(boosted(&mut a, c));
    assert_eq!(pool.taken(), 1);
    a.s.sync_boost();
    assert_eq!(pool.taken(), 1);
    let closed = a.s.close(a.now);
    pool.put_back(closed.budget);
    assert_eq!(pool.taken(), 0);
}
