//! 受信のバッファの会計が崩れたときの、接続の側の配線の試験です。
//!
//! 崩れた状態は白箱で作ります (区間の数 `n`、順序外の byte の合計 `ooo`、`read_off`)。期待するのは、崩れを見つけた
//! 操作が会計の不整合 (`accounting_faults`) をちょうど 1 つ数え、RST を 1 つ送り、以後の `read` が
//! `Error::Accounting` を返すことと、後の操作が RST や不整合を重ねないことです。overflow-checks の有無の両方で同じ
//! 主張になります。

use super::*;
use crate::Error;
use crate::boost_tests::{DEMAND_BYTES, Two, boost_two_with, inject_at};
use crate::testnet_tests::{PeerConn, TestNet, build_peer, small_limits};
use crate::wire::{FLAG_ACK, FLAG_RST};
use core::time::Duration;

/// 白箱で壊す会計の欄です。
#[derive(Clone, Copy, Debug)]
enum Skew {
    /// 区間の数を 0 にする。
    IntervalCount,
    /// 順序外の byte の合計を 0 にする。
    OooBytes,
}

fn rsts(outs: &[crate::testnet_tests::Out]) -> usize {
    outs.iter().filter(|o| o.has(FLAG_RST)).count()
}

/// 区間が 1 つある接続の会計を壊して穴を埋める segment を送ると、会計の不整合がちょうど 1 つ数えられ、RST が 1 つ出て、
/// `read` が `Error::Accounting` を返します。後の `read` と時間の経過は、RST も不整合も重ねません。
fn hole_fill_after_skew(skew: Skew, check_read: bool) {
    let mut n = TestNet::new(small_limits());
    let (c, mut p) = n.accepted(false);
    let nxt = n.s.conn(c.slot).b.rcv.nxt_off;
    inject_at(&mut n, &mut p, c, nxt + 100, &[1; 100]);
    n.drain();
    {
        let v = n.s.conn(c.slot);
        assert_eq!(
            (v.b.rcv.intervals_len(), v.b.rcv.ooo_bytes()),
            (1, 100),
            "{skew:?}: setup"
        );
    }
    {
        let v = n.s.conn(c.slot);
        match skew {
            Skew::IntervalCount => v.b.rcv.n = 0,
            Skew::OooBytes => v.b.rcv.ooo = 0,
        }
    }
    let before = n.s.stats().accounting_faults;
    inject_at(&mut n, &mut p, c, nxt, &[2; 100]);
    let outs = n.drain();
    assert_eq!(
        n.s.stats().accounting_faults,
        before + 1,
        "{skew:?}: one more accounting fault"
    );
    assert_eq!(rsts(&outs), 1, "{skew:?}: one RST");
    let mut buf = [0u8; 400];
    if check_read {
        assert_eq!(
            n.s.read(n.now, c, &mut buf),
            Err(Error::Accounting),
            "{skew:?}: read after the fault"
        );
        assert_eq!(n.s.read(n.now, c, &mut buf), Err(Error::Accounting));
    }
    n.advance(Duration::from_secs(5));
    let later = n.drain();
    assert_eq!(rsts(&later), 0, "{skew:?}: no further RST");
    assert_eq!(
        n.s.stats().accounting_faults,
        before + 1,
        "{skew:?}: no further fault"
    );
}

#[test]
fn skewed_interval_count_on_a_hole_fill_faults_the_connection_once() {
    hole_fill_after_skew(Skew::IntervalCount, false);
}

#[test]
fn skewed_ooo_bytes_on_a_hole_fill_faults_the_connection_once() {
    hole_fill_after_skew(Skew::OooBytes, false);
}

/// 同じ場面で `read` は、バッファに残った未読を返さずに `Error::Accounting` を返します (接続は閉じています)。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn skewed_interval_count_on_a_hole_fill_makes_read_fail() {
    hole_fill_after_skew(Skew::IntervalCount, true);
}

#[test]
#[ignore = "fixed by the follow-up PR"]
fn skewed_ooo_bytes_on_a_hole_fill_makes_read_fail() {
    hole_fill_after_skew(Skew::OooBytes, true);
}

/// 不変条件の確かめを挟まずに、相手から `bytes` byte を送ります (壊した会計を `TestNet` の確かめが先に見つけない
/// ため)。出力は読み捨てます。
fn bulk_unchecked(n: &mut TestNet, p: &mut PeerConn, bytes: usize) {
    let mut out = vec![0u8; 65536];
    let mut left = bytes;
    while left > 0 {
        let k = left.min(1000);
        let seg = p.seg(FLAG_ACK, &vec![0u8; k]);
        n.s.handle_packet(n.now, &build_peer(&seg));
        p.snd = p.snd.wrapping_add(k as u32);
        left -= k;
        while n.s.poll_transmit(n.now, &mut out).is_some() {}
    }
}

/// boost の保有者が枠を渡すときの取り消し (`demote`) が、崩れた順序外の byte の合計を見つけたら、同じく会計の不整合
/// を 1 つ数え、RST を 1 つ送り、`read` が `Error::Accounting` を返します。
#[test]
fn skewed_ooo_bytes_on_a_boost_demotion_fault_the_connection_once() {
    let Two {
        mut n,
        c1,
        mut p1,
        c2,
        mut p2,
    } = boost_two_with(true);
    let (nxt, edge) = {
        let v = n.s.conn(c1.slot);
        (v.b.rcv.nxt_off, v.b.rcv.read_off + RECV_FLOOR)
    };
    inject_at(&mut n, &mut p1, c1, nxt + 1000, &[0u8; 1000]);
    inject_at(&mut n, &mut p1, c1, edge - 500, &[0u8; 1000]); // floor の境をまたぐ
    inject_at(&mut n, &mut p1, c1, nxt + (3 << 20), &[0u8; 1000]);
    n.drain();
    // 取り合いがあり、1 秒より長く黙った保有者から枠を取り上げる
    n.advance(Duration::from_secs(2));
    n.s.conn(c1.slot).b.rcv.ooo = 0;
    let before = n.s.stats().accounting_faults;
    bulk_unchecked(&mut n, &mut p2, DEMAND_BYTES);
    let mut sink = vec![0u8; DEMAND_BYTES];
    let mut got = 0;
    while got < DEMAND_BYTES {
        got += n.s.read(n.now, c2, &mut sink[got..]).unwrap();
    }
    let mut rst = rsts(&n.drain());
    assert_eq!(
        n.s.stats().accounting_faults,
        before + 1,
        "one more accounting fault"
    );
    let mut buf = [0u8; 400];
    assert_eq!(n.s.read(n.now, c1, &mut buf), Err(Error::Accounting));
    n.advance(Duration::from_secs(5));
    rst += rsts(&n.drain());
    assert_eq!(rst, 1, "one RST for the faulted connection");
    assert_eq!(
        n.s.stats().accounting_faults,
        before + 1,
        "no further fault"
    );
}

/// 読み取りの位置が受信の位置を超えた接続の最初の `read` は `Error::Accounting` を返し、不整合を 1 つ数え、RST を 1 つ
/// 送ります。後の `read` は、同じ誤りを返しても、RST も不整合も重ねません。
#[test]
fn read_ahead_of_nxt_faults_once_and_later_reads_stay_quiet() {
    let mut n = TestNet::new(small_limits());
    let (c, mut p) = n.accepted(false);
    n.peer_ack(&mut p, &[5; 100]);
    n.drain();
    {
        let v = n.s.conn(c.slot);
        v.b.rcv.read_off = v.b.rcv.nxt_off + 1;
    }
    let before = n.s.stats().accounting_faults;
    let mut buf = [0u8; 64];
    assert_eq!(n.s.read(n.now, c, &mut buf), Err(Error::Accounting));
    assert_eq!(n.s.stats().accounting_faults, before + 1);
    assert_eq!(rsts(&n.drain()), 1, "one RST for the first read");
    for i in 0..3 {
        let r = n.s.read(n.now, c, &mut buf);
        assert!(r.is_err(), "read {i} after the fault: {r:?}");
        assert_eq!(
            n.s.stats().accounting_faults,
            before + 1,
            "read {i} counted another fault"
        );
        assert_eq!(rsts(&n.drain()), 0, "read {i} sent another RST");
    }
}
