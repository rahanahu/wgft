//! 境界の値と会計の誤用の試験です。panic を期待せず、安全側の結果 (断った、数えた、上限で止まった) を確かめるので、
//! overflow-checks の有無の両方で同じ主張になります。

use super::*;

/// 区間の表をちょうど満たす順序外の segment を入れ、穴を 1 つの segment で埋めると、数と byte の合計が 0 に戻ります。
#[test]
fn full_interval_table_then_hole_fill_returns_to_zero() {
    for (cap, h) in [(RECV_FLOOR, FLOOR_INTERVALS), (BOOST_SIZE, BOOST_INTERVALS)] {
        let mut p = ChunkPool::new().unwrap();
        let mut b = RecvBuf::owning(cap, table(h), 0);
        // 1 byte の区間を 1 つおきに h 個
        for k in 0..h as u64 {
            assert!(
                b.insert(2 + 2 * k, &[1], cap, &mut p).ooo,
                "cap {cap} interval {k}"
            );
        }
        assert_eq!(
            (b.intervals_len(), b.ooo_bytes()),
            (h, h as u64),
            "cap {cap}"
        );
        b.check().unwrap();
        // 満杯のまま新しい区間を作る segment は捨て、会計を変えない
        let res = b.insert(2 + 2 * h as u64 + 1, &[1], cap, &mut p);
        assert!(res.dropped, "cap {cap}: {res:?}");
        assert_eq!(
            (b.intervals_len(), b.ooo_bytes()),
            (h, h as u64),
            "cap {cap}"
        );
        let fill = vec![7u8; 2 + 2 * h - 1];
        let res = b.insert(0, &fill, cap, &mut p);
        assert!(res.filled && res.advanced, "cap {cap}: {res:?}");
        assert_eq!((b.intervals_len(), b.ooo_bytes()), (0, 0), "cap {cap}");
        assert_eq!(b.nxt_off, fill.len() as u64);
        b.check().unwrap();
        b.r.release(&mut p);
    }
}

/// `renege` の境の値です。limit が 1 (呼び手が渡す最小)、右端ちょうど、右端の 1 つ前、max_n が 0 のとき、数と byte の
/// 合計が区間の実際と合い続けます。
#[test]
fn renege_boundaries_keep_the_counts() {
    let mut p = ChunkPool::new().unwrap();
    for (limit, max_n, dropped, left) in [
        (1u64, 16usize, 15u64, 0usize),
        (35, 16, 0, 3),
        (34, 16, 1, 3),
        (1000, 0, 15, 0),
        (1000, 3, 0, 3),
        (1000, 2, 5, 2),
    ] {
        let mut b = RecvBuf::owning(BOOST_SIZE, table(16), 0);
        for s in [10u64, 20, 30] {
            b.insert(s, &[1; 5], BOOST_SIZE, &mut p);
        }
        assert_eq!(
            b.renege(limit, max_n),
            dropped,
            "limit {limit} max_n {max_n}"
        );
        assert_eq!(b.intervals_len(), left, "limit {limit} max_n {max_n}");
        assert_eq!(b.ooo_bytes(), 15 - dropped, "limit {limit} max_n {max_n}");
        b.check().unwrap();
        b.r.release(&mut p);
    }
    assert_eq!(p.held(), 0);
}

/// 未読が 0 のときの `unread` と `read` です。何も写さず、位置を動かしません。
#[test]
fn read_with_nothing_unread() {
    let mut p = ChunkPool::new().unwrap();
    let mut b = RecvBuf::owning(RECV_FLOOR, table(4), 0);
    let mut dst = [0u8; 16];
    assert_eq!((b.unread(), b.read(&mut dst, &mut p)), (0, 0));
    b.insert(0, &[9; 8], RECV_FLOOR, &mut p);
    assert_eq!(b.read(&mut dst, &mut p), 8);
    assert_eq!((b.unread(), b.read(&mut dst, &mut p)), (0, 0));
    assert_eq!((b.read_off, b.nxt_off), (8, 8));
    b.r.release(&mut p);
}

/// `renege` に limit 0 を渡しても、区間の表と会計は壊れません (呼び手は 1 以上を渡すが、前提は検査されない)。
#[test]
fn renege_with_limit_zero_is_refused() {
    let mut p = ChunkPool::new().unwrap();
    let mut b = RecvBuf::owning(BOOST_SIZE, table(16), 0);
    for s in [10u64, 20] {
        b.insert(s, &[1; 5], BOOST_SIZE, &mut p);
    }
    let before = b.ooo_bytes();
    let dropped = b.renege(0, 16);
    assert!(dropped <= before, "dropped {dropped} of {before}");
    assert!(b.ooo_bytes() <= before);
    b.check().unwrap();
    b.r.release(&mut p);
}

/// 読み取りの位置が受信の位置を超えた (会計の誤り) とき、未読は 0 で、`read` は何も写しません。
#[test]
fn read_ahead_of_nxt_reads_nothing() {
    let mut p = ChunkPool::new().unwrap();
    let mut b = RecvBuf::owning(RECV_FLOOR, table(4), 0);
    b.insert(0, &[5; 100], RECV_FLOOR, &mut p);
    b.read_off = b.nxt_off + 1;
    assert_eq!(b.unread(), 0);
    let mut dst = [0u8; 64];
    assert_eq!(b.read(&mut dst, &mut p), 0);
    assert_eq!(dst, [0; 64], "nothing is copied");
}

/// 区間の数がずれた状態 (白箱で 0 にする) で穴を埋めても、数は表の容量を超えて回り込みません。
#[test]
fn skewed_interval_count_does_not_wrap_on_release() {
    let mut p = ChunkPool::new().unwrap();
    let mut b = RecvBuf::owning(RECV_FLOOR, table(8), 0);
    b.insert(10, &[1; 5], RECV_FLOOR, &mut p);
    b.n = 0;
    b.insert(0, &[2; 10], RECV_FLOOR, &mut p);
    assert!(
        b.intervals_len() <= b.intervals_capacity(),
        "n {}",
        b.intervals_len()
    );
    b.r.release(&mut p);
}

/// 順序外の byte の合計がずれた状態 (白箱で 0 にする) で穴を埋めても、取り消しても、合計は受信の容量を超える値に
/// 回り込みません。
#[test]
fn skewed_ooo_bytes_do_not_wrap() {
    for renege in [false, true] {
        let mut p = ChunkPool::new().unwrap();
        let mut b = RecvBuf::owning(RECV_FLOOR, table(8), 0);
        b.insert(10, &[1; 5], RECV_FLOOR, &mut p);
        b.ooo = 0;
        if renege {
            b.renege(12, 8);
        } else {
            b.insert(0, &[2; 10], RECV_FLOOR, &mut p);
        }
        assert!(
            b.ooo_bytes() <= RECV_FLOOR,
            "renege {renege}: ooo {}",
            b.ooo_bytes()
        );
        b.r.release(&mut p);
    }
}

/// 窓の空き (W8):未読と順序外の和が回り込んでも、広告する右端は受信の上限を超えません。
#[test]
fn window_free_never_exceeds_the_clamp_when_counts_break() {
    use crate::testnet_tests::{TestNet, small_limits};
    let mut n = TestNet::new(small_limits());
    let (c, _p) = n.accepted(true);
    let v = n.s.conn(c.slot);
    let clamp = v.rcv_clamp();
    // 未読が回り込む (read_off が nxt_off より先)
    v.b.rcv.read_off = v.b.rcv.nxt_off + 1;
    assert!(v.rcv_free() <= clamp, "free {} clamp {clamp}", v.rcv_free());
    assert!(v.rcv_target() <= v.b.rcv.nxt_off + clamp);
    v.b.rcv.read_off = v.b.rcv.nxt_off;
    // 順序外の合計が巨大
    v.b.rcv.ooo = u64::MAX;
    assert!(v.rcv_free() <= clamp, "free {} clamp {clamp}", v.rcv_free());
    v.b.rcv.ooo = 0;
}
