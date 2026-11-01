//! boost の取得と回収と取り消し、受信の窓の boost の段 (Go の `boost_test.go`、`rcvwin_test.go`) の白箱の試験。
//!
//! Go の試験は枠 1 つの集まりを作りますが、Rust の `Budget` は枠が 16 本に固定です。枠の取り合いの試験は、枠を
//! 持たせた接続を 15 本足して 16 本すべてを埋め、1 本目の接続 (枠 0) から回収させます。
#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "tests collect segments"
)]
#![expect(
    clippy::cast_possible_truncation,
    clippy::many_single_char_names,
    reason = "test names and sequence numbers kept as the low 32 bits"
)]

use crate::ConnId;
use crate::buf::recv::splitmix64;
use crate::buf::{BOOST_RECORDS, BOOST_SIZE, FLOOR_RECORDS, RECV_FLOOR, SEND_FLOOR};
use crate::config::Limits;
use crate::seq;
use crate::stack::ns;
use crate::tcp::RCV_WINDOW_SHIFT;
use crate::tcp::rcv_window::RCV_GROW_MIN;
use crate::testnet_tests::{Out, PeerConn, TEST_MTU, TestNet, small_limits};
use crate::wire::FLAG_ACK;
use core::time::Duration;

/// 区間に読めたか受け入れた byte がこの値以上なら需要があります (Go の `demandBytes`)。
pub(crate) const DEMAND_BYTES: usize = 64 << 10;
/// timestamp を使う接続の中身の大きさです (Go の `rwMSS`)。
const RW_MSS: usize = TEST_MTU - 40 - 12;

/// 16 本の枠すべてを埋める試験のための、接続の数に余裕のある表の大きさです。
pub(crate) fn wide_limits() -> Limits {
    Limits {
        max_flows: 40,
        ..small_limits()
    }
}

/// 相手から `bytes` byte を MSS ごとに送り、核の ACK を読み捨てます (Go の `sendBulk`)。
pub(crate) fn send_bulk(n: &mut TestNet, p: &mut PeerConn, bytes: usize) {
    let mut left = bytes;
    while left > 0 {
        let k = left.min(RW_MSS);
        n.peer_ack(p, &vec![0u8; k]);
        left -= k;
        n.drain();
    }
}

/// `k` byte をちょうど読みます (Go の `readN`)。
pub(crate) fn read_n(n: &mut TestNet, c: ConnId, k: usize) {
    let mut b = vec![0u8; k];
    let mut got = 0;
    while got < k {
        got += n.s.read(n.now, c, &mut b[got..]).unwrap();
    }
    assert_eq!(got, k);
}

/// 接続が枠を持つかです。
pub(crate) fn boosted(n: &mut TestNet, c: ConnId) -> bool {
    n.s.conn(c.slot).b.boost.is_some()
}

/// 貸している枠の数です (Go の `pool.held()`)。
pub(crate) fn lent(n: &mut TestNet) -> usize {
    n.s.conn(0).s.budget.lent()
}

/// boost の接続の窓の上限と歩みの上限を予約まで上げ、広げた窓を知らせます (Go の `openWindow`)。
pub(crate) fn open_window(n: &mut TestNet, c: ConnId) {
    let now = ns(n.now);
    let mut v = n.s.conn(c.slot);
    v.t.rcv_want = v.t.rcv_cap;
    v.t.rcv_ssthresh = v.t.rcv_cap;
    v.t.ack_now = true;
    v.after_input(now);
    n.drain();
}

/// 相手から受信の offset `off` に `data` を送ります (Go の `injectAt`)。
pub(crate) fn inject_at(n: &mut TestNet, p: &mut PeerConn, c: ConnId, off: u64, data: &[u8]) {
    let irs = n.s.conn(c.slot).t.irs;
    let mut s = p.seg(FLAG_ACK, data);
    s.seq = irs.wrapping_add(1).wrapping_add(off as u32);
    n.inject(&s);
}

/// 受信の区間を始まりの順に集めます (Go の `rcv.intervals(nil)`)。
pub(crate) fn intervals(n: &mut TestNet, c: ConnId) -> Vec<(u64, u64)> {
    let mut v = Vec::new();
    n.s.conn(c.slot).b.rcv.for_each_interval(&mut |s, e| {
        v.push((s, e));
        true
    });
    v
}

/// 枠の集まりを満たして取り合う 2 本の接続です (Go の `boostTwo`)。
pub(crate) struct Two {
    pub(crate) n: TestNet,
    pub(crate) c1: ConnId,
    pub(crate) p1: PeerConn,
    pub(crate) c2: ConnId,
    pub(crate) p2: PeerConn,
}

/// 枠が 16 本すべて埋まった集まりで、1 本目に枠 0 を持たせ、2 本目は持たせません。`sack` で SACK を交渉するかを
/// 選びます (Go の `boostTwoWith`)。残りの 15 本の枠は、需要を示して枠を得た接続が持ちます。
pub(crate) fn boost_two_with(sack: bool) -> Two {
    let mut n = TestNet::new(wide_limits());
    let l = n.listen(80);
    let mut p1 = n.handshake_sack(40000, 80, true, sack, true);
    let c1 = n.accept(l);
    let p2 = n.handshake_sack(40001, 80, true, sack, true);
    let c2 = n.accept(l);
    send_bulk(&mut n, &mut p1, DEMAND_BYTES);
    read_n(&mut n, c1, DEMAND_BYTES);
    n.drain();
    assert!(boosted(&mut n, c1), "first connection not boosted");
    assert_eq!(n.s.conn(c1.slot).b.boost, Some(0));
    for i in 0..15 {
        let mut p = n.handshake_sack(41000 + i, 80, true, sack, true);
        let c = n.accept(l);
        send_bulk(&mut n, &mut p, DEMAND_BYTES);
        read_n(&mut n, c, DEMAND_BYTES);
        n.drain();
        assert!(boosted(&mut n, c), "filler {i} not boosted");
    }
    assert_eq!(lent(&mut n), 16);
    open_window(&mut n, c1);
    Two { n, c1, p1, c2, p2 }
}

fn boost_two() -> Two {
    boost_two_with(false)
}

/// 受信の需要で枠を得て、受信の窓の予約を boost の大きさにしますが、広告する窓は floor を超えません (Go の
/// `TestBoostOnReceiveDemand`)。hook の記録は、Go の `OnBoost` の初めの `false` の呼び出しが無い分だけ短くなります。
#[test]
fn boost_on_receive_demand() {
    let mut n = TestNet::new(small_limits());
    let l = n.listen(80);
    let mut p = n.handshake(40000, 80, true, true);
    let c = n.accept(l);
    send_bulk(&mut n, &mut p, DEMAND_BYTES);
    read_n(&mut n, c, DEMAND_BYTES);
    {
        let v = n.s.conn(c.slot);
        assert!(
            v.b.boost.is_some()
                && v.k.rcv_boost
                && v.t.rcv_cap == BOOST_SIZE
                && v.t.snd_cap == BOOST_SIZE,
            "boosted {:?} rcv_boost {} caps {} {}",
            v.b.boost,
            v.k.rcv_boost,
            v.t.rcv_cap,
            v.t.snd_cap
        );
    }
    assert_eq!(n.s.hook.changes, vec![(c, true)], "hook changes");
    // 予約は 4 MiB にするが、測定が窓の上限を上げるまで広告する窓は floor を超えない (rcvwin.go)
    for o in n.drain() {
        assert!(
            u64::from(o.wnd) << RCV_WINDOW_SHIFT <= RECV_FLOOR,
            "window jumped beyond the floor on boost: {o}"
        );
    }
    let v = n.s.conn(c.slot);
    assert!(
        v.rcv_clamp() == RECV_FLOOR && v.t.adv_right <= v.b.rcv.read_off + RECV_FLOOR,
        "window clamp {}, edge {} past the floor from {}",
        v.rcv_clamp(),
        v.t.adv_right,
        v.b.rcv.read_off
    );
}

/// 送信の需要で枠を得ても受信の floor は保ち、後から受信の需要が生じたら同じ枠のまま受信の窓を広げます (Go の
/// `TestBoostOnSendDemandKeepsReceiveFloor`)。
#[test]
fn boost_on_send_demand_keeps_receive_floor() {
    let mut n = TestNet::new(small_limits());
    let l = n.listen(80);
    let mut p = n.handshake(40000, 80, true, true);
    p.wnd = 65535;
    let c = n.accept(l);
    n.drain();
    let w = n.s.write(n.now, c, &vec![0u8; DEMAND_BYTES]).unwrap();
    assert_eq!(w, DEMAND_BYTES, "the write fits in the send floor");
    {
        let v = n.s.conn(c.slot);
        assert!(
            v.b.boost.is_some()
                && !v.k.rcv_boost
                && v.t.rcv_cap == RECV_FLOOR
                && v.t.snd_cap == BOOST_SIZE,
            "boosted {:?} rcv_boost {} caps {} {}",
            v.b.boost,
            v.k.rcv_boost,
            v.t.rcv_cap,
            v.t.snd_cap
        );
        assert_eq!(v.b.recs.capacity(), BOOST_RECORDS, "record ring");
    }
    // 後から受信の向きの需要が生じたら同じ枠のまま受信の窓を広げる
    let outs = n.drain();
    p.absorb(&outs);
    send_bulk(&mut n, &mut p, DEMAND_BYTES);
    read_n(&mut n, c, DEMAND_BYTES);
    let v = n.s.conn(c.slot);
    assert!(
        v.k.rcv_boost && v.t.rcv_cap == BOOST_SIZE,
        "receive window not opened on receive demand"
    );
    assert_eq!(lent(&mut n), 1, "pool holds slots");
}

/// 1 秒より前の需要では回収せず、1 秒を超えた需要で保有者を floor に戻し、戻した後も広告した右端を縮めず、floor の
/// 外のデータを捨てることを確かめます (Go の `TestBoostReclaimFromIdleHolder`)。
#[test]
fn boost_reclaim_from_idle_holder() {
    let Two {
        mut n,
        c1,
        mut p1,
        c2,
        mut p2,
    } = boost_two();
    // 1 秒より前の需要では回収しない
    n.advance(Duration::from_millis(500));
    send_bulk(&mut n, &mut p2, DEMAND_BYTES);
    read_n(&mut n, c2, DEMAND_BYTES);
    assert!(
        !boosted(&mut n, c2),
        "reclaimed from a holder idle for less than a second"
    );
    n.advance(Duration::from_secs(1));
    send_bulk(&mut n, &mut p2, DEMAND_BYTES);
    read_n(&mut n, c2, DEMAND_BYTES);
    assert!(
        !boosted(&mut n, c1) && boosted(&mut n, c2),
        "after reclaim: holder and requester"
    );
    {
        let v = n.s.conn(c1.slot);
        assert!(
            v.t.rcv_cap == RECV_FLOOR
                && v.t.snd_cap == SEND_FLOOR
                && v.b.recs.capacity() == FLOOR_RECORDS,
            "holder not back at the floor"
        );
    }
    // 戻した後も広告した右端は縮めず、floor の外のデータは ACK せずに捨てて重複した ACK を返す
    n.drain();
    let (adv, read_off, irs) = {
        let v = n.s.conn(c1.slot);
        (v.t.adv_right, v.b.rcv.read_off, v.t.irs)
    };
    assert!(
        adv > read_off + RECV_FLOOR,
        "advertised edge {adv} did not extend beyond the floor {}",
        read_off + RECV_FLOOR
    );
    let before = p1.snd;
    let mut s = p1.seg(FLAG_ACK, &[0u8; 1000]);
    // floor の外、広告した右端の内側
    s.seq = irs
        .wrapping_add(1)
        .wrapping_add((read_off + RECV_FLOOR + 100) as u32);
    n.inject(&s);
    let outs = n.drain();
    assert!(
        outs.len() == 1 && outs[0].ack == before,
        "data beyond the floor: {}",
        crate::testnet_tests::show(&outs)
    );
    assert_eq!(
        n.s.conn(c1.slot).b.rcv.intervals_len(),
        0,
        "data beyond the floor was kept"
    );
    assert_eq!(n.s.stats().boost_reclaimed, 1, "reclaim not counted");
}

/// hook の `may_return` が偽を返す保有者は、2 秒の間需要が無くても枠を渡さないことを確かめます (Go の
/// `TestBoostDemotionRefusedByOnBoost`)。Rust の `allow_return` は接続ごとではなく核で 1 つです。
#[test]
fn boost_demotion_refused_by_hook() {
    let Two {
        mut n,
        c1,
        c2,
        mut p2,
        ..
    } = boost_two();
    n.s.hook.allow_return = false;
    n.advance(Duration::from_secs(2));
    send_bulk(&mut n, &mut p2, DEMAND_BYTES);
    read_n(&mut n, c2, DEMAND_BYTES);
    assert!(
        boosted(&mut n, c1) && !boosted(&mut n, c2),
        "may_return returning false did not keep the slot"
    );
    assert!(n.s.hook.asked.contains(&c1), "the holder was not asked");
    assert!(
        n.s.hook.changes.iter().all(|&(_, granted)| granted),
        "a slot was returned despite the refusal"
    );
}

/// floor の外に SACK 済みの順序外のデータを持つ保有者が、枠の取り合いがあり 1 秒の間需要が無いときだけ、floor の外の
/// 分を取り消して枠を渡すことを確かめます (Go の `TestBoostRenegeOnlyOnContentionAfterIdle`)。最近の区間の印は
/// `for_each_recent` で調べます。
#[test]
fn boost_renege_only_on_contention_after_idle() {
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
    inject_at(&mut n, &mut p1, c1, nxt + 1000, &[0u8; 1000]); // floor の内側
    inject_at(&mut n, &mut p1, c1, edge - 500, &[0u8; 1000]); // floor の境をまたぐ
    inject_at(&mut n, &mut p1, c1, nxt + (3 << 20), &[0u8; 1000]); // 3 MiB 先
    n.drain();
    {
        let v = n.s.conn(c1.slot);
        assert!(
            v.b.rcv.intervals_len() == 3 && v.b.rcv.ooo_bytes() == 3000,
            "setup: {} intervals, {} out-of-order bytes",
            v.b.rcv.intervals_len(),
            v.b.rcv.ooo_bytes()
        );
    }
    let adv = n.s.conn(c1.slot).t.adv_right;
    // 需要が 1 秒より新しい保有者からは、取り合いがあっても取り消さない
    n.advance(Duration::from_millis(500));
    send_bulk(&mut n, &mut p2, DEMAND_BYTES);
    read_n(&mut n, c2, DEMAND_BYTES);
    assert!(
        boosted(&mut n, c1) && !boosted(&mut n, c2) && n.s.conn(c1.slot).b.rcv.intervals_len() == 3,
        "holder idle for less than a second"
    );
    // 取り合いが無ければ、長く黙っても取り消さない
    n.advance(Duration::from_secs(30));
    n.drain();
    {
        let v = n.s.conn(c1.slot);
        assert!(
            v.b.boost.is_some() && v.b.rcv.intervals_len() == 3 && v.b.rcv.ooo_bytes() == 3000,
            "without contention: {} intervals, {} out-of-order bytes",
            v.b.rcv.intervals_len(),
            v.b.rcv.ooo_bytes()
        );
    }
    // 取り合いがあり、1 秒より長く黙った保有者は floor の外を取り消して枠を渡す
    send_bulk(&mut n, &mut p2, DEMAND_BYTES);
    read_n(&mut n, c2, DEMAND_BYTES);
    assert!(
        !boosted(&mut n, c1) && boosted(&mut n, c2),
        "after contention: holder and requester"
    );
    let got = intervals(&mut n, c1);
    let want = [(nxt + 1000, nxt + 2000), (edge - 500, edge)];
    assert!(
        got == want && n.s.conn(c1.slot).b.rcv.ooo_bytes() == 1500,
        "kept intervals {got:?}; want {want:?}, 1500 out-of-order bytes"
    );
    assert_eq!(n.s.conn(c1.slot).t.adv_right, adv, "advertised edge moved");
    assert_eq!(
        n.s.stats().boost_reneged_bytes,
        1500,
        "reneged bytes counted"
    );
    // 最近の区間の印は残した区間の始まりだけを指す。取り消した区間の印が残ると、後でその位置に作る区間の
    // block を先頭に置いてしまう
    let mut marks = Vec::new();
    n.s.conn(c1.slot)
        .b
        .rcv
        .for_each_recent(&mut |x| marks.push(x));
    assert_eq!(
        marks.len(),
        2,
        "{} recent-interval marks after the renege, want 2",
        marks.len()
    );
    for x in marks {
        assert!(
            want.iter().any(|&(s, _)| s == x),
            "recent-interval mark {x} is not the start of a kept interval"
        );
    }
    // 次の ACK の SACK の block は floor の内側だけを知らせる
    inject_at(&mut n, &mut p1, c1, nxt + 5000, &[0u8; 10]);
    let outs = n.drain();
    assert!(
        outs.len() == 1 && outs[0].sack.len() == 3,
        "ACK after the renege: {}",
        crate::testnet_tests::show(&outs)
    );
    let base = n.s.conn(c1.slot).t.irs.wrapping_add(1);
    for b in &outs[0].sack {
        assert!(
            !seq::gt(b.right, base.wrapping_add(edge as u32)),
            "SACK block {b:?} reports reneged data beyond {}",
            base.wrapping_add(edge as u32)
        );
    }
}

/// 相手が枠を得た接続に floor の外の 1 byte を送って穴を埋めずに黙っても、枠を持ち続けられないことを確かめます
/// (Go の `TestBoostPinnedByOneOutOfOrderByteIsReclaimed`)。枠の数は 2 本ではなく 16 本です。
#[test]
fn boost_pinned_by_one_out_of_order_byte_is_reclaimed() {
    const SLOTS: u16 = 16;
    let mut n = TestNet::new(wide_limits());
    let l = n.listen(80);
    let mut pinned = Vec::new();
    for i in 0..SLOTS {
        let mut p = n.handshake_sack(40000 + i, 80, true, true, true);
        let c = n.accept(l);
        let mut rounds = 0;
        loop {
            assert!(rounds < 40, "the window did not open past the floor");
            rounds += 1;
            send_bulk(&mut n, &mut p, DEMAND_BYTES);
            read_n(&mut n, c, DEMAND_BYTES);
            n.advance(Duration::from_millis(10));
            n.drain();
            let v = n.s.conn(c.slot);
            if v.b.boost.is_some() && v.t.adv_right > v.b.rcv.read_off + RECV_FLOOR + 2000 {
                break;
            }
        }
        let read_off = n.s.conn(c.slot).b.rcv.read_off;
        inject_at(&mut n, &mut p, c, read_off + RECV_FLOOR + 1000, &[0x41]);
        n.drain();
        assert_eq!(
            n.s.conn(c.slot).b.rcv.intervals_len(),
            1,
            "out-of-order byte beyond the floor not held"
        );
        pinned.push(c);
    }
    n.advance(Duration::from_secs(30));
    let mut p3 = n.handshake_sack(40100, 80, true, true, true);
    let c3 = n.accept(l);
    send_bulk(&mut n, &mut p3, DEMAND_BYTES);
    read_n(&mut n, c3, DEMAND_BYTES);
    assert!(
        boosted(&mut n, c3),
        "a connection with demand got no slot from holders pinned by one out-of-order byte"
    );
    let mut reneged = 0;
    for &c in &pinned {
        if !boosted(&mut n, c) {
            reneged += 1;
            let v = n.s.conn(c.slot);
            assert!(
                v.b.rcv.intervals_len() == 0 && v.b.rcv.ooo_bytes() == 0,
                "demoted holder kept {} intervals, {} bytes",
                v.b.rcv.intervals_len(),
                v.b.rcv.ooo_bytes()
            );
        }
    }
    assert!(
        reneged == 1 && lent(&mut n) == usize::from(SLOTS),
        "{reneged} holders demoted, pool holds {}",
        lent(&mut n)
    );
}

/// 取り消しの後に相手が累積の確認から送り直すと、取り消さずに残した順序外のデータと送り直したデータが、壊れずに順に
/// 届くことを確かめます (Go の `TestBoostRenegeThenRetransmitDeliversInOrder`)。
#[test]
fn boost_renege_then_retransmit_delivers_in_order() {
    const TOTAL: usize = 600 << 10;
    const MSS: usize = 1380;
    let Two {
        mut n,
        c1,
        mut p1,
        c2,
        mut p2,
    } = boost_two_with(true);
    let start = n.s.conn(c1.slot).b.rcv.nxt_off;
    let data: Vec<u8> = (0..TOTAL).map(|i| splitmix64(i as u64) as u8).collect();
    let send = |n: &mut TestNet, p: &mut PeerConn, lo: usize, hi: usize| {
        let mut o = lo;
        while o < hi {
            inject_at(n, p, c1, start + o as u64, &data[o..(o + MSS).min(hi)]);
            o += MSS;
        }
    };
    // 先頭の segment を欠いて残りを送る。残りは 1 つの区間になり、SACK で知らせる
    send(&mut n, &mut p1, MSS, TOTAL);
    n.drain();
    {
        let v = n.s.conn(c1.slot);
        assert!(
            v.b.rcv.intervals_len() == 1 && v.b.rcv.ooo_bytes() == (TOTAL - MSS) as u64,
            "setup: {} intervals, {} out-of-order bytes",
            v.b.rcv.intervals_len(),
            v.b.rcv.ooo_bytes()
        );
    }
    n.advance(Duration::from_secs(2));
    send_bulk(&mut n, &mut p2, DEMAND_BYTES);
    read_n(&mut n, c2, DEMAND_BYTES);
    assert!(!boosted(&mut n, c1), "holder not demoted");
    {
        let v = n.s.conn(c1.slot);
        let kept = v.b.rcv.read_off + RECV_FLOOR - start - MSS as u64;
        assert_eq!(v.b.rcv.ooo_bytes(), kept, "kept out-of-order bytes");
    }
    // 穴だけを送り直すと、残した区間までが順序どおりになる
    send(&mut n, &mut p1, 0, MSS);
    n.drain();
    let mut got: Vec<u8> = Vec::new();
    let read_all = |n: &mut TestNet, got: &mut Vec<u8>| {
        let k = n.s.conn(c1.slot).b.rcv.unread() as usize;
        if k > 0 {
            let mut buf = vec![0u8; k];
            let mut r = 0;
            while r < k {
                r += n.s.read(n.now, c1, &mut buf[r..]).unwrap();
            }
            got.extend_from_slice(&buf);
        }
    };
    read_all(&mut n, &mut got);
    assert_eq!(
        got.len() as u64,
        RECV_FLOOR,
        "bytes read after the hole was filled"
    );
    // 相手は累積の確認から送り直す。floor の外のデータは読んで空くまで捨てられる
    let mut rounds = 0;
    while got.len() < TOTAL {
        assert!(rounds < 100, "stalled at {} of {TOTAL} bytes", got.len());
        rounds += 1;
        let from = (n.s.conn(c1.slot).b.rcv.nxt_off - start) as usize;
        send(&mut n, &mut p1, from, TOTAL);
        n.drain();
        read_all(&mut n, &mut got);
    }
    assert!(
        got == data,
        "bytes delivered after the renege differ from the bytes sent"
    );
}

/// 接続を閉じると枠を返すことを確かめます (Go の `TestBoostReturnedWhenSlotFreed`)。
#[test]
fn boost_returned_when_slot_freed() {
    let mut n = TestNet::new(small_limits());
    let l = n.listen(80);
    let mut p = n.handshake(40000, 80, true, true);
    let c = n.accept(l);
    send_bulk(&mut n, &mut p, DEMAND_BYTES);
    read_n(&mut n, c, DEMAND_BYTES);
    assert_eq!(lent(&mut n), 1, "not boosted");
    n.s.abort(n.now, c);
    n.drain();
    assert_eq!(lent(&mut n), 0, "slot not returned on abort");
}

// ---- 受信の窓の自動調整 (Go の `rcvwin_test.go`) ----

/// timestamp と、`sack` が真なら SACK を許した接続を開き、受信の向きの boost を得させます (Go の `rwBoostedTS`)。
fn rw_boosted_ts(sack: bool, ts: bool) -> (TestNet, ConnId, PeerConn) {
    let mut n = TestNet::new(small_limits());
    let l = n.listen(80);
    let mut p = n.handshake_sack(40000, 80, ts, sack, true);
    let c = n.accept(l);
    send_bulk(&mut n, &mut p, DEMAND_BYTES);
    read_n(&mut n, c, DEMAND_BYTES);
    let outs = n.drain();
    p.absorb(&outs);
    assert!(n.s.conn(c.slot).k.rcv_boost, "no receive boost");
    (n, c, p)
}

fn rw_boosted(sack: bool) -> (TestNet, ConnId, PeerConn) {
    rw_boosted_ts(sack, true)
}

/// ACK の右端 (受信の offset) です。窓の欄は scale で切り下げた値です (Go の `rwEdge`)。
fn rw_edge(n: &mut TestNet, c: ConnId, o: &Out) -> u64 {
    let v = n.s.conn(c.slot);
    u64::from(o.ack.wrapping_sub(v.t.irs.wrapping_add(1))) + (u64::from(o.wnd) << v.t.rcv_wscale)
}

/// 相手から `k` byte の segment を 1 つ送り、核の ACK を受けて返します (Go の `rwSend`)。
fn rw_send(n: &mut TestNet, p: &mut PeerConn, k: usize) -> Vec<Out> {
    n.peer_ack(p, &vec![0u8; k]);
    let outs = n.drain();
    p.absorb(&outs);
    outs
}

/// 右端が予約の内側にあり、後ろへ戻っていないことを確かめ、今の右端を返します (Go の `rwCheck`)。
fn rw_check(n: &mut TestNet, c: ConnId, prev: u64, ctx: &str) -> u64 {
    let v = n.s.conn(c.slot);
    let (adv, read_off, cap) = (v.t.adv_right, v.b.rcv.read_off, v.t.rcv_cap);
    assert!(
        adv >= prev,
        "{ctx}: advertised edge went back from {prev} to {adv}"
    );
    assert!(
        adv <= read_off + cap,
        "{ctx}: advertised edge {adv} beyond the reservation {cap} from {read_off}"
    );
    let (clamp, ss) = (v.rcv_clamp(), v.t.rcv_ssthresh);
    assert!(
        clamp <= cap && ss <= clamp.max(RECV_FLOOR),
        "{ctx}: clamp {clamp}, rcv_ssthresh {ss}, reservation {cap}"
    );
    adv
}

/// 窓の上限が受け手の RTT ごとに読んだ量が増えたときだけ上がり、読む量が増えなければ上がらず、測定で下がらないことを
/// 確かめます。相手は広告された窓の内側だけを送ります (Go の `recvClampFollowsReads`)。
fn recv_clamp_follows_reads(ts: bool) {
    let (mut n, c, mut p) = rw_boosted_ts(false, ts);
    let mss = if ts { RW_MSS } else { TEST_MTU - 40 };
    assert_eq!(
        n.s.conn(c.slot).rcv_clamp(),
        RECV_FLOOR,
        "clamp right after the boost"
    );
    let mut edge = n.s.conn(c.slot).t.adv_right;
    let mut clamps: Vec<u64> = Vec::new();
    // 往復ごとに読む量:5 回倍にし、1 回 1 割だけ増やし、同じ量を続け、半分に減らしてから元に戻す。1 割の
    // 増加の目標は前の目標より小さいが、上限は下げない。減った後に元の量へ戻っても、前の区間の最大を超えない
    // ので上限は上がらない
    let kib = |k: usize| k << 10;
    let chunks = [
        kib(32),
        kib(64),
        kib(128),
        kib(256),
        kib(512),
        kib(563),
        kib(563),
        kib(563),
        kib(563),
        kib(563),
        kib(281),
        kib(281),
        kib(563),
        kib(563),
    ];
    for (round, chunk) in chunks.into_iter().enumerate() {
        n.advance(Duration::from_millis(50));
        let mut sent = 0;
        while sent < chunk {
            let room = {
                let v = n.s.conn(c.slot);
                v.t.adv_right.saturating_sub(v.b.rcv.nxt_off) as usize
            };
            let k = (chunk - sent).min(mss).min(room);
            assert!(
                k > 0,
                "round {round}: window closed with the reader keeping up"
            );
            rw_send(&mut n, &mut p, k);
            read_n(&mut n, c, k);
            edge = rw_check(&mut n, c, edge, "read rounds");
            sent += k;
        }
        clamps.push(n.s.conn(c.slot).rcv_clamp());
    }
    println!("clamps per round {clamps:?}");
    for i in 1..clamps.len() {
        assert!(
            clamps[i] >= clamps[i - 1],
            "clamp lowered by a measurement: {clamps:?}"
        );
    }
    assert!(
        clamps[4] > RECV_FLOOR,
        "clamp did not rise while reads doubled every RTT: {clamps:?}"
    );
    assert_eq!(
        clamps[9], clamps[6],
        "clamp kept rising while reads stayed flat: {clamps:?}"
    );
    assert_eq!(
        clamps[13], clamps[9],
        "clamp rose when reads came back to an earlier level: {clamps:?}"
    );
}

/// 窓の上限が測定に従うことを timestamp のある相手で確かめます (Go の `TestRecvWindowClampFollowsMeasuredReads` の
/// `timestamps`)。
#[test]
fn recv_window_clamp_follows_measured_reads_timestamps() {
    recv_clamp_follows_reads(true);
}

/// timestamp を持たない相手 (多くの Windows) は窓による標本だけで受け手の RTT を得ます (Go の
/// `TestRecvWindowClampFollowsMeasuredReads` の `no-timestamps`)。
#[test]
fn recv_window_clamp_follows_measured_reads_no_timestamps() {
    recv_clamp_follows_reads(false);
}

/// boost の後も読み取りの測定が無ければ、届く segment が窓の上限 (floor) の外へ右端を広げないことを確かめます (Go の
/// `TestRecvWindowWithoutReadsStaysAtFloor`)。
#[test]
fn recv_window_without_reads_stays_at_floor() {
    let (mut n, c, mut p) = rw_boosted(true);
    let mut edge = n.s.conn(c.slot).t.adv_right;
    for _ in 0..300 {
        let v = n.s.conn(c.slot);
        if v.t.adv_right - v.b.rcv.nxt_off < RW_MSS as u64 {
            break;
        }
        n.advance(Duration::from_millis(1));
        rw_send(&mut n, &mut p, RW_MSS);
        edge = rw_check(&mut n, c, edge, "no reads");
    }
    let v = n.s.conn(c.slot);
    assert!(
        v.t.adv_right <= v.b.rcv.read_off + RECV_FLOOR,
        "edge {} beyond the floor from the oldest unread byte {} without a measured read",
        v.t.adv_right,
        v.b.rcv.read_off
    );
}

/// 窓の上限が上がった後の右端が、届いた segment ごとに有界の量 (rcv_ssthresh の歩みの 2 MSS と、確認で進む 1
/// segment) だけ広がり、一度に開かないことを確かめます (Go の `TestRecvWindowStepPerSegment`)。
#[test]
fn recv_window_step_per_segment() {
    let (mut n, c, mut p) = rw_boosted(true);
    n.s.conn(c.slot).t.rcv_want = BOOST_SIZE; // 測定が上限を上げた後の状態
    // 読んだ分の右端をまず知らせ、そこから測る
    rw_send(&mut n, &mut p, RW_MSS);
    read_n(&mut n, c, RW_MSS);
    let outs = n.drain(); // 読み終えた時の ACK
    p.absorb(&outs);
    let mut edge = n.s.conn(c.slot).t.adv_right;
    let start = edge;
    let unit = 1u64 << n.s.conn(c.slot).t.rcv_wscale;
    let mut segs = 0u64;
    for _ in 0..400 {
        n.advance(Duration::from_millis(1));
        let ss = n.s.conn(c.slot).t.rcv_ssthresh;
        let mut outs = rw_send(&mut n, &mut p, RW_MSS);
        {
            let v = n.s.conn(c.slot);
            let d = v.t.rcv_ssthresh - ss;
            assert!(
                d <= 2 * u64::from(v.rcv_mss()).max(RW_MSS as u64),
                "rcv_ssthresh stepped {d} on one segment"
            );
            assert!(
                !(v.t.adv_right > edge && v.t.adv_right > v.b.rcv.nxt_off + v.t.rcv_ssthresh),
                "edge {} beyond RCV.NXT {} + rcv_ssthresh {}",
                v.t.adv_right,
                v.b.rcv.nxt_off,
                v.t.rcv_ssthresh
            );
        }
        read_n(&mut n, c, RW_MSS);
        let read = n.drain(); // 読み終えた時の ACK
        p.absorb(&read);
        outs.extend(read);
        segs += 1;
        let Some(last) = outs.last() else {
            continue;
        };
        // 窓の欄の切り下げで、欄から読む右端は論理の右端より最大 1 単位手前にある
        let got = rw_edge(&mut n, c, last);
        let mss = u64::from(n.s.conn(c.slot).rcv_mss());
        assert!(
            got <= edge + segs * 3 * mss + unit,
            "edge stepped from {edge} to {got} over {segs} segments"
        );
        edge = rw_check(&mut n, c, edge, "step");
        edge = edge.max(got);
        segs = 0;
    }
    let v = n.s.conn(c.slot);
    assert!(
        v.t.adv_right - start >= 400 * u64::from(v.rcv_mss()),
        "edge grew only {} bytes over 400 segments",
        v.t.adv_right - start
    );
    assert!(
        v.t.rcv_ssthresh <= v.rcv_clamp(),
        "rcv_ssthresh {} above the clamp {}",
        v.t.rcv_ssthresh,
        v.rcv_clamp()
    );
}

/// rcv_ssthresh の歩みの規則を確かめます。順序どおりの 128 byte 未満の segment と、SACK の無い接続の順序外の segment
/// では広げず、広げる量は自分の MSS の 2 倍と中身の 2 倍の大きい方で、上限と空きの小さい方を超えません (Go の
/// `TestRecvSsthreshStep`)。Go は `rcv.ooo` を直接書きますが、Rust は実際に順序外のデータを送って保持させ、穴を埋めて
/// 読むことで 0 に戻します。
#[test]
fn recv_ssthresh_step() {
    let (mut n, c, mut p) = rw_boosted(true);
    {
        let mut v = n.s.conn(c.slot);
        let mss = u64::from(v.rcv_mss());
        v.t.rcv_want = BOOST_SIZE;
        v.t.rcv_ssthresh = RECV_FLOOR;
        v.rcv_grow(RCV_GROW_MIN - 1, false);
        assert_eq!(
            v.t.rcv_ssthresh,
            RECV_FLOOR,
            "grew on a {} byte segment",
            RCV_GROW_MIN - 1
        );
        v.rcv_grow(RCV_GROW_MIN, false);
        assert_eq!(
            v.t.rcv_ssthresh,
            RECV_FLOOR + 2 * mss,
            "step on a small segment"
        );
        v.rcv_grow(4000, true);
        assert_eq!(
            v.t.rcv_ssthresh,
            RECV_FLOOR + 2 * mss + 8000,
            "step on a 4000 byte out-of-order segment"
        );
        v.t.sack_ok = false;
        let before = v.t.rcv_ssthresh;
        v.rcv_grow(mss as usize, true);
        assert_eq!(
            v.t.rcv_ssthresh, before,
            "grew on out-of-order data without SACK"
        );
        v.t.sack_ok = true;
    }
    // 余地は上限と空きの小さい方まで。保持するデータの分だけ空きが上限より小さい。実際に順序外のデータを保持させる
    let hole = p.snd;
    p.snd += RW_MSS as u32; // 失われた segment
    for _ in 0..37 {
        rw_send(&mut n, &mut p, RW_MSS);
    }
    let mut v = n.s.conn(c.slot);
    let mss = v.rcv_mss() as usize;
    assert!(v.b.rcv.ooo_bytes() > 0, "no out-of-order data held");
    let free = v.rcv_free();
    assert_eq!(
        free,
        v.rcv_clamp() - v.b.rcv.unread() - v.b.rcv.ooo_bytes(),
        "free does not count held data"
    );
    v.t.rcv_ssthresh = free - 100;
    v.rcv_grow(mss, false);
    assert_eq!(v.t.rcv_ssthresh, free, "rcv_ssthresh, want the free space");
    v.rcv_grow(mss, false);
    assert_eq!(v.t.rcv_ssthresh, free, "grew past the free space");
    // 穴を埋めて読み、保持するデータを 0 に戻す
    p.snd = hole;
    rw_send(&mut n, &mut p, RW_MSS);
    let unread = {
        let v = n.s.conn(c.slot);
        assert_eq!(v.b.rcv.ooo_bytes(), 0, "hole fill left out-of-order data");
        v.b.rcv.unread() as usize
    };
    read_n(&mut n, c, unread);
    let mut v = n.s.conn(c.slot);
    assert_eq!(v.b.rcv.unread() + v.b.rcv.ooo_bytes(), 0);
    v.t.rcv_ssthresh = v.rcv_clamp() - 100;
    v.rcv_grow(mss, false);
    v.rcv_grow(mss, false);
    assert_eq!(
        v.t.rcv_ssthresh,
        v.rcv_clamp(),
        "rcv_ssthresh, want the clamp"
    );
}

/// 保持する順序外のデータが空きを減らし、歩みの上限が届いている間は重複した ACK の右端と窓の欄が変わらないこと、穴を
/// 埋めても読むまで右端が進まないこと、読んだ後に進むことを確かめます (Go の `TestRecvWindowHeldOutOfOrder`)。
#[test]
fn recv_window_held_out_of_order() {
    let (mut n, c, mut p) = rw_boosted(true);
    let now = ns(n.now);
    {
        let mut v = n.s.conn(c.slot);
        // 歩みの上限が上限に届いた状態
        v.t.rcv_want = RECV_FLOOR + (64 << 10);
        v.t.rcv_ssthresh = RECV_FLOOR + (64 << 10);
        v.t.ack_now = true;
        v.after_input(now);
    }
    let outs = n.drain();
    p.absorb(&outs);
    let mut edge = rw_check(&mut n, c, 0, "start");
    {
        let v = n.s.conn(c.slot);
        assert_eq!(edge, v.b.rcv.read_off + v.rcv_clamp(), "edge at start");
    }
    let hole = p.snd;
    p.snd += RW_MSS as u32; // 失われた segment
    let mut wnd = 0;
    for i in 0..20 {
        let outs = rw_send(&mut n, &mut p, RW_MSS);
        assert!(
            outs.len() == 1 && outs[0].ack == hole,
            "out-of-order segment {i}: {}",
            crate::testnet_tests::show(&outs)
        );
        if i > 0 {
            assert_eq!(
                outs[0].wnd, wnd,
                "window field changed on duplicate ACK {i}"
            );
        }
        wnd = outs[0].wnd;
        edge = rw_check(&mut n, c, edge, "holes");
        assert_eq!(n.s.conn(c.slot).t.adv_right, edge, "edge moved");
    }
    {
        let v = n.s.conn(c.slot);
        assert_eq!(
            v.b.rcv.ooo_bytes(),
            20 * RW_MSS as u64,
            "held out-of-order bytes"
        );
        let got = v.rcv_target();
        assert!(
            got <= v.b.rcv.read_off + v.rcv_clamp() - v.b.rcv.ooo_bytes(),
            "target {got} does not count {} held out-of-order bytes",
            v.b.rcv.ooo_bytes()
        );
    }
    // 穴を埋める。読むまで保持するデータは同じなので右端は進まない
    let end = p.snd;
    p.snd = hole;
    let outs = rw_send(&mut n, &mut p, RW_MSS);
    p.snd = end;
    let ooo = n.s.conn(c.slot).b.rcv.ooo_bytes();
    assert!(
        outs.len() == 1 && outs[0].ack == end && ooo == 0,
        "hole fill: {}, ooo {ooo}",
        crate::testnet_tests::show(&outs)
    );
    assert_eq!(
        rw_check(&mut n, c, edge, "fill"),
        edge,
        "edge moved before the reader read"
    );
    read_n(&mut n, c, 21 * RW_MSS);
    let outs = n.drain();
    p.absorb(&outs);
    rw_send(&mut n, &mut p, RW_MSS);
    rw_send(&mut n, &mut p, RW_MSS); // 2 segment で ACK を返す
    assert!(
        rw_check(&mut n, c, edge, "read") > edge,
        "edge did not move after the reader drained the buffer"
    );
}

/// 歩みの上限が上限より小さい間は、SACK の接続の順序外の segment が歩みの上限を広げ、重複した ACK の窓の欄が大きく
/// なることを確かめます (Go の `TestRecvWindowOutOfOrderGrowsBelowClamp`、Linux の tcp_data_queue_ofo)。
#[test]
fn recv_window_out_of_order_grows_below_clamp() {
    let (mut n, c, mut p) = rw_boosted(true);
    n.s.conn(c.slot).t.rcv_want = BOOST_SIZE;
    p.snd += RW_MSS as u32;
    let mut edge = n.s.conn(c.slot).t.adv_right;
    let before = n.s.conn(c.slot).t.rcv_ssthresh;
    let mut last = 0;
    let mut grew = 0;
    for i in 0..10 {
        let outs = rw_send(&mut n, &mut p, RW_MSS);
        assert_eq!(
            outs.len(),
            1,
            "out-of-order segment {i}: {}",
            crate::testnet_tests::show(&outs)
        );
        if i > 0 && outs[0].wnd > last {
            grew += 1;
        }
        last = outs[0].wnd;
        edge = rw_check(&mut n, c, edge, "ofo growth");
    }
    let v = n.s.conn(c.slot);
    assert!(
        v.t.rcv_ssthresh == before + 10 * 2 * u64::from(v.rcv_mss()) && grew == 9,
        "rcv_ssthresh {} from {before}, window field grew on {grew} of 9 duplicate ACKs",
        v.t.rcv_ssthresh
    );
}

/// floor に戻すと歩みの上限も floor に戻り、右端は縮めないことを確かめます (Go の
/// `TestRecvWindowDemoteLowersSsthresh`)。
#[test]
fn recv_window_demote_lowers_ssthresh() {
    let Two {
        mut n,
        c1,
        c2,
        mut p2,
        ..
    } = boost_two();
    let edge = n.s.conn(c1.slot).t.adv_right;
    n.advance(Duration::from_secs(2));
    send_bulk(&mut n, &mut p2, DEMAND_BYTES);
    read_n(&mut n, c2, DEMAND_BYTES);
    assert!(!boosted(&mut n, c1), "holder not demoted");
    let v = n.s.conn(c1.slot);
    assert!(
        v.t.rcv_ssthresh <= RECV_FLOOR && v.rcv_clamp() == RECV_FLOOR && v.t.adv_right == edge,
        "after demotion: rcv_ssthresh {}, clamp {}, edge {} (was {edge})",
        v.t.rcv_ssthresh,
        v.rcv_clamp(),
        v.t.adv_right
    );
}

/// 相手から `bytes` byte 以上を `RW_MSS` の segment で送り、核の出力を読み捨てます。
fn peer_send(n: &mut TestNet, p: &mut PeerConn, bytes: usize) {
    let mut sent = 0;
    while sent < bytes {
        n.peer_ack(p, &[0u8; RW_MSS]);
        sent += RW_MSS;
        n.drain();
    }
}

/// 接続 `c` からちょうど `bytes` byte を読みます。
fn read_exact(n: &mut TestNet, c: ConnId, bytes: usize) {
    let mut b = vec![0u8; bytes];
    let mut got = 0;
    while got < bytes {
        got += n.s.read(n.now, c, &mut b[got..]).unwrap();
    }
}

/// boost を得る時に送信の輪の chunk を確保できなければ、枠を返して floor の段のままにし、次の需要で得ます。
#[test]
fn boost_acquire_survives_a_failed_send_ring() {
    use crate::buf::chunk::fail_chunks_after;
    let mut n = TestNet::new(small_limits());
    let (c, _) = n.accepted_sack(true, true);
    let data = vec![1u8; DEMAND_BYTES];
    // 書き込み自身が floor の輪に 4 つの chunk を取り、boost の輪へ写す 5 つ目で失敗します。
    fail_chunks_after(Some(4));
    n.s.write(n.now, c, &data).unwrap();
    fail_chunks_after(None);
    n.s.check_invariants().unwrap();
    let v = n.s.conn(c.slot);
    assert!(v.b.boost.is_none() && v.t.snd_cap == SEND_FLOOR && v.s.budget.lent() == 0);
    n.drain();
    n.advance(Duration::from_millis(300));
    n.s.write(n.now, c, &data).unwrap();
    n.s.check_invariants().unwrap();
    let v = n.s.conn(c.slot);
    assert!(v.b.boost.is_some() && v.t.snd_cap == BOOST_SIZE);
}

/// 受信の輪を boost の段に移す chunk を確保できなければ、受信を floor の段のままにし、次の需要で移します。
#[test]
fn boost_receive_growth_survives_a_failed_ring() {
    use crate::buf::chunk::fail_chunks_after;
    let mut n = TestNet::new(small_limits());
    let (c, mut p) = n.accepted_sack(true, true);
    peer_send(&mut n, &mut p, DEMAND_BYTES + 20 * RW_MSS);
    // 読み取りが需要に届き、空の送信の輪を移した後の受信の輪の写しで失敗します。
    fail_chunks_after(Some(0));
    read_exact(&mut n, c, DEMAND_BYTES);
    fail_chunks_after(None);
    n.s.check_invariants().unwrap();
    let v = n.s.conn(c.slot);
    assert!(v.b.boost.is_some() && !v.k.rcv_boost && v.t.rcv_cap == RECV_FLOOR);
    n.drain();
    n.advance(Duration::from_millis(300));
    peer_send(&mut n, &mut p, 2 * DEMAND_BYTES);
    read_exact(&mut n, c, DEMAND_BYTES);
    n.s.check_invariants().unwrap();
    let v = n.s.conn(c.slot);
    assert!(v.k.rcv_boost && v.t.rcv_cap == BOOST_SIZE);
}

/// floor に戻す輪の chunk を確保できなければ、保有者は boost の段のままで、求めた接続は枠を得ません。
#[test]
fn boost_demotion_survives_a_failed_ring() {
    use crate::buf::chunk::fail_chunks_after;
    let mut n = TestNet::new(wide_limits());
    let l = n.listen(80);
    let mut holders = Vec::new();
    for i in 0..16u16 {
        let mut p = n.handshake_sack(41000 + i, 80, true, true, true);
        let c = n.accept(l);
        // 未読のデータを残し、floor に戻す時に受信の輪を写させます。
        peer_send(&mut n, &mut p, DEMAND_BYTES + 4 * RW_MSS);
        read_exact(&mut n, c, DEMAND_BYTES);
        n.drain();
        holders.push(c);
    }
    let mut p = n.handshake_sack(42000, 80, true, true, true);
    let c = n.accept(l);
    assert_eq!(n.s.conn(c.slot).s.budget.lent(), 16);
    n.advance(Duration::from_secs(2));
    peer_send(&mut n, &mut p, DEMAND_BYTES);
    fail_chunks_after(Some(0));
    read_exact(&mut n, c, DEMAND_BYTES);
    fail_chunks_after(None);
    n.s.check_invariants().unwrap();
    assert!(n.s.conn(c.slot).b.boost.is_none());
    for h in &holders {
        assert!(n.s.conn(h.slot).b.boost.is_some());
    }
    // 保有者はすべて問われて戻りを許しましたが、どれも floor に戻っていません。
    assert_eq!(n.s.hook.asked.len(), 16);
    assert!(n.s.hook.changes.iter().all(|&(_, granted)| granted));
    assert_eq!(n.s.stats().boost_reclaimed, 0);
}
