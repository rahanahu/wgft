//! 順序外の segment ごとの重複した ACK の試験 (RFC 5681 3.2、wgstack-rs.md の「起床ごとの ACK の合わせ」)。
//!
//! 試験は `drain` の前に複数の segment を入れて、1 回の起床の受信の相を写します。

#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "tests collect segments and format failures"
)]
#![expect(clippy::cast_possible_truncation, reason = "test data")]

use crate::output::ACKS_PER_CONN;
use crate::testnet_tests::{Out, PeerConn, TestNet, show, small_limits};
use crate::{ConnId, Limits};
use crate::wire::{FLAG_ACK, FLAG_RST, SackBlock};
use core::time::Duration;

const SEG: u32 = 100;
/// 1 回の起床に入れる順序外の segment の数です。
const K: u32 = 8;

fn blk(left: u32, right: u32) -> SackBlock {
    SackBlock { left, right }
}

/// 接続の始めの quickack を使い切ったことにします。
fn skip_quickack(n: &mut TestNet) {
    let now = crate::stack::ns(n.now);
    let ids: Vec<u32> = n.s.conns.in_use().collect();
    for i in ids {
        let t = n.s.conns.tcb_mut(i);
        (t.rcvd_data, t.last_data_rcvd, t.quick_acks) = (true, now, 0);
    }
}

/// 相手の番号 `seq` から `SEG` byte の segment を入れます。相手の SND.NXT は変えません。
fn inject_at(n: &mut TestNet, p: &mut PeerConn, seq: u32) {
    let mut s = p.seg(FLAG_ACK, &[0x5a; SEG as usize]);
    s.seq = seq;
    n.inject(&s);
}

/// 核の出力のうち、中身の無い ACK です。
fn pure_acks(outs: &[Out]) -> Vec<&Out> {
    outs.iter()
        .filter(|o| o.payload.is_empty() && o.flags == FLAG_ACK)
        .collect()
}

#[test]
fn an_out_of_order_burst_gets_one_duplicate_ack_per_segment() {
    for sack in [true, false] {
        let mut n = TestNet::new(small_limits());
        let (_c, mut p) = n.accepted_sack(true, sack);
        let hole = p.snd;
        for i in 0..K {
            inject_at(&mut n, &mut p, hole + SEG * (i + 1));
        }
        let outs = n.drain();
        let acks = pure_acks(&outs);
        assert_eq!(acks.len(), K as usize, "sack {sack}: {}", show(&outs));
        for (i, a) in acks.iter().enumerate() {
            assert_eq!(a.ack, hole, "sack {sack}: ACK {i} is not a duplicate");
            if sack {
                // 各 ACK はその segment を受けた時の区間を最初の block で知らせます (RFC 2018)。
                let want = blk(hole + SEG, hole + SEG * (i as u32 + 2));
                assert_eq!(a.sack, vec![want], "sack {sack}: ACK {i}");
            } else {
                assert_eq!(a.sack, vec![]);
            }
        }
        let tsv: Vec<u32> = acks.iter().map(|a| a.ts.unwrap().0).collect();
        assert!(tsv.is_sorted(), "timestamps go back: {tsv:?}");
        assert_eq!(n.s.stats().dup_acks_merged, 0);
        // 遅らせた ACK は残りません。
        n.advance(Duration::from_millis(500));
        assert!(n.drain().is_empty());
    }
}

#[test]
fn segments_filling_holes_each_get_an_ack() {
    let mut n = TestNet::new(small_limits());
    let (c, mut p) = n.accepted_sack(true, true);
    let h = p.snd;
    // 穴を 2 つ残し、[h+100, h+200) と [h+300, h+400) を先に入れ、続けて 2 つの穴を順に埋めます。
    for off in [1, 3, 0, 2] {
        inject_at(&mut n, &mut p, h + SEG * off);
    }
    let outs = n.drain();
    let acks = pure_acks(&outs);
    let got: Vec<(u32, Vec<SackBlock>)> = acks.iter().map(|a| (a.ack - h, a.sack.clone())).collect();
    let want = vec![
        (0, vec![blk(h + 100, h + 200)]),
        (0, vec![blk(h + 300, h + 400), blk(h + 100, h + 200)]),
        (200, vec![blk(h + 300, h + 400)]),
        (400, vec![]),
    ];
    assert_eq!(got, want, "{}", show(&outs));
    assert_eq!(n.read_all(c).len(), 400);
}

#[test]
fn in_order_data_stays_merged_in_one_wake() {
    let mut n = TestNet::new(small_limits());
    let (_c, mut p) = n.accepted_sack(true, true);
    for _ in 0..6 {
        n.peer_ack(&mut p, &[1; SEG as usize]);
    }
    let outs = n.drain();
    let acks = pure_acks(&outs);
    assert!(
        acks.len() == 1 && acks[0].ack == p.snd,
        "in-order data in one wake gets one ACK: {}",
        show(&outs)
    );
}

#[test]
fn a_pending_in_order_ack_goes_out_before_the_duplicate_acks() {
    // quickack の間は順序どおりの segment が ACK の必要を立て、その ACK は順序外の segment の ACK と分かれます。
    let mut n = TestNet::new(small_limits());
    let (_c, mut p) = n.accepted_sack(true, true);
    n.peer_ack(&mut p, &[1; SEG as usize]);
    let a = p.snd;
    inject_at(&mut n, &mut p, a + SEG);
    inject_at(&mut n, &mut p, a + 2 * SEG);
    let outs = n.drain();
    let got: Vec<(u32, Vec<SackBlock>)> = pure_acks(&outs)
        .iter()
        .map(|o| (o.ack, o.sack.clone()))
        .collect();
    let want = vec![
        (a, vec![]),
        (a, vec![blk(a + SEG, a + 2 * SEG)]),
        (a, vec![blk(a + SEG, a + 3 * SEG)]),
    ];
    assert_eq!(got, want, "{}", show(&outs));
}

#[test]
fn a_delayed_ack_is_taken_by_the_first_duplicate_ack() {
    // 遅らせた ACK を待つ間に順序外の segment が届くと、その ACK が順序どおりのデータも確認し、遅らせる
    // タイマーを止めます。続く順序外の segment はそれぞれ ACK を得ます。
    let mut n = TestNet::new(small_limits());
    let (_c, mut p) = n.accepted_sack(true, true);
    skip_quickack(&mut n);
    n.peer_ack(&mut p, &[1; SEG as usize]);
    assert!(n.drain().is_empty(), "one small segment waits for the delayed ACK");
    let a = p.snd;
    inject_at(&mut n, &mut p, a + SEG);
    inject_at(&mut n, &mut p, a + 2 * SEG);
    let outs = n.drain();
    let acks = pure_acks(&outs);
    assert!(
        acks.len() == 2 && acks.iter().all(|o| o.ack == a),
        "{}",
        show(&outs)
    );
    n.advance(Duration::from_millis(200));
    assert!(n.drain().is_empty(), "the delayed ACK timer was stopped");
}

#[test]
fn a_full_ring_merges_the_rest() {
    // 輪の枠を 1 つの接続の上限より少なくし、輪が満ちる所を見ます。
    let limits = Limits {
        ctl_slots: 4,
        ..small_limits()
    };
    let mut n = TestNet::new(limits);
    let (_c, mut p) = n.accepted_sack(true, true);
    let slots = limits.ctl_slots as u32;
    let hole = p.snd;
    let extra = 3;
    // 最初の segment は ACK の必要を立てるだけで、続く segment が前の ACK を輪に積みます。輪が満ちた後の
    // segment の ACK は次の ACK と合わさります。
    for i in 0..1 + slots + extra {
        inject_at(&mut n, &mut p, hole + SEG * (i + 1));
    }
    assert_eq!(n.s.held().ack_queued, slots as usize);
    assert_eq!(n.s.stats().dup_acks_merged, u64::from(extra));
    let outs = n.drain();
    let acks = pure_acks(&outs);
    assert_eq!(acks.len(), slots as usize + 1, "{}", show(&outs));
    let last = acks.last().unwrap();
    assert_eq!(
        last.sack[0],
        blk(hole + SEG, hole + SEG * (2 + slots + extra)),
        "the last ACK carries everything received"
    );
    assert_eq!(n.s.held().ack_queued, 0);
    // 輪が空けば、次の起床でまた segment ごとに ACK を返します。
    let base = hole + SEG * (2 + slots + extra);
    for i in 0..3 {
        inject_at(&mut n, &mut p, base + SEG * (i + 1));
    }
    assert_eq!(pure_acks(&n.drain()).len(), 3);
}

#[test]
fn one_connection_queues_at_most_its_share() {
    let mut n = TestNet::new(small_limits());
    let (_c, mut p) = n.accepted_sack(true, true);
    let cap = u32::from(ACKS_PER_CONN);
    let hole = p.snd;
    let extra = 5;
    for i in 0..1 + cap + extra {
        inject_at(&mut n, &mut p, hole + SEG * (i + 1));
    }
    assert!(small_limits().ctl_slots > cap as usize, "the cap, not the ring, binds");
    assert_eq!(n.s.held().ack_queued, cap as usize);
    assert_eq!(n.s.stats().dup_acks_merged, u64::from(extra));
    let acks = pure_acks(&n.drain()).len();
    assert_eq!(acks, cap as usize + 1);
}

/// 80 番で待ち受け、相手の `ports` から接続を開いて accept し、接続と相手の側の接続を返します。
fn accept_many(n: &mut TestNet, ports: &[u16]) -> Vec<(ConnId, PeerConn)> {
    let l = n.listen(80);
    let mut out = Vec::new();
    for &port in ports {
        let p = n.handshake_sack(port, 80, true, true, true);
        let c = n.accept(l);
        out.push((c, p));
    }
    n.drain();
    out
}

#[test]
fn a_flooding_connection_does_not_hold_back_another() {
    let mut n = TestNet::new(small_limits());
    let mut conns = accept_many(&mut n, &[40000, 40001]);
    let (b, _) = conns[1];
    let (_, ref mut pa) = conns[0];
    let hole = pa.snd;
    for i in 0..40 {
        inject_at(&mut n, pa, hole + SEG * (i + 1));
    }
    assert_eq!(n.s.write(n.now, b, &[3; 2000]), Ok(2000));
    let outs = n.drain();
    // 出力の list の順は A、B です。A は輪の ACK を 1 つ送って list の末尾に回り、B は輪を待たずに送ります。
    let first_b = outs.iter().position(|o| o.lport == 80 && o.rport == 40001).unwrap();
    assert!(first_b <= 1, "B waited behind {first_b} packets: {}", show(&outs));
    assert_ne!(outs[first_b].payload.len(), 0);
    let a_acks = outs
        .iter()
        .filter(|o| o.rport == 40000 && o.payload.is_empty())
        .count();
    assert_eq!(a_acks, usize::from(ACKS_PER_CONN) + 1, "{}", show(&outs));
    // A の ACK は作った順に出ます。
    let a_sack_ends: Vec<u32> = outs
        .iter()
        .filter(|o| o.rport == 40000)
        .map(|o| o.sack[0].right)
        .collect();
    assert!(a_sack_ends.is_sorted(), "{a_sack_ends:?}");
}

#[test]
fn two_connections_share_the_ring() {
    let mut n = TestNet::new(small_limits());
    let mut conns = accept_many(&mut n, &[40000, 40001]);
    let holes: Vec<u32> = conns.iter().map(|(_, p)| p.snd).collect();
    for i in 0..4 {
        for (k, (_, p)) in conns.iter_mut().enumerate() {
            inject_at(&mut n, p, holes[k] + SEG * (i + 1));
        }
    }
    assert_eq!(n.s.held().ack_queued, 6);
    let outs = n.drain();
    for (k, port) in [40000u16, 40001].into_iter().enumerate() {
        let acks: Vec<&Out> = outs.iter().filter(|o| o.rport == port).collect();
        assert_eq!(acks.len(), 4, "{port}: {}", show(&outs));
        for (i, a) in acks.iter().enumerate() {
            assert_eq!(a.ack, holes[k]);
            assert_eq!(a.sack, vec![blk(holes[k] + SEG, holes[k] + SEG * (i as u32 + 2))]);
        }
    }
}

#[test]
fn a_repeated_out_of_order_segment_gets_its_own_d_sack() {
    let mut n = TestNet::new(small_limits());
    let (_c, mut p) = n.accepted_sack(true, true);
    let h = p.snd;
    // [h+100, h+200) を 2 度入れ、続けて [h+200, h+300) を入れます。
    for off in [1, 1, 2] {
        inject_at(&mut n, &mut p, h + SEG * off);
    }
    let outs = n.drain();
    let got: Vec<Vec<SackBlock>> = pure_acks(&outs).iter().map(|o| o.sack.clone()).collect();
    let x = blk(h + 100, h + 200);
    // 2 つ目の ACK は重複した segment の ACK で、D-SACK の block を先頭に持ちます (RFC 2883)。
    let want = vec![vec![x], vec![x, x], vec![blk(h + 100, h + 300)]];
    assert_eq!(got, want, "{}", show(&outs));
}

#[test]
fn the_right_edge_never_moves_back() {
    let mut n = TestNet::new(small_limits());
    let (c, mut p) = n.accepted_sack(true, true);
    let ws = n.s.conns.tcb(c.slot).rcv_wscale;
    let hole = p.snd;
    for i in 0..6 {
        inject_at(&mut n, &mut p, hole + SEG * (i + 1));
    }
    // 続けて穴を埋めます。
    inject_at(&mut n, &mut p, hole);
    let outs = n.drain();
    assert_eq!(pure_acks(&outs).len(), 7, "{}", show(&outs));
    let edges: Vec<u64> = outs
        .iter()
        .map(|o| u64::from(o.ack.wrapping_sub(hole)) + (u64::from(o.wnd) << ws))
        .collect();
    // 窓の欄は scale で右に shift した値なので、ACK の右端は 2^scale byte 未満だけ切り捨てられます (RFC 7323 の窓の scale)。
    // 核の広告した右端 (`adv_right`) は戻らないので、どの ACK の右端も前の ACK の右端からその量を超えて下がりません。
    let quantum = 1u64 << ws;
    for w in edges.windows(2) {
        assert!(w[1] + quantum > w[0], "the right edge moved back: {edges:?}");
    }
}

#[test]
fn a_reused_slot_does_not_send_the_old_connections_acks() {
    let mut n = TestNet::new(small_limits());
    let (c, mut p) = n.accepted_sack(true, true);
    let hole = p.snd;
    for i in 0..4 {
        inject_at(&mut n, &mut p, hole + SEG * (i + 1));
    }
    assert_eq!(n.s.held().ack_queued, 3);
    // 輪の ACK を、同じ枠を前に使った接続 (1 つ前の世代) のものにします。枠の今の接続は ACK を積んでいません。
    let generation = n.s.conns.tcb(c.slot).generation;
    n.s.s.out.acks.retag(generation.wrapping_sub(1));
    n.s.conns.tcb_mut(c.slot).acks_queued = 0;
    n.check();
    let outs = n.drain();
    assert_eq!(pure_acks(&outs).len(), 1, "only the slot's own ACK: {}", show(&outs));
    assert_eq!(n.s.held().ack_queued, 0);
}

#[cfg(feature = "harness")]
#[test]
fn the_go_compat_switch_merges_the_acks() {
    let mut n = TestNet::new(small_limits());
    let (_c, mut p) = n.accepted_sack(true, true);
    let hole = p.snd;
    crate::set_go_compat_merge_ooo_acks(true);
    for i in 0..K {
        inject_at(&mut n, &mut p, hole + SEG * (i + 1));
    }
    crate::set_go_compat_merge_ooo_acks(false);
    let outs = n.drain();
    assert_eq!(pure_acks(&outs).len(), 1, "{}", show(&outs));
    assert_eq!(n.s.stats().dup_acks_merged, 0);
}

#[test]
fn queued_acks_of_a_reset_connection_are_dropped() {
    let mut n = TestNet::new(small_limits());
    let (_c, mut p) = n.accepted_sack(true, true);
    let hole = p.snd;
    for i in 0..4 {
        inject_at(&mut n, &mut p, hole + SEG * (i + 1));
    }
    assert!(n.s.held().ack_queued > 0);
    let rst = p.seg(FLAG_RST, &[]);
    n.inject(&rst);
    let outs = n.drain();
    assert!(outs.is_empty(), "{}", show(&outs));
    assert_eq!(n.s.held().ack_queued, 0);
}

#[test]
fn queued_acks_go_before_the_connections_data() {
    let mut n = TestNet::new(small_limits());
    let (c, mut p) = n.accepted_sack(true, true);
    let hole = p.snd;
    assert_eq!(n.s.write(n.now, c, &[7; 3000]), Ok(3000));
    for i in 0..3 {
        inject_at(&mut n, &mut p, hole + SEG * (i + 1));
    }
    n.advance(Duration::from_millis(1));
    let outs = n.drain();
    let first_data = outs.iter().position(|o| !o.payload.is_empty()).unwrap();
    assert!(
        first_data == 2 && outs[..2].iter().all(|o| o.payload.is_empty()),
        "{}",
        show(&outs)
    );
    // 中身を持つ segment は最後の状態の SACK を運びます。
    assert_eq!(
        outs[first_data].sack,
        vec![blk(hole + SEG, hole + 4 * SEG)],
        "{}",
        show(&outs)
    );
    let tsv: Vec<u32> = outs.iter().map(|o| o.ts.unwrap().0).collect();
    assert!(tsv.is_sorted(), "timestamps go back: {tsv:?}");
}
