//! 核の作成と閉じる時の会計と不変条件の試験です (Go の TestCloseReturnsEverything の表の部分)。

#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    reason = "tests format errors"
)]
#![expect(
    clippy::large_stack_arrays,
    clippy::many_single_char_names,
    reason = "test data"
)]

use super::*;
use crate::buf::BOOST_SIZE;
use crate::buf::chunk::CHUNK_SIZE;
use crate::buf::ring::Ring;
use crate::config::Limits;
use crate::tcp::listen::enqueue;
use crate::tcp::syn::SynRow;
use crate::tcp::timewait::TwRow;
use crate::wire::Tuple;
use core::net::Ipv4Addr;

fn small() -> Config {
    Config {
        addr: Ipv4Addr::new(10, 9, 0, 1),
        mtu: 1420,
        limits: Limits {
            max_flows: 16,
            accept_queue: 8,
            syn_rows: 16,
            tw_rows: 32,
            ctl_slots: 16,
            frag_entries: 4,
            frag_pieces: 8,
            udp_rx_datagrams: 8,
            udp_tx_datagrams: 8,
        },
        ..Config::new(Ipv4Addr::new(10, 9, 0, 1), 1420)
    }
}

fn tup(rport: u16) -> Tuple {
    Tuple {
        laddr: 0x0a09_0001,
        raddr: 0x0a09_0002,
        lport: 80,
        rport,
    }
}

#[test]
fn rejects_a_bad_config_and_returns_the_budget() {
    let e = Stack::new(
        Config {
            mtu: 100,
            ..small()
        },
        Budget::new().unwrap(),
        &[0; 64],
        NoHook,
    )
    .unwrap_err();
    assert_eq!(e.kind(), NewErrorKind::Config(ConfigError::Mtu(100)));
    assert_eq!(e.into_budget().slots(), crate::buf::BOOST_SLOTS);
}

/// 表を使った状態から閉じると、保持がすべて 0 に戻り、Budget の配列が戻ります。
#[test]
fn close_returns_everything() {
    let mut s = Stack::new(small(), Budget::new().unwrap(), &[7; 64], NoHook).unwrap();
    let g = s.s.listeners.open(80).unwrap();
    // 接続 2 本を確立したとして、表と待ち行列と boost に入れます。
    for rport in [1000, 1001] {
        let i = s.conns.alloc(&mut s.s.conn_free).unwrap().unwrap();
        let id = s.conns.id(i);
        let (t, _, c) = s.conns.parts_mut(i);
        t.tup = tup(rport);
        t.in_index = true;
        (t.snd_cap, t.rcv_cap) = (crate::buf::SEND_FLOOR, crate::buf::RECV_FLOOR);
        t.cwnd = 1;
        s.s.conn_idx.insert(tup(rport), i, id.generation);
        c.snd
            .write(0, &[1; 3 * CHUNK_SIZE], &mut s.s.chunks)
            .unwrap();
        t.tail_off = 3 * CHUNK_SIZE as u64;
        let l = s.s.listeners.get(80, g).unwrap();
        l.qlen += 1;
        s.s.queued += 1;
        enqueue(l, 80, &mut s.s.qlinks, i);
    }
    let first = s.conns.id(0);
    let (b, a) = s.s.budget.acquire(first).unwrap();
    // 送信と受信の両方を boost の段に移します。
    let (t, _, c) = s.conns.parts_mut(0);
    c.boost = Some(b);
    let end = 3 * CHUNK_SIZE as u64;
    c.snd
        .move_to(Ring::with_table(BOOST_SIZE, a.snd), 0, end, &mut s.s.chunks);
    c.spare_recs = c.recs.resize(a.recs);
    let next = c
        .rcv
        .copied_ring(Ring::with_table(BOOST_SIZE, a.rcv), &mut s.s.chunks)
        .unwrap();
    c.rcv.r.release(&mut s.s.chunks);
    c.rcv.r = next;
    c.spare_iv = c.rcv.set_intervals(a.iv).unwrap();
    (t.snd_cap, t.rcv_cap) = (BOOST_SIZE, BOOST_SIZE);
    // 2 本目は送信だけを boost の段に移し、boost の区間の表と受信の輪の表を控えに持ちます。
    let second = s.conns.id(1);
    let (b2, a2) = s.s.budget.acquire(second).unwrap();
    let (t, _, c) = s.conns.parts_mut(1);
    c.boost = Some(b2);
    c.snd.move_to(
        Ring::with_table(BOOST_SIZE, a2.snd),
        0,
        end,
        &mut s.s.chunks,
    );
    c.spare_recs = c.recs.resize(a2.recs);
    c.spare_iv = a2.iv;
    c.spare_tbl = a2.rcv;
    t.snd_cap = BOOST_SIZE;
    s.s.syn
        .insert(SynRow {
            tup: tup(2000),
            listener: 80,
            ..SynRow::default()
        })
        .unwrap();
    s.s.listeners.get(80, g).unwrap().syn_count += 1;
    s.s.tw.insert(TwRow {
        tup: tup(3000),
        ..TwRow::default()
    });
    s.s.out.ctl.slot().unwrap()[0] = 1;
    s.s.out.ctl.commit(40);
    s.s.events.raise(0, 1);
    s.check_invariants().unwrap();
    let h = s.held();
    assert_eq!(
        (
            h.conns,
            h.syn_rows,
            h.tw_rows,
            h.accept_queued,
            h.ctl_queued,
            h.boosted,
            h.events
        ),
        (2, 1, 1, 2, 1, 2, 1)
    );
    assert_eq!(h.chunk_bytes, 6 * CHUNK_SIZE);
    assert!(h.record_bytes > 0 && h.interval_bytes > 0 && h.reserved > 0);
    let closed = s.close(Time::from_nanos(5));
    assert!(closed.held.is_zero(), "{:?}", closed.held);
    assert_eq!(closed.budget.lent(), 0);
    closed.budget.check().unwrap();
}

#[test]
fn invariants_catch_a_broken_count() {
    let mut s = Stack::new(small(), Budget::new().unwrap(), &[7; 64], NoHook).unwrap();
    s.check_invariants().unwrap();
    s.s.queued = 1;
    assert_eq!(
        s.check_invariants().unwrap_err().what(),
        "the accept queue lengths disagree with the total"
    );
    s.s.queued = 0;
    let i = s.conns.alloc(&mut s.s.conn_free).unwrap().unwrap();
    {
        let t = s.conns.tcb_mut(i);
        (t.snd_cap, t.rcv_cap) = (crate::buf::SEND_FLOOR, crate::buf::RECV_FLOOR);
        t.cwnd = 1;
    }
    s.conns.bufs_mut(i).boost = Some(3);
    assert!(
        s.check_invariants().is_err(),
        "a slot that claims a boost slot it does not hold"
    );
    s.conns.bufs_mut(i).boost = None;
    s.check_invariants().unwrap();
    // 輪の外に出した chunk は置き場の数と合いません。
    let c = s.s.chunks.get().unwrap();
    assert_eq!(
        s.check_invariants().unwrap_err().what(),
        "the chunk pool count disagrees with the rings"
    );
    s.s.chunks.put(c);
    // タイマーの欄と輪が合わない。
    s.conns.tcb_mut(i).tdl[0] = 5;
    assert_eq!(
        s.check_invariants().unwrap_err().what(),
        "a connection timer disagrees with the wheel"
    );
    s.conns.tcb_mut(i).tdl[0] = 0;
    // 予約と輪の容量が合わない。
    s.conns.tcb_mut(i).snd_cap = 1;
    assert_eq!(
        s.check_invariants().unwrap_err().what(),
        "a connection's reservation disagrees with its rings"
    );
    s.conns.tcb_mut(i).snd_cap = crate::buf::SEND_FLOOR;
    s.check_invariants().unwrap();
    let text = s
        .check_invariants()
        .map_or_else(|e| e.to_string(), |()| "ok".to_owned());
    assert_eq!(text, "ok");
    assert_eq!(s.config().mtu, 1420);
    let _ = format!("{s:?}");
    let _ = s.close(Time::ZERO);
}

/// floor に戻す間に接続が持つ chunk は、その接続の boost の枠の予約 (両方の向きの boost の段) の内にあります
/// (`bound::STAGE_CHANGE_FITS`)。受信の取り消しは区間の表だけを変えるので、順序外のデータで満ちた古い受信の輪は、
/// 新しい floor の輪を作る間も chunk を持ったままです。
#[test]
fn demote_holds_within_the_connection_s_reservation() {
    use crate::buf::chunk::{held_peak, reset_held_peak};
    use crate::buf::{RECV_FLOOR, SEND_FLOOR};
    use crate::tcp::boost::IDLE_RECLAIM;
    let mut s = Stack::new(small(), Budget::new().unwrap(), &[7; 64], NoHook).unwrap();
    let i = s.conns.alloc(&mut s.s.conn_free).unwrap().unwrap();
    let id = s.conns.id(i);
    let (b, a) = s.s.budget.acquire(id).unwrap();
    let pool = &mut s.s.chunks;
    let (t, k, c) = s.conns.parts_mut(i);
    c.boost = Some(b);
    // 送信:boost の段の輪に、境目のそろわない floor の分の送り残しを持ちます。
    let una = 100;
    c.snd
        .move_to(Ring::with_table(BOOST_SIZE, a.snd), una, una, pool);
    c.snd
        .write(una, &vec![5u8; usize::try_from(SEND_FLOOR).unwrap()], pool)
        .unwrap();
    c.spare_recs = c.recs.resize(a.recs);
    (t.una_off, t.tail_off) = (una, una + SEND_FLOOR);
    t.snd_cap = BOOST_SIZE;
    t.cwnd = 1;
    // 受信:順序どおりの未読は floor の内で、小さな穴の先の boost の段の輪の残りを順序外のデータで満たします。
    // 順序外のデータのうち floor の内の分は取り消しの後も残るので、新しい floor の輪も満ちます。
    let next = c
        .rcv
        .copied_ring(Ring::with_table(BOOST_SIZE, a.rcv), pool)
        .unwrap();
    c.rcv.r.release(pool);
    c.rcv.r = next;
    c.spare_iv = c.rcv.set_intervals(a.iv).unwrap();
    k.rcv_boost = true;
    t.rcv_cap = BOOST_SIZE;
    assert_eq!(c.rcv.insert(0, &[1; 1000], BOOST_SIZE, pool).accepted, 1000);
    let ooo = 2000;
    let data = vec![2u8; usize::try_from(BOOST_SIZE - ooo).unwrap()];
    assert_eq!(
        c.rcv.insert(ooo, &data, BOOST_SIZE, pool).accepted,
        data.len()
    );
    k.last_demand = 0;
    let conn_before = c.held_chunks();
    let held_before = s.s.chunks.held();
    s.check_invariants().unwrap();

    reset_held_peak(held_before);
    assert!(
        s.demote(id, IDLE_RECLAIM + 1),
        "the idle holder returns to the floor"
    );
    let growth = held_peak() - held_before;
    let c = CHUNK_SIZE as u64;
    let reservation = usize::try_from(2 * BOOST_SIZE / c).unwrap();
    eprintln!(
        "demote: the connection held {conn_before} chunks, grew by at most {growth} while it moved, against a reservation of {reservation}"
    );
    // 最も多く持つ場合 (bound::STAGE_CHANGE_FITS の demote の和) に届きます。
    let (f, b) = (RECV_FLOOR / c, BOOST_SIZE / c);
    assert_eq!(
        conn_before + growth,
        usize::try_from(b + 3 * f + 1).unwrap()
    );
    assert!(
        conn_before + growth <= reservation,
        "the connection held {conn_before} chunks and grew by {growth} while it moved, above its reservation of {reservation}"
    );
    let after = s.conns.bufs_mut(i).held_chunks();
    assert!(
        after <= usize::try_from((SEND_FLOOR + RECV_FLOOR) / c).unwrap(),
        "{after} chunks after demote"
    );
    assert_eq!(s.s.chunks.held(), held_before - conn_before + after);
    assert_eq!(s.s.budget.lent(), 0);
    s.check_invariants().unwrap();
    let closed = s.close(Time::from_nanos(IDLE_RECLAIM.unsigned_abs() + 2));
    assert!(closed.held.is_zero(), "{:?}", closed.held);
}

/// 試験と fuzz の build だけにある欄の byte の和 `HARNESS_BYTES` が、欄の型の大きさの和と一致します。
/// 欄を足して `HARNESS_BYTES` を直し忘れると、上界の式が build ごとに違う大きさを使うので、ここで落とします。
#[test]
fn harness_bytes_match_the_harness_only_fields() {
    let s = Stack::new(small(), Budget::new().unwrap(), &[7; 64], NoHook).unwrap();
    let sum = s.conns.harness_bytes()
        + s.s.events.harness_bytes()
        + s.s.budget.harness_bytes()
        + s.s.listeners.harness_bytes()
        + s.s.udp.eps.harness_bytes();
    assert_eq!(sum, HARNESS_BYTES);
}
