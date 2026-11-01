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
    let (b, recs, iv) = s.s.budget.acquire(first).unwrap();
    // 送信と受信の両方を boost の段に移します。
    let (t, _, c) = s.conns.parts_mut(0);
    c.boost = Some(b);
    c.snd
        .resize(BOOST_SIZE, &mut s.s.chunks, |f| f(0, 3 * CHUNK_SIZE as u64))
        .unwrap();
    c.spare_recs = c.recs.resize(recs);
    c.rcv.resize_ring(BOOST_SIZE, &mut s.s.chunks).unwrap();
    c.spare_iv = c.rcv.set_intervals(iv).unwrap();
    (t.snd_cap, t.rcv_cap) = (BOOST_SIZE, BOOST_SIZE);
    // 2 本目は送信だけを boost の段に移し、boost の区間の表を控えに持ちます。
    let second = s.conns.id(1);
    let (b2, recs2, iv2) = s.s.budget.acquire(second).unwrap();
    let (t, _, c) = s.conns.parts_mut(1);
    c.boost = Some(b2);
    c.snd
        .resize(BOOST_SIZE, &mut s.s.chunks, |f| f(0, 3 * CHUNK_SIZE as u64))
        .unwrap();
    c.spare_recs = c.recs.resize(recs2);
    c.spare_iv = iv2;
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
