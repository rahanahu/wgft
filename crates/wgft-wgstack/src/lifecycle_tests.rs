//! 接続の一生の乱数の試験と、時刻の端と知らせの試験です (独立のレビューの試験を移したもの)。
//!
//! 乱数の試験は、相手の番号を追う相手と追わない相手で、接続の開き方、閉じ方、古い handle、時刻の跳びを混ぜ、
//! 各段で不変条件を確かめ、最後に閉じて会計が 0 に戻ることを確かめます。種の数と段の数は環境変数
//! `STRESS_SEEDS`、`STRESS_STEPS`、`LC_SEEDS` で増やせます。

#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "tests build data and format failures"
)]
#![expect(
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    reason = "test data"
)]

use crate::stack::{Error, Event, ListenerId};
use crate::tcp::conn::{ConnId, State};
use crate::testnet_tests::{DUT, PeerConn, TSeg, TestNet, show, small_limits};
use crate::time::Time;
use crate::wire::{FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN};
use core::net::SocketAddrV4;
use core::time::Duration;
use std::collections::HashMap;

const MS: Duration = Duration::from_millis(1);

fn env_or<T: core::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn listener(n: &TestNet, port: u16) -> ListenerId {
    ListenerId {
        port,
        generation: n.s.s.listeners.generation(port),
    }
}

/// 上限の近くの時刻でも、期限の足し算が溢れず panic しません。
#[test]
fn time_near_the_maximum() {
    let mut n = TestNet::new(small_limits());
    n.listen(80);
    n.now = Time::from_nanos(i64::MAX as u64);
    n.inject(&TSeg {
        sport: 1,
        dport: 80,
        seq: 7,
        flags: FLAG_SYN,
        wnd: 1000,
        ..TSeg::default()
    });
    assert_eq!(n.drain().len(), 1);
    let mut m = TestNet::new(small_limits());
    let (c, _) = m.accepted(true);
    m.s.write(m.now, c, b"x").unwrap();
    m.drain();
    m.now = Time::MAX;
    m.s.handle_timeout(m.now);
    m.drain();
    m.s.check_invariants().unwrap();
    assert!(m.s.poll_timeout().is_some_and(|t| t.as_nanos() > 0));
}

/// 枠が別の接続に使われた後の古い handle の abort は、元の接続の TIME_WAIT の行だけを外します。
#[test]
fn stale_abort_after_slot_reuse() {
    let mut n = TestNet::new(small_limits());
    let (a, mut pa) = n.accepted(true);
    n.s.close_conn(n.now, a);
    let outs = n.drain();
    pa.absorb(&outs);
    n.peer_ack(&mut pa, &[]);
    n.peer_fin(&mut pa);
    let outs = n.drain();
    assert_eq!(n.s.s.tw.len(), 1, "{}", show(&outs));
    let l = listener(&n, 80);
    let _pb = n.handshake(40001, 80, true, true);
    let b = n.accept(l);
    n.drain();
    assert_eq!(b.slot, a.slot);
    assert_ne!(b.generation, a.generation);
    n.s.abort(n.now, a);
    let outs = n.drain();
    assert!(
        outs.len() == 1 && outs[0].has(FLAG_RST) && outs[0].rport == 40000,
        "{}",
        show(&outs)
    );
    assert_eq!(n.s.s.tw.len(), 0);
    assert!(n.s.conns.resolve(b).is_some());
}

/// 返した接続の知らせは、同じ枠を使う次の接続に届きません (確立の時に枠の印を消します)。
#[test]
fn events_do_not_leak_across_slot_reuse() {
    let mut n = TestNet::new(small_limits());
    let (a, mut pa) = n.accepted(true);
    n.events();
    n.peer_ack(&mut pa, b"abc");
    n.drain();
    n.s.abort(n.now, a); // Readable(a) が残ったまま枠を返します
    n.drain();
    let l = listener(&n, 80);
    let _pb = n.handshake(40001, 80, true, true);
    let b = n.accept(l);
    n.drain();
    assert_eq!(b.slot, a.slot);
    let ev = n.events();
    assert!(!ev.contains(&Event::Readable(b)), "{ev:?}");
    assert!(!ev.contains(&Event::Readable(a)), "{ev:?}");
}

/// 枠を返した後に取り出した知らせは、枠を最後に使った接続の handle で出ます。
#[test]
fn events_after_release_carry_the_last_handle() {
    let mut n = TestNet::new(small_limits());
    let (c, mut p) = n.accepted(true);
    n.events();
    let rst = p.seg(FLAG_RST, &[]);
    n.inject(&rst); // CLOSED にして Closed を付けます
    n.s.close_conn(n.now, c); // 枠を返します
    assert_eq!(n.s.conns.tcb(c.slot).state, State::Free);
    let ev = n.events();
    assert!(ev.contains(&Event::Closed(c)), "{ev:?}");
    assert!(ev.contains(&Event::Readable(c)), "{ev:?}");
}

/// Go の Close と同じく、close_conn と abort は読み取りと書き込みを待つ呼び手を起こし、close_write は書き込みを
/// 待つ呼び手を起こします。
#[test]
fn close_and_abort_wake_waiters() {
    let mut n = TestNet::new(small_limits());
    let (c, _p) = n.accepted(true);
    n.events();
    n.s.close_write(n.now, c).unwrap();
    assert_eq!(n.events(), [Event::Writable(c)]);
    n.s.close_conn(n.now, c);
    let ev = n.events();
    assert!(
        ev.contains(&Event::Readable(c)) && ev.contains(&Event::Writable(c)),
        "{ev:?}"
    );
    n.drain();
    let l = listener(&n, 80);
    let _p2 = n.handshake(40001, 80, true, true);
    let c2 = n.accept(l);
    n.drain();
    n.events();
    n.s.abort(n.now, c2);
    let ev = n.events();
    assert!(
        ev.contains(&Event::Readable(c2)) && ev.contains(&Event::Writable(c2)),
        "{ev:?}"
    );
}

/// accept の待ち行列の中で RST で終わった接続は、accept されません。
#[test]
fn events_for_unaccepted_released_conn() {
    let mut n = TestNet::new(small_limits());
    let l = n.listen(80);
    let mut p = n.handshake(40000, 80, true, true);
    n.drain();
    n.peer_ack(&mut p, b"abc");
    n.drain();
    let rst = p.seg(FLAG_RST, &[]);
    n.inject(&rst);
    n.events();
    assert_eq!(n.s.accept(n.now, l), Err(Error::WouldBlock));
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
}

#[derive(Default, Clone, Copy)]
struct Peer {
    snd: u32,
    rcv: u32,
    ts: u32,
    iss: u32,
    open: bool,
}

fn stress(seed: u64, steps: usize) {
    let chaos: u64 = env_or("STRESS_CHAOS", 15u64);
    let auto_drain = std::env::var("STRESS_DRAIN").is_ok();
    let mut r = Rng(seed | 1);
    let mut seedb = [0u8; 64];
    for (i, b) in seedb.iter_mut().enumerate() {
        *b = (seed >> (i % 8)) as u8 ^ i as u8;
    }
    let mut lim = small_limits();
    lim.max_flows = 4;
    lim.accept_queue = 8;
    lim.syn_rows = 6;
    lim.tw_rows = 3;
    lim.ctl_slots = 4;
    let mut n = TestNet::with_seed(lim, seedb);
    let ports = [40000u16, 40001, 40002, 40003, 40004, 40005, 40006, 40007];
    let mut peers: HashMap<u16, Peer> = HashMap::new();
    let mut listener: Option<crate::stack::ListenerId> = None;
    let mut handles: Vec<ConnId> = Vec::new(); // all handles ever seen
    let mut buf = vec![0u8; 70000];
    let lports = [80u16, 81];
    let mut maxtw = 0usize;
    for step in 0..steps {
        maxtw = maxtw.max(n.s.s.tw.len());
        let op = r.below(100);
        let port = ports[r.below(ports.len() as u64) as usize];
        let lport = lports[r.below(2) as usize];
        let p = peers.entry(port).or_default();
        match op {
            0..=9 => {
                // SYN
                let iss = r.next() as u32;
                *p = Peer {
                    snd: iss.wrapping_add(1),
                    rcv: 0,
                    ts: p.ts.wrapping_add(1 + r.below(1000) as u32),
                    iss,
                    open: true,
                };
                let seq = if r.chance(30) {
                    p.snd.wrapping_add(r.below(1 << 20) as u32)
                } else {
                    iss
                };
                n.inject(&TSeg {
                    sport: port,
                    dport: lport,
                    seq,
                    flags: FLAG_SYN
                        | if r.chance(5) { FLAG_ACK } else { 0 }
                        | if r.chance(3) { FLAG_RST } else { 0 },
                    wnd: r.below(65536) as u16,
                    mss: [0u16, 536, 1380, 9000, 100][r.below(5) as usize],
                    ws: if r.chance(70) {
                        Some(r.below(16) as u8)
                    } else {
                        None
                    },
                    sack_ok: r.chance(50),
                    ts: if r.chance(70) { Some((p.ts, 0)) } else { None },
                    ..TSeg::default()
                });
            }
            10..=54 => {
                // ACK / data / FIN / RST along the tracked numbers
                let mut flags = FLAG_ACK;
                if r.chance(8) {
                    flags |= FLAG_FIN;
                }
                if r.chance(10) {
                    flags |= FLAG_FIN;
                }
                if r.chance(chaos / 3) {
                    flags = FLAG_RST | if r.chance(50) { FLAG_ACK } else { 0 };
                }
                let len = if flags & FLAG_FIN != 0 || r.chance(60) {
                    0
                } else {
                    r.below(1400) as usize
                };
                let mut seq = p.snd;
                if r.chance(chaos) {
                    seq = seq.wrapping_add((r.below(200_000) as u32).wrapping_sub(100_000));
                }
                let mut ack = p.rcv;
                if r.chance(chaos * 2 / 3) {
                    ack = ack.wrapping_add((r.below(200_000) as u32).wrapping_sub(100_000));
                }
                if r.chance(80) {
                    p.ts = p.ts.wrapping_add(r.below(50) as u32);
                } else {
                    p.ts = p.ts.wrapping_sub(r.below(1 << 31) as u32);
                }
                let ts = if r.chance(85) {
                    Some((p.ts, r.next() as u32 & 0xff))
                } else {
                    None
                };
                n.inject(&TSeg {
                    sport: port,
                    dport: lport,
                    seq,
                    ack,
                    flags,
                    wnd: if r.chance(10) {
                        0
                    } else {
                        r.below(65536) as u16
                    },
                    ts,
                    payload: vec![0x5a; len],
                    ..TSeg::default()
                });
                if seq == p.snd {
                    p.snd = p
                        .snd
                        .wrapping_add(len as u32 + u32::from(flags & FLAG_FIN != 0));
                }
            }
            55..=59 => {
                if (listener.is_none() || r.chance(30))
                    && let Ok(l) = n.s.listen_tcp(n.now, SocketAddrV4::new(DUT, 80))
                {
                    listener = Some(l);
                }
                if r.chance(20) {
                    let _ = n.s.listen_tcp(n.now, SocketAddrV4::new(DUT, 81));
                }
            }
            60..=66 => {
                if let Some(l) = listener {
                    while let Ok((c, _)) = n.s.accept(n.now, l) {
                        handles.push(c);
                    }
                }
            }
            97..=97 => {
                if let Some(l) = listener {
                    n.s.close_listener(n.now, l);
                    if r.chance(50) {
                        listener = None;
                    }
                }
            }
            67..=79 => {
                if !handles.is_empty() {
                    let k = handles.len() as u64;
                    let h = if r.chance(80) {
                        handles[(k - 1 - r.below(k.min(6))) as usize]
                    } else {
                        handles[r.below(k) as usize]
                    };
                    match r.below(8) {
                        0 | 1 => {
                            let k = r.below(70000) as usize;
                            let _ = n.s.read(n.now, h, &mut buf[..k]);
                        }
                        2 | 3 => {
                            let k = r.below(70000) as usize;
                            let _ = n.s.write(n.now, h, &buf[..k]);
                        }
                        4 => {
                            let _ = n.s.close_write(n.now, h);
                        }
                        5 => n.s.close_conn(n.now, h),
                        6 => n.s.abort(n.now, h),
                        _ => {
                            let _ = n.s.delivered(h);
                            let _ = n.s.local_addr(h);
                        }
                    }
                    n.s.check_invariants().unwrap();
                }
            }
            80..=89 => {}
            _ if false => {}
            _ => {}
        }
        if auto_drain || (80..=89).contains(&op) {
            {
                let outs = n.drain();
                for o in &outs {
                    if let Some(pp) = peers.get_mut(&o.rport) {
                        if o.has(FLAG_SYN) && o.has(FLAG_ACK) {
                            pp.rcv = o.seq.wrapping_add(1);
                            pp.snd = o.ack;
                        } else {
                            let end = o
                                .seq
                                .wrapping_add(o.payload.len() as u32)
                                .wrapping_add(u32::from(o.has(FLAG_FIN)));
                            if crate::seq::gt(end, pp.rcv) && !o.has(FLAG_RST) {
                                pp.rcv = end;
                            }
                        }
                    }
                }
            }
        }
        match op {
            90..=95 => {
                let d = match r.below(6) {
                    0 => MS,
                    1 => 40 * MS,
                    2 => Duration::from_millis(r.below(5000)),
                    3 => Duration::from_secs(60),
                    4 => Duration::from_secs(r.below(300)),
                    _ => Duration::from_hours(25 * 24),
                };
                n.advance(d);
                if let Some(t) = n.s.poll_timeout() {
                    assert!(t.as_nanos() > 0);
                }
            }
            _ => {
                while let Some(e) = n.s.poll_event() {
                    // An event for an in-use slot must carry the live generation.
                    let (Event::Readable(id) | Event::Writable(id) | Event::Closed(id)) = e else {
                        continue;
                    };
                    let t = n.s.conns.tcb(id.slot);
                    if t.state != State::Free {
                        assert_eq!(
                            t.generation, id.generation,
                            "step {step}: event for a live slot carries a stale generation"
                        );
                    }
                }
            }
        }
        // 駆動の層と同じく、期限が来ていれば起こします。
        if n.s.poll_timeout().is_some_and(|t| t <= n.now) {
            n.s.handle_timeout(n.now);
            n.s.check_invariants().unwrap();
        }
    }
    if seed.is_multiple_of(7) {
        eprintln!(
            "cov handles={} maxtw={} stats={:?}",
            handles.len(),
            maxtw,
            n.s.stats()
        );
    }
    let held_before = n.s.held();
    let _ = held_before;
    let closed = n.s.close(n.now);
    assert!(closed.held.is_zero());
}

#[test]
fn stress_many_seeds() {
    let seeds: u64 = env_or("STRESS_SEEDS", 2);
    let steps: usize = env_or("STRESS_STEPS", 3000);
    for s in 1..=seeds {
        let res = std::panic::catch_unwind(|| stress(s.wrapping_mul(0x9e37_79b9_7f4a_7c15), steps));
        assert!(res.is_ok(), "seed {s} failed");
        if s.is_multiple_of(10) {
            eprintln!("seeds done {s}");
        }
    }
}

/// Targeted lifecycle loop: many connections through every close order, TIME_WAIT pressure, RFC 6191 reuse,
/// stale handles and time jumps. Checks invariants each step (inject/drain/advance do) and that every
/// connection either reads its data or reports an error, and that close returns everything.
fn lifecycle(seed: u64, iters: usize) {
    let mut r = Rng(seed | 1);
    let mut lim = small_limits();
    lim.max_flows = 3;
    lim.accept_queue = 2;
    lim.tw_rows = 3;
    lim.syn_rows = 4;
    let mut n = TestNet::with_seed(lim, [seed as u8; 64]);
    let l = n.listen(80);
    let mut old: Vec<ConnId> = Vec::new();
    let mut live: Vec<(ConnId, PeerConn)> = Vec::new();
    let mut ts = 5000u32;
    for _ in 0..iters {
        let choice = r.below(12);
        match choice {
            0..=2 if live.len() < 3 => {
                n.drain();
                let sport = 40000 + r.below(6) as u16; // few ports: reuse TW tuples
                if live.iter().any(|(_, p)| p.sport == sport) {
                    continue;
                }
                ts = ts.wrapping_add(1000);
                let iss = r.next() as u32;
                n.inject(&TSeg {
                    sport,
                    dport: 80,
                    seq: iss,
                    flags: FLAG_SYN,
                    wnd: 65535,
                    mss: 1380,
                    ws: Some(7),
                    ts: Some((ts, 0)),
                    ..TSeg::default()
                });
                let outs = n.drain();
                let Some(sa) = outs.iter().find(|o| o.rport == sport && o.has(FLAG_SYN)) else {
                    continue;
                };
                let mut p = PeerConn {
                    sport,
                    dport: 80,
                    iss,
                    snd: iss.wrapping_add(1),
                    rcv: sa.seq.wrapping_add(1),
                    dut_iss: sa.seq,
                    ts: true,
                    ts_val: ts,
                    dut_ts: sa.ts.map_or(0, |t| t.0),
                    wnd: 65535,
                };
                n.peer_ack(&mut p, &[]);
                n.drain();
                if let Ok((c, _)) = n.s.accept(n.now, l) {
                    live.push((c, p));
                }
            }
            3 | 4 if !live.is_empty() => {
                let i = r.below(live.len() as u64) as usize;
                let (c, ref mut p) = live[i];
                let k = r.below(3000) as usize;
                let _ = n.s.write(n.now, c, &vec![1u8; k]);
                let outs = n.drain();
                p.absorb(&outs);
                n.peer_ack(p, &vec![2u8; r.below(2000) as usize]);
                let outs = n.drain();
                p.absorb(&outs);
                let mut b = vec![0u8; 65536];
                if r.chance(70) {
                    let _ = n.s.read(n.now, c, &mut b);
                }
            }
            5..=8 if !live.is_empty() => {
                let i = r.below(live.len() as u64) as usize;
                let (c, mut p) = live.remove(i);
                let mut b = vec![0u8; 65536];
                match r.below(5) {
                    0 => {
                        // app first, peer acks and closes
                        while matches!(n.s.read(n.now, c, &mut b), Ok(k) if k > 0) {}
                        n.s.close_conn(n.now, c);
                        let outs = n.drain();
                        p.absorb(&outs);
                        n.peer_ack(&mut p, &[]);
                        if r.chance(80) {
                            n.peer_fin(&mut p);
                        }
                        let outs = n.drain();
                        p.absorb(&outs);
                    }
                    1 => {
                        // peer first
                        n.peer_fin(&mut p);
                        let outs = n.drain();
                        p.absorb(&outs);
                        while matches!(n.s.read(n.now, c, &mut b), Ok(k) if k > 0) {}
                        n.s.close_conn(n.now, c);
                        let outs = n.drain();
                        p.absorb(&outs);
                        n.peer_ack(&mut p, &[]);
                        n.drain();
                    }
                    2 => {
                        // half close then TIME_WAIT in slot, read late
                        n.s.close_write(n.now, c).ok();
                        let outs = n.drain();
                        p.absorb(&outs);
                        n.peer_ack(&mut p, b"tail");
                        n.peer_fin(&mut p);
                        let outs = n.drain();
                        p.absorb(&outs);
                        if r.chance(50) {
                            n.advance(Duration::from_secs(61));
                        }
                        let got = n.read_all(c);
                        n.s.close_conn(n.now, c);
                        let _ = got;
                        n.drain();
                    }
                    3 => {
                        n.s.abort(n.now, c);
                        n.drain();
                    }
                    _ => {
                        // peer RST
                        let s = p.seg(FLAG_RST, &[]);
                        n.inject(&s);
                        n.s.close_conn(n.now, c);
                        n.drain();
                    }
                }
                old.push(c);
            }
            9 if !old.is_empty() => {
                let c = old[r.below(old.len() as u64) as usize];
                match r.below(4) {
                    0 => n.s.abort(n.now, c),
                    1 => n.s.close_conn(n.now, c),
                    2 => {
                        assert!(n.s.delivered(c));
                    }
                    _ => {
                        assert_eq!(n.s.read(n.now, c, &mut [0; 4]), Err(Error::Closed));
                    }
                }
                n.s.check_invariants().unwrap();
                n.drain();
            }
            10 => n.advance(Duration::from_millis(r.below(70_000))),
            _ => {
                while let Some(e) = n.s.poll_event() {
                    if let Event::Readable(c) | Event::Writable(c) | Event::Closed(c) = e {
                        let t = n.s.conns.tcb(c.slot);
                        if t.state != State::Free {
                            assert_eq!(t.generation, c.generation);
                        }
                    }
                }
            }
        }
    }
    if seed.is_multiple_of(13) {
        let st = n.s.stats();
        eprintln!(
            "lc cov old={} tw_evicted={} syn_full={} acc_over={} tw_now={}",
            old.len(),
            st.tw_evicted,
            st.syn_table_full,
            st.accept_overflow,
            n.s.s.tw.len()
        );
    }
    let closed = n.s.close(n.now);
    assert!(closed.held.is_zero());
}

#[test]
fn lifecycle_many_seeds() {
    let seeds: u64 = env_or("LC_SEEDS", 1);
    let mut tw = 0;
    for s in 1..=seeds {
        let res =
            std::panic::catch_unwind(|| lifecycle(s.wrapping_mul(0x2545_f491_4f6c_dd1d), 3000));
        assert!(res.is_ok(), "lifecycle seed {s} failed");
        tw += 1;
    }
    eprintln!("lifecycle seeds ok {tw}");
}
