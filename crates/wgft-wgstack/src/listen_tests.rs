//! 待ち受けの守りの試験 (wgstack-rs.md の「待ち受けの守り」):SYN cookie と、待ち受けへの SYN と FIN の組です。
//!
//! どちらも凍結した Go の wgstack と意図して違う所なので、Go の試験の写しではありません。

#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "tests build data and format failures"
)]
#![expect(
    clippy::cast_possible_truncation,
    clippy::many_single_char_names,
    reason = "test data"
)]

use crate::stack::{Error, ListenerId};
use crate::tcp::cookie::{COOKIE_PERIOD, MSS_TABLE};
use crate::testnet_tests::{PeerConn, TEST_MTU, TSeg, TestNet, show, small_limits};
use crate::wire::{FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN};
use core::net::Ipv4Addr;
use core::time::Duration;

fn spoofed(i: u32) -> Ipv4Addr {
    Ipv4Addr::from_bits(0xc612_0000 | (i & 0xffff))
}

/// 偽の送信元から `n` 個の SYN を送り、出力を捨てます。待ち受け 1 つの行は表の半分で止まります。
fn flood(n: &mut TestNet, from: u32, count: u32) {
    for i in from..from + count {
        n.inject(&TSeg {
            src: Some(spoofed(i)),
            sport: 1024 + (i % 50000) as u16,
            dport: 80,
            seq: i.wrapping_mul(2_654_435_761),
            flags: FLAG_SYN,
            wnd: 1000,
            mss: 1380,
            ..TSeg::default()
        });
        if i % 8 == 0 {
            n.drain();
        }
        n.s.check_invariants().unwrap();
    }
    n.drain();
}

fn flooded() -> (TestNet, ListenerId) {
    let mut n = TestNet::new(small_limits());
    let l = n.listen(80);
    flood(&mut n, 0, 200);
    let h = n.s.held();
    assert_eq!(h.syn_rows, small_limits().syn_rows / 2, "{h:?}");
    assert_eq!(h.conns, 0);
    assert!(n.s.stats().syn_cookies_sent > 0);
    (n, l)
}

/// 相手の SYN を送り、cookie の SYN-ACK を 1 つ受けます。
fn cookie_syn(n: &mut TestNet, sport: u16, ts: bool, sack: bool, ws: bool) -> PeerConn {
    let before = n.s.stats().syn_cookies_sent;
    let rows = n.s.held().syn_rows;
    let p = n.handshake_sack(sport, 80, ts, sack, ws);
    assert_eq!(
        n.s.stats().syn_cookies_sent,
        before + 1,
        "a cookie answered"
    );
    assert_eq!(n.s.held().syn_rows, rows, "the cookie made no row");
    p
}

#[test]
fn flood_keeps_the_listener_accepting() {
    let (mut n, l) = flooded();
    // timestamp を示す相手:窓の scale と SACK を cookie で運びます。
    let mut p = cookie_syn(&mut n, 40000, true, true, true);
    n.s.check_invariants().unwrap();
    assert_eq!(n.s.stats().syn_cookies_accepted, 1);
    let c = n.accept(l);
    let i = c.slot;
    let t = *n.s.conns.tcb(i);
    assert!(t.ts_ok && t.sack_ok && t.ws_ok, "{t:?}");
    assert_eq!((t.snd_wscale, t.peer_mss), (7, 1380));
    // 両方向のデータ。相手の窓は scale 7 で 65535 << 7 です。
    n.peer_ack(&mut p, b"hello");
    assert_eq!(n.read_all(c), b"hello");
    let msg = vec![b'x'; 40_000];
    assert_eq!(n.s.write(n.now, c, &msg), Ok(40_000));
    let mut got = Vec::new();
    for _ in 0..20 {
        let outs = n.drain();
        got.extend(p.absorb(&outs));
        if got.len() == msg.len() {
            break;
        }
        n.peer_ack(&mut p, &[]);
    }
    assert_eq!(got, msg);
    n.s.check_invariants().unwrap();
    let closed = n.s.close(n.now);
    assert!(closed.held.is_zero());
}

#[test]
fn cookie_without_timestamps_drops_wscale_and_sack() {
    let (mut n, l) = flooded();
    n.inject(&TSeg {
        sport: 40001,
        dport: 80,
        seq: 77,
        flags: FLAG_SYN,
        wnd: 65535,
        mss: 1452,
        ws: Some(7),
        sack_ok: true,
        ..TSeg::default()
    });
    let outs = n.drain();
    assert_eq!(outs.len(), 1, "{}", show(&outs));
    let sa = &outs[0];
    assert!(
        sa.ts.is_none() && sa.wscale.is_none() && !sa.sack_ok,
        "{sa:?}"
    );
    assert_eq!(sa.mss, Some((TEST_MTU - 40) as u16));
    n.inject(&TSeg {
        sport: 40001,
        dport: 80,
        seq: 78,
        ack: sa.seq.wrapping_add(1),
        flags: FLAG_ACK,
        wnd: 1000,
        payload: b"abc".to_vec(),
        ..TSeg::default()
    });
    let c = n.accept(l);
    let t = *n.s.conns.tcb(c.slot);
    assert!(!t.ts_ok && !t.sack_ok && !t.ws_ok, "{t:?}");
    assert_eq!(
        t.peer_mss,
        u32::from(MSS_TABLE[6]),
        "1452 rounds down to 1440"
    );
    assert_eq!(n.read_all(c), b"abc", "the final ACK's data is kept");
}

#[test]
fn forged_altered_and_expired_cookies_are_rejected() {
    let (mut n, _l) = flooded();
    let ack = |seq: u32, ack: u32, ts: Option<(u32, u32)>| TSeg {
        sport: 40002,
        dport: 80,
        seq,
        ack,
        flags: FLAG_ACK,
        wnd: 1000,
        ts,
        ..TSeg::default()
    };
    // 偽の cookie には RST を返し、数えます。
    for k in 0..100u32 {
        n.inject(&ack(5000, k.wrapping_mul(0x9e37_79b9), None));
        let outs = n.drain();
        assert!(outs.len() == 1 && outs[0].has(FLAG_RST), "{}", show(&outs));
    }
    assert_eq!(n.s.stats().syn_cookies_rejected, 100);
    assert_eq!(n.s.stats().syn_cookies_accepted, 0);

    // 本物の cookie の TSecr の option を書き換えると通りません。
    n.inject(&TSeg {
        sport: 40002,
        dport: 80,
        seq: 5000,
        flags: FLAG_SYN,
        wnd: 65535,
        mss: 1380,
        ws: Some(7),
        sack_ok: true,
        ts: Some((9, 0)),
        ..TSeg::default()
    });
    let sa = n.drain().remove(0);
    let (tsv, _) = sa.ts.unwrap();
    n.inject(&ack(5001, sa.seq.wrapping_add(1), Some((10, tsv ^ 0x10))));
    n.inject(&ack(5001, sa.seq.wrapping_add(1), None));
    n.inject(&ack(5002, sa.seq.wrapping_add(1), Some((10, tsv))));
    assert_eq!(n.s.stats().syn_cookies_rejected, 103);
    assert_eq!(n.s.held().conns, 0);

    // 2 周期の後の cookie は通りません。洪水が続く間 (cookie を送る窓が開いている間) に確かめます。
    n.advance(Duration::from_nanos(2 * COOKIE_PERIOD as u64));
    flood(&mut n, 1000, 4);
    n.inject(&ack(5001, sa.seq.wrapping_add(1), Some((10, tsv))));
    let outs = n.drain();
    assert!(outs.iter().any(|o| o.has(FLAG_RST)), "{}", show(&outs));
    assert_eq!(n.s.stats().syn_cookies_rejected, 104);
    assert_eq!(n.s.held().conns, 0);

    // 1 周期の内の cookie は通ります。
    n.inject(&TSeg {
        sport: 40003,
        dport: 80,
        seq: 6000,
        flags: FLAG_SYN,
        wnd: 65535,
        mss: 1380,
        ..TSeg::default()
    });
    let sa = n.drain().remove(0);
    n.advance(Duration::from_nanos(COOKIE_PERIOD as u64));
    n.inject(&TSeg {
        sport: 40003,
        dport: 80,
        seq: 6001,
        ack: sa.seq.wrapping_add(1),
        flags: FLAG_ACK,
        wnd: 1000,
        ..TSeg::default()
    });
    assert_eq!(n.s.stats().syn_cookies_accepted, 1);
    n.s.check_invariants().unwrap();
}

#[test]
fn replayed_cookie_acks_make_no_second_connection() {
    let (mut n, l) = flooded();
    let mut p = cookie_syn(&mut n, 40004, true, false, true);
    let c = n.accept(l);
    let last = p.seg(FLAG_ACK, &[]);
    // 接続がある間の写しは接続が受けます。
    n.inject(&TSeg {
        ts: last.ts.map(|(v, e)| (v - 1, e)),
        seq: p.iss + 1,
        ..last.clone()
    });
    n.drain();
    assert_eq!(n.s.held().conns, 1);
    assert_eq!(n.s.stats().syn_cookies_accepted, 1);
    // 自分から閉じて TIME_WAIT に入った後の写しは TIME_WAIT の行が受けます。
    n.s.close_conn(n.now, c);
    let outs = n.drain();
    p.absorb(&outs);
    n.peer_ack(&mut p, &[]);
    n.peer_fin(&mut p);
    n.drain();
    assert_eq!((n.s.held().conns, n.s.held().tw_rows), (0, 1));
    n.inject(&TSeg {
        seq: p.iss + 1,
        ..last.clone()
    });
    n.drain();
    assert_eq!(n.s.held().conns, 0, "a replay made a connection");
    assert_eq!(n.s.stats().syn_cookies_accepted, 1);
    // cookie を送らなくなった後は ACK を cookie として確かめず、RST を返すだけです。
    n.advance(Duration::from_nanos(3 * COOKIE_PERIOD as u64));
    let rejected = n.s.stats().syn_cookies_rejected;
    n.inject(&TSeg {
        sport: 40005,
        ..last.clone()
    });
    let outs: Vec<_> = n.drain().into_iter().filter(|o| o.rport == 40005).collect();
    assert!(outs.len() == 1 && outs[0].has(FLAG_RST), "{}", show(&outs));
    assert_eq!(n.s.stats().syn_cookies_rejected, rejected);
    n.s.check_invariants().unwrap();
}

#[test]
fn cookie_ack_waits_for_room_in_the_accept_queue() {
    let (mut n, l) = flooded();
    // 待ち受けの分 (Q の半分) を cookie の接続で埋めます。
    let half = small_limits().accept_queue / 2;
    for i in 0..half {
        cookie_syn(&mut n, 41000 + i as u16, false, false, false);
    }
    assert_eq!(n.s.held().accept_queued, half);
    let overflow = n.s.stats().accept_overflow;
    let mut p = n.handshake_sack(42000, 80, true, false, false);
    assert!(
        n.drain().is_empty(),
        "an ACK past the queue is dropped quietly"
    );
    assert_eq!(n.s.stats().accept_overflow, overflow + 1);
    assert_eq!(n.s.held().conns, half);
    // accept で空いた後、相手の次の segment で接続を作ります。
    let _ = n.accept(l);
    n.peer_ack(&mut p, b"late");
    assert_eq!(n.s.held().accept_queued, half);
    assert_eq!(n.s.stats().syn_cookies_accepted, half as u64 + 1);
    n.s.check_invariants().unwrap();
    let mut got = Vec::new();
    loop {
        match n.s.accept(n.now, l) {
            Ok((c, _)) => got.push(c),
            Err(Error::WouldBlock) => break,
            Err(e) => panic!("accept: {e}"),
        }
    }
    let last = *got.last().unwrap();
    assert_eq!(n.read_all(last), b"late");
}

#[test]
fn listener_drops_syn_fin() {
    let mut n = TestNet::new(small_limits());
    let _l = n.listen(80);
    n.inject(&TSeg {
        sport: 40000,
        dport: 80,
        seq: 1,
        flags: FLAG_SYN | FLAG_FIN,
        wnd: 1000,
        mss: 1380,
        ..TSeg::default()
    });
    let outs = n.drain();
    assert!(outs.is_empty(), "{}", show(&outs));
    assert_eq!(n.s.held().syn_rows, 0);
    // 閉じたポートへの SYN と FIN の組には、今までどおり RST を返します。
    n.inject(&TSeg {
        sport: 40000,
        dport: 81,
        seq: 1,
        flags: FLAG_SYN | FLAG_FIN,
        wnd: 1000,
        ..TSeg::default()
    });
    let outs = n.drain();
    assert!(outs.len() == 1 && outs[0].has(FLAG_RST), "{}", show(&outs));
}

#[test]
fn syn_fin_does_not_reuse_a_time_wait_row() {
    let mut n = TestNet::new(small_limits());
    let l = n.listen(80);
    let mut p = n.handshake(40000, 80, false, false);
    let c = n.accept(l);
    n.s.close_conn(n.now, c);
    let outs = n.drain();
    p.absorb(&outs);
    n.peer_ack(&mut p, &[]);
    n.peer_fin(&mut p);
    n.drain();
    assert_eq!(n.s.held().tw_rows, 1);
    n.inject(&TSeg {
        sport: 40000,
        dport: 80,
        seq: p.snd.wrapping_add(100_000),
        flags: FLAG_SYN | FLAG_FIN,
        wnd: 1000,
        mss: 1380,
        ..TSeg::default()
    });
    let outs = n.drain();
    assert!(outs.iter().all(|o| o.flags == FLAG_ACK), "{}", show(&outs));
    assert_eq!((n.s.held().tw_rows, n.s.held().syn_rows), (1, 0));
}

#[test]
fn cookie_ts_val_never_runs_ahead_of_later_segments() {
    let (mut n, l) = flooded();
    // TSval の下位 5 bit に入る option の値は時計の値の下位 5 bit より大きいことが多いので、多くの握手で
    // 確かめます。
    for k in 0..48u16 {
        let mut p = cookie_syn(&mut n, 43000 + k, true, k % 2 == 0, true);
        let syn_ack_ts = p.dut_ts;
        let c = n.accept(l);
        n.advance(Duration::from_millis(u64::from(k % 7)));
        n.s.write(n.now, c, b"x").unwrap();
        let outs = n.drain();
        let data = outs
            .iter()
            .find(|o| o.rport == 43000 + k && !o.payload.is_empty())
            .unwrap_or_else(|| panic!("no data: {}", show(&outs)));
        let (v, _) = data.ts.unwrap();
        assert!(
            crate::seq::ge(v, syn_ack_ts),
            "the SYN-ACK's TSval {syn_ack_ts} runs ahead of the next segment's {v}"
        );
        p.absorb(&outs);
        n.s.abort(n.now, c);
        n.drain();
    }
}

#[test]
fn data_that_fails_the_cookie_is_dropped_without_rst() {
    let (mut n, l) = flooded();
    n.inject(&TSeg {
        sport: 44000,
        dport: 80,
        seq: 100,
        flags: FLAG_SYN,
        wnd: 65535,
        mss: 1380,
        ..TSeg::default()
    });
    let sa = n.drain().remove(0);
    let data = |seq: u32, payload: &[u8]| TSeg {
        sport: 44000,
        dport: 80,
        seq,
        ack: sa.seq.wrapping_add(1),
        flags: FLAG_ACK,
        wnd: 65535,
        payload: payload.to_vec(),
        ..TSeg::default()
    };
    // 最後の ACK と最初の中身を失い、2 つ目の中身が先に届きます。
    let rejected = n.s.stats().syn_cookies_rejected;
    n.inject(&data(201, b"second"));
    let outs = n.drain();
    assert!(outs.is_empty(), "{}", show(&outs));
    assert_eq!(n.s.stats().syn_cookies_rejected, rejected + 1);
    assert_eq!(n.s.held().conns, 0);
    // FIN だけの segment も同じです。中身の無い ACK には今までどおり RST を返します。
    n.inject(&TSeg {
        flags: FLAG_ACK | FLAG_FIN,
        ..data(300, b"")
    });
    assert!(n.drain().is_empty());
    n.inject(&data(300, b""));
    let outs = n.drain();
    assert!(outs.len() == 1 && outs[0].has(FLAG_RST), "{}", show(&outs));
    // 最初の中身の再送で接続を作ります。
    let first = vec![b'a'; 100];
    n.inject(&data(101, &first));
    let c = n.accept(l);
    assert_eq!(n.read_all(c), first);
    n.s.check_invariants().unwrap();
}

#[test]
fn a_delayed_cookie_ack_wins_over_a_later_row() {
    let (mut n, l) = flooded();
    let syn = TSeg {
        sport: 45000,
        dport: 80,
        seq: 500,
        flags: FLAG_SYN,
        wnd: 65535,
        mss: 1380,
        ..TSeg::default()
    };
    n.inject(&syn);
    let cookie = n.drain().remove(0);
    // 洪水の行を RST で外して表に空きを作ります。
    for i in 0..200u32 {
        n.inject(&TSeg {
            src: Some(spoofed(i)),
            sport: 1024 + (i % 50000) as u16,
            dport: 80,
            seq: i.wrapping_mul(2_654_435_761).wrapping_add(1),
            flags: FLAG_RST,
            ..TSeg::default()
        });
    }
    n.drain();
    assert_eq!(n.s.held().syn_rows, 0);
    // 相手は SYN を送り直し、今度は行ができます。
    n.inject(&syn);
    let row_syn_ack = n.drain().remove(0);
    assert_ne!(row_syn_ack.seq, cookie.seq);
    assert_eq!(n.s.held().syn_rows, 1);
    // 遅れて届いた cookie の SYN-ACK に相手が ACK します。
    n.inject(&TSeg {
        seq: 501,
        ack: cookie.seq.wrapping_add(1),
        flags: FLAG_ACK,
        payload: b"hi".to_vec(),
        ..syn.clone()
    });
    let outs = n.drain();
    assert!(outs.iter().all(|o| !o.has(FLAG_RST)), "{}", show(&outs));
    assert_eq!((n.s.held().syn_rows, n.s.held().conns), (0, 1));
    assert_eq!(n.s.stats().syn_cookies_accepted, 1);
    let c = n.accept(l);
    assert_eq!(n.read_all(c), b"hi");
    // cookie の窓の外では、行の ISN に合わない ACK に今までどおり RST を返します。
    n.advance(Duration::from_nanos(3 * COOKIE_PERIOD as u64));
    let syn2 = TSeg {
        sport: 45001,
        ..syn.clone()
    };
    n.inject(&syn2);
    n.drain();
    n.inject(&TSeg {
        seq: 501,
        ack: 12345,
        flags: FLAG_ACK,
        ..syn2
    });
    let outs = n.drain();
    assert!(outs.iter().any(|o| o.has(FLAG_RST)), "{}", show(&outs));
    n.s.check_invariants().unwrap();
}
