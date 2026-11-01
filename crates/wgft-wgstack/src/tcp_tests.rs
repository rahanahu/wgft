//! TCP の白箱の試験 (Go の `tcp_test.go`、`lifecycle_test.go`、`orphan_test.go`、`regress_test.go` など)。
//!
//! SACK の印付けと回復、RACK-TLP、不要な再送の取り消し、CUBIC、boost の試験は `sack_tests.rs` にあります。

#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "tests build data and format failures"
)]
#![expect(
    clippy::cast_possible_truncation,
    clippy::many_single_char_names,
    clippy::unchecked_time_subtraction,
    reason = "test data"
)]

use crate::stack::{Error, Event};
use crate::tcp::conn::State;
use crate::testnet_tests::{DUT, PeerConn, TEST_MTU, TSeg, TestNet, show, small_limits};
use crate::wire::{FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN};
use core::net::SocketAddrV4;
use core::time::Duration;

const MS: Duration = Duration::from_millis(1);

fn net() -> TestNet {
    TestNet::new(small_limits())
}

/// 接続の始めの quickack を使い切ったことにします (Go の `skipQuickack`)。
fn skip_quickack(n: &mut TestNet) {
    let now = crate::stack::ns(n.now);
    let ids: Vec<u32> = n.s.conns.in_use().collect();
    for i in ids {
        let t = n.s.conns.tcb_mut(i);
        (t.rcvd_data, t.last_data_rcvd) = (true, now);
    }
}

fn mss_ts() -> usize {
    TEST_MTU - 40 - 12
}

#[test]
fn handshake_options() {
    let mut n = net();
    n.listen(80);
    n.inject(&TSeg {
        sport: 40000,
        dport: 80,
        seq: 1000,
        flags: FLAG_SYN,
        wnd: 65535,
        mss: 1380,
        ws: Some(7),
        sack_ok: true,
        ts: Some((5000, 0)),
        ..TSeg::default()
    });
    let outs = n.drain();
    assert_eq!(outs.len(), 1);
    let sa = &outs[0];
    assert_eq!(sa.mss, Some((TEST_MTU - 40) as u16));
    assert_eq!(sa.wscale, Some(crate::tcp::RCV_WINDOW_SHIFT));
    assert_eq!(sa.ts.map(|t| t.1), Some(5000), "TSecr");
    assert!(sa.sack_ok, "SACK-permitted");
    assert_eq!(sa.wnd, 64296);
}

#[test]
fn handshake_bare() {
    let mut n = net();
    let l = n.listen(80);
    n.inject(&TSeg {
        sport: 1,
        dport: 80,
        seq: 7,
        flags: FLAG_SYN,
        wnd: 1000,
        ..TSeg::default()
    });
    let outs = n.drain();
    assert_eq!(outs.len(), 1);
    let o = &outs[0];
    assert!(o.ts.is_none() && !o.sack_ok && o.wscale.is_none() && o.mss.is_some());
    // 最後の ACK の後、MSS の無い相手には 536 で送ります。
    n.inject(&TSeg {
        sport: 1,
        dport: 80,
        seq: 8,
        ack: o.seq + 1,
        flags: FLAG_ACK,
        wnd: 65535,
        ..TSeg::default()
    });
    let c = n.accept(l);
    n.s.write(n.now, c, &[0; 2000]).unwrap();
    let outs = n.drain();
    assert_eq!(outs[0].payload.len(), 536, "{}", show(&outs));
}

#[test]
fn data_both_ways() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    n.peer_ack(&mut p, b"hello");
    assert_eq!(n.read_all(c), b"hello");
    let msg = vec![b'x'; 5000];
    assert_eq!(n.s.write(n.now, c, &msg), Ok(5000));
    let outs = n.drain();
    assert_eq!(p.absorb(&outs), msg);
    assert_eq!(
        n.s.peer_addr(c),
        Some(SocketAddrV4::new(crate::testnet_tests::PEER, 40000))
    );
    assert_eq!(n.s.local_addr(c), Some(SocketAddrV4::new(DUT, 80)));
}

#[test]
fn delayed_ack() {
    let mut n = net();
    n.listen(80);
    let mut p = n.handshake(40000, 80, true, true);
    n.drain();
    skip_quickack(&mut n);
    n.peer_ack(&mut p, &[0; 100]);
    assert!(n.drain().is_empty(), "immediate ACK for one small segment");
    n.advance(39 * MS);
    assert!(n.drain().is_empty(), "ACK before the delayed ACK timer");
    n.advance(MS);
    let outs = n.drain();
    assert!(outs.len() == 1 && outs[0].ack == p.snd, "{}", show(&outs));
    // MSS 2 つ分で即座に ACK します。
    let full = vec![0; mss_ts()];
    n.peer_ack(&mut p, &full);
    assert!(n.drain().is_empty(), "ACK after one full segment");
    n.peer_ack(&mut p, &full);
    let outs = n.drain();
    assert!(outs.len() == 1 && outs[0].ack == p.snd, "{}", show(&outs));
}

#[test]
fn retransmit_backoff() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    n.s.write(n.now, c, b"data").unwrap();
    let first = n.drain();
    assert_eq!(first.len(), 1);
    let mut last = Duration::ZERO;
    for i in 0..4 {
        let mut elapsed = Duration::ZERO;
        loop {
            n.advance(MS);
            elapsed += MS;
            let outs = n.drain();
            if let Some(o) = outs.first() {
                assert!(o.seq == first[0].seq && o.payload == b"data", "{o}");
                break;
            }
            assert!(elapsed <= Duration::from_secs(10), "no retransmission");
        }
        if i > 0 {
            assert!(
                elapsed + 2 * MS >= 2 * last,
                "gap {i} {elapsed:?} is not double {last:?}"
            );
        }
        last = elapsed;
    }
    p.absorb(&first);
    n.peer_ack(&mut p, &[]);
    n.advance(Duration::from_secs(5));
    assert!(n.drain().is_empty(), "sent after the ACK");
    assert!(n.s.stats().rtos >= 4 && n.s.stats().rtos_backed_off >= 3);
}

#[test]
fn fast_retransmit_new_reno() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    let mss = mss_ts();
    n.s.write(n.now, c, &vec![0; 10 * mss]).unwrap();
    let outs = n.drain();
    assert_eq!(outs.len(), 10, "IW10");
    // 2 つ目を失ったとして、1 つ目の確認と重複した ACK を 3 つ送ります。
    p.rcv = outs[0].seq + mss as u32;
    n.peer_ack(&mut p, &[]);
    n.drain();
    for _ in 0..3 {
        n.peer_ack(&mut p, &[]);
    }
    let got = n.drain();
    assert!(
        !got.is_empty() && got[0].seq == outs[1].seq,
        "{}",
        show(&got)
    );
    assert!(n.s.conns.tcb(c.slot).in_recovery);
    // 部分の確認で次の穴を再送します。
    p.rcv = outs[2].seq;
    n.peer_ack(&mut p, &[]);
    let got = n.drain();
    assert!(
        !got.is_empty() && got[0].seq == outs[2].seq,
        "{}",
        show(&got)
    );
    // 全部の確認で回復を終えます。
    p.rcv = outs[9].seq + mss as u32;
    n.peer_ack(&mut p, &[]);
    n.drain();
    assert!(!n.s.conns.tcb(c.slot).in_recovery);
    let st = n.s.stats();
    assert_eq!((st.fast_recoveries, st.partial_acks), (1, 1));
}

#[test]
fn zero_window_probe() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    p.wnd = 0;
    n.peer_ack(&mut p, &[]);
    n.drain();
    n.s.write(n.now, c, b"blocked").unwrap();
    assert!(n.drain().is_empty(), "sent into a zero window");
    let mut probes = Vec::new();
    let mut el = Duration::ZERO;
    while probes.len() < 3 && el < Duration::from_secs(10) {
        n.advance(MS);
        el += MS;
        for o in n.drain() {
            assert!(o.seq == p.rcv - 1 && o.payload.is_empty(), "probe {o}");
            probes.push(el);
            n.peer_ack(&mut p, &[]); // 窓は 0 のまま応えます
            n.drain();
        }
    }
    assert!(probes.len() >= 3, "{probes:?}");
    let (g1, g2) = (probes[1] - probes[0], probes[2] - probes[1]);
    assert!(g2 + 2 * MS >= 2 * g1, "probe backoff {g1:?} {g2:?}");
    p.wnd = 65535;
    n.peer_ack(&mut p, &[]);
    let outs = n.drain();
    assert_eq!(p.absorb(&outs), b"blocked");
}

#[test]
fn rfc5961() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    // 窓の内側で番号の合わない RST には challenge ACK
    let mut s = p.seg(FLAG_RST, &[]);
    s.seq += 100;
    n.inject(&s);
    let outs = n.drain();
    assert!(
        outs.len() == 1 && outs[0].flags == FLAG_ACK && outs[0].ack == p.snd,
        "{}",
        show(&outs)
    );
    // 窓の外の RST は無視します。
    let mut s = p.seg(FLAG_RST, &[]);
    s.seq = s.seq.wrapping_add(1 << 30);
    n.inject(&s);
    assert!(n.drain().is_empty());
    // 確立後の SYN には challenge ACK
    let s = p.seg(FLAG_SYN, &[]);
    n.inject(&s);
    let outs = n.drain();
    assert!(
        outs.len() == 1 && outs[0].flags == FLAG_ACK,
        "{}",
        show(&outs)
    );
    // 番号の合う RST で接続を終えます。
    let s = p.seg(FLAG_RST, &[]);
    n.inject(&s);
    assert!(n.drain().is_empty());
    assert_eq!(n.s.read(n.now, c, &mut [0; 10]), Err(Error::Reset));
    assert!(n.events().contains(&Event::Closed(c)));
}

#[test]
fn paws() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    let mut s = p.seg(FLAG_ACK, b"old");
    s.ts = Some((1, p.dut_ts)); // 前の timestamp より古い
    n.inject(&s);
    let outs = n.drain();
    assert!(outs.len() == 1 && outs[0].ack == p.snd, "{}", show(&outs));
    assert_eq!(n.s.read(n.now, c, &mut [0; 10]), Err(Error::WouldBlock));
}

#[test]
fn half_close_and_time_wait_row() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    n.s.write(n.now, c, b"bye").unwrap();
    n.s.close_write(n.now, c).unwrap();
    let outs = n.drain();
    assert_eq!(p.absorb(&outs), b"bye");
    assert!(outs.last().unwrap().has(FLAG_FIN), "{}", show(&outs));
    // 相手は書き続け、FIN を送ります。
    n.peer_ack(&mut p, b"more");
    n.peer_fin(&mut p);
    n.drain();
    assert_eq!(n.s.conns.tcb(c.slot).state, State::TimeWait);
    let mut buf = [0u8; 10];
    assert_eq!(n.s.read(n.now, c, &mut buf), Ok(4));
    assert_eq!(&buf[..4], b"more");
    assert_eq!(n.s.read(n.now, c, &mut buf), Ok(0), "EOF after the FIN");
    assert!(!n.s.delivered(c), "delivered before close");
    n.s.close_conn(n.now, c);
    let h = n.s.held();
    assert_eq!((h.conns, h.tw_rows), (0, 1));
    // 古い handle
    assert!(n.s.delivered(c));
    assert_eq!(n.s.read(n.now, c, &mut buf), Err(Error::Closed));
    assert_eq!(n.s.write(n.now, c, &buf), Err(Error::Closed));
    n.s.close_conn(n.now, c);
    // 行は再送された FIN に ACK を返します。
    let mut s = p.seg(FLAG_ACK | FLAG_FIN, &[]);
    s.seq = p.snd - 1;
    n.inject(&s);
    let outs = n.drain();
    assert!(outs.len() == 1 && outs[0].ack == p.snd, "{}", show(&outs));
    // RFC 6191:timestamp の大きい SYN は行を外して待ち受けに渡ります。
    n.inject(&TSeg {
        sport: 40000,
        dport: 80,
        seq: p.snd + 100_000,
        flags: FLAG_SYN,
        wnd: 65535,
        mss: 1380,
        ws: Some(7),
        ts: Some((p.ts_val + 10, 0)),
        ..TSeg::default()
    });
    let outs = n.drain();
    assert!(
        outs.len() == 1 && outs[0].flags == FLAG_SYN | FLAG_ACK,
        "{}",
        show(&outs)
    );
    assert_eq!(n.s.held().tw_rows, 0, "row not removed");
    // 古い handle の abort は何もしません。
    n.s.abort(n.now, c);
    assert!(n.drain().is_empty());
}

#[test]
fn stale_abort_sends_rst_for_row() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    n.s.close_conn(n.now, c);
    let outs = n.drain();
    p.absorb(&outs);
    n.peer_ack(&mut p, &[]); // FIN を確認します -> FIN_WAIT_2 の行
    let h = n.s.held();
    assert_eq!((h.tw_rows, h.conns), (1, 0));
    n.s.abort(n.now, c);
    let outs = n.drain();
    assert!(outs.len() == 1 && outs[0].has(FLAG_RST), "{}", show(&outs));
    assert_eq!(n.s.held().tw_rows, 0);
}

#[test]
fn fin_wait2_row_data_rst() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    n.s.close_conn(n.now, c);
    let outs = n.drain();
    p.absorb(&outs);
    n.peer_ack(&mut p, &[]);
    n.peer_ack(&mut p, b"late");
    let outs = n.drain();
    assert!(outs.len() == 1 && outs[0].has(FLAG_RST), "{}", show(&outs));
    assert_eq!(n.s.held().tw_rows, 0);
}

#[test]
fn close_with_unread_data_sends_rst() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    n.peer_ack(&mut p, b"unread");
    n.drain();
    n.s.close_conn(n.now, c);
    let outs = n.drain();
    assert!(outs.len() == 1 && outs[0].has(FLAG_RST), "{}", show(&outs));
    let h = n.s.held();
    assert_eq!((h.conns, h.tw_rows), (0, 0));
}

#[test]
fn abort() {
    let mut n = net();
    let (c, p) = n.accepted(true);
    n.s.abort(n.now, c);
    let outs = n.drain();
    assert!(
        outs.len() == 1 && outs[0].flags == FLAG_RST | FLAG_ACK && outs[0].seq == p.rcv,
        "{}",
        show(&outs)
    );
    assert_eq!(n.s.held().conns, 0);
    assert!(n.s.delivered(c));
}

#[test]
fn mss_floor() {
    let mut n = net();
    n.listen(80);
    let syn = |sport, mss| TSeg {
        sport,
        dport: 80,
        seq: 1,
        flags: FLAG_SYN,
        wnd: 1000,
        mss,
        ..TSeg::default()
    };
    n.inject(&syn(1, 535));
    assert!(n.drain().is_empty(), "answered a SYN with MSS 535");
    assert_eq!(n.s.stats().mss_floor_drops, 1);
    let line = n.s.poll_log().unwrap();
    assert_eq!(line.kind, crate::LogKind::MssFloor);
    n.inject(&syn(2, 536));
    assert_eq!(n.drain().len(), 1);
}

#[test]
fn closed_port_rst() {
    let mut n = net();
    let seg = |seq, ack, flags| TSeg {
        sport: 1,
        dport: 81,
        seq,
        ack,
        flags,
        wnd: 1000,
        ..TSeg::default()
    };
    n.inject(&seg(100, 0, FLAG_SYN));
    let outs = n.drain();
    assert!(
        outs.len() == 1 && outs[0].flags == FLAG_RST | FLAG_ACK && outs[0].ack == 101,
        "{}",
        show(&outs)
    );
    n.inject(&seg(100, 555, FLAG_ACK));
    let outs = n.drain();
    assert!(
        outs.len() == 1 && outs[0].flags == FLAG_RST && outs[0].seq == 555,
        "{}",
        show(&outs)
    );
    n.inject(&seg(100, 0, FLAG_RST));
    assert!(n.drain().is_empty());
}

#[test]
fn listener_close_resets() {
    let mut n = net();
    let l = n.listen(80);
    n.handshake(40000, 80, true, true); // 待ち行列に入ります
    assert!(n.events().contains(&Event::Acceptable(l)));
    n.inject(&TSeg {
        sport: 40001,
        dport: 80,
        seq: 1,
        flags: FLAG_SYN,
        wnd: 1000,
        ..TSeg::default()
    });
    n.drain();
    let h = n.s.held();
    assert_eq!((h.conns, h.syn_rows, h.accept_queued), (1, 1, 1));
    n.s.close_listener(n.now, l);
    let outs = n.drain();
    assert!(
        outs.len() == 2 && outs[0].has(FLAG_RST) && outs[1].has(FLAG_RST),
        "{}",
        show(&outs)
    );
    let h = n.s.held();
    assert_eq!((h.conns, h.syn_rows, h.accept_queued), (0, 0, 0));
    assert_eq!(n.s.accept(n.now, l), Err(Error::Closed));
    // ポートはその場で空きます。
    let l2 = n.listen(80);
    assert_ne!(l, l2);
}

#[test]
fn accept_queue_rst_removes() {
    let mut n = net();
    n.listen(80);
    let mut p = n.handshake(40000, 80, true, true);
    let s = p.seg(FLAG_RST, &[]);
    n.inject(&s);
    let h = n.s.held();
    assert_eq!((h.conns, h.accept_queued), (0, 0));
}

#[test]
fn syn_ack_retransmit_and_iw1() {
    let mut n = net();
    let l = n.listen(80);
    let syn = |sport, seq, ack, flags, wnd| TSeg {
        sport,
        dport: 80,
        seq,
        ack,
        flags,
        wnd,
        mss: if flags == FLAG_SYN { 1380 } else { 0 },
        ws: (flags == FLAG_SYN).then_some(7),
        ..TSeg::default()
    };
    n.inject(&syn(9, 1, 0, FLAG_SYN, 65535));
    let first = n.drain();
    let mut times = Vec::new();
    let mut el = Duration::ZERO;
    while el < Duration::from_secs(70) {
        n.advance(100 * MS);
        el += 100 * MS;
        for o in n.drain() {
            assert!(
                o.flags == FLAG_SYN | FLAG_ACK && o.seq == first[0].seq,
                "{o}"
            );
            times.push(el);
        }
    }
    let want = [1, 3, 7, 15, 31].map(Duration::from_secs);
    assert_eq!(times.len(), want.len(), "{times:?}");
    for (got, want) in times.iter().zip(want) {
        assert!(*got >= want && *got - want <= 100 * MS, "{got:?} {want:?}");
    }
    assert_eq!(n.s.held().syn_rows, 0);
    // 再送した後に成立した接続の初期の窓は 1 segment です。
    n.inject(&syn(10, 1, 0, FLAG_SYN, 65535));
    let sa = n.drain().remove(0);
    n.advance(Duration::from_secs(1));
    n.drain();
    n.inject(&syn(10, 2, sa.seq + 1, FLAG_ACK, 1000));
    let c = n.accept(l);
    n.s.write(n.now, c, &[0; 10000]).unwrap();
    assert_eq!(n.drain().len(), 1);
}

#[test]
fn close_with_pending_data_retires_after_delivery() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    assert_eq!(n.s.write(n.now, c, &vec![0; 100_000]), Ok(100_000));
    n.s.close_conn(n.now, c);
    let mut total = 0;
    for _ in 0..2000 {
        if n.s.held().tw_rows != 0 {
            break;
        }
        let outs = n.drain();
        total += p.absorb(&outs).len();
        n.peer_ack(&mut p, &[]);
        n.advance(MS);
    }
    let h = n.s.held();
    assert_eq!((total, h.tw_rows, h.conns), (100_000, 1, 0));
    assert!(n.s.delivered(c));
}

#[test]
fn fin_held_while_window_is_zero() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    p.wnd = 0;
    n.peer_ack(&mut p, &[]);
    n.s.close_write(n.now, c).unwrap();
    assert!(n.drain().is_empty(), "sent into a zero window");
    let mut probes = 0;
    for _ in 0..3000 {
        if probes >= 2 {
            break;
        }
        n.advance(MS);
        for o in n.drain() {
            assert!(!o.has(FLAG_FIN) && o.seq == p.rcv - 1, "{o}");
            probes += 1;
            n.peer_ack(&mut p, &[]);
        }
    }
    assert!(probes >= 2, "no window probes while the FIN is held");
    p.wnd = 100;
    n.peer_ack(&mut p, &[]);
    let outs = n.drain();
    assert!(
        outs.len() == 1 && outs[0].has(FLAG_FIN) && outs[0].seq == p.rcv,
        "{}",
        show(&outs)
    );
}

#[test]
fn fin_not_piggybacked_beyond_the_window() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    p.wnd = 1; // scale 7 で 128 byte
    n.peer_ack(&mut p, &[]);
    n.s.write(n.now, c, &[0; 128]).unwrap();
    n.s.close_write(n.now, c).unwrap();
    let outs = n.drain();
    assert!(
        outs.len() == 1 && outs[0].payload.len() == 128 && !outs[0].has(FLAG_FIN),
        "{}",
        show(&outs)
    );
    p.absorb(&outs);
    n.peer_ack(&mut p, &[]);
    let outs = n.drain();
    assert!(outs.len() == 1 && outs[0].has(FLAG_FIN), "{}", show(&outs));
}

#[test]
fn fin_wait2_row_ignores_out_of_window_and_paws() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    n.s.close_conn(n.now, c);
    let outs = n.drain();
    p.absorb(&outs);
    n.peer_ack(&mut p, &[]);
    let mut s = p.seg(FLAG_ACK, b"far");
    s.seq = s.seq.wrapping_add(1 << 30);
    n.inject(&s);
    n.drain();
    assert_eq!(
        n.s.held().tw_rows,
        1,
        "an out-of-window segment removed the row"
    );
    let mut s = p.seg(FLAG_ACK, b"old");
    s.ts = Some((1, p.dut_ts));
    n.inject(&s);
    n.drain();
    assert_eq!(
        n.s.held().tw_rows,
        1,
        "a PAWS-rejected segment removed the row"
    );
    n.peer_ack(&mut p, b"late");
    let outs = n.drain();
    assert!(outs.len() == 1 && outs[0].has(FLAG_RST), "{}", show(&outs));
    assert_eq!(n.s.held().tw_rows, 0);
}

#[test]
fn paws_forgets_ts_recent_after_24_days() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    n.now = n.now + Duration::from_hours(25 * 24);
    let mut s = p.seg(FLAG_ACK, b"new");
    s.ts = Some((1, p.dut_ts)); // 相手の時計が一周した後の値
    n.inject(&s);
    n.drain();
    assert_eq!(n.read_all(c), b"new");
}

#[test]
fn paws_applies_right_after_a_late_handshake() {
    let mut n = net();
    n.now = n.now + Duration::from_hours(30 * 24);
    let l = n.listen(80);
    let mut p = PeerConn {
        sport: 40000,
        dport: 80,
        iss: 1000,
        snd: 0,
        rcv: 0,
        dut_iss: 0,
        ts: true,
        ts_val: 5000,
        dut_ts: 0,
        wnd: 65535,
    };
    n.inject(&TSeg {
        sport: 40000,
        dport: 80,
        seq: p.iss,
        flags: FLAG_SYN,
        wnd: 65535,
        mss: 1380,
        ws: Some(7),
        ts: Some((p.ts_val, 0)),
        ..TSeg::default()
    });
    let sa = n.drain();
    assert!(sa.len() == 1 && sa[0].flags == FLAG_SYN | FLAG_ACK);
    (p.snd, p.rcv, p.dut_ts) = (p.iss + 1, sa[0].seq + 1, sa[0].ts.unwrap().0);
    // 握手の最後の ACK は timestamp を持ちません (SYN と SYN-ACK では交渉しました)。
    let mut last = p.seg(FLAG_ACK, &[]);
    last.ts = None;
    n.inject(&last);
    let c = n.accept(l);
    n.drain();
    let mut s = p.seg(FLAG_ACK, b"old");
    s.ts = Some((1, p.dut_ts));
    n.inject(&s);
    n.drain();
    assert_eq!(n.s.read(n.now, c, &mut [0; 10]), Err(Error::WouldBlock));
}

/// 古い handle は、同じ枠を使う次の接続を読みません (Go の TestStaleHandleDoesNotReadTheNextConnection)。
#[test]
fn stale_handle_does_not_read_the_next_connection() {
    let mut n = net();
    let (c, _p) = n.accepted(true);
    n.s.abort(n.now, c);
    n.drain();
    let mut p2 = n.handshake(40001, 80, true, true);
    let l = crate::stack::ListenerId {
        port: 80,
        generation: n.s.s.listeners.generation(80),
    };
    let c2 = n.accept(l);
    assert_eq!(c2.slot, c.slot, "the returned slot is used first");
    n.peer_ack(&mut p2, b"next");
    assert_eq!(n.s.read(n.now, c, &mut [0; 10]), Err(Error::Closed));
    assert!(n.s.delivered(c));
    assert_eq!(n.read_all(c2), b"next");
}

/// 枠を返した後に、タイマー、出力の節、表の項目が残りません (Go の TestFreedSlotHoldsNoTimerOutputOrIndexEntry)。
#[test]
fn freed_slot_holds_no_timer_output_or_index_entry() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    n.s.write(n.now, c, b"x").unwrap();
    n.peer_ack(&mut p, &[0; 100]);
    // 遅延 ACK と再送のタイマーと出力の節がある状態で abort します。
    n.s.abort(n.now, c);
    let t = n.s.conns.tcb(c.slot);
    assert!(t.tdl.iter().all(|&d| d == 0) && !t.in_index);
    assert!(!n.s.s.out.conns.contains(c.slot));
    assert!(n.s.s.wheel.deadline(c.slot * 4).is_none());
    n.s.check_invariants().unwrap();
}

/// 再送の回数を使い切った接続は RST を送って閉じ、読み書きは時間切れの誤りを返します。
#[test]
fn retransmit_deadline_aborts() {
    let mut n = net();
    let (c, _p) = n.accepted(true);
    n.s.write(n.now, c, b"lost").unwrap();
    n.drain();
    let mut rst = false;
    for _ in 0..1000 {
        n.advance(Duration::from_secs(1));
        if n.drain().iter().any(|o| o.has(FLAG_RST)) {
            rst = true;
            break;
        }
    }
    assert!(rst, "no RST after the retransmit deadline");
    assert_eq!(n.s.read(n.now, c, &mut [0; 4]), Err(Error::TimedOut));
    assert_eq!(n.s.stats().retransmit_aborts, 1);
    n.s.close_conn(n.now, c);
    assert_eq!(n.s.held().conns, 0);
}

/// TIME_WAIT の 4 つ組を使い直す SYN の ISN は、前の接続の SND.NXT の 65537 先より前に置きません。
#[test]
fn time_wait_reuse_iss() {
    let mut n = net();
    let (c, mut p) = n.accepted(false);
    n.s.close_conn(n.now, c);
    let outs = n.drain();
    p.absorb(&outs);
    n.peer_fin(&mut p);
    n.drain();
    assert_eq!(n.s.held().tw_rows, 1);
    let prev_snd = p.rcv;
    n.inject(&TSeg {
        sport: 40000,
        dport: 80,
        seq: p.snd + 10,
        flags: FLAG_SYN,
        wnd: 65535,
        ..TSeg::default()
    });
    let outs = n.drain();
    assert!(outs.len() == 1 && outs[0].has(FLAG_SYN), "{}", show(&outs));
    assert!(
        crate::seq::ge(outs[0].seq, prev_snd.wrapping_add(65536)),
        "ISS {} too close to {prev_snd}",
        outs[0].seq
    );
}

/// 一度に書いた送り残しは、相手の確認に応じて IW10 の後も届き続けます (slow start と輻輳の回避)。
#[test]
fn bulk_send_completes_with_acks() {
    let mut n = net();
    let (c, mut p) = n.accepted(false);
    let msg: Vec<u8> = (0..200_000u32).map(|i| (i * 7) as u8).collect();
    let mut off = 0;
    let mut got = Vec::new();
    for _ in 0..10_000 {
        if off < msg.len()
            && let Ok(k) = n.s.write(n.now, c, &msg[off..])
        {
            off += k;
        }
        let outs = n.drain();
        got.extend(p.absorb(&outs));
        if got.len() == msg.len() {
            break;
        }
        n.peer_ack(&mut p, &[]);
        n.advance(MS);
    }
    assert_eq!(got.len(), msg.len());
    assert!(got.iter().eq(msg.iter()));
    assert!(n.s.conns.tcb(c.slot).cwnd > 10 * 1368, "the window grew");
    assert!(n.events().iter().any(|e| matches!(e, Event::Writable(_))));
}

/// 相手の大きな送信を読みながら受けます。受信の窓は読み取りに応じて開き、データは順に届きます。
#[test]
fn bulk_receive_with_reads() {
    let mut n = net();
    let (c, mut p) = n.accepted(false);
    let mss = TEST_MTU - 40;
    let mut sent = 0usize;
    let mut got = Vec::new();
    for round in 0..2000u32 {
        let outs = n.drain();
        // 核の ACK が示す窓の内側だけを送ります。
        for o in &outs {
            if o.has(FLAG_ACK) {
                p.wnd = o.wnd;
            }
        }
        let window = (u32::from(p.wnd) << 7) as usize;
        let inflight = (p.snd - p.iss - 1) as usize - got.len();
        if inflight < window && sent < 500_000 {
            let k = mss.min(window - inflight).min(500_000 - sent);
            let data: Vec<u8> = (0..k).map(|i| (sent + i) as u8).collect();
            n.peer_ack(&mut p, &data);
            sent += k;
        }
        got.extend(n.read_all(c));
        if round % 7 == 0 {
            n.advance(MS);
        }
        if got.len() == 500_000 {
            break;
        }
    }
    assert_eq!(got.len(), 500_000);
    assert!(got.iter().enumerate().all(|(i, &b)| b == i as u8));
}

/// 閉じた接続の FIN を窓が 0 の相手が持たせ続けても、Linux と同じく後退を含めた RTO が上限に届いた後の期限で
/// 打ち切ります (Go の TestOrphanHeldFINIsBoundedAgainstAZeroWindowPeer)。
#[test]
fn orphan_held_fin_is_bounded_against_a_zero_window_peer() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    p.wnd = 0;
    n.peer_ack(&mut p, &[]);
    n.s.close_conn(n.now, c);
    for i in 0..2 * 3600 {
        n.advance(Duration::from_secs(1));
        for o in n.drain() {
            if o.has(FLAG_RST) {
                assert!(n.s.held().conns == 0 && n.s.delivered(c));
                assert!(
                    (300..=400).contains(&i),
                    "orphan aborted after {i} s, want about 325 s"
                );
                return;
            }
            n.peer_ack(&mut p, &[]);
        }
    }
    panic!("a closed connection still holds its slot after 2 h");
}

/// 閉じていない接続の窓の probe は、相手が応える間は 1 時間でも打ち切りません。
#[test]
fn open_conn_not_orphan_limited() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    p.wnd = 0;
    n.peer_ack(&mut p, &[]);
    n.s.write(n.now, c, &[0; 5000]).unwrap();
    for i in 0..3600 {
        n.advance(Duration::from_secs(1));
        for o in n.drain() {
            assert!(
                !o.has(FLAG_RST),
                "an open connection was aborted after {i} s"
            );
            n.peer_ack(&mut p, &[]);
        }
    }
    assert!(n.s.held().conns == 1 && !n.s.delivered(c));
}

/// 閉じた接続を窓の probe で打ち切った後、枠が返り、delivered が真になり、打ち切りが数えられます。
#[test]
fn orphan_abort_delivered_and_slot() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    p.wnd = 0;
    n.peer_ack(&mut p, &[]);
    n.s.write(n.now, c, &[0; 5000]).unwrap();
    n.advance(Duration::from_secs(30)); // 閉じる前の probe
    for _ in n.drain() {
        n.peer_ack(&mut p, &[]);
    }
    n.s.close_conn(n.now, c);
    let closed_at = n.now;
    let mut aborted_at = None;
    for _ in 0..3600 {
        if aborted_at.is_some() {
            break;
        }
        n.advance(Duration::from_secs(1));
        for o in n.drain() {
            if o.has(FLAG_RST) {
                aborted_at = Some(n.now);
            }
            n.peer_ack(&mut p, &[]);
        }
    }
    let at = aborted_at.expect("no abort");
    assert!(at > closed_at && n.s.held().conns == 0 && n.s.delivered(c));
    assert_eq!(n.s.stats().probe_aborts, 1);
}

/// TIME_WAIT の 4 つ組を使い直す SYN を握手の途中の表の上限で捨てた後も、相手が再送した SYN は前の接続の
/// SND.NXT の先から ISN を受けます (Go の TestReuseISSKeptWhenTheReuseSYNIsRefused)。
#[test]
fn reuse_iss_kept_when_the_reuse_syn_is_refused() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    let data = vec![0u8; 1 << 20];
    let mut off = 0;
    let mut closed = false;
    for i in 0..100_000 {
        if n.s.held().tw_rows != 0 {
            break;
        }
        if off < data.len()
            && let Ok(k) = n.s.write(n.now, c, &data[off..])
        {
            off += k;
        }
        if off == data.len() && !closed {
            n.s.close_conn(n.now, c);
            closed = true;
        }
        let outs = n.drain();
        p.absorb(&outs);
        n.peer_ack(&mut p, &[]);
        if i % 50 == 0 {
            n.advance(MS);
        }
    }
    n.peer_fin(&mut p);
    n.drain();
    assert_eq!(n.s.held().tw_rows, 1, "no TIME_WAIT row");
    let old_nxt = p.rcv;
    // 偽の送信元の SYN で、この待ち受けの握手の途中の行を上限まで埋めます。
    let half = small_limits().syn_rows / 2;
    let spoofed = |i: usize| core::net::Ipv4Addr::new(10, 9, 1, i as u8 + 1);
    for i in 0..half {
        n.inject(&TSeg {
            src: Some(spoofed(i)),
            sport: 100 + i as u16,
            dport: 80,
            seq: 1,
            flags: FLAG_SYN,
            wnd: 1000,
            mss: 1380,
            ..TSeg::default()
        });
    }
    n.drain();
    n.advance(Duration::from_secs(1));
    p.ts_val += 1000;
    let mut syn = TSeg {
        sport: 40000,
        dport: 80,
        seq: p.snd + 100_000,
        flags: FLAG_SYN,
        wnd: 65535,
        mss: 1380,
        ws: Some(7),
        ts: Some((p.ts_val, 0)),
        ..TSeg::default()
    };
    n.inject(&syn);
    n.drain();
    assert!(n.s.stats().syn_table_full >= 1);
    for i in 0..half {
        n.inject(&TSeg {
            src: Some(spoofed(i)),
            sport: 100 + i as u16,
            dport: 80,
            seq: 2,
            flags: FLAG_RST,
            ..TSeg::default()
        });
    }
    n.drain();
    syn.ts = Some((p.ts_val + 1, 0));
    n.inject(&syn); // 相手の SYN の再送
    let outs = n.drain();
    let sa = outs
        .iter()
        .find(|o| o.flags == FLAG_SYN | FLAG_ACK && o.rport == 40000)
        .expect("no SYN-ACK for the retransmitted SYN");
    assert!(
        !crate::seq::lt(sa.seq, old_nxt.wrapping_add(65537)),
        "ISS {} behind the old SND.NXT {old_nxt}",
        sa.seq
    );
}

/// 窓が 0 の相手に、RTO の下限は RTTVAR の項に掛かります (Go の TestRTOFloorAppliesToTheVarianceTerm の要点)。
#[test]
fn rto_floor_applies_to_the_variance_term() {
    let mut n = net();
    let (c, mut p) = n.accepted(false);
    for _ in 0..20 {
        n.s.write(n.now, c, b"x").unwrap();
        let outs = n.drain();
        p.absorb(&outs);
        n.advance(Duration::from_millis(50));
        n.peer_ack(&mut p, &[]);
        n.drain();
    }
    let t = n.s.conns.tcb(c.slot);
    assert!(t.has_rtt);
    assert_eq!(t.rto, t.srtt + (4 * t.rttvar).max(crate::tcp::RTO_MIN));
    assert!(
        t.rto > crate::tcp::RTO_MIN,
        "the floor is not on the whole RTO"
    );
}

/// `n` byte をちょうど読みます。
fn read_n(n: &mut TestNet, c: crate::ConnId, k: usize) {
    let mut b = vec![0u8; k];
    let mut got = 0;
    while got < k {
        got += n.s.read(n.now, c, &mut b[got..]).unwrap();
    }
}

/// 読み取りが受信のバッファを空にすると、遅延 ACK を待つ小さな segment に ACK をすぐ返します。
#[test]
fn small_segment_acked_when_read_drains_the_buffer() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    skip_quickack(&mut n);
    for i in 0..3 {
        n.peer_ack(&mut p, &[0; 200]);
        assert!(n.drain().is_empty(), "message {i}: ACK before the read");
        read_n(&mut n, c, 200);
        let outs = n.drain();
        assert!(
            outs.len() == 1 && outs[0].ack == p.snd && outs[0].payload.is_empty(),
            "message {i}: {}",
            show(&outs)
        );
        n.advance(20 * MS);
        n.drain();
    }
}

/// quickack を使い切った後も、読み取りが空にすれば推定した MSS の大きさの segment にも ACK をすぐ返します。
#[test]
fn full_segment_acked_when_read_drains_the_buffer() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    skip_quickack(&mut n);
    let full = mss_ts();
    for i in 0..3 {
        n.peer_ack(&mut p, &vec![0; full]);
        assert!(n.drain().is_empty(), "segment {i}: ACK before the read");
        read_n(&mut n, c, full);
        let outs = n.drain();
        assert!(
            outs.len() == 1 && outs[0].ack == p.snd && outs[0].payload.is_empty(),
            "segment {i}: {}",
            show(&outs)
        );
    }
    let v = n.s.conn(c.slot);
    assert_eq!(v.t.rcv_mss_est, v.rcv_mss());
}

/// 受けた直後にデータで応える対話の流れでは、読み終えても中身の無い ACK を足しません。
#[test]
fn no_drain_ack_in_interactive_flow() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    n.peer_ack(&mut p, &[0; 200]);
    read_n(&mut n, c, 200);
    n.drain();
    n.s.write(n.now, c, &[0; 100]).unwrap(); // 受けた直後に応えます
    let outs = n.drain();
    p.absorb(&outs);
    n.peer_ack(&mut p, &[0; 200]);
    read_n(&mut n, c, 200);
    assert!(
        n.drain().is_empty(),
        "pure ACK on drain in an interactive flow"
    );
}

/// 接続の始めの segment と RTO より長く黙った後の segment には ACK を遅らせず、その数は上限で止まります。
#[test]
fn quickack_at_start_and_after_a_gap() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    let full = mss_ts();
    let mut immediate = 0;
    for _ in 0..40 {
        n.peer_ack(&mut p, &vec![0; full]);
        if !n.drain().is_empty() {
            immediate += 1;
        }
    }
    read_n(&mut n, c, 40 * full);
    n.drain();
    // 最初の 16 個は 1 つずつ、その後は 2 つに 1 つ ACK します。
    let want = 16 + (40 - 16) / 2;
    assert!(
        (want - 1..=want + 1).contains(&immediate),
        "{immediate} immediate ACKs"
    );
    n.advance(Duration::from_secs(2)); // RTO より長く黙ります
    n.peer_ack(&mut p, &vec![0; full]);
    assert_eq!(n.drain().len(), 1, "after a gap, want an immediate ACK");
}

/// 未読のデータが残る間は、読み取りで中身の無い ACK を送りません。
#[test]
fn no_drain_ack_while_data_is_unread() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    skip_quickack(&mut n);
    n.peer_ack(&mut p, &[0; 200]);
    read_n(&mut n, c, 200);
    let outs = n.drain();
    p.absorb(&outs);
    n.peer_ack(&mut p, &[0; 1000]);
    assert!(n.drain().is_empty(), "ACK before the read");
    read_n(&mut n, c, 400);
    assert!(n.drain().is_empty(), "ACK with 600 bytes unread");
    read_n(&mut n, c, 600);
    let outs = n.drain();
    assert!(outs.len() == 1 && outs[0].ack == p.snd, "{}", show(&outs));
}

/// quickack が ACK を返した後に読み取りが空にしても、同じ番号の ACK を繰り返しません。
#[test]
fn no_drain_ack_after_an_immediate_ack() {
    let mut n = net();
    let (c, mut p) = n.accepted(true);
    for i in 0..3 {
        n.peer_ack(&mut p, &[0; 200]);
        let outs = n.drain();
        assert!(
            outs.len() == 1 && outs[0].ack == p.snd,
            "message {i}: {}",
            show(&outs)
        );
        read_n(&mut n, c, 200);
        assert!(
            n.drain().is_empty(),
            "message {i}: repeated ACK after the read"
        );
    }
}

/// 遅延 ACK と即座の ACK を数えます (Go の TestStatsCountDelayedAndImmediateAcks の要点)。
#[test]
fn stats_count_delayed_and_immediate_acks() {
    let mut n = net();
    let (_c, mut p) = n.accepted(true);
    skip_quickack(&mut n);
    n.peer_ack(&mut p, &[0; 100]);
    n.advance(Duration::from_millis(40));
    n.drain();
    assert_eq!(n.s.stats().acks_delayed, 1);
    n.peer_ack(&mut p, &vec![0; 3 * mss_ts()]);
    n.drain();
    assert_eq!(n.s.stats().acks_immediate, 1);
}
