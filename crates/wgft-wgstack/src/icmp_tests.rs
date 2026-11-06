//! echo と ping、ICMP の誤りと PMTU の引き下げ、断片の入口の白箱の試験 (Go の `udp_test.go` の ICMP の部分、
//! `frag_test.go`、`fragidle_test.go`、`sack_test.go` と `observe_test.go` の PMTU の試験)。

#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "tests collect packets"
)]
#![expect(clippy::cast_possible_truncation, reason = "small test sizes")]

use crate::config::Config;
use crate::icmp::{DST_UNREACH, ECHO, ECHO_REPLY, PARAM_PROBLEM, PING_ENDPOINTS, TIME_EXCEEDED};
use crate::sack_tests::{TEST_SEG_PAYLOAD, sack_conn};
use crate::sackpeer_tests::check_scoreboard;
use crate::stack::Event;
use crate::tcp::RTX_PMTU;
use crate::testnet_tests::{
    DUT, PEER, PeerConn, TEST_MTU, TSeg, TestNet, build_icmp, build_peer, build_udp, parse_out,
    small_limits, split_ipv4,
};
use crate::wire::{self, FLAG_SYN, IP_HEADER_LEN, PROTO_ICMP, PROTO_UDP, parse_ipv4};
use crate::{Error, seq};
use core::net::{Ipv4Addr, SocketAddrV4};
use core::time::Duration;

const PEER_UDP: SocketAddrV4 = SocketAddrV4::new(PEER, 5000);

#[test]
fn icmp_echo() {
    let mut n = TestNet::new(small_limits());
    let req = [ECHO, 0, 0, 0, 0x12, 0x34, 0, 1, b'h', b'i'];
    n.write(&build_icmp(PEER, &req));
    let pkts = n.drain_raw();
    assert_eq!(pkts.len(), 1);
    let ip = parse_ipv4(&pkts[0]).unwrap();
    let m = ip.payload();
    assert!(
        ip.proto == PROTO_ICMP
            && ip.dst == PEER.to_bits()
            && m[0] == ECHO_REPLY
            && m[4..] == req[4..]
            && !wire::checksum(0, m) == 0,
        "echo reply {:x?}",
        pkts[0]
    );
    // echo の応答は DF を立てず、IPv4 の header の checksum は正しくあります。
    assert_eq!(pkts[0][6] & 0x40, 0, "DF set");
    // 壊れた echo は捨て、MTU を超える echo の応答は断片に分けて全部返します (RFC 1122 3.2.2.6)。
    let mut bad = build_icmp(PEER, &req);
    let last = bad.len() - 1;
    bad[last] ^= 1;
    n.write(&bad);
    let mut big = vec![0u8; TEST_MTU];
    big[0] = ECHO;
    for f in split_ipv4(&build_icmp(PEER, &big), 1000, 5) {
        n.write(&f);
    }
    let pkts = n.drain_raw();
    assert_eq!(pkts.len(), 2);
    let sizes: usize = pkts.iter().map(|p| p.len() - IP_HEADER_LEN).sum();
    assert_eq!(sizes, TEST_MTU);
    assert_eq!(n.s.stats().icmp_dropped, 1);
}

#[test]
fn ping_endpoints() {
    let mut n = TestNet::new(small_limits());
    let pc = n.s.open_ping(n.now, PEER).unwrap();
    n.s.send_ping(
        n.now,
        pc,
        &[ECHO, 0, 0, 0, 0, 1, 0, 7, b'w', b'g', b'f', b't'],
    )
    .unwrap();
    let pkts = n.drain_raw();
    assert_eq!(pkts.len(), 1);
    let ip = parse_ipv4(&pkts[0]).unwrap();
    assert!(
        ip.dst == PEER.to_bits()
            && ip.payload()[0] == ECHO
            && !wire::checksum(0, ip.payload()) == 0,
        "echo request {:x?}",
        pkts[0]
    );
    let ident = u16::from_be_bytes([ip.payload()[4], ip.payload()[5]]);
    let mut reply = ip.payload().to_vec();
    reply[0] = ECHO_REPLY;
    n.write(&build_icmp(PEER, &reply));
    assert_eq!(n.events(), [Event::PingReply(pc)]);
    let mut other = reply.clone();
    other[7] = 8;
    n.write(&build_icmp(PEER, &other)); // 1 つ持つ間に届いた応答は捨てます
    let mut b = [0u8; 100];
    let k = n.s.recv_ping(n.now, pc, &mut b).unwrap();
    assert_eq!(k, reply.len());
    assert_eq!(u16::from_be_bytes([b[4], b[5]]), ident);
    assert_eq!(b[7], 7);
    assert_eq!(n.s.recv_ping(n.now, pc, &mut b), Err(Error::WouldBlock));
    // 短い buffer は応答を切ります。
    n.write(&build_icmp(PEER, &reply));
    assert_eq!(n.s.recv_ping(n.now, pc, &mut b[..4]), Ok(4));
    // 別の送信元からの応答は捨てます。
    n.write(&build_icmp(Ipv4Addr::new(10, 9, 0, 3), &reply));
    assert_eq!(n.s.recv_ping(n.now, pc, &mut b), Err(Error::WouldBlock));
    // 誤った message は送りません。
    assert_eq!(
        n.s.send_ping(n.now, pc, &[ECHO_REPLY, 0, 0, 0, 0, 0, 0, 0]),
        Err(Error::InvalidMessage)
    );
    assert_eq!(
        n.s.send_ping(n.now, pc, &[ECHO]),
        Err(Error::InvalidMessage)
    );
    // 表は 16 件で満ちます。
    let mut conns = Vec::new();
    for _ in 0..PING_ENDPOINTS - 1 {
        conns.push(n.s.open_ping(n.now, PEER).unwrap());
    }
    assert_eq!(n.s.open_ping(n.now, PEER), Err(Error::TableFull));
    assert_eq!(n.s.held().ping_endpoints, PING_ENDPOINTS);
    n.s.close_ping(n.now, pc);
    assert_eq!(n.s.recv_ping(n.now, pc, &mut b), Err(Error::Closed));
    assert_eq!(
        n.s.send_ping(n.now, pc, &[ECHO, 0, 0, 0, 0, 0, 0, 0]),
        Err(Error::Closed)
    );
    let again = n.s.open_ping(n.now, PEER).unwrap();
    assert_ne!(again, pc);
    // 識別子は使っている endpoint と重なりません。
    let mut idents: Vec<u16> = Vec::new();
    for c in conns.iter().chain([&again]) {
        n.s.send_ping(n.now, *c, &[ECHO, 0, 0, 0, 0, 0, 0, 0])
            .unwrap();
        let p = n.drain_raw().pop().unwrap();
        idents.push(u16::from_be_bytes([p[24], p[25]]));
    }
    idents.sort_unstable();
    idents.dedup();
    assert_eq!(idents.len(), PING_ENDPOINTS);
    n.s.check_invariants().unwrap();
}

/// 制御の輪が満杯なら ping の送信は誤りで、IP の ID は Go と同じく使います。
#[test]
fn ping_send_with_a_full_control_ring() {
    let mut n = TestNet::new(small_limits());
    let pc = n.s.open_ping(n.now, PEER).unwrap();
    for i in 0..small_limits().ctl_slots {
        n.s.send_ping(n.now, pc, &[ECHO, 0, 0, 0, 0, 0, 0, i as u8])
            .unwrap();
    }
    assert_eq!(
        n.s.send_ping(n.now, pc, &[ECHO, 0, 0, 0, 0, 0, 0, 0]),
        Err(Error::NoBufferSpace)
    );
    let ids: Vec<u16> = n
        .drain_raw()
        .iter()
        .map(|p| u16::from_be_bytes([p[4], p[5]]))
        .collect();
    n.s.send_ping(n.now, pc, &[ECHO, 0, 0, 0, 0, 0, 0, 0])
        .unwrap();
    let p = n.drain_raw().pop().unwrap();
    let last = ids[ids.len() - 1];
    assert_eq!(u16::from_be_bytes([p[4], p[5]]), last.wrapping_add(2));
}

/// TCP の Fragmentation Needed は、外側の送信元が引用の宛先と一致し、MTU が下限以上のときだけ PMTU を下げます
/// (Go の `TestICMPErrorSourceCheck`)。
#[test]
fn icmp_error_source_check() {
    let mut n = TestNet::new(small_limits());
    let (c, _) = n.accepted(true);
    n.s.write(n.now, c, &[0; 3000]).unwrap();
    let pkts = n.drain_raw();
    let quote = pkts[0][..IP_HEADER_LEN + 8].to_vec();
    let frag = |src: Ipv4Addr, mtu: u16| {
        let mut m = vec![0u8; 8 + quote.len()];
        m[0] = DST_UNREACH;
        m[1] = 4;
        m[6..8].copy_from_slice(&mtu.to_be_bytes());
        m[8..].copy_from_slice(&quote);
        build_icmp(src, &m)
    };
    n.write(&frag(Ipv4Addr::new(10, 9, 0, 3), 1000)); // 引用の宛先と違う送信元
    n.write(&frag(PEER, 500)); // 552 より小さい
    assert_eq!(n.s.conn(c.slot).t.pmtu, TEST_MTU as u32);
    assert_eq!(n.s.stats().icmp_dropped, 2);
    n.write(&frag(PEER, 1000));
    assert_eq!(n.s.conn(c.slot).t.pmtu, 1000);
    // 次の segment は新しい大きさに収まります。
    for p in n.drain_raw() {
        assert!(p.len() <= 1000, "{} bytes after the PMTU drop", p.len());
    }
}

/// 待ち受けに届いた Port Unreachable と、ほかの ICMP の誤りは捨てます。
#[test]
fn other_icmp_errors_are_dropped() {
    let mut n = TestNet::new(small_limits());
    let (c, _) = n.accepted(true);
    n.s.write(n.now, c, &[0; 100]).unwrap();
    let pkts = n.drain_raw();
    let quote = pkts[0][..IP_HEADER_LEN + 8].to_vec();
    for (typ, code) in [
        (DST_UNREACH, 3),
        (DST_UNREACH, 1),
        (TIME_EXCEEDED, 0),
        (5, 0),
        (4, 0),
    ] {
        let mut m = vec![0u8; 8 + quote.len()];
        m[0] = typ;
        m[1] = code;
        m[8..].copy_from_slice(&quote);
        n.write(&build_icmp(PEER, &m));
    }
    n.write(&build_icmp(PEER, &[13, 0, 0, 0, 0, 0, 0, 0])); // 知らない種類
    assert_eq!(n.s.stats().icmp_dropped, 6);
    assert!(n.drain_raw().is_empty(), "no reply to ICMP errors");
    assert_eq!(n.s.conn(c.slot).t.pmtu, TEST_MTU as u32);
}

/// echo の洪水は制御の輪だけを満たし、UDP の組は配分の分だけ進み続けます (Go の
/// `TestBoundEchoFloodFillsOnlyTheControlRing`)。
#[test]
fn bound_echo_flood_fills_only_the_control_ring() {
    let mut n = TestNet::new(small_limits());
    let pc = n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
    for i in 0..1000u16 {
        let [hi, lo] = i.to_be_bytes();
        n.s.handle_packet(n.now, &build_icmp(PEER, &[ECHO, 0, 0, 0, 0, 1, hi, lo]));
    }
    n.s.check_invariants().unwrap();
    let h = n.s.held();
    // echo の応答が輪に置けるのは枠の 1/4 までで、洪水はそこで止まります。
    let cap = (small_limits().ctl_slots / 4).max(1);
    assert_eq!(h.ctl_queued, cap);
    assert!(n.s.stats().ctl_dropped > 0);
    // 残りの枠はほかの制御の packet (ICMP の誤り) のために空いています。
    let free = small_limits().ctl_slots - cap;
    for i in 0..free as u16 {
        n.s.handle_packet(
            n.now,
            &build_udp(SocketAddrV4::new(PEER, 6000 + i), 9, b"x"),
        );
    }
    assert_eq!(n.s.held().ctl_queued, small_limits().ctl_slots);
    n.s.send_to(n.now, pc, b"still here", PEER_UDP).unwrap();
    let mut buf = vec![0u8; TEST_MTU];
    let mut udp = false;
    for _ in 0..2 * TEST_MTU / 28 {
        let Some(k) = n.s.poll_transmit(n.now, &mut buf) else {
            break;
        };
        udp = parse_ipv4(&buf[..k]).unwrap().proto == PROTO_UDP;
        if udp {
            break;
        }
    }
    assert!(udp, "the UDP class was starved by the control ring");
}

/// ICMP の誤りは 1 秒に 1000 個までです。
#[test]
fn icmp_errors_are_rate_limited() {
    let mut n = TestNet::new(small_limits());
    let mut sent = 0;
    for i in 0..1100u16 {
        n.s.handle_packet(n.now, &build_udp(SocketAddrV4::new(PEER, i), 9, b"x"));
        sent += n.drain_raw().len();
    }
    assert_eq!(sent, 1000);
    assert_eq!(n.s.stats().icmp_limited, 100);
    n.advance(Duration::from_secs(1));
    n.write(&build_udp(PEER_UDP, 9, b"x"));
    assert_eq!(n.drain_raw().len(), 1);
}

#[test]
fn fragmented_udp_is_reassembled() {
    let mut n = TestNet::new(small_limits());
    let pc = n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
    let msg: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
    let frags = split_ipv4(&build_udp(PEER_UDP, 53, &msg), 1000, 77);
    for f in frags.iter().rev() {
        n.write(f); // 逆の順で届きます
    }
    let mut b = vec![0u8; 4000];
    let (k, from) = n.s.recv_from(n.now, pc, &mut b).unwrap();
    assert_eq!((&b[..k], from), (&msg[..], PEER_UDP));
    assert_eq!(n.s.stats().fragments_dropped, frags.len() as u64 - 1);
    assert_eq!(n.s.held().frag_bytes, 0);
}

#[test]
fn fragment_timeout_sends_time_exceeded() {
    let mut n = TestNet::new(small_limits());
    n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
    let frags = split_ipv4(&build_udp(PEER_UDP, 53, &[0; 3000]), 1000, 78);
    n.write(&frags[0]);
    n.advance(Duration::from_secs(31));
    let pkts = n.drain_raw();
    assert_eq!(pkts.len(), 1, "packets after the reassembly timeout");
    let ip = parse_ipv4(&pkts[0]).unwrap();
    let m = ip.payload();
    assert!(
        ip.proto == PROTO_ICMP && m[0] == TIME_EXCEEDED && m[1] == 1 && m[8..36] == frags[0][..28],
        "Time Exceeded {:x?}",
        pkts[0]
    );
    assert!(!n.s.s.frag.has_entries());
    assert_eq!(n.s.poll_timeout(), None);
}

/// TCP のタイマーを持たない核が断片を 1 つ保持したとき、`poll_timeout` は掃除の時刻を返し、その時刻を追う駆動の
/// 層が寿命の後に Time Exceeded を送ります (Go の `TestIdleDeviceSweepsAHeldFragment`)。
#[test]
fn idle_core_sweeps_a_held_fragment() {
    let mut n = TestNet::new(small_limits());
    n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
    assert_eq!(n.s.poll_timeout(), None);
    n.advance(Duration::from_millis(50));
    let frags = split_ipv4(&build_udp(PEER_UDP, 53, &[0; 3000]), 1000, 78);
    n.write(&frags[0]);
    let mut wakes = 0;
    loop {
        let t =
            n.s.poll_timeout()
                .expect("a sweep deadline while a fragment is held");
        assert!(t > n.now);
        n.now = t;
        n.s.handle_timeout(t);
        wakes += 1;
        let pkts = n.drain_raw();
        if let Some(p) = pkts.first() {
            assert_eq!(parse_ipv4(p).unwrap().payload()[0], TIME_EXCEEDED);
            break;
        }
        assert!(wakes < 40, "no Time Exceeded after {wakes} wakes");
    }
    assert!((30..=31).contains(&wakes), "{wakes} wakes");
}

fn frag_with_options(offset: usize, more: bool, opts: &[u8], data: &[u8]) -> Vec<u8> {
    let hlen = 20 + opts.len();
    let mut p = vec![0u8; hlen + data.len()];
    p[0] = 0x40 | (hlen / 4) as u8;
    let len = p.len() as u16;
    p[2..4].copy_from_slice(&len.to_be_bytes());
    p[4] = 0x12;
    p[5] = 0x34;
    let mut fl = (offset / 8) as u16;
    if more {
        fl |= 0x2000;
    }
    p[6..8].copy_from_slice(&fl.to_be_bytes());
    p[8] = 64;
    p[9] = PROTO_UDP;
    p[12..16].copy_from_slice(&PEER.octets());
    p[16..20].copy_from_slice(&DUT.octets());
    p[20..hlen].copy_from_slice(opts);
    p[hlen..].copy_from_slice(data);
    wire::set_ipv4_checksum(&mut p[..hlen]);
    p
}

/// 不正な option を持つ最初の断片に Parameter Problem を返し、pointer は option の位置を指します (Go の
/// `TestParamProblemForFragmentOptions`)。先頭でない断片への組は RFC 1122 3.2.2 に合わせて外しました。
#[test]
fn param_problem_for_fragment_options() {
    let mut n = TestNet::new(small_limits());
    n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
    n.write(&frag_with_options(0, true, &[0x82, 1, 0, 0], b"abcdefgh"));
    let pkts = n.drain_raw();
    assert_eq!(pkts.len(), 1, "{:?}", n.s.stats());
    let ip = parse_ipv4(&pkts[0]).unwrap();
    let m = ip.payload();
    assert!(
        ip.proto == PROTO_ICMP && m[0] == PARAM_PROBLEM && m[4] == 20,
        "{:x?}",
        pkts[0]
    );
}

/// 断片の洪水でも再組み立ての表は上限の内側に留まり、寿命の後に空になります (Go の `TestBoundFragmentFlood`)。
#[test]
fn bound_fragment_flood() {
    let mut n = TestNet::new(small_limits());
    n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
    for i in 0..2000u16 {
        let frags = split_ipv4(&build_udp(PEER_UDP, 53, &[0; 8000]), 1400, i);
        // 最初と 3 つめの断片だけを送り、datagram を完成させません。
        n.s.handle_packet(n.now, &frags[0]);
        n.s.handle_packet(n.now, &frags[2]);
    }
    n.s.check_invariants().unwrap();
    let (used, entries, pieces) = n.s.s.frag.usage();
    let l = crate::frag::LIMITS;
    assert!(
        used <= l.bytes
            && entries <= l.entries
            && pieces <= l.fragments
            && n.s.s.frag.evicted() > 0,
        "used {used} entries {entries} pieces {pieces}"
    );
    // 追い出しは Stats に数えます。datagram ごとに 2 つの断片を送ったので、表に残る項目のほかは追い出されています。
    assert_eq!(n.s.stats().fragments_evicted, n.s.s.frag.evicted());
    assert_eq!(
        n.s.stats().fragments_evicted,
        2000 - entries as u64,
        "every datagram not left in the table was evicted"
    );
    assert!(n.s.bound().frag >= used as u64);
    for _ in 0..40 {
        n.advance(Duration::from_secs(1));
    }
    let (_, entries, pieces) = n.s.s.frag.usage();
    assert_eq!((entries, pieces), (0, 0));
    assert_eq!(n.s.held().frag_bytes, 0);
}

/// 引用した番号が SND.UNA 以上 SND.NXT 未満にない Fragmentation Needed で PMTU を下げず、内側にあるものでだけ
/// 下げます (RFC 5927、Go の `TestFragNeededOutsideTheSendWindowIsIgnored`)。
#[test]
fn frag_needed_outside_the_send_window_is_ignored() {
    let mut n = TestNet::new(small_limits());
    let (c, _) = n.accepted(true);
    n.s.write(n.now, c, &[0; 3000]).unwrap();
    let pkts = n.drain_raw();
    let quote = pkts[0][..IP_HEADER_LEN + 8].to_vec();
    let mk = |seq: u32| {
        let mut q = quote.clone();
        q[IP_HEADER_LEN + 4..IP_HEADER_LEN + 8].copy_from_slice(&seq.to_be_bytes());
        let mut m = vec![0u8; 8 + q.len()];
        m[0] = DST_UNREACH;
        m[1] = 4;
        m[6..8].copy_from_slice(&1000u16.to_be_bytes());
        m[8..].copy_from_slice(&q);
        build_icmp(PEER, &m)
    };
    let (una, nxt) = {
        let t = &n.s.conn(c.slot).t;
        (t.snd_una, t.snd_nxt)
    };
    n.write(&mk(nxt)); // SND.NXT は外です
    n.write(&mk(una.wrapping_sub(1))); // SND.UNA より前
    assert_eq!(n.s.conn(c.slot).t.pmtu, TEST_MTU as u32);
    n.write(&mk(una));
    assert_eq!(n.s.conn(c.slot).t.pmtu, 1000);
}

/// PMTU の引き下げで、SACK の無い接続は SND.UNA から新しい大きさで送り直し、原因ごとの数に数えます (Go の
/// `TestStatsCountPMTUResend`)。
#[test]
fn stats_count_pmtu_resend() {
    let mut n = TestNet::new(small_limits());
    let (c, _) = n.accepted(true);
    n.s.write(n.now, c, &[0; 3000]).unwrap();
    let outs = n.drain();
    let now = crate::stack::ns(n.now);
    n.s.conn(c.slot).pmtu_drop(outs[0].seq, 1000, now);
    let resent = n.drain();
    let st = n.s.stats();
    assert!(
        st.retrans[usize::from(RTX_PMTU)] > 0
            && st.retrans[usize::from(RTX_PMTU)] == resent.len() as u64
            && st.rtos == 0,
        "stats {st:?} after {} resent segments",
        resent.len()
    );
}

/// PMTU の引き下げで、SACK を使う接続は記録の境目を保ち、新しい大きさに入らない記録だけを小さな segment で
/// 送り直します。SACK 済みのデータは送り直しません (Go の `TestPMTUDropResendsLargeRecordsInPieces`)。
#[test]
fn pmtu_drop_resends_large_records_in_pieces() {
    let (mut n, c, mut q, outs) = sack_conn(10);
    // 5 から 9 を SACK で知らせます。
    q.deliver_with(&mut n, &outs, |i, _| i < 5);
    n.drain();
    let recs = n.s.conn(c.slot).b.recs.len();
    let now = crate::stack::ns(n.now);
    n.s.conn(c.slot).pmtu_drop(outs[0].seq, 600, now);
    assert_eq!(n.s.conn(c.slot).b.recs.len(), recs);
    let end = outs[5].seq;
    let mut covered = outs[0].seq;
    let mut sent = 0u64;
    for _ in 0..50 {
        let got = n.drain();
        if got.is_empty() {
            break;
        }
        for o in got.iter().filter(|o| !o.payload.is_empty()) {
            sent += 1;
            assert!(
                o.payload.len() <= 600 - 40 - 12,
                "segment of {} bytes after the PMTU drop",
                o.payload.len()
            );
            assert!(
                seq::lt(o.seq, end),
                "resent SACKed data at {}",
                o.seq.wrapping_sub(outs[0].seq)
            );
            if o.seq == covered {
                covered = covered.wrapping_add(o.payload.len() as u32);
            }
        }
        q.deliver(&mut n, &got);
        check_scoreboard(&mut n.s.conn(c.slot));
    }
    let t = &n.s.conn(c.slot).t;
    assert!(
        covered == end && t.snd_una == t.snd_max,
        "resent up to {}, want {}",
        covered.wrapping_sub(outs[0].seq),
        end.wrapping_sub(outs[0].seq)
    );
    check_scoreboard(&mut n.s.conn(c.slot));
    assert_eq!(n.s.stats().retrans[usize::from(RTX_PMTU)], sent);
}

/// PMTU の引き下げで、新しい大きさに入る記録は送り直しません (入る記録は届いているかもしれません。Linux と同じです。
/// Go の `TestPMTUDropKeepsRecordsThatFit`)。
#[test]
fn pmtu_drop_keeps_records_that_fit() {
    let (mut n, c, _, outs) = sack_conn(2);
    n.s.write(n.now, c, &[0; 100]).unwrap(); // 新しい大きさに入る小さな記録
    let small = n.drain();
    assert!(
        small.len() == 1 && small[0].payload.len() == 100,
        "{small:?}"
    );
    let now = crate::stack::ns(n.now);
    n.s.conn(c.slot).pmtu_drop(outs[0].seq, 600, now);
    for o in n.drain() {
        assert!(
            o.seq != small[0].seq || o.payload.is_empty(),
            "resent the {}-byte record that fits the new PMTU",
            o.payload.len()
        );
    }
    check_scoreboard(&mut n.s.conn(c.slot));
}

/// 古い大きさで分けて送っている途中の先頭の記録が PMTU の引き下げで損失になったとき、分けた位置を捨てて新しい
/// 大きさで初めから送り直します (Go の `TestPMTUDropRestartsAHeadResentInPieces`)。
#[test]
fn pmtu_drop_restarts_a_head_resent_in_pieces() {
    let (mut n, c, _, outs) = sack_conn(3);
    let now = crate::stack::ns(n.now);
    {
        let mut cs = n.s.conn(c.slot);
        (cs.t.rxt_idx, cs.t.rxt_off, cs.t.rxt_mid) = (0, 500, true); // 先頭を古い大きさで途中まで送りました
        cs.pmtu_drop(outs[0].seq, 600, now);
        assert!(
            cs.t.rxt_idx == 0 && cs.t.rxt_off == 0 && !cs.t.rxt_mid,
            "the split position survived the PMTU drop: idx {} off {} mid {}",
            cs.t.rxt_idx,
            cs.t.rxt_off,
            cs.t.rxt_mid
        );
    }
    let got = n.drain();
    assert!(
        !got.is_empty() && got[0].seq == outs[0].seq,
        "the first resend after the PMTU drop is {got:?}, want the head from its start"
    );
    assert!(got[0].payload.len() <= TEST_SEG_PAYLOAD);
}

/// RFC 1122 3.2.2 の守り:ICMP の誤りに誤りを返さず、multicast と broadcast と 0 の送信元に返さず、引用は
/// 576 byte の IPv4 の packet に収めます。
#[test]
fn icmp_error_guards() {
    let mut n = TestNet::new(small_limits());
    n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
    // 断片で届いた ICMP の Destination Unreachable が期限を過ぎても、Time Exceeded を返しません。echo request の
    // 断片には返します。
    let mut unreach = vec![0u8; 600];
    unreach[0] = DST_UNREACH;
    let mut echo = vec![0u8; 600];
    echo[0] = ECHO;
    n.write(&split_ipv4(&build_icmp(PEER, &unreach), 304, 90)[0]);
    n.write(&split_ipv4(&build_icmp(PEER, &echo), 304, 91)[0]);
    n.advance(Duration::from_secs(31));
    let pkts = n.drain_raw();
    assert_eq!(pkts.len(), 1, "only the echo fragment gets Time Exceeded");
    let m = parse_ipv4(&pkts[0]).unwrap().payload().to_vec();
    assert_eq!(
        (m[0], m[8 + 9], m[8 + IP_HEADER_LEN]),
        (TIME_EXCEEDED, PROTO_ICMP, ECHO)
    );
    // multicast、broadcast、0 の送信元からの閉じたポートへの UDP には Port Unreachable を返しません。
    for src in [
        Ipv4Addr::new(224, 0, 0, 1),
        Ipv4Addr::new(239, 1, 2, 3),
        Ipv4Addr::BROADCAST,
        Ipv4Addr::UNSPECIFIED,
    ] {
        n.write(&build_udp(SocketAddrV4::new(src, 5000), 9, b"x"));
    }
    assert_eq!(n.drain_raw().len(), 0);
    // 引用は 576 byte の packet に収めます。
    n.write(&build_udp(PEER_UDP, 9, &[7; 1000]));
    let pkts = n.drain_raw();
    assert_eq!(pkts.len(), 1);
    assert_eq!(pkts[0].len(), 576);
}

/// 断片を保持した時、過ぎた掃除の時刻は今から 1 秒後に張り直します。
#[test]
fn frag_sweep_rearms_when_a_fragment_is_held() {
    let mut n = TestNet::new(small_limits());
    let pc = n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
    let frags = split_ipv4(&build_udp(PEER_UDP, 53, &[0; 3000]), 1000, 80);
    n.write(&frags[0]);
    assert_eq!(n.s.poll_timeout(), Some(n.now + Duration::from_secs(1)));
    for f in &frags[1..] {
        n.write(f);
    }
    assert_eq!(n.s.poll_timeout(), None);
    n.s.recv_from(n.now, pc, &mut [0; 4000]).unwrap();
    // 掃除を動かさずに時刻が進んだ後に保持すると、前の掃除の時刻は過ぎているので張り直します。
    n.now = n.now + Duration::from_secs(10);
    n.write(&split_ipv4(&build_udp(PEER_UDP, 53, &[0; 3000]), 1000, 81)[0]);
    assert_eq!(n.s.poll_timeout(), Some(n.now + Duration::from_secs(1)));
}

/// 引用の送信元が自分でない Fragmentation Needed は捨てます。
#[test]
fn frag_needed_needs_our_quoted_source() {
    let mut n = TestNet::new(small_limits());
    let (c, _) = n.accepted(true);
    n.s.write(n.now, c, &[0; 3000]).unwrap();
    let pkts = n.drain_raw();
    let mut quote = pkts[0][..IP_HEADER_LEN + 8].to_vec();
    quote[12..16].copy_from_slice(&Ipv4Addr::new(10, 9, 0, 9).octets());
    let mut m = vec![0u8; 8 + quote.len()];
    m[0] = DST_UNREACH;
    m[1] = 4;
    m[6..8].copy_from_slice(&1000u16.to_be_bytes());
    m[8..].copy_from_slice(&quote);
    n.write(&build_icmp(PEER, &m));
    assert_eq!(n.s.conn(c.slot).t.pmtu, TEST_MTU as u32);
    assert_eq!(n.s.stats().icmp_dropped, 1);
}

/// PMTU の引き下げは、中身がちょうど新しい大きさの記録を損失にせず、それより長い記録だけを損失にします。
#[test]
fn mark_lost_longer_keeps_records_of_the_new_size() {
    let (mut n, c, _, _) = sack_conn(2);
    let mut cs = n.s.conn(c.slot);
    let len = TEST_SEG_PAYLOAD as u32;
    cs.mark_lost_longer(len, RTX_PMTU);
    assert_eq!(
        cs.t.lost_q.n, 0,
        "a record of exactly the new size was marked lost"
    );
    cs.mark_lost_longer(len - 1, RTX_PMTU);
    assert_eq!(cs.t.lost_q.n, 2);
}

/// PMTU の引き下げは、小さくなった MSS で DupThresh の byte の規則を数え直し、損失の境目を進めます。
#[test]
fn pmtu_drop_recounts_the_loss_frontier() {
    let (mut n, c, mut q, outs) = sack_conn(10);
    // 8 と 9 だけを SACK で知らせます。2 つの記録は古い MSS では閾値に届きません。
    q.deliver_with(&mut n, &outs, |i, _| i < 8);
    assert_eq!(n.s.conn(c.slot).t.loss_idx, 0);
    let now = crate::stack::ns(n.now);
    n.s.conn(c.slot).pmtu_drop(outs[0].seq, 600, now);
    assert!(
        n.s.conn(c.slot).t.loss_idx > 0,
        "the loss frontier did not move with the smaller MSS"
    );
}

// RFC 6864 4.3 と 5.2: DF を下ろした packet (UDP の datagram と echo の応答) の IPv4 ID は、DF を立てた packet
// (TCP の segment と ICMP の誤り) の数えから独立でなければなりません。

fn ip_id(p: &[u8]) -> u16 {
    u16::from_be_bytes([p[4], p[5]])
}

/// 0 を飛ばす数えの次の値です。
fn id_after(id: u16) -> u16 {
    match id.wrapping_add(1) {
        0 => 1,
        n => n,
    }
}

/// UDP の datagram を 1 つ送り、核が出した packet を返します。
fn send_udp_and_drain(n: &mut TestNet, pc: crate::udp::UdpId, len: usize) -> Vec<Vec<u8>> {
    n.s.send_to(n.now, pc, &vec![0x5a; len], PEER_UDP).unwrap();
    let pkts = n.drain_raw();
    assert!(
        pkts.iter().all(|p| p[9] == PROTO_UDP),
        "only UDP expected: {pkts:x?}"
    );
    pkts
}

/// DF を立てた packet を多数出させます。TCP の segment と、ICMP の誤り (Port Unreachable) です。相手が segment を
/// ACK して窓を開き直すので、何度呼んでも TCP の segment が出ます。戻り値は出た TCP の segment の数です。
fn emit_df_traffic(n: &mut TestNet, c: crate::tcp::conn::ConnId, peer: &mut PeerConn) -> usize {
    let mut tcp = 0;
    for _ in 0..4 {
        n.s.write(n.now, c, &[0; 4000]).ok();
        for i in 0..5u16 {
            n.write(&build_udp(SocketAddrV4::new(PEER, 6000 + i), 9, b"x"));
        }
        let pkts = n.drain_raw();
        for p in &pkts {
            assert_eq!(p[6] & 0x40, 0x40, "DF clear on {p:x?}");
        }
        let outs: Vec<_> = pkts
            .iter()
            .filter(|p| p[9] == wire::PROTO_TCP)
            .map(|p| parse_out(p))
            .collect();
        tcp += pkts.iter().filter(|p| p[9] == wire::PROTO_TCP).count();
        peer.absorb(&outs);
        n.peer_ack(peer, &[]);
        n.drain_raw();
    }
    assert!(tcp >= 8, "only {tcp} TCP segments");
    tcp
}

/// UDP の datagram の間に TCP の segment と ICMP の誤りを送っても、UDP の ID は進みません
/// (RFC 6864 4.3、5.2: 非 atomic の datagram の ID は独立した数えから取ります)。
#[test]
fn udp_ids_are_not_advanced_by_df_traffic() {
    let mut n = TestNet::new(small_limits());
    let pc = n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
    let (c, mut peer) = n.accepted(true);
    n.drain_raw();
    let mut prev = {
        let a = send_udp_and_drain(&mut n, pc, 100);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0][6] & 0x40, 0, "DF set on UDP");
        ip_id(&a[0])
    };
    for round in 0..3 {
        emit_df_traffic(&mut n, c, &mut peer);
        let b = send_udp_and_drain(&mut n, pc, 100);
        assert_eq!(b.len(), 1);
        assert_eq!(
            ip_id(&b[0]),
            id_after(prev),
            "round {round}: the UDP ID counter was advanced by TCP or ICMP error traffic"
        );
        prev = ip_id(&b[0]);
    }
}

/// echo の応答も非 atomic で、UDP と同じ数えに従います。DF を立てた packet は数えを進めません。
#[test]
fn echo_replies_and_udp_share_a_counter_that_df_traffic_does_not_advance() {
    let mut n = TestNet::new(small_limits());
    let pc = n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
    let (c, mut peer) = n.accepted(true);
    n.drain_raw();
    let first = ip_id(&send_udp_and_drain(&mut n, pc, 100)[0]);
    emit_df_traffic(&mut n, c, &mut peer);
    n.write(&build_icmp(PEER, &[ECHO, 0, 0, 0, 0, 1, 0, 1, b'x']));
    let reply = n.drain_raw();
    assert_eq!(reply.len(), 1);
    assert_eq!(reply[0][6] & 0x40, 0, "DF set on the echo reply");
    assert_eq!(ip_id(&reply[0]), id_after(first), "echo reply ID");
    emit_df_traffic(&mut n, c, &mut peer);
    let last = ip_id(&send_udp_and_drain(&mut n, pc, 100)[0]);
    assert_eq!(
        last,
        id_after(id_after(first)),
        "UDP ID after the echo reply"
    );
}

/// 断片に分けた datagram の断片は 1 つの ID を共有し、次の datagram は次の ID を使います。間に DF を立てた
/// packet があっても数えは進みません。
#[test]
fn fragmented_udp_shares_one_id_and_ignores_df_traffic() {
    let mut n = TestNet::new(small_limits());
    let pc = n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
    let (c, mut peer) = n.accepted(true);
    n.drain_raw();
    let a = send_udp_and_drain(&mut n, pc, 3000);
    assert!(a.len() >= 3, "{} fragments", a.len());
    let id_a = ip_id(&a[0]);
    for p in &a {
        assert_eq!(ip_id(p), id_a, "fragments of one datagram differ in ID");
        assert_eq!(p[6] & 0x40, 0, "DF set on a fragment");
    }
    emit_df_traffic(&mut n, c, &mut peer);
    let b = send_udp_and_drain(&mut n, pc, 3000);
    let id_b = ip_id(&b[0]);
    assert!(b.iter().all(|p| ip_id(p) == id_b));
    assert_eq!(id_b, id_after(id_a), "the next datagram's ID");
}

/// 間に何も送らなければ、断片は 1 つの ID を共有し、次の datagram は別の ID を使います (現行の挙動の確認です)。
#[test]
fn fragmented_udp_ids_without_other_traffic() {
    let mut n = TestNet::new(small_limits());
    let pc = n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
    let a = send_udp_and_drain(&mut n, pc, 3000);
    let b = send_udp_and_drain(&mut n, pc, 3000);
    assert!(a.len() >= 3 && b.len() >= 3);
    assert!(a.iter().all(|p| ip_id(p) == ip_id(&a[0])));
    assert!(b.iter().all(|p| ip_id(p) == ip_id(&b[0])));
    assert_ne!(ip_id(&a[0]), ip_id(&b[0]));
}

fn echo_reply_id(n: &mut TestNet) -> u16 {
    n.write(&build_icmp(PEER, &[ECHO, 0, 0, 0, 0, 1, 0, 1, b'x']));
    let r = n.drain_raw();
    assert_eq!(r.len(), 1);
    ip_id(&r[0])
}

/// 非 atomic の数えが 16 bit を一周するとき、UDP の datagram も echo の応答も 0xffff の次に 1 を使います。
/// 0 は使いません (RFC 6864 の読み方は PR の説明に従います)。
#[test]
fn open_id_counter_wraps_past_zero() {
    let mut n = TestNet::new(small_limits());
    let pc = n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
    n.s.s.ip_id_open = 0xfffe;
    assert_eq!(ip_id(&send_udp_and_drain(&mut n, pc, 10)[0]), 0xffff);
    assert_eq!(ip_id(&send_udp_and_drain(&mut n, pc, 10)[0]), 1);
    n.s.s.ip_id_open = 0xfffe;
    assert_eq!(echo_reply_id(&mut n), 0xffff);
    assert_eq!(echo_reply_id(&mut n), 1);
    n.s.s.ip_id_open = 0xfffe;
    assert_eq!(echo_reply_id(&mut n), 0xffff);
    assert_eq!(ip_id(&send_udp_and_drain(&mut n, pc, 10)[0]), 1);
    assert_eq!(echo_reply_id(&mut n), 2);
}

/// 凍結した Go との照合の切り替えでは、数えを共有し、UDP は 0 を飛ばし、echo の応答は飛ばしません。
#[cfg(feature = "harness")]
#[test]
fn go_compat_shared_id_wrap_skips_zero_for_udp_only() {
    crate::stack::set_go_compat_shared_id(true);
    let mut n = TestNet::new(small_limits());
    let pc = n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
    n.s.s.ip_id = 0xfffe;
    assert_eq!(ip_id(&send_udp_and_drain(&mut n, pc, 10)[0]), 0xffff);
    assert_eq!(
        ip_id(&send_udp_and_drain(&mut n, pc, 10)[0]),
        1,
        "UDP skips 0"
    );
    n.s.s.ip_id = 0xfffe;
    assert_eq!(echo_reply_id(&mut n), 0xffff);
    assert_eq!(echo_reply_id(&mut n), 0, "an echo reply does not skip 0");
    assert_eq!(echo_reply_id(&mut n), 1);
    crate::stack::set_go_compat_shared_id(false);
}

/// 先頭でない断片の option が不正でも、ICMP の Parameter Problem は返さず、黙って捨てます (RFC 1122 3.2.2:
/// 先頭でない断片への ICMP の誤りは MUST NOT)。上の `param_problem_for_fragment_options` の offset 8 の組は
/// 現行の挙動を固定しているので、直す時にその組を外します。
#[test]
fn non_initial_fragment_with_bad_options_gets_no_icmp() {
    for (offset, more) in [(8, false), (8, true), (1400, false)] {
        for opts in [[0x82u8, 1, 0, 0], [0x07, 0x40, 0, 0]] {
            let mut n = TestNet::new(small_limits());
            let pc = n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
            n.write(&frag_with_options(offset, more, &opts, b"abcdefgh"));
            let pkts = n.drain_raw();
            assert!(
                pkts.is_empty(),
                "offset {offset} more {more} opts {opts:x?}: replied {pkts:x?}"
            );
            let mut b = [0u8; 64];
            assert_eq!(n.s.recv_from(n.now, pc, &mut b), Err(Error::WouldBlock));
        }
    }
}

// RFC 1122 3.2.1.3: 送信元が 0/8、127/8、224/4、240/4 または 255.255.255.255 の datagram は黙って捨てます。
// RFC 1122 3.2.2: そのような送信元には ICMP の誤りを送りません。

const INVALID_SOURCES: [Ipv4Addr; 11] = [
    Ipv4Addr::UNSPECIFIED,
    Ipv4Addr::new(0, 1, 2, 3),
    Ipv4Addr::LOCALHOST,
    Ipv4Addr::new(127, 255, 255, 254),
    Ipv4Addr::new(224, 0, 0, 1),
    Ipv4Addr::new(239, 255, 255, 250),
    Ipv4Addr::new(240, 0, 0, 1),
    Ipv4Addr::new(250, 9, 0, 2),
    Ipv4Addr::new(255, 255, 255, 254),
    Ipv4Addr::BROADCAST,
    Ipv4Addr::new(0, 255, 255, 255),
];

/// packet の送信元を書き換え、header の checksum を直します。
fn with_source(mut p: Vec<u8>, src: Ipv4Addr) -> Vec<u8> {
    let hlen = usize::from(p[0] & 0x0f) * 4;
    p[12..16].copy_from_slice(&src.octets());
    wire::set_ipv4_checksum(&mut p[..hlen]);
    p
}

/// どの送信元の UDP、echo request、TCP の SYN も、待ち受けにも閉じた port にも届かず、何も返しません。
#[test]
fn datagrams_from_invalid_sources_are_discarded_silently() {
    let mut n = TestNet::new(small_limits());
    let pc = n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
    let l = n.listen(80);
    let mut buf = [0u8; 64];
    for src in INVALID_SOURCES {
        let syn = |dport| TSeg {
            sport: 40000,
            dport,
            src: Some(src),
            seq: 1000,
            flags: FLAG_SYN,
            wnd: 65535,
            mss: 1360,
            ..TSeg::default()
        };
        let what: [(&str, Vec<u8>); 5] = [
            (
                "UDP to a bound port",
                build_udp(SocketAddrV4::new(src, 5000), 53, b"hi"),
            ),
            (
                "UDP to a closed port",
                build_udp(SocketAddrV4::new(src, 5000), 9, b"hi"),
            ),
            (
                "echo request",
                build_icmp(src, &[ECHO, 0, 0, 0, 0, 1, 0, 1, b'x']),
            ),
            ("SYN to a listener", build_peer(&syn(80))),
            ("SYN to a closed port", build_peer(&syn(81))),
        ];
        for (name, pkt) in what {
            n.write(&pkt);
            let out = n.drain_raw();
            assert!(out.is_empty(), "{src}: {name} was answered: {out:x?}");
            assert_eq!(
                n.s.recv_from(n.now, pc, &mut buf),
                Err(Error::WouldBlock),
                "{src}: {name} was delivered"
            );
            assert!(
                n.events().is_empty(),
                "{src}: {name} raised an event: {:?}",
                n.s.stats()
            );
        }
    }
    assert_eq!(n.s.accept(n.now, l), Err(Error::WouldBlock));
    // 対照: 正しい送信元の UDP は届きます。
    n.write(&build_udp(PEER_UDP, 53, b"hi"));
    assert_eq!(n.s.recv_from(n.now, pc, &mut buf).map(|r| r.0), Ok(2));
}

/// 無効な送信元には、Port Unreachable も Time Exceeded も Parameter Problem も送りません。
#[test]
fn no_icmp_error_is_sent_to_invalid_sources() {
    for src in INVALID_SOURCES {
        let mut n = TestNet::new(small_limits());
        n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
        // 閉じた port への UDP。
        n.write(&build_udp(SocketAddrV4::new(src, 5000), 9, b"x"));
        assert!(n.drain_raw().is_empty(), "{src}: Port Unreachable");
        // 最初の断片だけが届き、再組み立ての期限が切れます。
        let frags = split_ipv4(
            &build_udp(SocketAddrV4::new(src, 5000), 53, &[0; 3000]),
            1000,
            78,
        );
        n.write(&frags[0]);
        n.advance(Duration::from_secs(31));
        assert!(n.drain_raw().is_empty(), "{src}: Time Exceeded");
        // 最初の断片の option が不正です。
        n.write(&with_source(
            frag_with_options(0, true, &[0x82, 1, 0, 0], b"abcdefgh"),
            src,
        ));
        assert!(n.drain_raw().is_empty(), "{src}: Parameter Problem");
    }
    // 対照: 正しい送信元には Port Unreachable が返ります。
    let mut n = TestNet::new(small_limits());
    n.write(&build_udp(PEER_UDP, 9, b"x"));
    assert_eq!(n.drain_raw().len(), 1);
}

/// MTU を超える echo reply が要る echo request (断片で届いて組み立てた) に、応答を捨てずに返します (RFC 1122
/// 3.2.2.6: echo request の data は応答に全部含める。意図した断片化を実装しないなら、MTU に切って送る)。
/// 要るのは、応答が出ること、MTU に収まること、data が request の data の先頭から続くことです。断片に分けて
/// 全部を返す実装も許します。
#[test]
fn oversized_echo_request_gets_a_fragmented_reply() {
    let mut n = TestNet::new(small_limits());
    let mut msg = vec![0u8; TEST_MTU];
    msg[0] = ECHO;
    msg[4..8].copy_from_slice(&[0x12, 0x34, 0, 9]);
    for (i, b) in msg[8..].iter_mut().enumerate() {
        *b = i as u8;
    }
    for f in split_ipv4(&build_icmp(PEER, &msg), 1000, 5) {
        n.write(&f);
    }
    let pkts = n.drain_raw();
    assert!(!pkts.is_empty(), "no echo reply: {:?}", n.s.stats());
    let mut parts: Vec<(usize, Vec<u8>, bool)> = Vec::new();
    for p in &pkts {
        let ip = parse_ipv4(p).unwrap();
        assert!(
            ip.proto == PROTO_ICMP && ip.src == DUT.to_bits() && ip.dst == PEER.to_bits(),
            "unexpected packet {p:x?}"
        );
        let flags = u16::from_be_bytes([p[6], p[7]]);
        parts.push((
            usize::from(flags & 0x1fff) * 8,
            ip.payload().to_vec(),
            flags & 0x2000 != 0,
        ));
    }
    parts.sort_by_key(|x| x.0);
    let reply: Vec<u8> = parts.iter().flat_map(|x| x.1.clone()).collect();
    if pkts.len() == 1 {
        // 切り詰めた応答は、ちょうど MTU の大きさです。
        assert_eq!(pkts[0].len(), TEST_MTU, "truncated reply size");
        assert!(!parts[0].2);
    } else {
        assert!(!parts.last().unwrap().2 && parts[..parts.len() - 1].iter().all(|x| x.2));
        assert_eq!(
            reply.len(),
            msg.len(),
            "fragmented reply must carry all data"
        );
    }
    assert_eq!(reply[0], ECHO_REPLY);
    assert_eq!(reply[1], 0);
    assert_eq!(reply[4..8], msg[4..8], "identifier and sequence");
    assert_eq!(reply[8..], msg[8..reply.len()], "echoed data");
    assert_eq!(!wire::checksum(0, &reply), 0, "ICMP checksum");
}

// 制御の輪 (256 枠、FIFO) の受け入れの規則: echo の応答は同時に 64 枠までです。応答は断片がすべて収まるときだけ
// 積み、収まらなければ応答ごと捨てます (一部だけ積みません)。捨てた数は TCP の制御 (RST と cookie の SYN-ACK)、
// ICMP の誤り、echo に分けて数え、`ctl_dropped` は合計です。

const ECHO_CAP: usize = 64;

/// `Stats` の欄を Debug の表現から読みます。欄が無ければ失敗します (欄の追加より前の核でも試験が組めます)。
fn stat(s: &crate::Stats, name: &str) -> u64 {
    let d = format!("{s:?}");
    let key = format!(" {name}: ");
    let at = d
        .find(&key)
        .unwrap_or_else(|| panic!("Stats has no field {name}"));
    d[at + key.len()..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap()
}

/// 長さ `len` の ICMP の message を持つ echo request を、1400 byte の断片 (ID は `ip_id`) で核に渡します。
fn send_big_echo(n: &mut TestNet, ip_id: u16, len: usize) {
    let mut msg = vec![0xa5u8; len];
    msg[0] = ECHO;
    msg[1] = 0;
    msg[4..8].copy_from_slice(&[0x12, 0x34, 0, 1]);
    for f in split_ipv4(&build_icmp(PEER, &msg), 1400, ip_id) {
        n.s.handle_packet(n.now, &f);
    }
}

fn is_echo_fragment(p: &[u8]) -> bool {
    let flags = u16::from_be_bytes([p[6], p[7]]);
    p[9] == PROTO_ICMP && (flags & 0x3fff != 0 || p[20] == ECHO_REPLY)
}

/// 出た echo の応答の断片を、応答 (IP の ID) ごとに `(offset, 中身の長さ, MF)` の列にします。
fn echo_replies(pkts: &[Vec<u8>]) -> std::collections::BTreeMap<u16, Vec<(usize, usize, bool)>> {
    let mut m = std::collections::BTreeMap::<u16, Vec<_>>::new();
    for p in pkts.iter().filter(|p| is_echo_fragment(p)) {
        let flags = u16::from_be_bytes([p[6], p[7]]);
        m.entry(ip_id(p)).or_default().push((
            usize::from(flags & 0x1fff) * 8,
            p.len() - IP_HEADER_LEN,
            flags & 0x2000 != 0,
        ));
    }
    for v in m.values_mut() {
        v.sort_unstable();
    }
    m
}

/// 応答の断片が先頭から隙間なく続き、最後だけ MF が無く、中身が `len` byte であることを確かめます。
fn assert_whole_reply(id: u16, frags: &[(usize, usize, bool)], len: usize) {
    let mut at = 0;
    for (i, &(off, l, more)) in frags.iter().enumerate() {
        assert_eq!(off, at, "reply {id}: a gap before fragment {i}");
        assert_eq!(more, i + 1 < frags.len(), "reply {id}: MF of fragment {i}");
        at += l;
    }
    assert_eq!(at, len, "reply {id} is partial: {frags:?}");
}

fn is_rst(p: &[u8]) -> bool {
    p[9] == wire::PROTO_TCP && p[33] & 0x04 != 0
}

fn is_icmp_error(p: &[u8]) -> bool {
    p[9] == PROTO_ICMP && (u16::from_be_bytes([p[6], p[7]]) << 2) == 0 && p[20] == DST_UNREACH
}

fn closed_port_syn(n: &mut TestNet, sport: u16) {
    let seg = TSeg {
        sport,
        dport: 81,
        seq: 1000,
        flags: FLAG_SYN,
        wnd: 65535,
        mss: 1360,
        ..TSeg::default()
    };
    n.s.handle_packet(n.now, &build_peer(&seg));
}

/// 同じ drain の間に大きな echo request を多数送っても、echo の断片は 64 枠までで、出た応答はどれも断片が揃います。
#[test]
fn echo_replies_hold_at_most_64_ring_slots_and_none_is_partial() {
    let mut n = TestNet::new(crate::config::Limits::default());
    for i in 0..100u16 {
        send_big_echo(&mut n, 100 + i, 3000);
    }
    let pkts = n.drain_raw();
    let echo = pkts.iter().filter(|p| is_echo_fragment(p)).count();
    assert!(
        (1..=ECHO_CAP).contains(&echo),
        "{echo} echo fragments in one drain"
    );
    let replies = echo_replies(&pkts);
    assert!(!replies.is_empty());
    for (id, frags) in &replies {
        assert_whole_reply(*id, frags, 3000);
    }
}

/// echo だけの洪水の中でも、同じ drain の間の RST と ICMP の誤り (合わせて 192 未満) はすべて出ます。
/// RST や ICMP の誤りが落ちないとは主張しません。この規模では落ちないことだけを確かめます。
#[test]
fn echo_flood_leaves_room_for_rst_and_icmp_errors() {
    let mut n = TestNet::new(crate::config::Limits::default());
    for i in 0..200u16 {
        send_big_echo(&mut n, 100 + i, 3000);
    }
    for i in 0..100u16 {
        closed_port_syn(&mut n, 40000 + i);
    }
    for i in 0..80u16 {
        n.s.handle_packet(
            n.now,
            &build_udp(SocketAddrV4::new(PEER, 6000 + i), 9, b"x"),
        );
    }
    let pkts = n.drain_raw();
    assert_eq!(pkts.iter().filter(|p| is_rst(p)).count(), 100, "RSTs");
    assert_eq!(
        pkts.iter().filter(|p| is_icmp_error(p)).count(),
        80,
        "ICMP errors"
    );
    for (id, frags) in &echo_replies(&pkts) {
        assert_whole_reply(*id, frags, 3000);
    }
}

/// 捨てた応答ごとに ctl_dropped_echo が 1 増え、ctl_dropped は 3 種類の合計です。
#[test]
fn echo_drops_are_counted_per_whole_reply() {
    let mut n = TestNet::new(crate::config::Limits::default());
    let requests = 100u64;
    for i in 0..requests as u16 {
        send_big_echo(&mut n, 100 + i, 3000);
    }
    let st = n.s.stats();
    let pkts = n.drain_raw();
    let sent = echo_replies(&pkts).len() as u64;
    assert!(sent > 0 && sent < requests);
    assert_eq!(stat(&st, "ctl_dropped_echo"), requests - sent);
    assert_eq!(stat(&st, "ctl_dropped_tcp"), 0);
    assert_eq!(stat(&st, "ctl_dropped_icmp_error"), 0);
    assert_eq!(stat(&st, "ctl_dropped"), requests - sent);
}

/// 輪が RST で満ちると、RST、ICMP の誤り、echo の捨てがそれぞれの欄に数えられ、合計は 3 つの和です。
#[test]
fn drops_are_counted_by_kind_and_sum_to_the_total() {
    let mut n = TestNet::new(crate::config::Limits::default());
    let (rsts, errors, echoes) = (300u64, 50u64, 5u64);
    for i in 0..rsts as u16 {
        closed_port_syn(&mut n, 40000 + i);
    }
    for i in 0..errors as u16 {
        n.s.handle_packet(
            n.now,
            &build_udp(SocketAddrV4::new(PEER, 6000 + i), 9, b"x"),
        );
    }
    for i in 0..echoes as u16 {
        n.write(&build_icmp(PEER, &[ECHO, 0, 0, 0, 0, 1, 0, i as u8]));
    }
    let st = n.s.stats();
    let pkts = n.drain_raw();
    let out_rst = pkts.iter().filter(|p| is_rst(p)).count() as u64;
    let out_err = pkts.iter().filter(|p| is_icmp_error(p)).count() as u64;
    let out_echo = echo_replies(&pkts).len() as u64;
    let (tcp, icmp, echo) = (
        stat(&st, "ctl_dropped_tcp"),
        stat(&st, "ctl_dropped_icmp_error"),
        stat(&st, "ctl_dropped_echo"),
    );
    assert_eq!(tcp, rsts - out_rst, "TCP control drops");
    assert_eq!(icmp, errors - out_err, "ICMP error drops");
    assert_eq!(echo, echoes - out_echo, "echo drops");
    assert!(tcp > 0 && icmp > 0 && echo > 0, "{tcp} {icmp} {echo}");
    assert_eq!(stat(&st, "ctl_dropped"), tcp + icmp + echo);
}

/// 64 枠を超える断片が要る応答は、輪が空でも応答ごと捨てます。そのあとの小さな echo には答えます。
#[test]
fn a_reply_needing_more_fragments_than_the_cap_is_dropped_whole() {
    let config = Config {
        limits: crate::config::Limits::default(),
        ..Config::new(DUT, 576)
    };
    let mut n = TestNet::with_config(config, [7; 64]);
    // 中身 65000 byte の応答は、MTU 576 では 552 byte ずつ 118 個の断片になります。
    send_big_echo(&mut n, 100, 65000);
    let st = n.s.stats();
    let pkts = n.drain_raw();
    assert_eq!(
        pkts.iter().filter(|p| is_echo_fragment(p)).count(),
        0,
        "a partial or whole oversize reply came out"
    );
    assert_eq!(stat(&st, "ctl_dropped_echo"), 1);
    assert_eq!(stat(&st, "ctl_dropped"), 1);
    n.write(&build_icmp(PEER, &[ECHO, 0, 0, 0, 0, 1, 0, 2, b'x']));
    assert_eq!(echo_replies(&n.drain_raw()).len(), 1);
}

/// DF を立てた断片も、ほかの断片と同じく再組み立てます (RFC 6864 4.3: DF=1 の断片は、途中の router が分けたものを
/// 再び分けないという意味で、正当な断片です)。
#[test]
fn fragments_with_df_set_are_reassembled() {
    let mut n = TestNet::new(small_limits());
    let pc = n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
    let msg: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
    let mut frags = split_ipv4(&build_udp(PEER_UDP, 53, &msg), 1000, 79);
    for f in &mut frags {
        f[6] |= 0x40;
        wire::set_ipv4_checksum(&mut f[..IP_HEADER_LEN]);
    }
    for f in frags.iter().rev() {
        n.write(f);
    }
    let mut b = vec![0u8; 4000];
    let (k, from) =
        n.s.recv_from(n.now, pc, &mut b)
            .unwrap_or_else(|e| panic!("{e:?}: {:?}", n.s.stats()));
    assert_eq!((&b[..k], from), (&msg[..], PEER_UDP));
    assert_eq!(n.s.held().frag_bytes, 0);
    assert!(n.drain_raw().is_empty(), "unexpected reply");
}

/// DF の立った断片と立たない断片が混ざっても組み上がります。
#[test]
fn mixed_df_fragments_are_reassembled() {
    let mut n = TestNet::new(small_limits());
    let pc = n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
    let msg: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
    let mut frags = split_ipv4(&build_udp(PEER_UDP, 53, &msg), 1000, 80);
    frags[1][6] |= 0x40;
    wire::set_ipv4_checksum(&mut frags[1][..IP_HEADER_LEN]);
    for f in &frags {
        n.write(f);
    }
    let mut b = vec![0u8; 4000];
    let (k, _) =
        n.s.recv_from(n.now, pc, &mut b)
            .unwrap_or_else(|e| panic!("{e:?}: {:?}", n.s.stats()));
    assert_eq!(&b[..k], &msg[..]);
}

// RFC 1122 3.3.2 と RFC 792: 最初の断片を受けた再組み立ての項目が期限切れになったら Time Exceeded (code 1) を
// 送ります。期限を過ぎて掃除を待つ項目を表の追い出しが外した場合も同じです。

/// 表が満ちて最も古い項目が追い出されるまで、別の datagram の最初の断片を送ります。追い出しの数を返します。
fn flood_until_eviction(n: &mut TestNet) -> u64 {
    let before = n.s.s.frag.evicted();
    for i in 0..(crate::frag::LIMITS.entries + 8) as u16 {
        let frags = split_ipv4(&build_udp(PEER_UDP, 53, &[0; 3000]), 1000, 6000 + i);
        n.s.handle_packet(n.now, &frags[0]);
        if n.s.s.frag.evicted() > before {
            return n.s.s.frag.evicted() - before;
        }
    }
    panic!("the table never evicted an entry");
}

fn assert_time_exceeded_for(pkts: &[Vec<u8>], first_fragment: &[u8]) {
    assert_eq!(pkts.len(), 1, "packets after the eviction: {pkts:x?}");
    let ip = parse_ipv4(&pkts[0]).unwrap();
    let m = ip.payload();
    assert!(
        ip.proto == PROTO_ICMP
            && ip.dst == PEER.to_bits()
            && m[0] == TIME_EXCEEDED
            && m[1] == 1
            && m[8..36] == first_fragment[..28],
        "Time Exceeded {:x?}",
        pkts[0]
    );
}

/// 期限を過ぎた項目が、掃除より先に表の追い出しで外れたとき、Time Exceeded を送ります。
#[test]
fn evicting_an_expired_entry_sends_time_exceeded() {
    let mut n = TestNet::new(small_limits());
    n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
    let frags = split_ipv4(&build_udp(PEER_UDP, 53, &[0; 3000]), 1000, 5000);
    n.write(&frags[0]);
    // 掃除 (handle_timeout) を呼ばずに、寿命の 30 秒を過ぎさせます。
    n.now = n.now + Duration::from_secs(31);
    assert_eq!(flood_until_eviction(&mut n), 1);
    assert_time_exceeded_for(&n.drain_raw(), &frags[0]);
}

/// 期限前の項目を追い出しても何も送りません (RFC の Time Exceeded は期限切れの知らせです)。
#[test]
fn evicting_a_live_entry_sends_nothing() {
    let mut n = TestNet::new(small_limits());
    n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
    let frags = split_ipv4(&build_udp(PEER_UDP, 53, &[0; 3000]), 1000, 5000);
    n.write(&frags[0]);
    n.now = n.now + Duration::from_secs(5);
    assert_eq!(flood_until_eviction(&mut n), 1);
    assert!(n.drain_raw().is_empty(), "ICMP for a live entry");
}

/// 最初の断片を受けていない項目は、期限が切れても追い出されても何も送りません (RFC 1122 3.3.2)。
#[test]
fn evicting_an_expired_entry_without_the_first_fragment_sends_nothing() {
    let mut n = TestNet::new(small_limits());
    n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
    let frags = split_ipv4(&build_udp(PEER_UDP, 53, &[0; 3000]), 1000, 5000);
    n.write(&frags[1]);
    n.now = n.now + Duration::from_secs(31);
    assert_eq!(flood_until_eviction(&mut n), 1);
    assert!(n.drain_raw().is_empty(), "ICMP without the first fragment");
}

/// 追い出しの Time Exceeded も、掃除と同じ速さの制限 (1 秒に 1000 個) に従います。
#[test]
fn eviction_time_exceeded_shares_the_icmp_rate_limit() {
    let mut n = TestNet::new(small_limits());
    n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
    let frags = split_ipv4(&build_udp(PEER_UDP, 53, &[0; 3000]), 1000, 5000);
    n.write(&frags[0]);
    n.now = n.now + Duration::from_secs(31);
    // 同じ秒の枠を使い切ります。
    let mut sent = 0;
    for i in 0..1000u16 {
        n.s.handle_packet(n.now, &build_udp(SocketAddrV4::new(PEER, i), 9, b"x"));
        sent += n.drain_raw().len();
    }
    assert_eq!(sent, 1000);
    let limited = n.s.stats().icmp_limited;
    assert_eq!(flood_until_eviction(&mut n), 1);
    assert!(n.drain_raw().is_empty(), "sent beyond the limit");
    assert_eq!(
        n.s.stats().icmp_limited,
        limited + 1,
        "the eviction's Time Exceeded did not go through the shared limiter"
    );
}

// RFC 1191 の Next-Hop MTU が 0 の Datagram Too Big と、PMTU の引き下げでの輻輳の窓の試験です。

/// 送信済みの先頭の segment を引用した Fragmentation Needed を作ります。`total_len` は引用した IP header の
/// Total Length に書き、`mtu` は Next-Hop MTU の欄に書きます。引用の番号は SND.UNA です。
fn frag_needed_quoting(pkts: &[Vec<u8>], total_len: u16, mtu: u16) -> Vec<u8> {
    let mut q = pkts[0][..IP_HEADER_LEN + 8].to_vec();
    q[2..4].copy_from_slice(&total_len.to_be_bytes());
    let mut m = vec![0u8; 8 + q.len()];
    m[0] = DST_UNREACH;
    m[1] = 4;
    m[6..8].copy_from_slice(&mtu.to_be_bytes());
    m[8..].copy_from_slice(&q);
    build_icmp(PEER, &m)
}

/// 1 つの接続に Fragmentation Needed を順に送り、そのたびの PMTU を返します。
fn pmtu_after(steps: &[(u16, u16)]) -> Vec<u32> {
    pmtu_after_with_mtu(TEST_MTU, steps)
}

/// `pmtu_after` と同じで、核の MTU を `mtu` にします。
fn pmtu_after_with_mtu(mtu: usize, steps: &[(u16, u16)]) -> Vec<u32> {
    let config = Config {
        limits: small_limits(),
        ..Config::new(DUT, mtu)
    };
    let mut n = TestNet::with_config(config, [7; 64]);
    let (c, _) = n.accepted(true);
    n.s.write(n.now, c, &[0; 3000]).unwrap();
    let pkts = n.drain_raw();
    steps
        .iter()
        .map(|&(total_len, nh)| {
            n.write(&frag_needed_quoting(&pkts, total_len, nh));
            n.s.conn(c.slot).t.pmtu
        })
        .collect()
}

/// RFC 1191 3 節:"Hosts MUST be able to deal with Datagram Too Big messages that do not include the next-hop
/// MTU" で、4 節と 7 節は引用した datagram の Total Length から plateau の表で見積もります。Total Length 未満の
/// 最大の plateau を PMTU にし、552 で止めます。Total Length が今の PMTU 以上なら、5 節の 4.2BSD の注に従い
/// 引用の header の長さの 4 倍を先に引きます (PMTU 1420 の接続で 1420 は 1400 になり 1006)。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn frag_needed_with_next_hop_mtu_zero_estimates_from_the_plateau_table() {
    assert_eq!(pmtu_after(&[(1420, 0)]), [1006]);
    assert_eq!(pmtu_after(&[(1300, 0)]), [1006]);
    assert_eq!(pmtu_after(&[(1200, 0)]), [1006]);
    assert_eq!(pmtu_after(&[(600, 0)]), [552]);
    // 1006 の後の 1006 の引用は 508 の plateau を 552 に引き上げた値へ、552 の後は下げません。
    assert_eq!(
        pmtu_after(&[(1420, 0), (1006, 0), (1006, 0)]),
        [1006, 552, 552]
    );
}

/// 対照:Next-Hop MTU が 0 でなければ、その値を使います (今の動作です)。
#[test]
fn frag_needed_with_a_next_hop_mtu_uses_it() {
    assert_eq!(pmtu_after(&[(1420, 1000)]), [1000]);
    assert_eq!(pmtu_after(&[(600, 1200)]), [1200]);
    // 0 以外の 552 未満の値は今までどおり捨てます。
    assert_eq!(pmtu_after(&[(1420, 300)]), [TEST_MTU as u32]);
}

/// 対照:Next-Hop MTU が 0 で、引用の Total Length が下限以下なら、PMTU を上げず接続も壊しません。
/// すでに 552 の接続では 552 のままで、データは引き続き送れます。
#[test]
fn frag_needed_with_next_hop_mtu_zero_at_the_floor_changes_nothing() {
    let mut n = TestNet::new(small_limits());
    let (c, _) = n.accepted(true);
    n.s.write(n.now, c, &[0; 3000]).unwrap();
    let pkts = n.drain_raw();
    n.write(&frag_needed_quoting(&pkts, 1420, 552));
    assert_eq!(n.s.conn(c.slot).t.pmtu, 552);
    for total_len in [552, 508, 400, 68] {
        n.write(&frag_needed_quoting(&pkts, total_len, 0));
        assert_eq!(n.s.conn(c.slot).t.pmtu, 552, "total length {total_len}");
    }
    n.s.write(n.now, c, &[0; 100]).unwrap();
    assert!(!n.drain_raw().is_empty(), "the connection stopped sending");
}

/// 新しい PMTU を報告する接続を作り、報告の前後の `(seg_mss, cwnd)` を返します。`peer_mss` が `Some` なら
/// 報告の前に相手の MSS をその値にします。
fn cwnd_across_pmtu_report(
    peer_mss: Option<u32>,
    mtu: u16,
    sack: bool,
) -> ((u32, u32), (u32, u32)) {
    let mut n = TestNet::new(small_limits());
    let (c, _) = n.accepted_sack(true, sack);
    if let Some(m) = peer_mss {
        n.s.conn(c.slot).t.peer_mss = m;
    }
    n.s.write(n.now, c, &vec![0; 30_000]).unwrap();
    let pkts = n.drain_raw();
    let before = {
        let cs = n.s.conn(c.slot);
        (cs.seg_mss(), cs.t.cwnd)
    };
    n.write(&frag_needed_quoting(&pkts, TEST_MTU as u16, mtu));
    let cs = n.s.conn(c.slot);
    (before, (cs.seg_mss(), cs.t.cwnd))
}

/// RFC 5681 3.1:"When initial congestion windows of more than one segment are implemented along with Path MTU
/// Discovery [RFC1191], and the MSS being used is found to be too large, the congestion window cwnd SHOULD be
/// reduced to prevent large bursts of smaller segments. Specifically, cwnd SHOULD be reduced by the ratio of the
/// old segment size to the new segment size." 初期窓は 10 segment なので、PMTU の引き下げの後の窓は同じ 10
/// segment を新しい大きさで数えた byte になります。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn pmtu_decrease_shrinks_cwnd_by_the_segment_size_ratio() {
    for sack in [false, true] {
        let ((old_mss, old_cwnd), (new_mss, new_cwnd)) = cwnd_across_pmtu_report(None, 1000, sack);
        assert!(new_mss < old_mss, "sack {sack}: the MSS did not shrink");
        assert_eq!(
            old_cwnd,
            10 * old_mss,
            "sack {sack}: unexpected initial window"
        );
        assert_eq!(
            new_cwnd,
            10 * new_mss,
            "sack {sack}: cwnd {old_cwnd} -> {new_cwnd}"
        );
    }
}

/// 対照:MSS が小さくならない PMTU の報告は輻輳の窓を変えません。PMTU が今以上の報告と、PMTU は下がるが
/// 相手の MSS が下限になっていて送る MSS が変わらない報告です。
#[test]
fn pmtu_report_that_keeps_the_mss_leaves_cwnd_alone() {
    for sack in [false, true] {
        let (before, after) = cwnd_across_pmtu_report(None, 1500, sack);
        assert_eq!(before, after, "sack {sack}: PMTU not below the current one");
        let (before, after) = cwnd_across_pmtu_report(Some(900), 1200, sack);
        assert_eq!(before, after, "sack {sack}: peer MSS still the limit");
    }
}

/// RFC 1191 5 節の 4.2BSD の注と 7 節の表の境目です。Total Length が今の PMTU 以上のときだけ header の長さの
/// 4 倍 (20 byte) を引き、Total Length 未満の最大の plateau を取ります (等しい plateau は取りません)。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn next_hop_mtu_zero_boundaries() {
    // PMTU 1420 を超える Total Length は引いてから表を引きます (1500 - 20 = 1480 なら 1492 は大きすぎます)。
    assert_eq!(pmtu_after(&[(1500, 0)]), [1006]);
    // 今の PMTU に等しい Total Length も引きます。1020 - 20 = 1000 なら 508 で、下限で止めます。
    assert_eq!(pmtu_after(&[(1420, 1020), (1020, 0)]), [1020, 552]);
    // 今の PMTU 未満なら引かず、Total Length 未満の plateau を取ります。
    assert_eq!(pmtu_after(&[(1010, 0)]), [1006]);
    // plateau に等しい Total Length は、その plateau ではなく一つ下を取ります。
    assert_eq!(pmtu_after(&[(1006, 0)]), [552]);
    assert_eq!(pmtu_after(&[(1420, 1080), (1080, 0)]), [1080, 1006]);
    // 見積もりが今の PMTU 以上なら PMTU を上げません。
    assert_eq!(pmtu_after(&[(65535, 0)]), [TEST_MTU as u32]);
}

/// RFC 1191 7 節の表の plateau の直上の Total Length から、その plateau を見積もります。PMTU の上限は核の
/// MTU で、設定の上限は 9216 です。表の 65535、32000、17914 は公開の API では届かないので、この試験の対象外です
/// (核に試験専用の口を足していません)。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn next_hop_mtu_zero_reaches_every_plateau() {
    const PLATEAUS: [u16; 7] = [8166, 4352, 2002, 1492, 1006, 508, 296];
    // 核の MTU は上限の 9216 とし、どの段にも今の PMTU 未満の Total Length で入ります。
    for w in PLATEAUS.windows(2) {
        let (upper, below) = (w[0], w[1]);
        assert_eq!(
            pmtu_after_with_mtu(9216, &[(upper, 0)]),
            [u32::from(below).max(552)],
            "total length {upper}"
        );
        assert_eq!(
            pmtu_after_with_mtu(9216, &[(upper + 1, 0)]),
            [u32::from(upper).max(552)],
            "total length {}",
            upper + 1
        );
    }
    // 上限の MTU に等しい Total Length は 20 を引いて 9196 とし、8166 を取ります。
    assert_eq!(pmtu_after_with_mtu(9216, &[(9216, 0)]), [8166]);
}

/// 窓を `window(旧 MSS)` の `(cwnd, ssthresh)` にして、1420 から 1000 への PMTU の引き下げの前後の
/// `(seg_mss, cwnd, ssthresh)` を返します。
fn drop_with_window(
    sack: bool,
    window: impl Fn(u32) -> (u32, u32),
) -> ((u32, u32, u32), (u32, u32, u32)) {
    let mut n = TestNet::new(small_limits());
    let (c, _) = n.accepted_sack(true, sack);
    n.s.write(n.now, c, &vec![0; 30_000]).unwrap();
    let pkts = n.drain_raw();
    let old_mss = n.s.conn(c.slot).seg_mss();
    let (cwnd, ssthresh) = window(old_mss);
    {
        let cs = n.s.conn(c.slot);
        cs.t.cwnd = cwnd;
        cs.t.ssthresh = ssthresh;
    }
    let snap = |n: &mut TestNet| {
        let cs = n.s.conn(c.slot);
        (cs.seg_mss(), cs.t.cwnd, cs.t.ssthresh)
    };
    let before = snap(&mut n);
    n.write(&frag_needed_quoting(&pkts, TEST_MTU as u16, 1000));
    (before, snap(&mut n))
}

/// RFC 5681 3.1 の比 (旧 segment size 対 新 segment size) で窓を縮めます。初期窓以外の窓でも切り捨ての比で、
/// ssthresh は RFC が求めないので変えません。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn pmtu_decrease_scales_a_non_initial_cwnd_and_leaves_ssthresh() {
    for sack in [false, true] {
        let (before, after) = drop_with_window(sack, |_| (20_001, 15_000));
        assert!(after.0 < before.0);
        let want = (20_001u64 * u64::from(after.0) / u64::from(before.0)) as u32;
        assert_eq!(after.1, want, "sack {sack}: {before:?} -> {after:?}");
        assert_eq!(after.2, 15_000, "sack {sack}: ssthresh changed");
    }
}

/// 比で縮めた窓が 1 segment に満たないときは、新しい segment size 1 つ分にします (窓の下限)。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn pmtu_decrease_keeps_one_segment_of_cwnd() {
    for sack in [false, true] {
        let (before, after) = drop_with_window(sack, |old| (old - 1, 4 * old));
        assert!(after.0 < before.0);
        assert_eq!(after.1, after.0, "sack {sack}: {before:?} -> {after:?}");
        assert_eq!(after.2, 4 * before.0, "sack {sack}: ssthresh changed");
    }
}

/// 窓が大きくても (4 MB 超) 比の計算が 32 bit であふれません。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn pmtu_decrease_scales_a_huge_cwnd_without_overflow() {
    for sack in [false, true] {
        let (before, after) = drop_with_window(sack, |_| (5_000_000, 6_000_000));
        let want = (5_000_000u64 * u64::from(after.0) / u64::from(before.0)) as u32;
        assert_eq!(after.1, want, "sack {sack}: {before:?} -> {after:?}");
        assert_eq!(after.2, 6_000_000, "sack {sack}: ssthresh changed");
    }
}

/// 引き下げの直後に出る送り直しの塊を返します。`(旧 MSS, 新 MSS, payload の長さの列)` です。
fn burst_after_drop(sack: bool) -> (u32, u32, Vec<usize>) {
    let mut n = TestNet::new(small_limits());
    let (c, _) = n.accepted_sack(true, sack);
    n.s.write(n.now, c, &vec![0; 30_000]).unwrap();
    let pkts = n.drain_raw();
    let old_mss = n.s.conn(c.slot).seg_mss();
    n.write(&frag_needed_quoting(&pkts, TEST_MTU as u16, 1000));
    let new_mss = n.s.conn(c.slot).seg_mss();
    let lens = n
        .drain()
        .iter()
        .map(|o| o.payload.len())
        .filter(|&l| l > 0)
        .collect();
    (old_mss, new_mss, lens)
}

/// 引き下げの直後に出る塊は、10 x 新 MSS byte (初期窓の 10 segment) を超えません。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn burst_after_pmtu_decrease_fits_ten_new_segments() {
    for sack in [false, true] {
        let (old_mss, new_mss, lens) = burst_after_drop(sack);
        let total: usize = lens.iter().sum();
        assert!(new_mss < old_mss);
        assert!(
            total <= 10 * new_mss as usize,
            "sack {sack}: {} segments, {total} bytes, limit {}",
            lens.len(),
            10 * new_mss
        );
    }
}

/// 対照:引き下げの後に出る segment は、どれも新しい MSS 以下です。
#[test]
fn segments_after_pmtu_decrease_fit_the_new_mss() {
    for sack in [false, true] {
        let (_, new_mss, lens) = burst_after_drop(sack);
        assert!(!lens.is_empty(), "sack {sack}: nothing was resent");
        assert!(
            lens.iter().all(|&l| l <= new_mss as usize),
            "sack {sack}: {lens:?} against {new_mss}"
        );
    }
}
