//! echo と ping、ICMP の誤りと PMTU の引き下げ、断片の入口の白箱の試験 (Go の `udp_test.go` の ICMP の部分、
//! `frag_test.go`、`fragidle_test.go`、`sack_test.go` と `observe_test.go` の PMTU の試験)。

#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "tests collect packets"
)]
#![expect(clippy::cast_possible_truncation, reason = "small test sizes")]

use crate::icmp::{DST_UNREACH, ECHO, ECHO_REPLY, PARAM_PROBLEM, PING_ENDPOINTS, TIME_EXCEEDED};
use crate::sack_tests::{TEST_SEG_PAYLOAD, sack_conn};
use crate::sackpeer_tests::check_scoreboard;
use crate::stack::Event;
use crate::tcp::RTX_PMTU;
use crate::testnet_tests::{
    DUT, PEER, TEST_MTU, TestNet, build_icmp, build_udp, small_limits, split_ipv4,
};
use crate::wire::{self, IP_HEADER_LEN, PROTO_ICMP, PROTO_UDP, parse_ipv4};
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
    // 壊れた echo と、MTU を超える echo は捨てます。
    let mut bad = build_icmp(PEER, &req);
    let last = bad.len() - 1;
    bad[last] ^= 1;
    n.write(&bad);
    let mut big = vec![0u8; TEST_MTU];
    big[0] = ECHO;
    for f in split_ipv4(&build_icmp(PEER, &big), 1000, 5) {
        n.write(&f);
    }
    assert_eq!(n.drain_raw().len(), 0);
    assert_eq!(n.s.stats().icmp_dropped, 2);
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
    assert_eq!(h.ctl_queued, small_limits().ctl_slots);
    assert!(n.s.stats().ctl_dropped > 0);
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

/// 不正な option を持つ断片に、最初の断片でも後の断片でも Parameter Problem を返し、pointer は option の位置を
/// 指します (Go の `TestParamProblemForFragmentOptions`)。
#[test]
fn param_problem_for_fragment_options() {
    for (offset, more) in [(0, true), (8, false)] {
        let mut n = TestNet::new(small_limits());
        n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
        n.write(&frag_with_options(
            offset,
            more,
            &[0x82, 1, 0, 0],
            b"abcdefgh",
        ));
        let pkts = n.drain_raw();
        assert_eq!(pkts.len(), 1, "offset {offset}: {:?}", n.s.stats());
        let ip = parse_ipv4(&pkts[0]).unwrap();
        let m = ip.payload();
        assert!(
            ip.proto == PROTO_ICMP && m[0] == PARAM_PROBLEM && m[4] == 20,
            "offset {offset}: {:x?}",
            pkts[0]
        );
    }
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

/// PMTU の引き下げで、新しい大きさに入る記録は送り直しません (入る記録は届いているかもしれません。Linux の
/// tcp_simple_retransmit と同じです。Go の `TestPMTUDropKeepsRecordsThatFit`)。
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
