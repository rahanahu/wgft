//! UDP の endpoint と予算の白箱の試験 (Go の `udp_test.go` と `checksum_test.go` の UDP の部分)。

#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "tests collect packets"
)]
#![expect(clippy::cast_possible_truncation, reason = "small test sizes")]

use super::*;
use crate::stack::Event;
use crate::testnet_tests::{DUT, PEER, TEST_MTU, TestNet, build_udp, small_limits};
use crate::wire::{PROTO_ICMP, parse_ipv4};

const PEER_UDP: SocketAddrV4 = SocketAddrV4::new(PEER, 5000);

fn bind(n: &mut TestNet, port: u16) -> UdpId {
    n.s.bind_udp(n.now, SocketAddrV4::new(DUT, port)).unwrap()
}

fn read(n: &mut TestNet, id: UdpId, size: usize) -> (Vec<u8>, SocketAddrV4) {
    let mut b = vec![0u8; size];
    let (k, from) = n.s.recv_from(n.now, id, &mut b).unwrap();
    n.s.check_invariants().unwrap();
    b.truncate(k);
    (b, from)
}

fn send(n: &mut TestNet, id: UdpId, data: &[u8], to: SocketAddrV4) -> Result<usize, Error> {
    let r = n.s.send_to(n.now, id, data, to);
    n.s.check_invariants().unwrap();
    r
}

/// 核が送った UDP の断片を組み立て、UDP の header と中身を返します。断片の欄と checksum を確かめます (Go の
/// `reassembleUDP`)。
fn reassemble(pkts: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut id = 0;
    for (i, p) in pkts.iter().enumerate() {
        let ip = parse_ipv4(p).unwrap();
        assert_eq!(ip.proto, PROTO_UDP, "packet {i}");
        let fl = u16::from_be_bytes([p[6], p[7]]);
        assert_eq!(fl & 0x4000, 0, "packet {i} has DF set");
        let pid = u16::from_be_bytes([p[4], p[5]]);
        assert!(pid != 0 && (i == 0 || pid == id), "packet {i} IP ID {pid}");
        id = pid;
        assert_eq!(
            usize::from(fl & 0x1fff) * 8,
            out.len(),
            "fragment {i} offset"
        );
        assert_eq!(fl & 0x2000 != 0, i < pkts.len() - 1, "fragment {i} MF");
        out.extend_from_slice(ip.payload());
    }
    let ip = parse_ipv4(&pkts[0]).unwrap();
    let sum = wire::pseudo_sum(ip.src, ip.dst, PROTO_UDP, out.len());
    assert_eq!(!wire::checksum(sum, &out), 0, "UDP checksum is wrong");
    out
}

#[test]
fn udp_round_trip() {
    let mut n = TestNet::new(small_limits());
    let pc = bind(&mut n, 53);
    n.write(&build_udp(PEER_UDP, 53, b"query"));
    assert_eq!(n.events(), [Event::UdpReadable(pc)]);
    let (got, from) = read(&mut n, pc, 100);
    assert_eq!((&got[..], from), (&b"query"[..], PEER_UDP));
    send(&mut n, pc, b"answer", from).unwrap();
    let pkts = n.drain_raw();
    assert_eq!(pkts.len(), 1);
    let u = reassemble(&pkts);
    assert_eq!(u16::from_be_bytes([u[0], u[1]]), 53);
    assert_eq!(u16::from_be_bytes([u[2], u[3]]), 5000);
    assert_eq!(&u[8..], b"answer");
    assert_eq!(
        n.s.recv_from(n.now, pc, &mut [0; 10]),
        Err(Error::WouldBlock)
    );
}

#[test]
fn udp_fragmented_send() {
    let mut n = TestNet::new(small_limits());
    let pc = bind(&mut n, 53);
    for size in [TEST_MTU - 28, TEST_MTU - 27, 5000, 20000, MAX_PAYLOAD] {
        let msg: Vec<u8> = (0..size).map(|i| (i * 13) as u8).collect();
        send(&mut n, pc, &msg, PEER_UDP).unwrap();
        let pkts = n.drain_raw();
        assert_eq!(pkts.len(), (size + 8).div_ceil((TEST_MTU - 20) & !7));
        let u = reassemble(&pkts);
        assert!(
            u[8..] == msg[..],
            "size {size}: the reassembled datagram differs"
        );
    }
    assert_eq!(
        send(&mut n, pc, &vec![0; MAX_PAYLOAD + 1], PEER_UDP),
        Err(Error::MessageTooLong)
    );
    assert_eq!(
        send(&mut n, pc, b"x", SocketAddrV4::new(PEER, 0)),
        Err(Error::InvalidAddress)
    );
    let h = n.s.held();
    assert_eq!((h.udp_tx_bytes, h.udp_tx_datagrams), (0, 0));
}

#[test]
fn udp_port_unreachable() {
    let mut n = TestNet::new(small_limits());
    let q = build_udp(PEER_UDP, 9999, b"x");
    n.write(&q);
    let pkts = n.drain_raw();
    assert_eq!(pkts.len(), 1);
    let ip = parse_ipv4(&pkts[0]).unwrap();
    let m = ip.payload();
    assert!(
        ip.proto == PROTO_ICMP && m[0] == 3 && m[1] == 3 && m[8..] == q[..],
        "Port Unreachable {:x?}",
        pkts[0]
    );
    // 閉じた endpoint のポートにも返します。
    let pc = bind(&mut n, 9999);
    n.s.close_udp(n.now, pc);
    n.write(&q);
    assert_eq!(n.drain_raw().len(), 1);
}

#[test]
fn udp_read_semantics() {
    let mut n = TestNet::new(small_limits());
    let pc = bind(&mut n, 53);
    // 短い読み取りは切り、残りを捨てます。
    n.write(&build_udp(PEER_UDP, 53, b"0123456789"));
    n.write(&build_udp(PEER_UDP, 53, b"next"));
    assert_eq!(read(&mut n, pc, 4).0, b"0123");
    assert_eq!(read(&mut n, pc, 100).0, b"next");
    assert_eq!(
        n.s.recv_from(n.now, pc, &mut [0; 10]),
        Err(Error::WouldBlock)
    );
    // 閉じた後の handle は閉じた誤りです。読まれていない datagram の予約は返ります。
    n.write(&build_udp(PEER_UDP, 53, b"left"));
    n.s.close_udp(n.now, pc);
    n.s.check_invariants().unwrap();
    assert_eq!(n.s.recv_from(n.now, pc, &mut [0; 10]), Err(Error::Closed));
    assert_eq!(send(&mut n, pc, b"x", PEER_UDP), Err(Error::Closed));
    assert_eq!(n.s.held().udp_rx_datagrams, 0);
    // ポートはその場で空き、新しい handle は前の handle と違います。
    let again = bind(&mut n, 53);
    assert_ne!(again, pc);
    assert_eq!(n.s.recv_from(n.now, pc, &mut [0; 10]), Err(Error::Closed));
    assert_eq!(
        n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)),
        Err(Error::AddrInUse)
    );
    assert_eq!(
        n.s.bind_udp(n.now, SocketAddrV4::new(PEER, 54)),
        Err(Error::AddrNotLocal)
    );
    assert_eq!(
        n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 0)),
        Err(Error::PortZero)
    );
    // 同じポートの TCP の待ち受けと UDP の endpoint は別です。
    n.listen(53);
}

#[test]
fn udp_checksum_handling() {
    let mut n = TestNet::new(small_limits());
    let pc = bind(&mut n, 53);
    let mut bad = build_udp(PEER_UDP, 53, b"bad");
    let last = bad.len() - 1;
    bad[last] ^= 1;
    n.write(&bad);
    let mut none = build_udp(PEER_UDP, 53, b"none");
    none[IP_HEADER_LEN + 6] = 0; // checksum 0 は確かめません
    none[IP_HEADER_LEN + 7] = 0;
    n.write(&none);
    assert_eq!(read(&mut n, pc, 100).0, b"none");
    assert_eq!(n.s.stats().bad_checksum, 1);
    // 長さの欄の壊れた datagram は UDP の捨てた数に入ります。
    let mut short = build_udp(PEER_UDP, 53, b"x");
    short[IP_HEADER_LEN + 4] = 0xff;
    n.write(&short);
    assert_eq!(n.s.stats().udp_dropped, 1);
}

/// 読まない endpoint への洪水でも、受信は予算と endpoint の上限の内側に留まり、閉じれば戻ります (Go の
/// `TestBoundUDPReceive`)。
#[test]
fn bound_udp_receive() {
    for size in [100, 1000, 9000, 60000] {
        let mut n = TestNet::new(small_limits());
        let pcs: Vec<UdpId> = (0..6).map(|p| bind(&mut n, 100 + p)).collect();
        for i in 0..3 * RX_DATAGRAMS {
            let pkt = build_udp(PEER_UDP, 100 + (i % 6) as u16, &vec![0; size]);
            // 毎回の不変条件の確かめは表を走査して遅いので、間を置いて確かめます。
            n.s.handle_packet(n.now, &pkt);
            if i % 997 == 0 {
                n.s.check_invariants().unwrap();
            }
        }
        n.s.check_invariants().unwrap();
        let h = n.s.held();
        assert!(
            h.udp_rx_bytes <= RX_BYTES && h.udp_rx_datagrams <= RX_DATAGRAMS,
            "size {size}: receive holds {h:?}"
        );
        let st = n.s.stats();
        assert!(st.udp_dropped > 0, "size {size}: no drops counted");
        assert_eq!(st.udp_dropped, st.udp_endpoint_full + st.udp_tunnel_full);
        let log = n.s.poll_log().expect("a gated log line");
        assert_eq!(log.kind, LogKind::UdpDropped);
        assert!(n.s.poll_log().is_none(), "one line a minute");
        for pc in pcs {
            n.s.close_udp(n.now, pc);
        }
        n.s.check_invariants().unwrap();
        let h = n.s.held();
        assert_eq!((h.udp_rx_bytes, h.udp_rx_datagrams), (0, 0), "size {size}");
    }
}

/// 5 つの endpoint のうち 4 つが上限まで大きな datagram を持つと、受信は予算をちょうど使い切り、5 つめは核の
/// 予算で断られます。最初に断るのが核の予算なので、ログの数は 2 つの数の和です。
#[test]
fn a_full_receive_budget_meets_its_term() {
    let mut n = TestNet::new(small_limits());
    let pcs: Vec<UdpId> = (0..5).map(|p| bind(&mut n, 100 + p)).collect();
    // endpoint 1 つの上限は 64 個の chunk で、60000 byte の datagram は 4 個を使うので 16 件です。
    for p in 0..4u16 {
        for _ in 0..16 {
            n.s.handle_packet(n.now, &build_udp(PEER_UDP, 100 + p, &vec![1; 60000]));
        }
    }
    assert_eq!(n.s.held().udp_rx_bytes, RX_BYTES);
    assert_eq!(n.s.stats().udp_dropped, 0);
    n.s.handle_packet(n.now, &build_udp(PEER_UDP, 104, &[1; 100]));
    let st = n.s.stats();
    assert_eq!((st.udp_endpoint_full, st.udp_tunnel_full), (0, 1));
    let log = n.s.poll_log().unwrap();
    assert_eq!((log.kind, log.count), (LogKind::UdpDropped, 1));
    // 上限に届いた endpoint は、核の予算を先に調べるので核の予算で断られます (Go と同じ順です)。
    n.s.handle_packet(n.now, &build_udp(PEER_UDP, 100, &[1; 100]));
    assert_eq!(n.s.stats().udp_tunnel_full, 2);
    n.s.check_invariants().unwrap();
    let b = n.s.bound();
    assert!(b.udp_rx >= RX_BYTES as u64);
    for pc in pcs {
        n.s.close_udp(n.now, pc);
    }
}

/// endpoint 1 つの chunk の上限は、ちょうど 64 個で断ります。
#[test]
fn endpoint_chunk_share_boundary() {
    let mut n = TestNet::new(small_limits());
    let pc = bind(&mut n, 53);
    let other = bind(&mut n, 54);
    // 16384 byte の datagram は区分の最後の枠で、chunk を 1 つずつ使います。
    for _ in 0..TX_BYTES / ENDPOINT_SHARE / CHUNK_SIZE {
        send(&mut n, pc, &[0; CHUNK_SIZE], PEER_UDP).unwrap();
    }
    assert_eq!(
        send(&mut n, pc, &[0; CHUNK_SIZE], PEER_UDP),
        Err(Error::WouldBlock)
    );
    send(&mut n, other, &[0; CHUNK_SIZE], PEER_UDP).unwrap();
    // 件数の上限ではなく chunk の上限で断っています。
    assert!(n.s.held().udp_tx_datagrams < TX_DATAGRAMS / ENDPOINT_SHARE);
}

/// 核の datagram の件数の予算は、ちょうど上限で断ります。
#[test]
fn tunnel_datagram_count_boundary() {
    let mut n = TestNet::new(crate::Limits {
        udp_rx_datagrams: 8,
        ..small_limits()
    });
    let pcs: Vec<UdpId> = (0..5).map(|p| bind(&mut n, 100 + p)).collect();
    for p in 0..4u16 {
        for _ in 0..2 {
            n.write(&build_udp(PEER_UDP, 100 + p, b"x"));
        }
    }
    assert_eq!(n.s.held().udp_rx_datagrams, 8);
    n.write(&build_udp(PEER_UDP, 104, b"x"));
    let st = n.s.stats();
    assert_eq!((st.udp_endpoint_full, st.udp_tunnel_full), (0, 1));
    assert_eq!(
        n.s.recv_from(n.now, pcs[4], &mut [0; 4]),
        Err(Error::WouldBlock)
    );
}

/// 送信で chunk を確保できなければ、待たずに `NoMemory` を返し、予約も待ちの list も残しません。確保の失敗は
/// 送信の予約が返るのを待っても解けないので、`WouldBlock` にすると `UdpWritable` が来ないまま待ち続けます。
#[test]
fn send_chunk_failure_returns_no_memory() {
    use crate::buf::chunk::fail_chunks_after;
    let mut n = TestNet::new(small_limits());
    let pc = bind(&mut n, 53);
    let free = n.s.s.udp.dg_free[TX].len();
    // 1 つめの chunk で失敗します。
    fail_chunks_after(Some(0));
    let r = n.s.send_to(n.now, pc, &[0; 100], PEER_UDP);
    fail_chunks_after(None);
    assert_eq!(r, Err(Error::NoMemory));
    // 2 つの chunk の datagram の 2 つめで失敗し、1 つめの chunk と datagram の番号を戻します。
    fail_chunks_after(Some(1));
    let r = n.s.send_to(n.now, pc, &vec![0; 20000], PEER_UDP);
    fail_chunks_after(None);
    assert_eq!(r, Err(Error::NoMemory));
    n.s.check_invariants().unwrap();
    assert_eq!(n.s.s.udp.dg_free[TX].len(), free);
    assert!(!n.s.s.udp.eps.by_port(53).unwrap().waiting);
    let h = n.s.held();
    assert_eq!((h.udp_tx_bytes, h.udp_tx_datagrams), (0, 0));
    assert_eq!(n.events(), []);
    send(&mut n, pc, &[0; 100], PEER_UDP).unwrap();
    // 受信の確保の失敗は核の予算で断ったことにします。
    fail_chunks_after(Some(0));
    n.s.handle_packet(n.now, &build_udp(PEER_UDP, 53, &[0; 3000]));
    fail_chunks_after(None);
    n.s.check_invariants().unwrap();
    assert_eq!(n.s.stats().udp_tunnel_full, 1);
    assert_eq!(n.s.held().udp_rx_datagrams, 0);
}

/// 同じポートの TCP の待ち受けと UDP の endpoint は知らせの対象を分け合い、片方の開閉は相手の知らせを消しません。
/// `bind_udp` は前の endpoint の UDP の印をすべて消します。
#[test]
fn shared_port_event_target() {
    let mut n = TestNet::new(small_limits());
    let pc = bind(&mut n, 53);
    n.write(&build_udp(PEER_UDP, 53, b"q"));
    let l = n.listen(53);
    n.s.close_listener(n.now, l);
    let l = n.listen(53);
    assert_eq!(n.events(), [Event::UdpReadable(pc)]);
    // 待ち受けの印は UDP の endpoint の開閉で消えません。
    n.handshake(40000, 53, false, false);
    n.s.close_udp(n.now, pc);
    let again = bind(&mut n, 53);
    assert_eq!(n.events(), [Event::Acceptable(l)]);
    // 前の endpoint の印が残っていても、開き直すと消えます。
    n.s.close_udp(n.now, again);
    let t = n.s.s.port_target(53);
    n.s.s.events.raise(t, crate::stack::shared::EV_UDP_WRITE);
    n.s.s.events.raise(t, EV_UDP_READ);
    bind(&mut n, 53);
    assert_eq!(n.events(), []);
}

/// 出力を読まない間、送信は endpoint の上限で `WouldBlock` になり、詰まりが解けると予約が返ります (Go の
/// `TestBoundUDPSendWaits`)。
#[test]
fn bound_udp_send_waits() {
    let mut n = TestNet::new(small_limits());
    let pc = bind(&mut n, 53);
    let mut sent = 0;
    while send(&mut n, pc, &[0; 1000], PEER_UDP).is_ok() {
        sent += 1;
    }
    assert_eq!(
        send(&mut n, pc, &[0; 1000], PEER_UDP),
        Err(Error::WouldBlock)
    );
    let h = n.s.held();
    assert_eq!(sent, TX_DATAGRAMS / ENDPOINT_SHARE);
    assert_eq!(h.udp_tx_datagrams, sent);
    assert_eq!(n.drain_raw().len(), sent);
    let h = n.s.held();
    assert_eq!((h.udp_tx_bytes, h.udp_tx_datagrams), (0, 0));
    assert!(n.events().contains(&Event::UdpWritable(pc)));
    send(&mut n, pc, b"x", PEER_UDP).unwrap();
}

/// 送信の予約の空きを待つ endpoint は、予約が返ると `UdpWritable` を 1 回受け、待っていない間は受けません (Go の
/// `TestUDPBlockedWriterWakes`)。
#[test]
fn udp_blocked_writer_wakes() {
    let mut n = TestNet::new(small_limits());
    let pc = bind(&mut n, 53);
    let other = bind(&mut n, 54);
    for _ in 0..TX_DATAGRAMS / ENDPOINT_SHARE {
        send(&mut n, pc, &[0; 10], PEER_UDP).unwrap();
    }
    assert_eq!(send(&mut n, pc, &[0; 10], PEER_UDP), Err(Error::WouldBlock));
    n.events();
    let mut buf = vec![0u8; TEST_MTU];
    assert!(n.s.poll_transmit(n.now, &mut buf).is_some());
    assert_eq!(n.events(), [Event::UdpWritable(pc)]);
    // 起こした後は待つ endpoint が無いので、次に予約が返っても知らせません。
    assert!(n.s.poll_transmit(n.now, &mut buf).is_some());
    assert_eq!(n.events(), []);
    send(&mut n, pc, &[0; 10], PEER_UDP).unwrap();
    send(&mut n, pc, &[0; 10], PEER_UDP).unwrap();
    assert_eq!(send(&mut n, pc, &[0; 10], PEER_UDP), Err(Error::WouldBlock));
    // 待っている endpoint を閉じると待ちの list から外れ、ほかの endpoint の待ちは残ります。
    for _ in 0..TX_DATAGRAMS / ENDPOINT_SHARE {
        send(&mut n, other, &[0; 10], PEER_UDP).unwrap();
    }
    assert_eq!(
        send(&mut n, other, &[0; 10], PEER_UDP),
        Err(Error::WouldBlock)
    );
    n.s.close_udp(n.now, pc);
    n.s.check_invariants().unwrap();
    n.events();
    assert!(n.s.poll_transmit(n.now, &mut buf).is_some());
    assert_eq!(n.events(), [Event::UdpWritable(other)]);
    // 閉じた endpoint の送り残しは送り終えるまで残り、核の予算だけを返します。
    n.drain_raw();
    let h = n.s.held();
    assert_eq!((h.udp_tx_bytes, h.udp_tx_datagrams), (0, 0));
}

/// 閉じた endpoint の送り残しは、同じポートを開き直した endpoint の上限に数えません。
#[test]
fn reopened_endpoint_has_its_own_share() {
    let mut n = TestNet::new(small_limits());
    let pc = bind(&mut n, 53);
    for _ in 0..TX_DATAGRAMS / ENDPOINT_SHARE {
        send(&mut n, pc, &[0; 10], PEER_UDP).unwrap();
    }
    n.s.close_udp(n.now, pc);
    let again = bind(&mut n, 53);
    for _ in 0..TX_DATAGRAMS / ENDPOINT_SHARE {
        send(&mut n, again, &[0; 10], PEER_UDP).unwrap();
    }
    assert_eq!(
        send(&mut n, again, &[0; 10], PEER_UDP),
        Err(Error::WouldBlock)
    );
    assert_eq!(n.drain_raw().len(), 2 * TX_DATAGRAMS / ENDPOINT_SHARE);
    let h = n.s.held();
    assert_eq!((h.udp_tx_bytes, h.udp_tx_datagrams), (0, 0));
    send(&mut n, again, b"x", PEER_UDP).unwrap();
}

/// 1 byte ずつ足す定義どおりの UDP の checksum です (Go の `refUDPChecksum`)。
fn ref_checksum(from: SocketAddrV4, to: SocketAddrV4, payload: &[u8]) -> u16 {
    let ulen = UDP_HEADER_LEN + payload.len();
    let mut d = Vec::new();
    d.extend_from_slice(&from.ip().octets());
    d.extend_from_slice(&to.ip().octets());
    d.extend_from_slice(&[0, PROTO_UDP]);
    d.extend_from_slice(&(ulen as u16).to_be_bytes());
    d.extend_from_slice(&from.port().to_be_bytes());
    d.extend_from_slice(&to.port().to_be_bytes());
    d.extend_from_slice(&(ulen as u16).to_be_bytes());
    d.extend_from_slice(&[0, 0]);
    d.extend_from_slice(payload);
    let mut s: u64 = 0;
    for (i, &b) in d.iter().enumerate() {
        s += if i % 2 == 0 {
            u64::from(b) << 8
        } else {
            u64::from(b)
        };
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    let cs = !(s as u16);
    if cs == 0 { 0xffff } else { cs }
}

/// 送る datagram の checksum を chunk ごとに求めても、1 byte ずつ足した値と一致します。区分の枠と chunk の列、
/// 奇数の長さ、chunk の境目、0 と 0xff の詰まった中身、乱数の中身と長さを流します (Go の
/// `TestUDPChecksumMatchesByteSum`)。
#[test]
fn udp_checksum_matches_byte_sum() {
    let mut n = TestNet::new(small_limits());
    let pc = bind(&mut n, 53);
    let mut r: u64 = 0x1234_5678;
    let mut next = move || {
        r ^= r << 13;
        r ^= r >> 7;
        r ^= r << 17;
        r
    };
    let mut lens = vec![
        0,
        1,
        2,
        3,
        7,
        8,
        255,
        256,
        257,
        1023,
        1024,
        1025,
        2047,
        2048,
        2049,
        4095,
        16383,
        16384,
        16385,
        32767,
        32769,
        49153,
        MAX_PAYLOAD,
    ];
    for _ in 0..100 {
        lens.push((next() % (MAX_PAYLOAD as u64 + 1)) as usize);
    }
    let from = SocketAddrV4::new(DUT, 53);
    let mut buf = vec![0u8; TEST_MTU];
    for l in lens {
        for fill in 0..3 {
            let b: Vec<u8> = (0..l)
                .map(|_| match fill {
                    0 => 0,
                    1 => 0xff,
                    _ => next() as u8,
                })
                .collect();
            let to = SocketAddrV4::new(PEER, 1 + (next() % 65535) as u16);
            n.s.send_to(n.now, pc, &b, to).unwrap();
            let u = &n.s.s.udp;
            let got = u.dg[TX][usize::from(u.tx_tail)].csum;
            assert_eq!(
                got,
                ref_checksum(from, to, &b),
                "checksum of a {l}-byte datagram, fill {fill}"
            );
            while n.s.poll_transmit(n.now, &mut buf).is_some() {}
        }
    }
    n.s.check_invariants().unwrap();
}

/// 和が 0xffff に畳まれる datagram の checksum の欄は 0 でなく 0xffff です (RFC 768、Go の
/// `TestUDPChecksumZeroIsSentAsAllOnes`)。
#[test]
fn udp_checksum_zero_is_sent_as_all_ones() {
    let mut n = TestNet::new(small_limits());
    let pc = bind(&mut n, 53);
    let from = SocketAddrV4::new(DUT, 53);
    let mut payload = [0u8; 2];
    let base = ref_checksum(from, PEER_UDP, &payload);
    // base は 2 byte の 0 の中身での補数なので、中身を base にすると和が 0xffff になります。
    payload.copy_from_slice(&base.to_be_bytes());
    assert_eq!(ref_checksum(from, PEER_UDP, &payload), 0xffff);
    send(&mut n, pc, &payload, PEER_UDP).unwrap();
    let pkts = n.drain_raw();
    assert_eq!(pkts[0].len(), IP_HEADER_LEN + UDP_HEADER_LEN + 2);
    assert_eq!(
        u16::from_be_bytes([pkts[0][IP_HEADER_LEN + 6], pkts[0][IP_HEADER_LEN + 7]]),
        0xffff
    );
}

/// 会計の不整合は最初の違反を保ち、核の UDP を止め、ログに 1 回だけ出します。
#[test]
fn accounting_fault_stops_udp() {
    let mut n = TestNet::new(small_limits());
    let pc = bind(&mut n, 53);
    n.write(&build_udp(PEER_UDP, 53, b"a"));
    // 枠の使っている数を壊してから読むと、枠を 2 回返したことになります。
    let u = &mut n.s.s.udp;
    let head = u.eps.by_port(53).unwrap().rx_head;
    let c = u.dg[RX][usize::from(head)].ck[0];
    u.ck[usize::from(c)].live = 0;
    let mut b = [0u8; 10];
    n.s.recv_from(n.now, pc, &mut b).unwrap();
    assert_eq!(n.s.udp_receive_fault(), Some(UdpFault::SlotReleasedTwice));
    let log = n.s.poll_log().unwrap();
    assert_eq!(log.kind, LogKind::UdpFault);
    assert!(n.s.poll_log().is_none());
    // 後の受信は捨て、送信と開き直しは誤りにします。
    let dropped = n.s.stats().udp_dropped;
    n.s.handle_packet(n.now, &build_udp(PEER_UDP, 53, b"b"));
    assert_eq!(n.s.stats().udp_dropped, dropped + 1);
    assert_eq!(
        n.s.send_to(n.now, pc, b"x", PEER_UDP),
        Err(Error::UdpStopped)
    );
    assert_eq!(
        n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 54)),
        Err(Error::UdpStopped)
    );
    assert_eq!(
        UdpFault::BudgetNegative {
            bytes: -16384,
            datagrams: 0
        }
        .to_string(),
        "UDP budget went negative: -16384 bytes 0 datagrams"
    );
}

/// 核を閉じると UDP の予約と chunk がすべて返ります。
#[test]
fn close_returns_udp_holdings() {
    let mut n = TestNet::new(small_limits());
    let pc = bind(&mut n, 53);
    for i in 0..10u16 {
        n.write(&build_udp(
            SocketAddrV4::new(PEER, 5000 + i),
            53,
            &vec![0; 30000],
        ));
        send(&mut n, pc, &[1; 3000], PEER_UDP).unwrap();
    }
    let h = n.s.held();
    assert!(h.udp_rx_datagrams == 10 && h.udp_tx_datagrams == 10);
    let TestNet { s, now, .. } = n;
    let closed = s.close(now);
    assert!(closed.held.is_zero(), "{:?}", closed.held);
}
