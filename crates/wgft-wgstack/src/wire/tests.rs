//! Go の `parts_test.go` と `checksum_test.go` の白箱の試験の写しと、`parse` の fuzz の corpus の回帰の試験です。

#![expect(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "tests may hold growing collections"
)]
#![expect(
    clippy::cast_possible_truncation,
    clippy::many_single_char_names,
    reason = "tests cut random words into bytes and lengths"
)]

use super::*;
use crate::rng::ChaCha8;

const DUT: u32 = 0x0a09_0001;
const PEER: u32 = 0x0a09_0002;

/// 2 byte ずつ足す定義どおりの和 (RFC 1071)。
fn ref_checksum(sum: u32, b: &[u8]) -> u16 {
    let mut s = u64::from(sum);
    for p in b.chunks(2) {
        s += u64::from(p[0]) << 8 | u64::from(*p.get(1).unwrap_or(&0));
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    s as u16
}

/// Go の試験の `tseg` と `buildPeer` に当たる、相手が送る segment の組み立てです。
#[derive(Default)]
struct Seg<'a> {
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    wnd: u16,
    mss: u16,
    ws: Option<u8>,
    sack_ok: bool,
    ts: Option<(u32, u32)>,
    sack: &'a [SackBlock],
    payload: &'a [u8],
}

fn build_peer(s: &Seg<'_>) -> Vec<u8> {
    let mut o = OptWriter::default();
    if s.mss != 0 {
        o.mss(s.mss);
    }
    if s.sack_ok {
        o.sack_perm();
    }
    if let Some((v, e)) = s.ts {
        o.ts(v, e);
    }
    if let Some(ws) = s.ws
        && s.flags & FLAG_SYN != 0
    {
        o.wscale(ws);
    }
    if !s.sack.is_empty() {
        o.sack(s.sack);
    }
    let mut b = vec![0u8; IP_HEADER_LEN + TCP_HEADER_LEN + MAX_OPTION_LEN + s.payload.len()];
    let h = TcpHeader {
        tup: Tuple {
            laddr: PEER,
            raddr: DUT,
            lport: s.sport,
            rport: s.dport,
        },
        seq: s.seq,
        ack: s.ack,
        flags: s.flags,
        wnd: s.wnd,
    };
    let off = write_tcp(&mut b, 1, &h, Some(&mut o), s.payload.len());
    b[off..off + s.payload.len()].copy_from_slice(s.payload);
    let n = finish_tcp(&mut b);
    b.truncate(n);
    b
}

#[test]
fn tcp_round_trip() {
    let mut b = build_peer(&Seg {
        sport: 1234,
        dport: 80,
        seq: 1,
        ack: 2,
        flags: FLAG_SYN | FLAG_ACK,
        wnd: 999,
        mss: 1380,
        ws: Some(7),
        sack_ok: true,
        ts: Some((11, 12)),
        payload: b"abc",
        ..Seg::default()
    });
    let ip = parse_ipv4(&b).unwrap();
    let s = parse_tcp(&ip).unwrap();
    let o = s.opt;
    assert_eq!((s.seq, s.ack, s.wnd, s.payload), (1, 2, 999, &b"abc"[..]));
    assert_eq!(
        (o.mss, o.wscale, o.sack_ok, o.ts),
        (Some(1380), Some(7), true, Some((11, 12)))
    );
    assert_eq!(
        s.tup,
        Tuple {
            laddr: DUT,
            raddr: PEER,
            lport: 80,
            rport: 1234
        }
    );
    assert_eq!(s.seq_len(), 4);
    assert!(s.has(FLAG_SYN) && !s.has(FLAG_RST | FLAG_PSH | FLAG_URG | FLAG_FIN));
    assert_eq!(ip.header().len(), IP_HEADER_LEN);
    // checksum を壊すと捨てます。
    let last = b.len() - 1;
    b[last] ^= 1;
    let ip = parse_ipv4(&b).unwrap();
    assert_eq!(parse_tcp(&ip).err(), Some(PayloadDrop::BadChecksum));
    // Total Length より後ろは切り捨てます。
    let mut b = build_peer(&Seg {
        sport: 1,
        dport: 2,
        flags: FLAG_ACK,
        ..Seg::default()
    });
    b.extend_from_slice(&[1, 2, 3]);
    let ip = parse_ipv4(&b).unwrap();
    assert_eq!(ip.payload().len(), TCP_HEADER_LEN);
}

#[test]
fn parse_options_malformed() {
    let o = parse_options(&[1, 2, 5, 1, 2], true); // option の長さが残りより長い
    assert!(o.malformed && o.mss.is_none());
    let o = parse_options(&[2, 4, 2, 0x18, 3, 3, 20], true);
    assert_eq!((o.mss, o.wscale), (Some(536), Some(14)));
    let o = parse_options(&[2, 4, 2, 0x18], false); // SYN でなければ MSS を読みません
    assert!(o.mss.is_none());
    let o = parse_options(&[8, 10, 0, 0, 0, 1, 0, 0, 0, 2, 0, 99], false); // EOL の後は読みません
    assert_eq!(o.ts, Some((1, 2)));
    assert!(!o.malformed);
    let o = parse_options(&[5, 2 + 8 * 5], false); // 長さが残りより長い SACK
    assert!(o.malformed && o.nsack == 0);
    let mut five = [0u8; 2 + 8 * 5];
    five[0] = 5;
    five[1] = 2 + 8 * 5;
    let o = parse_options(&five, false); // 5 つ目の block は持ちません
    assert_eq!(o.nsack, 4);
    assert_eq!(o.sack_blocks().len(), 4);
}

#[test]
fn ipv4_rejects() {
    let good = build_peer(&Seg {
        sport: 1,
        dport: 2,
        flags: FLAG_ACK,
        ..Seg::default()
    });
    assert!(parse_ipv4(&good).is_ok());
    assert_eq!(parse_ipv4(&good[..19]).err(), Some(Ipv4Drop::Malformed));
    let mut b = good.clone();
    b[0] = 0x65; // 版が 6
    assert_eq!(parse_ipv4(&b).err(), Some(Ipv4Drop::Malformed));
    let mut b = good.clone();
    b[0] = 0x44; // IHL が 4
    assert_eq!(parse_ipv4(&b).err(), Some(Ipv4Drop::Malformed));
    let mut b = good.clone();
    b[3] += 1; // Total Length が長い
    assert_eq!(parse_ipv4(&b).err(), Some(Ipv4Drop::Malformed));
    let mut b = good.clone();
    b[8] ^= 1; // TTL を変えて checksum を壊す
    assert_eq!(parse_ipv4(&b).err(), Some(Ipv4Drop::BadChecksum));
    let mut b = good;
    set_frag_field(&mut b, 0x2000);
    assert!(parse_ipv4(&b).unwrap().fragment);
}

#[test]
fn checksum_matches_definition() {
    let mut r = ChaCha8::new([1; 32]);
    let mut buf = [0u8; 2048];
    let sums = [0, 1, 0xffff, 0x10000, 0x5fffa, 0xffff_ffff];
    for n in 0..=300 {
        for fill in 0..3 {
            for x in &mut buf[..n] {
                *x = match fill {
                    0 => r.next_u64() as u8,
                    1 => 0xff,
                    _ => 0,
                };
            }
            for s in sums {
                assert_eq!(
                    checksum(s, &buf[..n]),
                    ref_checksum(s, &buf[..n]),
                    "len {n} fill {fill} sum {s:#x}"
                );
            }
        }
    }
    for _ in 0..20000 {
        let n = r.below(buf.len() as u64 + 1) as usize;
        for x in &mut buf[..n] {
            *x = r.next_u64() as u8;
        }
        let s = r.next_u64() as u32;
        assert_eq!(
            checksum(s, &buf[..n]),
            ref_checksum(s, &buf[..n]),
            "len {n} sum {s:#x}"
        );
    }
}

fn build_udp(sport: u16, dport: u16, payload: &[u8], with_checksum: bool) -> Vec<u8> {
    let ulen = UDP_HEADER_LEN + payload.len();
    let mut b = vec![0u8; IP_HEADER_LEN + ulen];
    write_ipv4_header(&mut b, IP_HEADER_LEN + ulen, 9, PROTO_UDP, PEER, DUT);
    b[IP_HEADER_LEN + UDP_HEADER_LEN..].copy_from_slice(payload);
    write_udp_header(&mut b[IP_HEADER_LEN..], sport, dport, ulen, 0);
    if with_checksum {
        b[IP_HEADER_LEN + 6..IP_HEADER_LEN + 8].fill(0);
        let cs = !checksum(pseudo_sum(PEER, DUT, PROTO_UDP, ulen), &b[IP_HEADER_LEN..]);
        let cs = if cs == 0 { 0xffff } else { cs };
        b[IP_HEADER_LEN + 6..IP_HEADER_LEN + 8].copy_from_slice(&cs.to_be_bytes());
    } else {
        b[IP_HEADER_LEN + 6..IP_HEADER_LEN + 8].fill(0);
    }
    b
}

#[test]
fn udp_parse() {
    let b = build_udp(53, 5353, b"hello", true);
    let ip = parse_ipv4(&b).unwrap();
    let u = parse_udp(&ip).unwrap();
    assert_eq!((u.sport, u.dport, u.payload), (53, 5353, &b"hello"[..]));
    // checksum の欄が 0 なら確かめません。
    let mut b = build_udp(1, 2, b"x", false);
    b[IP_HEADER_LEN + UDP_HEADER_LEN] ^= 0xff;
    assert!(parse_udp(&parse_ipv4(&b).unwrap()).is_ok());
    // 壊れた checksum。
    let mut b = build_udp(1, 2, b"xy", true);
    b[IP_HEADER_LEN + UDP_HEADER_LEN] ^= 0xff;
    assert_eq!(
        parse_udp(&parse_ipv4(&b).unwrap()).err(),
        Some(PayloadDrop::BadChecksum)
    );
    // UDP の長さの欄より後ろは切り捨てます。欄が中身より長ければ捨てます。
    let mut b = build_udp(1, 2, b"abcd", false);
    b[IP_HEADER_LEN + 5] = 10;
    assert_eq!(parse_udp(&parse_ipv4(&b).unwrap()).unwrap().payload, b"ab");
    b[IP_HEADER_LEN + 5] = 13;
    assert_eq!(
        parse_udp(&parse_ipv4(&b).unwrap()).err(),
        Some(PayloadDrop::Malformed)
    );
    b[IP_HEADER_LEN + 5] = 7;
    assert_eq!(
        parse_udp(&parse_ipv4(&b).unwrap()).err(),
        Some(PayloadDrop::Malformed)
    );
}

#[test]
fn icmp_parse_and_finish() {
    let mut b = [0u8; IP_HEADER_LEN + 12];
    write_ipv4_header(&mut b, IP_HEADER_LEN + 12, 3, PROTO_ICMP, PEER, DUT);
    let m = &mut b[IP_HEADER_LEN..];
    m[0] = 8;
    m[4..8].copy_from_slice(&0x0001_0002u32.to_be_bytes());
    m[8..].copy_from_slice(b"ping");
    finish_icmp(m);
    let ip = parse_ipv4(&b).unwrap();
    let i = parse_icmp(&ip).unwrap();
    assert_eq!(
        (i.typ, i.code, i.rest, i.body),
        (8, 0, 0x0001_0002, &b"ping"[..])
    );
    b[IP_HEADER_LEN + 9] ^= 1;
    assert_eq!(
        parse_icmp(&parse_ipv4(&b).unwrap()).err(),
        Some(PayloadDrop::BadChecksum)
    );
    let mut short = [0u8; IP_HEADER_LEN + 7];
    write_ipv4_header(&mut short, IP_HEADER_LEN + 7, 3, PROTO_ICMP, PEER, DUT);
    assert_eq!(
        parse_icmp(&parse_ipv4(&short).unwrap()).err(),
        Some(PayloadDrop::Malformed)
    );
}

#[test]
fn udp_checksum_zero_is_sent_as_all_ones() {
    let mut h = [0u8; 8];
    write_udp_header(&mut h, 1, 2, 10, 0);
    assert_eq!(h[6..], [0xff, 0xff]);
    write_udp_header(&mut h, 1, 2, 10, 0x1234);
    assert_eq!(h[6..], [0x12, 0x34]);
}

#[test]
fn sack_writer_fits_what_room_allows() {
    let blocks = [SackBlock { left: 1, right: 2 }; 4];
    let mut o = OptWriter::default();
    assert_eq!(o.sack(&blocks), 4);
    assert_eq!(o.len(), 36);
    let mut o = OptWriter::default();
    o.ts(1, 2);
    assert_eq!(o.sack(&blocks), 3);
    let mut o = OptWriter::default();
    o.ts(1, 2);
    o.sack(&blocks);
    assert_eq!(o.sack(&blocks), 0, "a full writer takes no more blocks");
    o.pad();
    assert_eq!(o.len() % 4, 0);
}

/// `parse` の fuzz の target の corpus (Go の `FuzzParse` の種) と、見つけた落ちる入力を流します。
/// nightly の無い CI でも回帰を確かめるためです。
#[test]
fn fuzz_parse_corpus_and_regressions() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz");
    let mut n = 0;
    for dir in ["corpus/parse", "regressions/parse"] {
        let Ok(entries) = std::fs::read_dir(root.join(dir)) else {
            continue;
        };
        for e in entries {
            let path = e.unwrap().path();
            fuzz_parse(&std::fs::read(&path).unwrap());
            n += 1;
        }
    }
    assert!(n >= 2, "the parse corpus holds the Go FuzzParse seeds");
}

#[test]
fn fuzz_parse_random_inputs() {
    let mut r = ChaCha8::new([2; 32]);
    let seed = build_peer(&Seg {
        sport: 1,
        dport: 2,
        flags: FLAG_SYN,
        mss: 1380,
        ws: Some(7),
        sack_ok: true,
        ts: Some((0, 0)),
        ..Seg::default()
    });
    let mut buf = [0u8; 256];
    for i in 0..5000 {
        let n = r.below(buf.len() as u64) as usize;
        for x in &mut buf[..n] {
            *x = r.next_u64() as u8;
        }
        // 半分は正しい packet の一部の byte を壊したものにします。
        if i % 2 == 0 {
            let m = seed.len().min(n);
            buf[..m].copy_from_slice(&seed[..m]);
            let at = r.below(m.max(1) as u64) as usize;
            if at < m {
                buf[at] ^= r.next_u64() as u8;
            }
        }
        fuzz_parse(&buf[..n]);
    }
}
