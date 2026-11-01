//! 凍結した Go の wgstack が書き出した値 (`testdata/go-golden.txt`) との bit の一致の試験です。
//! ファイルは `go test ./internal/wgstack -run TestRustGolden -update-rust-golden` が作ります。

#![expect(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "tests may hold growing collections"
)]

use crate::rng::{ChaCha8, Seeds};
use crate::siphash::SipKey;
use crate::wire::{
    OptWriter, SackBlock, TcpHeader, Tuple, clear_df, finish_tcp, set_frag_field,
    write_ipv4_header, write_tcp,
};

const GOLDEN: &str = include_str!("../testdata/go-golden.txt");

fn lines(kind: &str) -> Vec<Vec<&'static str>> {
    let v: Vec<Vec<&str>> = GOLDEN
        .lines()
        .map(|l| l.split_whitespace().collect::<Vec<_>>())
        .filter(|f| f.first() == Some(&kind))
        .map(|f| f[1..].to_vec())
        .collect();
    assert!(!v.is_empty(), "no {kind} lines in the golden file");
    v
}

fn h64(s: &str) -> u64 {
    u64::from_str_radix(s, 16).unwrap()
}

fn h32(s: &str) -> u32 {
    u32::from_str_radix(s, 16).unwrap()
}

fn dec<T: core::str::FromStr>(s: &str) -> T
where
    T::Err: core::fmt::Debug,
{
    s.parse().unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn siphash_matches_go() {
    for f in lines("siphash") {
        let k = SipKey {
            k0: h64(f[0]),
            k1: h64(f[1]),
        };
        assert_eq!(k.sum(h64(f[2]), h64(f[3])), h64(f[4]), "{f:?}");
    }
    for f in lines("tuplehash") {
        let k = SipKey {
            k0: h64(f[0]),
            k1: h64(f[1]),
        };
        let t = Tuple {
            laddr: h32(f[2]),
            raddr: h32(f[3]),
            lport: dec(f[4]),
            rport: dec(f[5]),
        };
        assert_eq!(k.hash_tuple(t), h64(f[6]), "{f:?}");
    }
}

#[test]
fn chacha8_matches_go() {
    for f in lines("chacha8") {
        let seed: [u8; 32] = unhex(f[0]).try_into().unwrap();
        let mut r = ChaCha8::new(seed);
        assert_eq!(f.len(), 301);
        for (i, want) in f[1..].iter().enumerate() {
            assert_eq!(r.next_u64(), h64(want), "seed {} value {i}", f[0]);
        }
    }
}

#[test]
fn seed_split_matches_go() {
    for f in lines("seeds") {
        let seed: [u8; 64] = unhex(f[0]).try_into().unwrap();
        let mut s = Seeds::new(&seed);
        assert_eq!(
            s.isn_key,
            SipKey {
                k0: h64(f[1]),
                k1: h64(f[2])
            }
        );
        assert_eq!(
            s.table_key,
            SipKey {
                k0: h64(f[3]),
                k1: h64(f[4])
            }
        );
        assert_eq!(
            s.ts_key,
            SipKey {
                k0: h64(f[5]),
                k1: h64(f[6])
            }
        );
        assert_eq!(s.ip_id, h32(f[7]));
        for pair in &f[8..] {
            let (n, want) = pair.split_once(':').unwrap();
            assert_eq!(
                s.rng.below(dec(n)),
                dec::<u64>(want),
                "seed {} draw {pair}",
                f[0]
            );
        }
    }
}

#[test]
fn tcp_build_matches_go() {
    for f in lines("tcpbuild") {
        let (mss, ws): (u16, i32) = (dec(f[8]), dec(f[9]));
        let (sack_ok, ts): (bool, bool) = (dec(f[10]), dec(f[11]));
        let flags: u8 = dec(f[6]);
        let mut sack = Vec::new();
        if f[14] != "-" {
            for b in f[14].split(',') {
                let (l, r) = b.split_once('-').unwrap();
                sack.push(SackBlock {
                    left: dec(l),
                    right: dec(r),
                });
            }
        }
        let payload = unhex(f[15]);
        // Go の buildPeer の option の順です。
        let mut o = OptWriter::default();
        if mss != 0 {
            o.mss(mss);
        }
        if sack_ok {
            o.sack_perm();
        }
        if ts {
            o.ts(dec(f[12]), dec(f[13]));
        }
        if ws >= 0 && flags & crate::wire::FLAG_SYN != 0 {
            o.wscale(u8::try_from(ws).unwrap());
        }
        if !sack.is_empty() {
            o.sack(&sack);
        }
        let h = TcpHeader {
            tup: Tuple {
                laddr: h32(f[0]),
                raddr: h32(f[1]),
                lport: dec(f[2]),
                rport: dec(f[3]),
            },
            seq: dec(f[4]),
            ack: dec(f[5]),
            flags,
            wnd: dec(f[7]),
        };
        let mut b = vec![0u8; 20 + 20 + 40 + payload.len()];
        let off = write_tcp(&mut b, 1, &h, Some(&mut o), payload.len());
        b[off..off + payload.len()].copy_from_slice(&payload);
        let n = finish_tcp(&mut b);
        assert_eq!(b[..n], unhex(f[16])[..], "{f:?}");
    }
}

#[test]
fn option_writer_matches_go() {
    for f in lines("opts") {
        let mut o = OptWriter::default();
        let mut wrote = 0;
        for op in f[0].split(',') {
            let parts: Vec<&str> = op.split(':').collect();
            match parts[0] {
                "mss" => o.mss(dec(parts[1])),
                "spts" => o.sack_perm_with_ts(dec(parts[1]), dec(parts[2])),
                "ts" => o.ts(dec(parts[1]), dec(parts[2])),
                "ws" => o.wscale(dec(parts[1])),
                "sack4" => {
                    let blocks = [(1, 2), (3, 4), (5, 6), (7, 8)]
                        .map(|(left, right)| SackBlock { left, right });
                    wrote = o.sack(&blocks);
                }
                other => panic!("unknown op {other}"),
            }
        }
        o.pad();
        assert_eq!(wrote, dec::<usize>(f[1]), "{f:?}");
        let mut b = [0u8; 80];
        let h = TcpHeader::default();
        write_tcp(&mut b, 0, &h, Some(&mut o), 0);
        let want = unhex(f[2]);
        assert_eq!(b[40..40 + want.len()], want[..], "{f:?}");
        assert_eq!(usize::from(b[32] >> 4) * 4, 20 + want.len());
    }
}

#[test]
fn ipv4_header_matches_go() {
    for f in lines("ipv4") {
        let mut h = [0u8; 20];
        write_ipv4_header(
            &mut h,
            1500,
            0x1234,
            crate::wire::PROTO_UDP,
            0x0a09_0001,
            0x0a09_0002,
        );
        assert_eq!(h[..], unhex(f[0])[..]);
        clear_df(&mut h);
        assert_eq!(h[..], unhex(f[1])[..]);
        set_frag_field(&mut h, 0x2000 | 0xb9);
        assert_eq!(h[..], unhex(f[2])[..]);
    }
}
