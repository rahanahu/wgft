//! トンネルの中の IPv4 の packet の検査と、外側の ECN の欄の写し (RFC 6040 4.2)。
//!
//! v1 のトンネルは IPv4 だけを運ぶ。復号した平文は 16 バイトの倍数まで 0 で詰めてあるので、
//! ヘッダの全長で切り詰めてから渡す。ヘッダの checksum は確かめない (wireguard-go と Linux の
//! WireGuard も確かめず、受け取る側の IP の層が確かめる)。ECN の欄を書き換えたときは、checksum を
//! 差分で直す (RFC 1624)。元の checksum が誤っていれば、直した後も同じだけ誤ったままになる。

use std::net::Ipv4Addr;

pub(crate) const IPV4_MIN_HEADER: usize = 20;

/// 検査を通った IPv4 の packet の、経路に要る値。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ipv4Header {
    pub(crate) total_len: usize,
    pub(crate) src: Ipv4Addr,
    pub(crate) dst: Ipv4Addr,
}

/// `packet` の先頭が IPv4 の packet として読めるかを確かめる。後ろの余り (詰め物) は許す。
pub(crate) fn parse_ipv4(packet: &[u8]) -> Option<Ipv4Header> {
    let header: &[u8; IPV4_MIN_HEADER] = packet.first_chunk()?;
    if header[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(header[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([header[2], header[3]]));
    if header_len < IPV4_MIN_HEADER || total_len < header_len || total_len > packet.len() {
        return None;
    }
    Some(Ipv4Header {
        total_len,
        src: Ipv4Addr::new(header[12], header[13], header[14], header[15]),
        dst: Ipv4Addr::new(header[16], header[17], header[18], header[19]),
    })
}

/// ECN の欄の codepoint (RFC 3168)。TOS の byte の下位 2 bit である。
const NOT_ECT: u8 = 0b00;
const ECT1: u8 = 0b01;
const ECT0: u8 = 0b10;
const CE: u8 = 0b11;
const ECN_MASK: u8 = 0b11;

/// RFC 6040 4.2 Figure 4:内側の ECN が `inner` の packet が外側の ECN `outer` で届いたときに、出す
/// packet の ECN。`None` は捨てることを示す。内側が Not-ECT なら外側の印を渡さず、外側が CE なら捨てる
/// (MUST)。それ以外は内側と外側の重い方 (CE、ECT(1)、ECT(0)、Not-ECT の順) にする (MUST)。
const fn egress_ecn(inner: u8, outer: u8) -> Option<u8> {
    match (inner, outer) {
        (NOT_ECT, CE) => None,
        (NOT_ECT, _) => Some(NOT_ECT),
        (_, CE) | (CE, _) => Some(CE),
        (ECT0, ECT1) => Some(ECT1),
        _ => Some(inner),
    }
}

/// 検査を通った IPv4 の `packet` に、外側の IP の header の ECN `outer_ecn` (下位 2 bit だけを見る) を
/// RFC 6040 4.2 の表で写す。ECN の欄を変えたら header checksum を差分で直す。捨てるべき packet なら
/// `false` を返し、packet は変えない。外側が Not-ECT なら packet を読まずに `true` を返す。
pub(crate) fn decapsulate_ecn(packet: &mut [u8], outer_ecn: u8) -> bool {
    let outer = outer_ecn & ECN_MASK;
    if outer == NOT_ECT {
        return true;
    }
    let Some(header) = packet.first_chunk_mut::<IPV4_MIN_HEADER>() else {
        return true;
    };
    let tos = header[1];
    let inner = tos & ECN_MASK;
    let Some(ecn) = egress_ecn(inner, outer) else {
        return false;
    };
    if ecn != inner {
        let new_tos = (tos & !ECN_MASK) | ecn;
        header[1] = new_tos;
        // RFC 1624 の式 3:HC' = ~(~HC + ~m + m')。m と m' は TOS を含む 16 bit の語の前後の値
        let old_word = u16::from_be_bytes([header[0], tos]);
        let new_word = u16::from_be_bytes([header[0], new_tos]);
        let sum = u16::from_be_bytes([header[10], header[11]]);
        let mut acc = u32::from(!sum) + u32::from(!old_word) + u32::from(new_word);
        while acc > 0xffff {
            acc = (acc & 0xffff) + (acc >> 16);
        }
        let folded = u16::try_from(acc).unwrap_or(u16::MAX);
        header[10..12].copy_from_slice(&(!folded).to_be_bytes());
    }
    true
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// 試験用の IPv4 の packet。中身は UDP のふりをした任意のバイト列。
    pub(crate) fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let total = u16::try_from(IPV4_MIN_HEADER + payload.len()).unwrap();
        let mut p = vec![0u8; usize::from(total)];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p[IPV4_MIN_HEADER..].copy_from_slice(payload);
        p
    }

    const A: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);
    const B: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 2);

    #[test]
    fn accepts_a_padded_packet_and_reports_its_length() {
        let mut p = ipv4_packet(A, B, b"hello");
        p.extend_from_slice(&[0; 7]);
        let h = parse_ipv4(&p).unwrap();
        assert_eq!(h.total_len, 25);
        assert_eq!((h.src, h.dst), (A, B));
    }

    #[test]
    fn accepts_options() {
        let mut p = ipv4_packet(A, B, &[0; 8]);
        p[0] = 0x47; // IHL 7: 8 バイトの option
        assert_eq!(parse_ipv4(&p).unwrap().total_len, 28);
    }

    #[test]
    fn rejects_malformed_headers() {
        let good = ipv4_packet(A, B, b"x");
        assert!(parse_ipv4(&good[..19]).is_none(), "shorter than a header");
        let mut v6 = good.clone();
        v6[0] = 0x65;
        assert!(parse_ipv4(&v6).is_none(), "IPv6 is not carried");
        let mut small_ihl = good.clone();
        small_ihl[0] = 0x44;
        assert!(parse_ipv4(&small_ihl).is_none(), "IHL below 5");
        let mut long = good.clone();
        long[2..4].copy_from_slice(&22u16.to_be_bytes());
        assert!(parse_ipv4(&long).is_none(), "total length past the buffer");
        let mut short = good.clone();
        short[2..4].copy_from_slice(&19u16.to_be_bytes());
        assert!(
            parse_ipv4(&short).is_none(),
            "total length below the header"
        );
        let mut big_ihl = good;
        big_ihl[0] = 0x4f;
        assert!(
            parse_ipv4(&big_ihl).is_none(),
            "header longer than the total length"
        );
        assert!(parse_ipv4(&[]).is_none());
    }

    fn folded(header: &[u8]) -> u16 {
        let mut sum: u32 = header
            .chunks(2)
            .map(|w| u32::from(u16::from_be_bytes([w[0], w[1]])))
            .sum();
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        u16::try_from(sum).unwrap()
    }

    /// `p` の header checksum を全体から計算し直したもの。
    fn with_checksum(mut p: Vec<u8>) -> Vec<u8> {
        let header = usize::from(p[0] & 0x0f) * 4;
        p[10..12].fill(0);
        let sum = !folded(&p[..header]);
        p[10..12].copy_from_slice(&sum.to_be_bytes());
        p
    }

    #[test]
    fn the_egress_table_takes_the_more_severe_mark_and_drops_ce_on_not_ect() {
        let severity = |c: u8| [0, 2, 1, 3][usize::from(c)];
        for inner in 0..4 {
            for outer in 0..4 {
                let want = match (inner, outer) {
                    (NOT_ECT, CE) => None,
                    (NOT_ECT, _) => Some(NOT_ECT),
                    _ if severity(outer) > severity(inner) => Some(outer),
                    _ => Some(inner),
                };
                assert_eq!(
                    egress_ecn(inner, outer),
                    want,
                    "inner {inner} outer {outer}"
                );
            }
        }
    }

    #[test]
    fn rewriting_the_ecn_field_keeps_the_dscp_and_a_valid_checksum() {
        // DSCP と TTL を変えて、checksum の語の和が折り返す値と、0 の近くになる値も通す
        for dscp in [0u8, 0b10_1110, 0b11_1111] {
            for ttl in [0u8, 1, 64, 255] {
                for (inner, outer, want) in [(ECT0, CE, CE), (ECT1, CE, CE), (ECT0, ECT1, ECT1)] {
                    let mut p = ipv4_packet(A, B, b"payload");
                    p[1] = (dscp << 2) | inner;
                    p[8] = ttl;
                    let p = with_checksum(p);
                    let mut got = p.clone();
                    assert!(decapsulate_ecn(&mut got, outer));
                    assert_eq!(got[1], (dscp << 2) | want);
                    assert_eq!(folded(&got[..20]), 0xffff, "{:02x?}", &got[..20]);
                    assert_eq!(got[..1], p[..1]);
                    assert_eq!(got[2..10], p[2..10]);
                    assert_eq!(got[12..], p[12..]);
                }
            }
        }
    }

    #[test]
    fn only_the_ecn_bits_of_the_outer_value_count_and_a_drop_leaves_the_packet() {
        let p = with_checksum(ipv4_packet(A, B, b"x"));
        let mut got = p.clone();
        // 外側の DSCP の bit は見ない
        assert!(decapsulate_ecn(&mut got, 0b1111_1100));
        assert_eq!(got, p);
        assert!(!decapsulate_ecn(&mut got, 0b1111_1111));
        assert_eq!(got, p, "a dropped packet is left as it was");
    }
}
