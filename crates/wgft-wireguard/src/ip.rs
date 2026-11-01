//! トンネルの中の IPv4 の packet の検査。
//!
//! v1 のトンネルは IPv4 だけを運ぶ。復号した平文は 16 バイトの倍数まで 0 で詰めてあるので、
//! ヘッダの全長で切り詰めてから渡す。ヘッダの checksum は確かめない (wireguard-go と Linux の
//! WireGuard も確かめず、受け取る側の IP の層が確かめる)。

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
}
