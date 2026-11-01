//! IPv4 の packet 全体の符号です。fragment、UDP、ICMP を含みます。Go の `internal/tcpharness/ip.go` の写しです。

use std::collections::BTreeMap;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};

use crate::packet::{checksum, fold, get16, get32, len16, pseudo_header, put16};

/// IP の protocol の番号です。
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// 20 byte の header を持つ 1 つの IPv4 の packet です。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4 {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: u8,
    pub id: u16,
    pub df: bool,
    pub mf: bool,
    /// fragment の offset (byte)
    pub offset: usize,
    pub ttl: u8,
    /// header の後、Total Length までの bytes
    pub payload: Vec<u8>,
}

impl Default for Ipv4 {
    fn default() -> Self {
        Self {
            src: Ipv4Addr::UNSPECIFIED,
            dst: Ipv4Addr::UNSPECIFIED,
            proto: 0,
            id: 0,
            df: false,
            mf: false,
            offset: 0,
            ttl: 0,
            payload: Vec::new(),
        }
    }
}

impl Ipv4 {
    /// 大きな datagram の fragment かどうかです。
    pub const fn fragment(&self) -> bool {
        self.mf || self.offset > 0
    }

    /// 正しい header の checksum を持つ bytes にします。TTL の 0 は 64 にします。
    pub fn marshal(&self) -> Vec<u8> {
        let mut pkt = vec![0u8; 20 + self.payload.len()];
        pkt[0] = 0x45;
        let n = len16(pkt.len());
        put16(&mut pkt[2..], n);
        put16(&mut pkt[4..], self.id);
        let mut frag = len16(self.offset / 8);
        if self.df {
            frag |= 0x4000;
        }
        if self.mf {
            frag |= 0x2000;
        }
        put16(&mut pkt[6..], frag);
        pkt[8] = if self.ttl == 0 { 64 } else { self.ttl };
        pkt[9] = self.proto;
        pkt[12..16].copy_from_slice(&self.src.octets());
        pkt[16..20].copy_from_slice(&self.dst.octets());
        let sum = fold(checksum(0, &pkt[..20]));
        put16(&mut pkt[10..], sum);
        pkt[20..].copy_from_slice(&self.payload);
        pkt
    }
}

impl fmt::Display for Ipv4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} > {} proto={} id={} len={}",
            self.src,
            self.dst,
            self.proto,
            self.id,
            20 + self.payload.len()
        )?;
        if self.fragment() {
            write!(f, " frag={}", self.offset)?;
            if self.mf {
                f.write_str("+")?;
            }
        }
        if self.df {
            f.write_str(" DF")?;
        }
        Ok(())
    }
}

fn header_fields(b: &[u8], ihl: usize, payload_end: usize) -> Ipv4 {
    let frag = get16(&b[6..]);
    Ipv4 {
        src: Ipv4Addr::new(b[12], b[13], b[14], b[15]),
        dst: Ipv4Addr::new(b[16], b[17], b[18], b[19]),
        proto: b[9],
        id: get16(&b[4..]),
        df: frag & 0x4000 != 0,
        mf: frag & 0x2000 != 0,
        offset: usize::from(frag & 0x1fff) * 8,
        ttl: b[8],
        payload: b[ihl..payload_end].to_vec(),
    }
}

/// IPv4 の packet を読み、header の checksum を確かめます。option は飛ばします。
pub fn parse_ipv4(pkt: &[u8]) -> Result<Ipv4, &'static str> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return Err("not IPv4");
    }
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    let total = usize::from(get16(&pkt[2..]));
    if ihl < 20 || total < ihl || total > pkt.len() {
        return Err("malformed IPv4 header");
    }
    if fold(checksum(0, &pkt[..ihl])) != 0 {
        return Err("bad IPv4 header checksum");
    }
    Ok(header_fields(pkt, ihl, total))
}

/// `p` の payload を byte の offset (8 の倍数) で順に切った fragment です。
pub fn fragments(p: &Ipv4, cuts: &[usize]) -> Vec<Ipv4> {
    let mut out = Vec::new();
    let mut start = 0;
    for &c in cuts.iter().chain(std::iter::once(&p.payload.len())) {
        out.push(frag(p, start, c));
        start = c;
    }
    out
}

/// `p` の payload の `[from, to)` を運ぶ fragment です。`to` が payload の終わりでなければ MF を立てます。
pub fn frag(p: &Ipv4, from: usize, to: usize) -> Ipv4 {
    Ipv4 {
        offset: from,
        mf: to < p.payload.len(),
        payload: p.payload[from..to].to_vec(),
        ..p.clone()
    }
}

/// 1 つの UDP の datagram です。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Udp {
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub payload: Vec<u8>,
    /// header の欄。0 は送り手が計算しなかったこと
    pub checksum: u16,
}

impl Default for Udp {
    fn default() -> Self {
        let z = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
        Self {
            src: z,
            dst: z,
            payload: Vec::new(),
            checksum: 0,
        }
    }
}

/// `src` から `dst` へ `payload` を運ぶ、正しい UDP の checksum を持つ fragment でない packet です。
pub fn udp_packet(src: SocketAddrV4, dst: SocketAddrV4, id: u16, payload: &[u8]) -> Ipv4 {
    let mut u = vec![0u8; 8 + payload.len()];
    put16(&mut u[0..], src.port());
    put16(&mut u[2..], dst.port());
    let n = len16(u.len());
    put16(&mut u[4..], n);
    u[8..].copy_from_slice(payload);
    let mut sum = fold(checksum(
        pseudo_header(src.ip().octets(), dst.ip().octets(), PROTO_UDP, u.len()),
        &u,
    ));
    if sum == 0 {
        sum = 0xffff;
    }
    put16(&mut u[6..], sum);
    Ipv4 {
        src: *src.ip(),
        dst: *dst.ip(),
        proto: PROTO_UDP,
        id,
        payload: u,
        ..Ipv4::default()
    }
}

/// fragment でないか組み直した packet の UDP の datagram を読み、checksum があれば確かめます。
pub fn parse_udp(p: &Ipv4) -> Result<Udp, String> {
    if p.proto != PROTO_UDP || p.fragment() {
        return Err("not a whole UDP datagram".to_owned());
    }
    let b = &p.payload;
    if b.len() < 8 {
        return Err("short UDP header".to_owned());
    }
    let n = usize::from(get16(&b[4..]));
    if n < 8 || n > b.len() {
        return Err(format!("UDP length {n} in a payload of {} bytes", b.len()));
    }
    let b = &b[..n];
    if get16(&b[6..]) != 0
        && fold(checksum(
            pseudo_header(p.src.octets(), p.dst.octets(), PROTO_UDP, n),
            b,
        )) != 0
    {
        return Err("bad UDP checksum".to_owned());
    }
    Ok(Udp {
        src: SocketAddrV4::new(p.src, get16(&b[0..])),
        dst: SocketAddrV4::new(p.dst, get16(&b[2..])),
        payload: b[8..].to_vec(),
        checksum: get16(&b[6..]),
    })
}

/// ICMP の type と code です。
pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_ECHO_REQUEST: u8 = 8;

/// 1 つの ICMP の message です。`rest` は checksum の後の 4 byte です。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Icmp {
    pub typ: u8,
    pub code: u8,
    pub rest: u32,
    pub body: Vec<u8>,
}

/// `m` を運ぶ、正しい checksum を持つ fragment でない packet です。
pub fn icmp_packet(src: Ipv4Addr, dst: Ipv4Addr, id: u16, m: &Icmp) -> Ipv4 {
    let mut b = vec![0u8; 8 + m.body.len()];
    b[0] = m.typ;
    b[1] = m.code;
    b[4..8].copy_from_slice(&m.rest.to_be_bytes());
    b[8..].copy_from_slice(&m.body);
    let sum = fold(checksum(0, &b));
    put16(&mut b[2..], sum);
    Ipv4 {
        src,
        dst,
        proto: PROTO_ICMP,
        id,
        payload: b,
        ..Ipv4::default()
    }
}

/// fragment でないか組み直した packet の ICMP の message を読み、checksum を確かめます。
pub fn parse_icmp(p: &Ipv4) -> Result<Icmp, &'static str> {
    if p.proto != PROTO_ICMP || p.fragment() {
        return Err("not a whole ICMP message");
    }
    let b = &p.payload;
    if b.len() < 8 {
        return Err("short ICMP header");
    }
    if fold(checksum(0, b)) != 0 {
        return Err("bad ICMP checksum");
    }
    Ok(Icmp {
        typ: b[0],
        code: b[1],
        rest: get32(&b[4..]),
        body: b[8..].to_vec(),
    })
}

/// ICMP の誤りが引く datagram の先頭です。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Quote {
    pub ip: Ipv4,
    /// header を含む引用の長さ
    pub bytes: usize,
}

/// ICMP の誤りの本体が引く datagram を読みます。引いた header の checksum は確かめません。
pub fn parse_quote(body: &[u8]) -> Option<Quote> {
    if body.len() < 20 || body[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(body[0] & 0x0f) * 4;
    if ihl < 20 || body.len() < ihl {
        return None;
    }
    Some(Quote {
        ip: header_fields(body, ihl, body.len()),
        bytes: body.len(),
    })
}

/// DUT の fragment を組み直します。試験台の側の stack がするのと同じです。
#[derive(Debug, Default)]
pub struct Reassembler {
    parts: BTreeMap<u16, Vec<Ipv4>>,
}

impl Reassembler {
    /// 1 つの packet を受け、datagram の fragment がすべて揃えば全体を返します。fragment でない packet は
    /// そのまま返します。
    pub fn add(&mut self, p: Ipv4) -> Option<Ipv4> {
        if !p.fragment() {
            return Some(p);
        }
        let id = p.id;
        let fs = self.parts.entry(id).or_default();
        fs.push(p);
        // Go の sort.Slice は少ない要素で安定な挿入の整列になる
        fs.sort_by_key(|f| f.offset);
        if fs.last().is_some_and(|f| f.mf) {
            return None;
        }
        let mut end = 0;
        for f in fs.iter() {
            if f.offset != end {
                return None;
            }
            end += f.payload.len();
        }
        let mut whole = fs[0].clone();
        whole.mf = false;
        whole.offset = 0;
        whole.payload = fs.iter().flat_map(|f| f.payload.iter().copied()).collect();
        self.parts.remove(&id);
        Some(whole)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_fragments_reassemble() {
        let src: SocketAddrV4 = "10.200.0.1:41000".parse().unwrap();
        let dst: SocketAddrV4 = "10.200.0.2:5300".parse().unwrap();
        let p = udp_packet(src, dst, 7, &[0x55; 3000]);
        let fs = fragments(&p, &[1000, 2000]);
        assert_eq!(fs.len(), 3);
        let mut r = Reassembler::default();
        assert!(r.add(fs[2].clone()).is_none());
        assert!(r.add(fs[0].clone()).is_none());
        let whole = r.add(fs[1].clone()).unwrap();
        let back = parse_ipv4(&whole.marshal()).unwrap();
        let u = parse_udp(&back).unwrap();
        assert_eq!(u.payload, vec![0x55; 3000]);
        assert_eq!(u.src, src);
    }

    #[test]
    fn icmp_round_trip() {
        let m = Icmp {
            typ: ICMP_ECHO_REQUEST,
            code: 0,
            rest: 0x1234_0001,
            body: b"abc".to_vec(),
        };
        let p = icmp_packet(
            Ipv4Addr::new(10, 200, 0, 1),
            Ipv4Addr::new(10, 200, 0, 2),
            3,
            &m,
        );
        assert_eq!(parse_icmp(&parse_ipv4(&p.marshal()).unwrap()).unwrap(), m);
    }
}
