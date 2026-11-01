//! 試験台の IPv4 と TCP の符号です。Go の `internal/tcpharness/packet.go` の写しです。
//!
//! 試験する engine の header の符号を使い回さず、試験台が自分の符号を持ちます。engine と符号が同じ誤りを
//! 持って隠れないためです。表示 (`Display`) は Go の `Segment.String` と同じ文字列で、log の行を Go と
//! 比べられます。

use std::fmt::{self, Write as _};
use std::net::{Ipv4Addr, SocketAddrV4};

/// TCP の flag です。
pub const FIN: u8 = 1;
pub const SYN: u8 = 1 << 1;
pub const RST: u8 = 1 << 2;
pub const PSH: u8 = 1 << 3;
pub const ACK: u8 = 1 << 4;
pub const URG: u8 = 1 << 5;
pub const ECE: u8 = 1 << 6;
pub const CWR: u8 = 1 << 7;

/// 立っている flag の名前を `SYN|ACK` の形で返します。Go の `FlagString` です。
pub fn flag_string(f: u8) -> String {
    const NAMES: [&str; 8] = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"];
    let out: Vec<&str> = NAMES
        .iter()
        .enumerate()
        .filter(|(i, _)| f & (1 << i) != 0)
        .map(|(_, n)| *n)
        .collect();
    if out.is_empty() {
        "none".to_owned()
    } else {
        out.join("|")
    }
}

/// SACK の 1 つの block です。sequence の空間の `[left, right)` です (RFC 2018)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SackBlock {
    pub left: u32,
    pub right: u32,
}

/// TCP の timestamps の option です (RFC 7323)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamps {
    pub val: u32,
    pub ecr: u32,
}

/// 試験台が読み書きする TCP の option です。`None` と負の `ws` は option が無いことを表します。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub mss: Option<u16>,
    /// window scale の shift。無ければ -1
    pub ws: i64,
    pub sack_permitted: bool,
    pub ts: Option<Timestamps>,
    pub sack: Vec<SackBlock>,
}

impl Options {
    /// option がすべて無い値です。Go の `NoOptions` です。
    pub const fn none() -> Self {
        Self {
            mss: None,
            ws: -1,
            sack_permitted: false,
            ts: None,
            sack: Vec::new(),
        }
    }
}

impl Default for Options {
    fn default() -> Self {
        Self::none()
    }
}

/// 試験台から見た 1 つの IPv4 の TCP の segment です。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    /// header の欄のまま。scale しません
    pub window: u16,
    pub opts: Options,
    pub payload: Vec<u8>,
    pub ttl: u8,
    pub df: bool,
    /// IPv4 の identification
    pub id: u16,
}

impl Default for Segment {
    fn default() -> Self {
        Self {
            src: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
            dst: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
            seq: 0,
            ack: 0,
            flags: 0,
            window: 0,
            opts: Options::none(),
            payload: Vec::new(),
            ttl: 0,
            df: false,
            id: 0,
        }
    }
}

impl Segment {
    /// `f` の flag がすべて立っているかどうかです。
    pub const fn has(&self, f: u8) -> bool {
        self.flags & f == f
    }

    /// sequence の空間の長さです。payload と SYN と FIN の和です。
    pub fn seq_len(&self) -> u32 {
        let mut n = u32::try_from(self.payload.len()).expect("payload below 4 GiB");
        if self.has(SYN) {
            n += 1;
        }
        if self.has(FIN) {
            n += 1;
        }
        n
    }

    /// 正しい checksum を持つ IPv4 の packet にします。TTL の 0 は 64 にします。
    pub fn marshal(&self) -> Vec<u8> {
        let opts = marshal_options(&self.opts);
        let tcp_len = 20 + opts.len() + self.payload.len();
        let mut pkt = vec![0u8; 20 + tcp_len];
        pkt[0] = 0x45;
        let n = len16(pkt.len());
        put16(&mut pkt[2..], n);
        if self.df {
            pkt[6] = 0x40;
        }
        put16(&mut pkt[4..], self.id);
        pkt[8] = if self.ttl == 0 { 64 } else { self.ttl };
        pkt[9] = 6;
        let src = self.src.ip().octets();
        let dst = self.dst.ip().octets();
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        let sum = fold(checksum(0, &pkt[..20]));
        put16(&mut pkt[10..], sum);

        let t = &mut pkt[20..];
        put16(&mut t[0..], self.src.port());
        put16(&mut t[2..], self.dst.port());
        t[4..8].copy_from_slice(&self.seq.to_be_bytes());
        t[8..12].copy_from_slice(&self.ack.to_be_bytes());
        t[12] = u8::try_from((20 + opts.len()) / 4).expect("at most 15 words") << 4;
        t[13] = self.flags;
        put16(&mut t[14..], self.window);
        t[20..20 + opts.len()].copy_from_slice(&opts);
        t[20 + opts.len()..].copy_from_slice(&self.payload);
        let sum = fold(checksum(pseudo_header(src, dst, 6, tcp_len), t));
        put16(&mut t[16..], sum);
        pkt
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} > {} [{}] seq={} ack={} win={} len={}",
            self.src,
            self.dst,
            flag_string(self.flags),
            self.seq,
            self.ack,
            self.window,
            self.payload.len()
        )?;
        if let Some(m) = self.opts.mss {
            write!(f, " mss={m}")?;
        }
        if self.opts.ws >= 0 {
            write!(f, " ws={}", self.opts.ws)?;
        }
        if self.opts.sack_permitted {
            f.write_str(" sackOK")?;
        }
        if let Some(ts) = self.opts.ts {
            write!(f, " ts={}/{}", ts.val, ts.ecr)?;
        }
        for b in &self.opts.sack {
            write!(f, " sack=[{},{})", b.left, b.right)?;
        }
        Ok(())
    }
}

pub(crate) fn put16(b: &mut [u8], v: u16) {
    b[..2].copy_from_slice(&v.to_be_bytes());
}

pub(crate) fn get16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

pub(crate) fn get32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// 長さを u16 の欄に入れます。Go の `uint16(len)` と同じく上位を落とします。
pub(crate) fn len16(n: usize) -> u16 {
    #[expect(clippy::cast_possible_truncation, reason = "Go's uint16 conversion")]
    let v = n as u16;
    v
}

fn marshal_options(o: &Options) -> Vec<u8> {
    let mut b = Vec::new();
    if let Some(m) = o.mss {
        b.extend_from_slice(&[2, 4]);
        b.extend_from_slice(&m.to_be_bytes());
    }
    if o.sack_permitted {
        b.extend_from_slice(&[1, 1, 4, 2]);
    }
    if let Some(ts) = o.ts {
        b.extend_from_slice(&[1, 1, 8, 10]);
        b.extend_from_slice(&ts.val.to_be_bytes());
        b.extend_from_slice(&ts.ecr.to_be_bytes());
    }
    if o.ws >= 0 {
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "Go's byte conversion"
        )]
        let ws = o.ws as u8;
        b.extend_from_slice(&[1, 3, 3, ws]);
    }
    if !o.sack.is_empty() {
        b.extend_from_slice(&[1, 1, 5, len16(2 + 8 * o.sack.len()).to_be_bytes()[1]]);
        for blk in &o.sack {
            b.extend_from_slice(&blk.left.to_be_bytes());
            b.extend_from_slice(&blk.right.to_be_bytes());
        }
    }
    while b.len() % 4 != 0 {
        b.push(0);
    }
    assert!(
        b.len() <= 40,
        "tcpharness: {} bytes of TCP options exceed 40",
        b.len()
    );
    b
}

fn parse_options(mut b: &[u8]) -> Result<Options, &'static str> {
    let mut o = Options::none();
    while !b.is_empty() {
        match b[0] {
            0 => return Ok(o),
            1 => {
                b = &b[1..];
                continue;
            }
            _ => {}
        }
        if b.len() < 2 || usize::from(b[1]) < 2 || usize::from(b[1]) > b.len() {
            return Err("malformed TCP option");
        }
        let kind = b[0];
        let body = &b[2..usize::from(b[1])];
        match (kind, body.len()) {
            (2, 2) => o.mss = Some(get16(body)),
            (3, 1) => o.ws = i64::from(body[0]),
            (4, 0) => o.sack_permitted = true,
            (8, 8) => {
                o.ts = Some(Timestamps {
                    val: get32(body),
                    ecr: get32(&body[4..]),
                });
            }
            (5, n) if n % 8 == 0 => {
                for c in body.as_chunks::<8>().0 {
                    o.sack.push(SackBlock {
                        left: get32(c),
                        right: get32(&c[4..]),
                    });
                }
            }
            _ => {}
        }
        b = &b[usize::from(b[1])..];
    }
    Ok(o)
}

pub(crate) fn checksum(mut sum: u32, b: &[u8]) -> u32 {
    let (pairs, rest) = b.as_chunks::<2>();
    for c in pairs {
        sum = sum.wrapping_add(u32::from(c[0]) << 8 | u32::from(c[1]));
    }
    if let [x] = rest {
        sum = sum.wrapping_add(u32::from(*x) << 8);
    }
    sum
}

pub(crate) fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    #[expect(clippy::cast_possible_truncation, reason = "folded below 2^16")]
    let v = !(sum as u16);
    v
}

pub(crate) fn pseudo_header(src: [u8; 4], dst: [u8; 4], proto: u8, len: usize) -> u32 {
    let s = checksum(0, &src);
    let s = checksum(s, &dst);
    #[expect(clippy::cast_possible_truncation, reason = "Go's uint32 conversion")]
    let n = len as u32;
    s.wrapping_add(u32::from(proto)).wrapping_add(n)
}

/// 正しい IPv4 の packet でも TCP でないことを表す `parse` の誤りの文です。
pub const NOT_TCP: &str = "not an IPv4 TCP packet";

/// IPv4 の TCP の packet を読み、2 つの checksum を確かめます。fragment は誤りです。誤りの文は Go の
/// `Parse` と同じです。
pub fn parse(pkt: &[u8]) -> Result<Segment, &'static str> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return Err(NOT_TCP);
    }
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    let total = usize::from(get16(&pkt[2..]));
    if ihl < 20 || total < ihl || total > pkt.len() {
        return Err("malformed IPv4 header");
    }
    if pkt[9] != 6 {
        return Err(NOT_TCP);
    }
    if fold(checksum(0, &pkt[..ihl])) != 0 {
        return Err("bad IPv4 header checksum");
    }
    if get16(&pkt[6..]) & 0x3fff != 0 {
        return Err("IPv4 fragment");
    }
    let src: [u8; 4] = pkt[12..16].try_into().expect("4 bytes");
    let dst: [u8; 4] = pkt[16..20].try_into().expect("4 bytes");
    let t = &pkt[ihl..total];
    if t.len() < 20 {
        return Err("short TCP header");
    }
    let off = usize::from(t[12] >> 4) * 4;
    if off < 20 || off > t.len() {
        return Err("bad TCP data offset");
    }
    if fold(checksum(pseudo_header(src, dst, 6, t.len()), t)) != 0 {
        return Err("bad TCP checksum");
    }
    let opts = parse_options(&t[20..off])?;
    Ok(Segment {
        src: SocketAddrV4::new(src.into(), get16(&t[0..])),
        dst: SocketAddrV4::new(dst.into(), get16(&t[2..])),
        seq: get32(&t[4..]),
        ack: get32(&t[8..]),
        flags: t[13],
        window: get16(&t[14..]),
        opts,
        payload: t[off..].to_vec(),
        ttl: pkt[8],
        df: pkt[6] & 0x40 != 0,
        id: get16(&pkt[4..]),
    })
}

/// `from` の router が、送った IPv4 の packet `orig` の送り手に返す ICMP の Destination Unreachable、
/// Fragmentation Needed です。次の hop の MTU は `mtu` で、`orig` の header と payload の先頭の 8 byte を
/// 引きます。Go の `FragNeeded` です。
pub fn frag_needed(from: Ipv4Addr, orig: &[u8], mtu: u16) -> Vec<u8> {
    let ihl = usize::from(orig[0] & 0x0f) * 4;
    let quote = &orig[..orig.len().min(ihl + 8)];
    let mut icmp = vec![0u8; 8 + quote.len()];
    icmp[0] = 3;
    icmp[1] = 4;
    put16(&mut icmp[6..], mtu);
    icmp[8..].copy_from_slice(quote);
    let sum = fold(checksum(0, &icmp));
    put16(&mut icmp[2..], sum);
    let mut pkt = vec![0u8; 20 + icmp.len()];
    pkt[0] = 0x45;
    put16(&mut pkt[2..], len16(20 + icmp.len()));
    pkt[8] = 64;
    pkt[9] = 1;
    pkt[12..16].copy_from_slice(&from.octets());
    pkt[16..20].copy_from_slice(&orig[12..16]);
    let sum = fold(checksum(0, &pkt[..20]));
    put16(&mut pkt[10..], sum);
    pkt[20..].copy_from_slice(&icmp);
    pkt
}

/// byte の列を、長さと先頭の 16 byte の 16 進で表します。
pub(crate) fn short_hex(b: &[u8]) -> String {
    let mut out = format!("{}:", b.len());
    for x in b.iter().take(16) {
        let _ = write!(out, "{x:02x}");
    }
    if b.len() > 16 {
        out.push_str("...");
    }
    out
}

/// IPv4 の packet を 1 行で表します。frame の表示に使い、Go の `PacketString` に倣います。
pub fn packet_string(p: &[u8]) -> String {
    let raw = short_hex;
    if p.len() < 20 || p[0] >> 4 != 4 {
        return format!("raw {}", raw(p));
    }
    let ihl = usize::from(p[0] & 0xf) * 4;
    let total = usize::from(get16(&p[2..]));
    if ihl < 20 || p.len() < ihl || total < ihl || total > p.len() {
        return format!("bad-ipv4 {}", raw(p));
    }
    let src = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
    let dst = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
    let mut b = format!("ipv4 id={}", get16(&p[4..]));
    if p[6] & 0x40 != 0 {
        b.push_str(" DF");
    }
    let l4 = &p[ihl..total];
    let _ = write!(b, " {src}>{dst} proto={} len={}", p[9], l4.len());
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marshal_parse_round_trip() {
        let s = Segment {
            src: "10.200.0.1:40001".parse().unwrap(),
            dst: "10.200.0.2:80".parse().unwrap(),
            seq: 100,
            ack: 7,
            flags: SYN | ACK,
            window: 65535,
            opts: Options {
                mss: Some(1380),
                ws: 7,
                sack_permitted: true,
                ts: Some(Timestamps { val: 1, ecr: 2 }),
                sack: vec![],
            },
            payload: b"hi".to_vec(),
            ttl: 64,
            df: true,
            id: 9,
        };
        let got = parse(&s.marshal()).unwrap();
        assert_eq!(got, s);
        assert_eq!(
            s.to_string(),
            "10.200.0.1:40001 > 10.200.0.2:80 [SYN|ACK] seq=100 ack=7 win=65535 len=2 mss=1380 ws=7 sackOK ts=1/2"
        );
    }

    #[test]
    fn go_syn_bytes() {
        // internal/dutproto の frame の例の SYN と同じ bytes。checksum は 0 のままの例なので header だけを比べる
        let s = Segment {
            src: "10.200.0.1:40001".parse().unwrap(),
            dst: "10.200.0.2:80".parse().unwrap(),
            seq: 100,
            flags: SYN,
            window: 0xffff,
            df: true,
            id: 1,
            ..Segment::default()
        };
        let b = s.marshal();
        assert_eq!(&b[..10], &[0x45, 0, 0, 40, 0, 1, 0x40, 0, 64, 6]);
        assert_eq!(parse(&b).unwrap().seq, 100);
    }
}
