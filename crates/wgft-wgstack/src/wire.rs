//! IPv4、TCP、UDP、ICMP の解釈と組み立てと checksum (Go の `packet.go` の写し)。
//!
//! 解釈はどの byte の列でも範囲の外を読まず、panic しません。`parse` の fuzz の target がこれを確かめます。
//! 組み立ては Go と同じ byte の列を作ります。Go が組み立てた packet との一致を試験で確かめます。

/// IP の protocol の番号。
pub(crate) const PROTO_ICMP: u8 = 1;
pub(crate) const PROTO_TCP: u8 = 6;
pub(crate) const PROTO_UDP: u8 = 17;

/// TCP の flag。
pub(crate) const FLAG_FIN: u8 = 0x01;
pub(crate) const FLAG_SYN: u8 = 0x02;
pub(crate) const FLAG_RST: u8 = 0x04;
pub(crate) const FLAG_PSH: u8 = 0x08;
pub(crate) const FLAG_ACK: u8 = 0x10;
#[cfg(test)]
pub(crate) const FLAG_URG: u8 = 0x20;

pub(crate) const IP_HEADER_LEN: usize = 20;
pub(crate) const TCP_HEADER_LEN: usize = 20;
pub(crate) const UDP_HEADER_LEN: usize = 8;
pub(crate) const ICMP_HEADER_LEN: usize = 8;
pub(crate) const MAX_OPTION_LEN: usize = 40;
pub(crate) const DEFAULT_TTL: u8 = 64;

#[inline]
pub(crate) fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

#[inline]
fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

#[inline]
fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_be_bytes());
}

#[inline]
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_be_bytes());
}

/// 長さを 16 bit の欄に書く値にします。呼び手は 65535 以下の長さだけを渡します。
/// 超える値は Go の `uint16(n)` と同じく下位の 16 bit にします。
#[inline]
#[expect(
    clippy::cast_possible_truncation,
    reason = "matches Go's uint16 conversion"
)]
fn len16(n: usize) -> u16 {
    n as u16
}

/// 接続の 4 つ組です。`laddr` と `lport` は wgstack の側、`raddr` と `rport` は相手の側です。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct Tuple {
    pub(crate) laddr: u32,
    pub(crate) raddr: u32,
    pub(crate) lport: u16,
    pub(crate) rport: u16,
}

/// `b` を 16 bit の 1 の補数で足した値を `sum` に足して畳みます。結果の補数が checksum です。
/// 1 の補数の和は語の幅によらないので、8 byte ずつ繰り上がりを回して足し、最後に 16 bit に畳みます
/// (RFC 1071 2 節)。
#[expect(
    clippy::cast_possible_truncation,
    reason = "the folded sum fits in 16 bits"
)]
pub(crate) fn checksum(sum: u32, b: &[u8]) -> u16 {
    #[inline]
    fn add(acc: u64, x: u64, carry: u64) -> (u64, u64) {
        let (s, c1) = acc.overflowing_add(x);
        let (s, c2) = s.overflowing_add(carry);
        (s, u64::from(c1) + u64::from(c2))
    }
    let mut acc = u64::from(sum);
    let mut carry = 0;
    let (blocks, rest) = b.as_chunks::<32>();
    for blk in blocks {
        for w in blk.as_chunks::<8>().0 {
            (acc, carry) = add(acc, u64::from_be_bytes(*w), carry);
        }
    }
    let (words, rest) = rest.as_chunks::<8>();
    for w in words {
        (acc, carry) = add(acc, u64::from_be_bytes(*w), carry);
    }
    // 繰り上がりが残るとき acc は 2^64 - 2 以下なので、足しても溢れません。
    acc += carry;
    acc = (acc >> 32) + (acc & 0xffff_ffff); // 33 bit 以下
    let (pairs, last) = rest.as_chunks::<2>();
    for p in pairs {
        acc += u64::from(u16::from_be_bytes(*p));
    }
    if let [last] = last {
        acc += u64::from(*last) << 8;
    }
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    acc as u16
}

/// TCP と UDP の擬似 header の和です。
#[expect(
    clippy::cast_possible_truncation,
    reason = "the length is at most 65535"
)]
pub(crate) fn pseudo_sum(src: u32, dst: u32, proto: u8, length: usize) -> u32 {
    // 長さは 65535 以下で、和は 32 bit に収まります。
    (src >> 16) + (src & 0xffff) + (dst >> 16) + (dst & 0xffff) + u32::from(proto) + length as u32
}

/// 解釈した IPv4 の header です。`packet` は Total Length で切った packet の全体です。
#[derive(Clone, Copy, Debug)]
pub(crate) struct Ipv4<'a> {
    pub(crate) src: u32,
    pub(crate) dst: u32,
    pub(crate) proto: u8,
    pub(crate) hlen: usize,
    /// MF か、0 でない offset です。
    pub(crate) fragment: bool,
    pub(crate) packet: &'a [u8],
}

impl<'a> Ipv4<'a> {
    /// option を含む header です。
    #[cfg(test)]
    pub(crate) fn header(&self) -> &'a [u8] {
        &self.packet[..self.hlen]
    }

    /// header の後ろの中身です。
    pub(crate) fn payload(&self) -> &'a [u8] {
        &self.packet[self.hlen..]
    }
}

/// IPv4 の packet を捨てた理由です。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ipv4Drop {
    Malformed,
    BadChecksum,
}

/// `b` を IPv4 の packet として解釈します。Total Length より後ろの byte は切り捨てます
/// (packet-validation.md の IPv4 の Total Length)。
pub(crate) fn parse_ipv4(b: &[u8]) -> Result<Ipv4<'_>, Ipv4Drop> {
    if b.len() < IP_HEADER_LEN || b[0] >> 4 != 4 {
        return Err(Ipv4Drop::Malformed);
    }
    let hlen = usize::from(b[0] & 0x0f) * 4;
    let total = usize::from(be16(b, 2));
    if hlen < IP_HEADER_LEN || total < hlen || total > b.len() {
        return Err(Ipv4Drop::Malformed);
    }
    let b = &b[..total];
    if checksum(0, &b[..hlen]) != 0xffff {
        return Err(Ipv4Drop::BadChecksum);
    }
    Ok(Ipv4 {
        src: be32(b, 12),
        dst: be32(b, 16),
        proto: b[9],
        hlen,
        fragment: be16(b, 6) & 0x3fff != 0,
        packet: b,
    })
}

/// SACK の 1 つの block `[left, right)` です。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SackBlock {
    pub(crate) left: u32,
    pub(crate) right: u32,
}

/// 解釈した TCP の option です。MSS、窓の scale、SACK の許可は SYN でだけ読みます。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct TcpOptions {
    pub(crate) mss: Option<u16>,
    pub(crate) wscale: Option<u8>,
    pub(crate) sack_ok: bool,
    /// timestamp の option の TSval と TSecr です。
    pub(crate) ts: Option<(u32, u32)>,
    pub(crate) nsack: usize,
    pub(crate) sack: [SackBlock; 4],
    /// 形の崩れた option で読み終えたことを表します。
    pub(crate) malformed: bool,
}

impl TcpOptions {
    /// 読んだ SACK の block です。
    pub(crate) fn sack_blocks(&self) -> &[SackBlock] {
        &self.sack[..self.nsack]
    }
}

/// TCP の option を読みます。長さの崩れた option で読むのをやめ、それまでに読んだ値を使います。
/// 知らない option は長さで飛ばします。
pub(crate) fn parse_options(mut b: &[u8], syn: bool) -> TcpOptions {
    let mut o = TcpOptions::default();
    while let Some(&kind) = b.first() {
        match kind {
            0 => break, // EOL
            1 => {
                b = &b[1..]; // NOP
                continue;
            }
            _ => {}
        }
        let Some(&size) = b.get(1) else {
            o.malformed = true;
            break;
        };
        let size = usize::from(size);
        if size < 2 || size > b.len() {
            o.malformed = true;
            break;
        }
        let body = &b[2..size];
        match kind {
            2 if size == 4 && syn => o.mss = Some(be16(body, 0)),
            3 if size == 3 && syn => o.wscale = Some(body[0].min(14)), // RFC 7323 2.3
            4 if size == 2 && syn => o.sack_ok = true,
            5 if (size - 2).is_multiple_of(8) && !syn => {
                // Go と同じく、続く SACK の option も 4 つの枠が埋まるまで足します。
                for blk in body.as_chunks::<8>().0.iter().take(o.sack.len() - o.nsack) {
                    o.sack[o.nsack] = SackBlock {
                        left: be32(blk, 0),
                        right: be32(blk, 4),
                    };
                    o.nsack += 1;
                }
            }
            8 if size == 10 => o.ts = Some((be32(body, 0), be32(body, 4))),
            _ => {}
        }
        b = &b[size..];
    }
    o
}

/// 解釈した TCP の segment です。`tup` は wgstack の側から見た 4 つ組です。
#[derive(Clone, Copy, Debug)]
pub(crate) struct Segment<'a> {
    pub(crate) tup: Tuple,
    pub(crate) seq: u32,
    pub(crate) ack: u32,
    pub(crate) flags: u8,
    pub(crate) wnd: u16,
    pub(crate) opt: TcpOptions,
    pub(crate) payload: &'a [u8],
}

impl Segment<'_> {
    pub(crate) fn has(&self, f: u8) -> bool {
        self.flags & f != 0
    }

    /// segment が使うシーケンス番号の長さ (中身と SYN と FIN) です。
    #[expect(
        clippy::cast_possible_truncation,
        reason = "a segment carries less than 64 KiB"
    )]
    pub(crate) fn seq_len(&self) -> u32 {
        let mut n = self.payload.len() as u32;
        if self.has(FLAG_SYN) {
            n += 1;
        }
        if self.has(FLAG_FIN) {
            n += 1;
        }
        n
    }
}

/// 中身の解釈で捨てた理由です。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PayloadDrop {
    Malformed,
    BadChecksum,
}

/// `ip` の中身を TCP の segment として解釈し、checksum を確かめます。
pub(crate) fn parse_tcp<'a>(ip: &Ipv4<'a>) -> Result<Segment<'a>, PayloadDrop> {
    let b = ip.payload();
    if b.len() < TCP_HEADER_LEN {
        return Err(PayloadDrop::Malformed);
    }
    let off = usize::from(b[12] >> 4) * 4;
    if off < TCP_HEADER_LEN || off > b.len() {
        return Err(PayloadDrop::Malformed);
    }
    if !checksum(pseudo_sum(ip.src, ip.dst, PROTO_TCP, b.len()), b) != 0 {
        return Err(PayloadDrop::BadChecksum);
    }
    let flags = b[13];
    Ok(Segment {
        tup: Tuple {
            laddr: ip.dst,
            raddr: ip.src,
            lport: be16(b, 2),
            rport: be16(b, 0),
        },
        seq: be32(b, 4),
        ack: be32(b, 8),
        flags,
        wnd: be16(b, 14),
        opt: parse_options(&b[TCP_HEADER_LEN..off], flags & FLAG_SYN != 0),
        payload: &b[off..],
    })
}

/// 解釈した UDP の datagram です。
#[derive(Clone, Copy, Debug)]
pub(crate) struct Udp<'a> {
    pub(crate) sport: u16,
    pub(crate) dport: u16,
    pub(crate) payload: &'a [u8],
}

/// `ip` の中身を UDP の datagram として解釈します。UDP の長さの欄より後ろは切り捨て、checksum の欄が 0 で
/// なければ確かめます (Go の `inputUDP` の検査)。
pub(crate) fn parse_udp<'a>(ip: &Ipv4<'a>) -> Result<Udp<'a>, PayloadDrop> {
    let b = ip.payload();
    if b.len() < UDP_HEADER_LEN {
        return Err(PayloadDrop::Malformed);
    }
    let ulen = usize::from(be16(b, 4));
    if ulen < UDP_HEADER_LEN || ulen > b.len() {
        return Err(PayloadDrop::Malformed);
    }
    let b = &b[..ulen];
    if be16(b, 6) != 0 && !checksum(pseudo_sum(ip.src, ip.dst, PROTO_UDP, ulen), b) != 0 {
        return Err(PayloadDrop::BadChecksum);
    }
    Ok(Udp {
        sport: be16(b, 0),
        dport: be16(b, 2),
        payload: &b[UDP_HEADER_LEN..],
    })
}

/// 解釈した ICMP の message です。`body` は type と code と checksum の後ろの 4 byte からの中身です。
#[derive(Clone, Copy, Debug)]
pub(crate) struct Icmp<'a> {
    pub(crate) typ: u8,
    pub(crate) code: u8,
    /// header の後半の 4 byte (echo の識別子と番号、PMTU の値など) です。
    pub(crate) rest: u32,
    /// header の後ろの中身 (echo の data、誤りの引用) です。
    pub(crate) body: &'a [u8],
}

/// `ip` の中身を ICMP の message として解釈し、checksum を確かめます (Go の `inputICMP` の検査)。
pub(crate) fn parse_icmp<'a>(ip: &Ipv4<'a>) -> Result<Icmp<'a>, PayloadDrop> {
    let b = ip.payload();
    if b.len() < ICMP_HEADER_LEN {
        return Err(PayloadDrop::Malformed);
    }
    if !checksum(0, b) != 0 {
        return Err(PayloadDrop::BadChecksum);
    }
    Ok(Icmp {
        typ: b[0],
        code: b[1],
        rest: be32(b, 4),
        body: &b[ICMP_HEADER_LEN..],
    })
}

/// `b[..20]` に option の無い IPv4 の header を書きます。DF を立て、TTL は 64 です。
pub(crate) fn write_ipv4_header(
    b: &mut [u8],
    total: usize,
    id: u16,
    proto: u8,
    src: u32,
    dst: u32,
) {
    b[0] = 0x45;
    b[1] = 0;
    put16(b, 2, len16(total));
    put16(b, 4, id);
    put16(b, 6, 0x4000);
    b[8] = DEFAULT_TTL;
    b[9] = proto;
    b[10] = 0;
    b[11] = 0;
    put32(b, 12, src);
    put32(b, 16, dst);
    let cs = !checksum(0, &b[..IP_HEADER_LEN]);
    put16(b, 10, cs);
}

/// [`write_ipv4_header`] で書いた `b[..20]` の DF を下ろし、checksum を直します。
pub(crate) fn clear_df(b: &mut [u8]) {
    set_frag_field(b, be16(b, 6) & !0x4000);
}

/// [`write_ipv4_header`] で書いた `b[..20]` の flag と断片の offset の欄 (6 から 7 byte 目) を `field` にし、
/// header の checksum を直します。
pub(crate) fn set_frag_field(b: &mut [u8], field: u16) {
    put16(b, 6, field);
    b[10] = 0;
    b[11] = 0;
    let cs = !checksum(0, &b[..IP_HEADER_LEN]);
    put16(b, 10, cs);
}

/// IPv4 の header の checksum を確かめます。`h` は option を含む header で、長さは偶数です。
pub(crate) fn ipv4_header_ok(h: &[u8]) -> bool {
    checksum(0, h) == 0xffff
}

/// IPv4 の header の checksum を書き直します。`h` は option を含む header です。
pub(crate) fn set_ipv4_checksum(h: &mut [u8]) {
    h[10] = 0;
    h[11] = 0;
    let cs = !checksum(0, h);
    put16(h, 10, cs);
}

/// 組み立てる TCP の header の値です。
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TcpHeader {
    pub(crate) tup: Tuple,
    pub(crate) seq: u32,
    pub(crate) ack: u32,
    pub(crate) flags: u8,
    pub(crate) wnd: u16,
}

/// TCP の option を固定の枠に書きます。
#[derive(Clone, Copy, Debug)]
pub(crate) struct OptWriter {
    b: [u8; MAX_OPTION_LEN],
    n: usize,
}

impl Default for OptWriter {
    fn default() -> Self {
        Self {
            b: [0; MAX_OPTION_LEN],
            n: 0,
        }
    }
}

impl OptWriter {
    pub(crate) fn len(&self) -> usize {
        self.n
    }

    pub(crate) fn mss(&mut self, v: u16) {
        self.b[self.n..self.n + 2].copy_from_slice(&[2, 4]);
        put16(&mut self.b, self.n + 2, v);
        self.n += 4;
    }

    /// Linux と同じ並び (SACK-perm、TS) で書きます。
    pub(crate) fn sack_perm_with_ts(&mut self, ts_val: u32, ts_ecr: u32) {
        self.b[self.n..self.n + 4].copy_from_slice(&[4, 2, 8, 10]);
        put32(&mut self.b, self.n + 4, ts_val);
        put32(&mut self.b, self.n + 8, ts_ecr);
        self.n += 12;
    }

    pub(crate) fn ts(&mut self, ts_val: u32, ts_ecr: u32) {
        self.b[self.n..self.n + 4].copy_from_slice(&[1, 1, 8, 10]);
        put32(&mut self.b, self.n + 4, ts_val);
        put32(&mut self.b, self.n + 8, ts_ecr);
        self.n += 12;
    }

    pub(crate) fn sack_perm(&mut self) {
        self.b[self.n..self.n + 4].copy_from_slice(&[1, 1, 4, 2]);
        self.n += 4;
    }

    pub(crate) fn wscale(&mut self, v: u8) {
        self.b[self.n..self.n + 4].copy_from_slice(&[1, 3, 3, v]);
        self.n += 4;
    }

    /// SACK の block を書きます。入る数だけ書き、書いた数を返します。
    #[expect(
        clippy::cast_possible_truncation,
        reason = "at most four blocks fit, so the length is at most 34"
    )]
    pub(crate) fn sack(&mut self, blocks: &[SackBlock]) -> usize {
        let room = MAX_OPTION_LEN.saturating_sub(self.n + 4) / 8;
        let n = room.min(blocks.len());
        if n == 0 {
            return 0;
        }
        self.b[self.n..self.n + 4].copy_from_slice(&[1, 1, 5, 2 + 8 * n as u8]);
        self.n += 4;
        for s in &blocks[..n] {
            put32(&mut self.b, self.n, s.left);
            put32(&mut self.b, self.n + 4, s.right);
            self.n += 8;
        }
        n
    }

    /// option の長さを 4 の倍数にします。
    pub(crate) fn pad(&mut self) {
        while !self.n.is_multiple_of(4) {
            self.b[self.n] = 0;
            self.n += 1;
        }
    }
}

/// `b` に IPv4 と TCP の header と option を書き、中身を置く位置を返します。呼び手は中身を
/// `b[off..off + pay_len]` に書いた後に [`finish_tcp`] を呼びます。`b` は全体が入る長さを持ちます。
#[expect(
    clippy::cast_possible_truncation,
    reason = "the TCP header is at most 60 bytes"
)]
pub(crate) fn write_tcp(
    b: &mut [u8],
    id: u16,
    h: &TcpHeader,
    opts: Option<&mut OptWriter>,
    pay_len: usize,
) -> usize {
    let opts = opts.map(|o| {
        o.pad();
        &*o
    });
    let opt_len = opts.map_or(0, OptWriter::len);
    let thl = TCP_HEADER_LEN + opt_len;
    let total = IP_HEADER_LEN + thl + pay_len;
    write_ipv4_header(b, total, id, PROTO_TCP, h.tup.laddr, h.tup.raddr);
    let t = &mut b[IP_HEADER_LEN..];
    put16(t, 0, h.tup.lport);
    put16(t, 2, h.tup.rport);
    put32(t, 4, h.seq);
    put32(t, 8, h.ack);
    t[12] = ((thl / 4) as u8) << 4;
    t[13] = h.flags;
    put16(t, 14, h.wnd);
    t[16..20].fill(0);
    if let Some(o) = opts {
        t[TCP_HEADER_LEN..thl].copy_from_slice(&o.b[..opt_len]);
    }
    IP_HEADER_LEN + thl
}

/// `b[..total]` の TCP の checksum を書き、packet の長さを返します。
pub(crate) fn finish_tcp(b: &mut [u8]) -> usize {
    let total = usize::from(be16(b, 2));
    let src = be32(b, 12);
    let dst = be32(b, 16);
    let t = &mut b[IP_HEADER_LEN..total];
    let cs = !checksum(pseudo_sum(src, dst, PROTO_TCP, t.len()), t);
    put16(t, 16, cs);
    total
}

/// ICMP の message `m` の checksum の欄を 0 にしてから、`m` 全体の checksum を書きます。
pub(crate) fn finish_icmp(m: &mut [u8]) {
    m[2] = 0;
    m[3] = 0;
    let cs = !checksum(0, m);
    put16(m, 2, cs);
}

/// `b[..8]` に UDP の header を書きます。checksum の欄は `csum` で、0 は Go と同じく 0xffff にして送ります
/// (RFC 768)。
pub(crate) fn write_udp_header(b: &mut [u8], sport: u16, dport: u16, ulen: usize, csum: u16) {
    put16(b, 0, sport);
    put16(b, 2, dport);
    put16(b, 4, len16(ulen));
    put16(b, 6, if csum == 0 { 0xffff } else { csum });
}

/// 解釈の入口をすべて通します。`parse` の fuzz の target と、その回帰の試験が呼びます。
/// Go の `FuzzParse` と同じく checksum を定義どおりの和と照らし、IPv4 と中身の解釈を通します。
/// 加えて、断片の再組み立ての表にも渡します。
#[cfg(any(test, fuzzing))]
pub(crate) fn fuzz_parse(b: &[u8]) {
    /// 2 byte ずつ足す定義どおりの和 (RFC 1071)。
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the folded sum fits in 16 bits"
    )]
    fn reference(sum: u32, b: &[u8]) -> u16 {
        let mut s = u64::from(sum);
        let (pairs, last) = b.as_chunks::<2>();
        for p in pairs {
            s += u64::from(u16::from_be_bytes(*p));
        }
        if let [last] = last {
            s += u64::from(*last) << 8;
        }
        while s >> 16 != 0 {
            s = (s & 0xffff) + (s >> 16);
        }
        s as u16
    }
    // 初めの値は、0 のほかは 0xffff の倍数でない値にします。倍数は 1 の補数の和で 0 とほぼ同じためです。
    for s in [
        0,
        0x1234,
        0xffff_fffe,
        pseudo_sum(0x0a09_0002, 0x0a09_0001, PROTO_TCP, b.len()),
    ] {
        assert_eq!(
            checksum(s, b),
            reference(s, b),
            "checksum({s:#x}, {} bytes)",
            b.len()
        );
    }
    if let Ok(ip) = parse_ipv4(b) {
        assert!(ip.hlen >= IP_HEADER_LEN && ip.packet.len() <= b.len());
        match ip.proto {
            PROTO_TCP => {
                if let Ok(s) = parse_tcp(&ip) {
                    assert!(s.opt.nsack <= 4);
                    assert!(s.payload.len() + TCP_HEADER_LEN <= ip.payload().len());
                }
            }
            PROTO_UDP => {
                let _ = parse_udp(&ip);
            }
            PROTO_ICMP => {
                let _ = parse_icmp(&ip);
            }
            _ => {}
        }
    }
    crate::frag::fuzz_table(b);
}

#[cfg(test)]
mod tests;
