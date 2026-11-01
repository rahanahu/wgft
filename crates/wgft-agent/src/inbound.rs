//! トンネルの入口の検査。TUN の外殻が、トンネルから届いた packet を TUN に書く前に呼ぶ。
//!
//! カーネルの TUN は、届いた packet をそのままホストの TCP/IP に渡す。検査が無いと、server はホストの
//! 0.0.0.0 で待ち受けるどのサービスにも届き、`ip_forward` が 1 なら LAN にも届く。v1 の agent は
//! netstack の中で packet を終わらせるので、この面を持たない。そこで次の packet だけを通す。
//!
//! - 宛先が agent のトンネルのアドレスで、TCP の宛先のポートが今開いているルールのポートのもの。
//!   中継の接続はそのポートを使うので、確立した接続の packet もこれに当たる。ポートを閉じると、
//!   その接続の packet もここで捨てる
//! - agent のトンネルのアドレスへの ICMP の echo reply (agent の keepalive の ping の答え)
//! - 開いているルールのポートの TCP の接続を引用する ICMP の Fragmentation Needed
//!
//! 開いていないポートへの TCP の SYN には、仕様のとおり RST を返す。それ以外はすべて捨てる。最初の
//! 適用の前はポートの集まりが空なので、TCP は何も通らない。agent のアドレス以外への packet は転送
//! しない。IPv4 の断片は捨てる (試作の制限)。MSS の option が 536 より小さい SYN は、仕様のトンネルの
//! 入口の検査のとおり捨てる。

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use wgft_wireguard_tun::Verdict;

use crate::relay::OpenPorts;

const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;
const MIN_MSS: u16 = 536;

/// 検査の状態。
#[derive(Debug, Clone)]
pub struct Inbound {
    /// agent のトンネルのアドレス。
    pub addr: Ipv4Addr,
    /// 今開いている TCP のルールのポート。
    pub open: OpenPorts,
    /// 判定ごとの数。
    pub counts: Arc<Counts>,
}

/// 入口の検査の判定ごとの数。server の正しい作りは、agent のアドレス以外への packet、断片、ルールの
/// 無いポートへの packet を送らない。これらの数が増えるのは、server が乗っ取られて agent のホストや
/// LAN を探っている兆候でありうるので、数を残して 1 分に 1 回までログに出す。
#[derive(Debug, Default)]
pub struct Counts {
    /// 通した packet。
    pub delivered: AtomicU64,
    /// 宛先が agent のトンネルのアドレスでない packet。
    pub not_for_agent: AtomicU64,
    /// IPv4 の断片。
    pub fragments: AtomicU64,
    /// ルールの無いポートへの TCP (RST を返した SYN を含む)。
    pub closed_port: AtomicU64,
    /// RST を返した SYN。
    pub resets: AtomicU64,
    /// それ以外の捨てた packet (UDP、通さない ICMP、壊れた packet、小さすぎる MSS)。
    pub other: AtomicU64,
}

/// [`Counts`] の写し。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CountsSnapshot {
    /// 通した packet。
    pub delivered: u64,
    /// 宛先が agent のトンネルのアドレスでない packet。
    pub not_for_agent: u64,
    /// IPv4 の断片。
    pub fragments: u64,
    /// ルールの無いポートへの TCP。
    pub closed_port: u64,
    /// RST を返した SYN。
    pub resets: u64,
    /// それ以外の捨てた packet。
    pub other: u64,
}

impl CountsSnapshot {
    /// 捨てたか RST を返した packet の数。
    #[must_use]
    pub fn refused(&self) -> u64 {
        self.not_for_agent + self.fragments + self.closed_port + self.other
    }
}

impl Counts {
    /// 今の値を読む。
    #[must_use]
    pub fn snapshot(&self) -> CountsSnapshot {
        let r = |a: &AtomicU64| a.load(Ordering::Relaxed);
        CountsSnapshot {
            delivered: r(&self.delivered),
            not_for_agent: r(&self.not_for_agent),
            fragments: r(&self.fragments),
            closed_port: r(&self.closed_port),
            resets: r(&self.resets),
            other: r(&self.other),
        }
    }
}

fn bump(a: &AtomicU64) {
    a.fetch_add(1, Ordering::Relaxed);
}

struct Ip<'a> {
    proto: u8,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    payload: &'a [u8],
    fragment: bool,
}

fn parse_ip(p: &[u8]) -> Option<Ip<'_>> {
    let vihl = *p.first()?;
    if vihl >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(vihl & 0x0f) * 4;
    if ihl < 20 || p.len() < ihl {
        return None;
    }
    let total = usize::from(u16::from_be_bytes([p[2], p[3]])).min(p.len());
    if total < ihl {
        return None;
    }
    let frag = u16::from_be_bytes([p[6], p[7]]);
    Some(Ip {
        proto: p[9],
        src: Ipv4Addr::new(p[12], p[13], p[14], p[15]),
        dst: Ipv4Addr::new(p[16], p[17], p[18], p[19]),
        payload: &p[ihl..total],
        // MF の印か、0 でない fragment offset
        fragment: frag & 0x3fff != 0,
    })
}

impl Inbound {
    fn is_open(&self, port: u16) -> bool {
        self.open
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&port)
    }

    /// 1 つの packet の扱いを決め、判定を数える。
    #[must_use]
    pub fn verdict(&self, packet: &[u8]) -> Verdict {
        let c = &self.counts;
        let Some(ip) = parse_ip(packet) else {
            bump(&c.other);
            return Verdict::Drop;
        };
        if ip.dst != self.addr {
            bump(&c.not_for_agent);
            return Verdict::Drop;
        }
        if ip.fragment {
            bump(&c.fragments);
            return Verdict::Drop;
        }
        let v = match ip.proto {
            PROTO_TCP => self.tcp(&ip),
            PROTO_ICMP => self.icmp(&ip),
            _ => Verdict::Drop,
        };
        match &v {
            Verdict::Deliver => bump(&c.delivered),
            Verdict::Reply(_) => {
                bump(&c.resets);
                bump(&c.closed_port);
            }
            Verdict::Drop => {
                if ip.proto == PROTO_TCP && ip.payload.len() >= 4 {
                    bump(&c.closed_port);
                } else {
                    bump(&c.other);
                }
            }
        }
        v
    }

    fn tcp(&self, ip: &Ip<'_>) -> Verdict {
        let t = ip.payload;
        if t.len() < 20 || usize::from(t[12] >> 4) * 4 < 20 {
            return Verdict::Drop;
        }
        let dport = u16::from_be_bytes([t[2], t[3]]);
        let flags = t[13];
        if flags & TCP_SYN != 0 && mss(t).is_some_and(|m| m < MIN_MSS) {
            return Verdict::Drop;
        }
        if self.is_open(dport) {
            return Verdict::Deliver;
        }
        // 待ち受けの無いポートへの SYN にだけ RST を返す。ほかの segment は捨てる
        if flags & (TCP_SYN | TCP_RST | TCP_ACK | TCP_FIN) != TCP_SYN {
            return Verdict::Drop;
        }
        tcp_reset(ip).map_or(Verdict::Drop, Verdict::Reply)
    }

    fn icmp(&self, ip: &Ip<'_>) -> Verdict {
        match (ip.payload.first(), ip.payload.get(1)) {
            // keepalive の ping の答え
            (Some(0), _) => Verdict::Deliver,
            // Fragmentation Needed は、開いているポートの TCP の接続を引用し、外側の送信元が引用の宛先と
            // 同じものだけ
            (Some(3), Some(4)) => {
                let Some(q) = ip.payload.get(8..).and_then(parse_ip) else {
                    return Verdict::Drop;
                };
                let quoted_port = q.payload.get(..2).map(|b| u16::from_be_bytes([b[0], b[1]]));
                if q.proto == PROTO_TCP
                    && q.src == self.addr
                    && q.dst == ip.src
                    && quoted_port.is_some_and(|p| self.is_open(p))
                {
                    Verdict::Deliver
                } else {
                    Verdict::Drop
                }
            }
            _ => Verdict::Drop,
        }
    }
}

/// TCP の option の MSS。無ければ `None`。
fn mss(t: &[u8]) -> Option<u16> {
    let off = usize::from(t[12] >> 4) * 4;
    let mut opts = t.get(20..off)?;
    while let Some(&kind) = opts.first() {
        match kind {
            0 => return None,
            1 => opts = &opts[1..],
            _ => {
                let len = usize::from(*opts.get(1)?);
                if len < 2 || opts.len() < len {
                    return None;
                }
                if kind == 2 && len == 4 {
                    return Some(u16::from_be_bytes([opts[2], opts[3]]));
                }
                opts = &opts[len..];
            }
        }
    }
    None
}

fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut odd: Option<u8> = None;
    for p in parts {
        for &b in *p {
            match odd.take() {
                Some(hi) => sum += u32::from(u16::from_be_bytes([hi, b])),
                None => odd = Some(b),
            }
        }
    }
    if let Some(hi) = odd {
        sum += u32::from(u16::from_be_bytes([hi, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(0)
}

/// 送信元 `src` から `dst` への IPv4 の header。
fn ip_header(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload_len: usize) -> Option<[u8; 20]> {
    let total = u16::try_from(20 + payload_len).ok()?;
    let mut h = [0u8; 20];
    h[0] = 0x45;
    h[2..4].copy_from_slice(&total.to_be_bytes());
    h[8] = 64;
    h[9] = proto;
    h[12..16].copy_from_slice(&src.octets());
    h[16..20].copy_from_slice(&dst.octets());
    let c = checksum(&[&h]);
    h[10..12].copy_from_slice(&c.to_be_bytes());
    Some(h)
}

fn pseudo_header(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, len: usize) -> [u8; 12] {
    let mut p = [0u8; 12];
    p[0..4].copy_from_slice(&src.octets());
    p[4..8].copy_from_slice(&dst.octets());
    p[9] = proto;
    p[10..12].copy_from_slice(&u16::try_from(len).unwrap_or(0).to_be_bytes());
    p
}

/// 待ち受けの無いポートへの SYN に返す RST (RFC 793)。ACK の番号は SYN の seq に、SYN と FIN を 1 と
/// 数えた segment の長さを足したもの。
fn tcp_reset(ip: &Ip<'_>) -> Option<Vec<u8>> {
    let t = ip.payload;
    let off = usize::from(t[12] >> 4) * 4;
    let flags = t[13];
    let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
    let data = u32::try_from(t.len().saturating_sub(off)).ok()?;
    let len = data + u32::from(flags & TCP_SYN != 0) + u32::from(flags & TCP_FIN != 0);
    let mut r = [0u8; 20];
    r[0..2].copy_from_slice(&t[2..4]);
    r[2..4].copy_from_slice(&t[0..2]);
    r[8..12].copy_from_slice(&seq.wrapping_add(len).to_be_bytes());
    r[12] = 5 << 4;
    r[13] = TCP_RST | TCP_ACK;
    let pseudo = pseudo_header(ip.dst, ip.src, PROTO_TCP, r.len());
    let c = checksum(&[&pseudo, &r]);
    r[16..18].copy_from_slice(&c.to_be_bytes());
    let mut out = ip_header(ip.dst, ip.src, PROTO_TCP, r.len())?.to_vec();
    out.extend_from_slice(&r);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::RwLock;

    const AGENT: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 2);
    const SERVER: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);

    fn inbound(ports: &[u16]) -> Inbound {
        Inbound {
            addr: AGENT,
            open: Arc::new(RwLock::new(ports.iter().copied().collect::<BTreeSet<_>>())),
            counts: Arc::default(),
        }
    }

    fn packet(proto: u8, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let mut p = ip_header(SERVER, dst, proto, payload.len())
            .unwrap()
            .to_vec();
        p.extend_from_slice(payload);
        p
    }

    fn tcp(dport: u16, flags: u8, seq: u32, opts: &[u8]) -> Vec<u8> {
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&40000u16.to_be_bytes());
        t[2..4].copy_from_slice(&dport.to_be_bytes());
        t[4..8].copy_from_slice(&seq.to_be_bytes());
        t[12] = u8::try_from((20 + opts.len()) / 4).unwrap() << 4;
        t[13] = flags;
        t.extend_from_slice(opts);
        t
    }

    fn drops(f: &Inbound, p: &[u8]) -> bool {
        matches!(f.verdict(p), Verdict::Drop)
    }

    fn delivers(f: &Inbound, p: &[u8]) -> bool {
        matches!(f.verdict(p), Verdict::Deliver)
    }

    #[test]
    fn delivers_tcp_to_an_open_port_only_at_the_agent_address() {
        let f = inbound(&[8080]);
        assert!(delivers(
            &f,
            &packet(PROTO_TCP, AGENT, &tcp(8080, TCP_SYN, 1, &[]))
        ));
        assert!(delivers(
            &f,
            &packet(PROTO_TCP, AGENT, &tcp(8080, TCP_ACK, 5, &[]))
        ));
        // agent のアドレス以外へは転送しない
        let lan = Ipv4Addr::new(192, 168, 1, 10);
        assert!(drops(
            &f,
            &packet(PROTO_TCP, lan, &tcp(8080, TCP_SYN, 1, &[]))
        ));
    }

    #[test]
    fn counts_each_decision() {
        let f = inbound(&[8080]);
        let _ = f.verdict(&packet(PROTO_TCP, AGENT, &tcp(8080, TCP_SYN, 1, &[])));
        let _ = f.verdict(&packet(PROTO_TCP, AGENT, &tcp(22, TCP_SYN, 1, &[])));
        let _ = f.verdict(&packet(PROTO_TCP, AGENT, &tcp(22, TCP_ACK, 1, &[])));
        let _ = f.verdict(&packet(
            PROTO_TCP,
            Ipv4Addr::new(192, 168, 1, 1),
            &tcp(80, TCP_SYN, 1, &[]),
        ));
        let _ = f.verdict(&packet(17, AGENT, &[0; 8]));
        let c = f.counts.snapshot();
        assert_eq!(
            c,
            CountsSnapshot {
                delivered: 1,
                not_for_agent: 1,
                fragments: 0,
                closed_port: 2,
                resets: 1,
                other: 1
            }
        );
        assert_eq!(c.refused(), 4);
    }

    #[test]
    fn nothing_tcp_passes_before_the_first_apply() {
        let f = inbound(&[]);
        assert!(drops(
            &f,
            &packet(PROTO_TCP, AGENT, &tcp(8080, TCP_ACK, 1, &[]))
        ));
    }

    #[test]
    fn closing_a_port_drops_its_flows() {
        let f = inbound(&[8080]);
        let p = packet(PROTO_TCP, AGENT, &tcp(8080, TCP_ACK, 1, &[]));
        assert!(delivers(&f, &p));
        f.open.write().unwrap().clear();
        assert!(drops(&f, &p));
    }

    #[test]
    fn answers_rst_to_a_syn_for_a_closed_port() {
        let f = inbound(&[8080]);
        let Verdict::Reply(r) = f.verdict(&packet(PROTO_TCP, AGENT, &tcp(22, TCP_SYN, 1000, &[])))
        else {
            panic!("no reply")
        };
        let ip = parse_ip(&r).unwrap();
        assert_eq!((ip.src, ip.dst, ip.proto), (AGENT, SERVER, PROTO_TCP));
        assert_eq!(checksum(&[&r[..20]]), 0);
        let t = ip.payload;
        assert_eq!(u16::from_be_bytes([t[0], t[1]]), 22);
        assert_eq!(u16::from_be_bytes([t[2], t[3]]), 40000);
        assert_eq!(t[13], TCP_RST | TCP_ACK);
        assert_eq!(u32::from_be_bytes([t[8], t[9], t[10], t[11]]), 1001);
        let pseudo = pseudo_header(ip.src, ip.dst, PROTO_TCP, t.len());
        assert_eq!(checksum(&[&pseudo, t]), 0);
    }

    #[test]
    fn other_segments_to_a_closed_port_are_dropped() {
        let f = inbound(&[8080]);
        for flags in [TCP_ACK, TCP_RST, TCP_SYN | TCP_ACK, TCP_FIN | TCP_ACK] {
            assert!(
                drops(&f, &packet(PROTO_TCP, AGENT, &tcp(22, flags, 1, &[]))),
                "{flags:#x}"
            );
        }
    }

    #[test]
    fn drops_syn_with_a_small_mss() {
        let f = inbound(&[8080]);
        let small = [2u8, 4, 0x02, 0x00]; // MSS 512
        let ok = [2u8, 4, 0x05, 0x8c]; // MSS 1420
        assert!(drops(
            &f,
            &packet(PROTO_TCP, AGENT, &tcp(8080, TCP_SYN, 1, &small))
        ));
        assert!(delivers(
            &f,
            &packet(PROTO_TCP, AGENT, &tcp(8080, TCP_SYN, 1, &ok))
        ));
    }

    #[test]
    fn icmp_echo_reply_and_frag_needed_for_open_flows_only() {
        let f = inbound(&[8080]);
        assert!(delivers(
            &f,
            &packet(PROTO_ICMP, AGENT, &[0, 0, 0, 0, 0, 1, 0, 1])
        ));
        assert!(drops(
            &f,
            &packet(PROTO_ICMP, AGENT, &[8, 0, 0, 0, 0, 1, 0, 1])
        ));
        // agent の 8080 から server への TCP を引用する Fragmentation Needed
        let mut quoted = ip_header(AGENT, SERVER, PROTO_TCP, 8).unwrap().to_vec();
        quoted.extend_from_slice(&[0x1f, 0x90, 0x9c, 0x40, 0, 0, 0, 0]);
        let mut err = vec![3u8, 4, 0, 0, 0, 0, 0x05, 0x00];
        err.extend_from_slice(&quoted);
        assert!(delivers(&f, &packet(PROTO_ICMP, AGENT, &err)));
        assert!(drops(&inbound(&[]), &packet(PROTO_ICMP, AGENT, &err)));
        let mut port_unreach = err.clone();
        port_unreach[1] = 3;
        assert!(drops(&f, &packet(PROTO_ICMP, AGENT, &port_unreach)));
        assert!(drops(
            &f,
            &packet(PROTO_ICMP, AGENT, &[11, 0, 0, 0, 0, 0, 0, 0])
        ));
        assert!(drops(
            &f,
            &packet(PROTO_ICMP, AGENT, &[5, 0, 0, 0, 0, 0, 0, 0])
        ));
    }

    #[test]
    fn udp_fragments_and_malformed_packets_are_dropped() {
        let f = inbound(&[8080]);
        assert!(drops(
            &f,
            &packet(17, AGENT, &[0x9c, 0x40, 0x1f, 0x90, 0, 9, 0, 0, b'x'])
        ));
        let mut frag = packet(PROTO_TCP, AGENT, &tcp(8080, TCP_ACK, 1, &[]));
        frag[6] = 0x20; // MF
        assert!(drops(&f, &frag));
        let mut later = packet(PROTO_TCP, AGENT, &tcp(8080, TCP_ACK, 1, &[]));
        later[7] = 1; // fragment offset 8
        assert!(drops(&f, &later));
        assert!(drops(&f, &[0x60; 40]));
        assert!(drops(&f, &[0x45; 10]));
        let mut bad_ihl = packet(PROTO_TCP, AGENT, &tcp(8080, TCP_SYN, 1, &[]));
        bad_ihl[0] = 0x4f;
        assert!(drops(&f, &bad_ihl[..30]));
        let mut short_tcp = packet(PROTO_TCP, AGENT, &tcp(8080, TCP_ACK, 1, &[]));
        short_tcp[20 + 12] = 0x10; // data offset 4 byte
        assert!(drops(&f, &short_tcp));
    }
}
