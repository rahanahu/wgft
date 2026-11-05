//! Hash S の振り分け (試作、independent-exploration.md の 6.8.2 節の規則 R0)。
//!
//! 鍵は向きによらない (トンネルの番号、protocol、ローカルのポート、相手のアドレス、相手のポート) で、受けた packet
//! では (dst のポート、src、src のポート)、送る packet では (src のポート、dst、dst のポート) から作る。agent の側は
//! いつも 1 つのアドレスなので、行きと戻りは同じ区画に着く。hash は起動ごとの乱数の鍵の SipHash (標準の
//! `RandomState`) で、核の ISN、timestamp、cookie の鍵とは別の値である。
//!
//! 区画 0 に送るもの:UDP、ICMP (TCP を引用する誤りを除く)、知らない protocol、自分のアドレス宛てでない packet、
//! 解釈できない packet。TCP の断片は試作では捨てて数える (E2 の範囲)。

use std::hash::{BuildHasher, RandomState};

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;

/// ICMP の誤りの型:宛先に届かない、発信元の抑制、時間切れ、引数の問題。
fn is_icmp_error(t: u8) -> bool {
    matches!(t, 3 | 4 | 11 | 12)
}

/// 受けた packet の行き先。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Route {
    /// 区画の番号。
    Part(usize),
    /// TCP の断片。試作は組み立てずに捨てて数える。
    TcpFragment,
}

/// 振り分けの鍵と区画の数。世代の中で変えない。
#[derive(Clone, Debug)]
pub(crate) struct Steer {
    hasher: RandomState,
    parts: usize,
    /// 自分のトンネルのアドレス (network の順の値)。
    addr: u32,
}

impl Steer {
    /// `parts` 個の区画に、トンネルのアドレス `addr` の packet を振る。鍵は起動ごとの乱数である。
    pub(crate) fn new(parts: usize, addr: std::net::Ipv4Addr) -> Self {
        Self {
            hasher: RandomState::new(),
            parts: parts.max(1),
            addr: addr.to_bits(),
        }
    }

    /// 区画の数。
    #[cfg(test)]
    pub(crate) fn parts(&self) -> usize {
        self.parts
    }

    /// TCP の流れの区画。区画 0 から P - 1 に一様に振る (E2a)。
    fn tcp(&self, tunnel: u16, lport: u16, raddr: u32, rport: u16) -> usize {
        let h = self
            .hasher
            .hash_one((tunnel, IPPROTO_TCP, lport, raddr, rport));
        // 掛けて上位を取る。剰余より偏りが小さい
        ((u128::from(h) * self.parts as u128) >> 64) as usize
    }

    /// トンネル `tunnel` から受けた復号済みの IPv4 の packet の行き先。
    pub(crate) fn inbound(&self, tunnel: u16, p: &[u8]) -> Route {
        let Some(h) = Header::parse(p) else {
            return Route::Part(0);
        };
        if h.dst != self.addr {
            return Route::Part(0);
        }
        match h.proto {
            IPPROTO_TCP => {
                if h.fragment {
                    return Route::TcpFragment;
                }
                match ports(p, h.ihl) {
                    Some((sport, dport)) => Route::Part(self.tcp(tunnel, dport, h.src, sport)),
                    None => Route::Part(0),
                }
            }
            IPPROTO_ICMP if !h.fragment => Route::Part(self.icmp(tunnel, &p[h.ihl..])),
            _ => Route::Part(0),
        }
    }

    /// ICMP の誤りが引用する内側の TCP の header から区画を決める。引用は自分が送った packet なので、引用の src
    /// が自分、src のポートがローカルのポートである。
    fn icmp(&self, tunnel: u16, icmp: &[u8]) -> usize {
        if icmp.len() < 8 || !is_icmp_error(icmp[0]) {
            return 0;
        }
        let quoted = &icmp[8..];
        let Some(h) = Header::parse_quoted(quoted) else {
            return 0;
        };
        if h.proto != IPPROTO_TCP || h.fragment || h.src != self.addr {
            return 0;
        }
        match ports(quoted, h.ihl) {
            Some((sport, dport)) => self.tcp(tunnel, sport, h.dst, dport),
            None => 0,
        }
    }

    /// 区画が送る packet の区画 (試験が行きと戻りの一致を確かめる)。TCP 以外は 0。
    #[cfg(test)]
    pub(crate) fn outbound(&self, tunnel: u16, p: &[u8]) -> usize {
        let Some(h) = Header::parse(p) else {
            return 0;
        };
        if h.proto != IPPROTO_TCP || h.src != self.addr {
            return 0;
        }
        match ports(p, h.ihl) {
            Some((sport, dport)) => self.tcp(tunnel, sport, h.dst, dport),
            None => 0,
        }
    }
}

/// IPv4 の header の、振り分けに要る欄。
struct Header {
    ihl: usize,
    proto: u8,
    /// MF か断片の位置が 0 でない。
    fragment: bool,
    src: u32,
    dst: u32,
}

impl Header {
    /// 版 4、IHL が 5 以上で、header が収まり、全長が header 以上の packet。
    fn parse(p: &[u8]) -> Option<Self> {
        let h = Self::parse_quoted(p)?;
        let total = usize::from(u16::from_be_bytes([p[2], p[3]]));
        (total >= h.ihl && total <= p.len()).then_some(h)
    }

    /// 引用の header。全長は確かめない (引用は切られている)。
    fn parse_quoted(p: &[u8]) -> Option<Self> {
        if p.len() < 20 || p[0] >> 4 != 4 {
            return None;
        }
        let ihl = usize::from(p[0] & 0x0f) * 4;
        if ihl < 20 || p.len() < ihl {
            return None;
        }
        let frag = u16::from_be_bytes([p[6], p[7]]);
        Some(Self {
            ihl,
            proto: p[9],
            fragment: frag & 0x3fff != 0,
            src: u32::from_be_bytes([p[12], p[13], p[14], p[15]]),
            dst: u32::from_be_bytes([p[16], p[17], p[18], p[19]]),
        })
    }
}

/// 層 4 の (src のポート、dst のポート)。
fn ports(p: &[u8], ihl: usize) -> Option<(u16, u16)> {
    let l4 = p.get(ihl..ihl + 4)?;
    Some((
        u16::from_be_bytes([l4[0], l4[1]]),
        u16::from_be_bytes([l4[2], l4[3]]),
    ))
}
