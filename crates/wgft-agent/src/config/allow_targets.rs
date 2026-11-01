//! `WGFT_AGENT_ALLOW_TARGETS` の値の解釈 (仕様 `cli-config.md` の同名の項と `testdata/spec/config/allow-targets.json`)。
//!
//! 形は `CIDR`、`CIDR:ポート`、`CIDR:下限-上限` をコンマで並べたもの。アドレスと CIDR の解釈は Go の
//! `net/netip` に従う。v1 が受けた `agent.env` を拒むと更新で止まるので、受け付ける集合を Go に合わせる。
//! 宛先が一覧に入るかの判定は [`AllowList::allows`] で、中継の宛先の規則 (`targets`) が使う。

use std::fmt::{self, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::gostd::quote;

/// 設定の名前。
pub const ENV: &str = "WGFT_AGENT_ALLOW_TARGETS";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ip {
    V4(u32),
    V6(u128),
}

/// 一覧の 1 項目。`lo` が 0 なら全ポートを許す。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    ip: Ip,
    bits: u8,
    lo: u16,
    hi: u16,
}

/// 宛先の許可一覧。順序と重複は書いたままである。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowList {
    entries: Vec<Entry>,
}

impl AllowList {
    /// 宛先 `addr` の `port` への接続を許すか。Go の `List.Allows` と同じく、IPv4 を写した IPv6 の
    /// アドレスは IPv4 として判定し、アドレスの族が違う項目には当てない。
    #[must_use]
    pub fn allows(&self, addr: IpAddr, port: u16) -> bool {
        let ip = match addr.to_canonical() {
            IpAddr::V4(a) => Ip::V4(a.into()),
            IpAddr::V6(a) => Ip::V6(a.into()),
        };
        self.entries.iter().any(|e| {
            let same_family = matches!((ip, e.ip), (Ip::V4(_), Ip::V4(_)) | (Ip::V6(_), Ip::V6(_)));
            same_family && mask(ip, e.bits) == e.ip && (e.lo == 0 || (e.lo..=e.hi).contains(&port))
        })
    }
}

impl fmt::Display for AllowList {
    /// 正規化した一覧。コンマ区切りで、起動ログに出す。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, e) in self.entries.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{e}")?;
        }
        Ok(())
    }
}

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v6 = matches!(self.ip, Ip::V6(_));
        if self.lo != 0 && v6 {
            f.write_str("[")?;
        }
        match self.ip {
            Ip::V4(a) => write!(f, "{}/{}", Ipv4Addr::from(a), self.bits)?,
            Ip::V6(a) => write!(f, "{}/{}", format_v6(a), self.bits)?,
        }
        if self.lo == 0 {
            return Ok(());
        }
        f.write_str(if v6 { "]:" } else { ":" })?;
        if self.lo == self.hi {
            write!(f, "{}", self.lo)
        } else {
            write!(f, "{}-{}", self.lo, self.hi)
        }
    }
}

/// Go の `netip.Addr.String` の IPv6。小文字で、2 つ以上続く 0 の最長の並びを `::` にする (同じ長さなら先頭)。
/// Rust の `Display` は IPv4 を写したアドレスを別の形で書くので使わない。
pub(crate) fn format_v6(a: u128) -> String {
    let groups: [u16; 8] = std::array::from_fn(|i| ((a >> (112 - 16 * i)) & 0xffff) as u16);
    let (mut best_at, mut best_len) = (0, 0);
    let mut i = 0;
    while i < 8 {
        let mut j = i;
        while j < 8 && groups[j] == 0 {
            j += 1;
        }
        if j - i >= 2 && j - i > best_len {
            (best_at, best_len) = (i, j - i);
        }
        i = j.max(i + 1);
    }
    let mut out = String::new();
    let mut i = 0;
    while i < 8 {
        if best_len > 0 && i == best_at {
            out.push_str("::");
            i += best_len;
            continue;
        }
        if !out.is_empty() && !out.ends_with(':') {
            out.push(':');
        }
        let _ = write!(out, "{:x}", groups[i]);
        i += 1;
    }
    out
}

/// 値を読む。空 (空白だけを含む) は制限しないことを表す `None`。項目が 1 つも無い値は誤りで、書いたつもりの
/// 一覧が黙って「制限なし」になるより、起動を止めるほうが安全である。誤りは最初に誤った項目で止まる。
pub fn parse(s: &str) -> Result<Option<AllowList>, String> {
    if s.trim().is_empty() {
        return Ok(None);
    }
    let mut entries = Vec::new();
    for f in s.split(',') {
        let f = f.trim();
        if f.is_empty() {
            continue;
        }
        entries.push(parse_entry(f)?);
    }
    if entries.is_empty() {
        return Err(format!(
            "{ENV}: {} has no entries; leave it unset to allow every target",
            quote(s)
        ));
    }
    Ok(Some(AllowList { entries }))
}

fn entry_err(whole: &str, what: &str) -> String {
    format!("{ENV}: entry {} {what}", quote(whole))
}

fn parse_entry(s: &str) -> Result<Entry, String> {
    let (addr_part, port_part) = if let Some(rest) = s.strip_prefix('[') {
        let Some(i) = rest.find(']') else {
            return Err(entry_err(s, "has no closing bracket"));
        };
        let after = &rest[i + 1..];
        let port = if after.is_empty() {
            ""
        } else if let Some(p) = after.strip_prefix(':') {
            p
        } else {
            return Err(entry_err(s, "has trailing text after the brackets"));
        };
        (&rest[..i], port)
    } else if s.matches(':').count() == 1 {
        s.split_once(':').unwrap_or((s, ""))
    } else {
        // コロンが無いか、ポートの無い IPv6 の項目。ポートを付けるなら角括弧が要る
        (s, "")
    };
    let (ip, bits) = parse_prefix(s, addr_part)?;
    if port_part.is_empty() {
        return Ok(Entry {
            ip,
            bits,
            lo: 0,
            hi: 0,
        });
    }
    let (lo, hi) = parse_ports(s, port_part)?;
    Ok(Entry { ip, bits, lo, hi })
}

const NOT_CIDR: &str = "is not a CIDR, CIDR:port or CIDR:lo-hi";

fn parse_prefix(whole: &str, addr_part: &str) -> Result<(Ip, u8), String> {
    let (ip, bits) = if let Some(slash) = addr_part.rfind('/') {
        let (a, zone) =
            parse_addr(&addr_part[..slash]).ok_or_else(|| entry_err(whole, NOT_CIDR))?;
        // ゾーンは接頭辞に付けられない
        if zone {
            return Err(entry_err(whole, NOT_CIDR));
        }
        let bits_str = &addr_part[slash + 1..];
        // Atoi は符号と先頭の 0 を受けるが、netip は受けない
        if bits_str.len() > 1 && !matches!(bits_str.as_bytes()[0], b'1'..=b'9') {
            return Err(entry_err(whole, NOT_CIDR));
        }
        let max = if matches!(a, Ip::V4(_)) { 32 } else { 128 };
        let bits = super::gostd::atoi(bits_str)
            .filter(|b| (0..=max).contains(b))
            .and_then(|b| u8::try_from(b).ok())
            .ok_or_else(|| entry_err(whole, NOT_CIDR))?;
        (mask(a, bits), bits)
    } else {
        let (a, zone) = parse_addr(addr_part).ok_or_else(|| entry_err(whole, NOT_CIDR))?;
        if zone {
            return Err(entry_err(whole, "must not carry an IPv6 zone"));
        }
        (a, if matches!(a, Ip::V4(_)) { 32 } else { 128 })
    };
    // IPv4 を写した IPv6 (::ffff:0:0/96)。接頭辞は掛けた後のアドレスで判定する (Go と同じ順)
    if matches!(ip, Ip::V6(a) if a >> 32 == 0xffff) {
        return Err(entry_err(
            whole,
            "is an IPv4-mapped IPv6 address; write it as IPv4",
        ));
    }
    Ok((ip, bits))
}

fn mask(ip: Ip, bits: u8) -> Ip {
    match ip {
        Ip::V4(a) => Ip::V4(a & u32::MAX.checked_shl(32 - u32::from(bits)).unwrap_or(0)),
        Ip::V6(a) => Ip::V6(a & u128::MAX.checked_shl(128 - u32::from(bits)).unwrap_or(0)),
    }
}

/// `netip.ParseAddr`。ゾーンがあれば第 2 の値が真。
fn parse_addr(s: &str) -> Option<(Ip, bool)> {
    match s.chars().find(|c| matches!(c, '.' | ':' | '%'))? {
        '.' => Some((Ip::V4(s.parse::<Ipv4Addr>().ok()?.into()), false)),
        ':' => {
            let (addr, zone) = match s.split_once('%') {
                Some((a, z)) if !z.is_empty() => (a, true),
                Some(_) => return None,
                None => (s, false),
            };
            Some((Ip::V6(addr.parse::<Ipv6Addr>().ok()?.into()), zone))
        }
        _ => None,
    }
}

fn parse_ports(whole: &str, port_part: &str) -> Result<(u16, u16), String> {
    let (lo_s, hi_s) = port_part.split_once('-').unwrap_or((port_part, port_part));
    let (Some(lo), Some(hi)) = (port(lo_s), port(hi_s)) else {
        return Err(entry_err(whole, "port is not an integer in 1-65535"));
    };
    if lo > hi {
        return Err(entry_err(whole, "port range is not in lo-hi order"));
    }
    Ok((lo, hi))
}

/// `ParseUint(s, 10, 16)` で 0 を除く。符号と `_` を受けない。
fn port(s: &str) -> Option<u16> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u16>().ok().filter(|&p| p != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_v6_like_go() {
        assert_eq!(format_v6(0), "::");
        assert_eq!(format_v6(1), "::1");
        assert_eq!(format_v6(0x2001_0db8 << 96), "2001:db8::");
        // 長さが同じなら先頭の並びを縮める
        assert_eq!(
            format_v6(0x2001_0000_0000_0001_0002_0000_0000_0003),
            "2001::1:2:0:0:3"
        );
        // 長い並びを縮める
        assert_eq!(
            format_v6(0x2001_0000_0000_0001_0000_0000_0000_0001),
            "2001:0:0:1::1"
        );
        // 単独の 0 は縮めない
        assert_eq!(
            format_v6(0x2001_0db8_0001_0000_0001_0002_0003_0004),
            "2001:db8:1:0:1:2:3:4"
        );
        // 下位 32 bit が IPv4 の形でも 16 進で書く
        assert_eq!(format_v6(0x0102_0304), "::102:304");
    }

    #[test]
    fn entries_are_normalised() {
        let l = parse("10.0.0.1/8,[2001:db8::1]:80-90").unwrap().unwrap();
        assert_eq!(l.to_string(), "10.0.0.0/8,[2001:db8::1/128]:80-90");
    }

    #[test]
    fn allows_judges_the_address_family_prefix_and_ports() {
        let l = parse("10.0.0.0/8:80-90, 192.168.1.10, [2001:db8::/32]:443, [::/0]:22")
            .unwrap()
            .unwrap();
        let ok = |a: &str, p| l.allows(a.parse().unwrap(), p);
        assert!(ok("10.1.2.3", 80) && ok("10.1.2.3", 90));
        assert!(!ok("10.1.2.3", 79) && !ok("10.1.2.3", 91));
        assert!(!ok("11.0.0.1", 80));
        // ポートの無い項目はどのポートも許す
        assert!(ok("192.168.1.10", 1) && ok("192.168.1.10", 65535));
        assert!(!ok("192.168.1.11", 1));
        assert!(ok("2001:db8::5", 443) && !ok("2001:db8::5", 444));
        // IPv4 を写した IPv6 は IPv4 として判定し、IPv6 の ::/0 には入らない
        assert!(ok("::ffff:10.0.0.1", 80));
        assert!(!ok("::ffff:11.0.0.1", 22));
        assert!(ok("fe80::1", 22));
        // 族の違う 0 の帯は他の族を含まない
        let v4all = parse("0.0.0.0/0").unwrap().unwrap();
        assert!(v4all.allows("1.2.3.4".parse().unwrap(), 1));
        assert!(!v4all.allows("2001:db8::1".parse().unwrap(), 1));
    }

    #[test]
    fn prefix_bits_are_judged_like_netip() {
        for ok in ["10.0.0.0/0", "10.0.0.0/32", "::/0", "::1/128"] {
            assert!(parse(ok).is_ok(), "{ok}");
        }
        for bad in [
            "10.0.0.0/",
            "10.0.0.0/+8",
            "10.0.0.0/08",
            "10.0.0.0/-1",
            "10.0.0.0/33",
            "::/129",
            "10.0.0.0/8/8",
            "fe80::1%eth0/64",
            "fe80::1%",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }
}
