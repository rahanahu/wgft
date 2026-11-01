//! server がエージェントに配る全体状態 (Go の `proto/state.go`)。

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::join::split_host_port;

/// 全体状態の wg の節。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgConfig {
    /// server の WireGuard の公開鍵 (base64)。
    #[serde(default)]
    pub server_pubkey: String,
    /// server の WireGuard の `host:port`。
    #[serde(default)]
    pub endpoint: String,
    /// エージェントのトンネルのアドレス。`10.200.0.2/24` の形。
    #[serde(default)]
    pub address: String,
    /// MTU。
    #[serde(default)]
    pub mtu: i64,
    /// persistent keepalive の秒。
    #[serde(default)]
    pub keepalive: i64,
    /// server の `nf_conntrack_udp_timeout` の秒。
    #[serde(default)]
    pub udp_timeout: i64,
    /// server の `nf_conntrack_udp_timeout_stream` の秒。
    #[serde(default)]
    pub udp_timeout_stream: i64,
}

/// ルールのプロトコル。Go では任意の文字列を持てる型なので、知らない値も保つ。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Proto {
    /// `tcp`
    Tcp,
    /// `udp`
    Udp,
    /// それ以外の値。エージェントは転送しない。
    Other(String),
}

impl Proto {
    /// JSON に書く文字列。
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Other(s) => s,
        }
    }
}

impl Serialize for Proto {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Proto {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(match s.as_str() {
            "tcp" => Proto::Tcp,
            "udp" => Proto::Udp,
            _ => Proto::Other(s),
        })
    }
}

/// 待ち受けるポートの範囲。JSON では `"2456"` か `"2456-2457"` の文字列。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PortRange {
    /// 先頭のポート。
    pub lo: u16,
    /// 末尾のポート。単一のポートなら `lo` と同じ。
    pub hi: u16,
}

/// ポートの範囲の誤り。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortRangeError(String);

impl fmt::Display for PortRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PortRangeError {}

fn parse_port(s: &str) -> Result<u16, PortRangeError> {
    let t = s.trim_matches(char::is_whitespace);
    match t.parse::<u16>() {
        Ok(n) if n != 0 && t.bytes().all(|c| c.is_ascii_digit()) => Ok(n),
        _ => Err(PortRangeError(format!(
            "port {s:?} is not an integer in 1-65535"
        ))),
    }
}

impl FromStr for PortRange {
    type Err = PortRangeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (lo, hi) = s.split_once('-').unwrap_or((s, s));
        let lo = parse_port(lo)?;
        let hi = parse_port(hi)?;
        if lo > hi {
            return Err(PortRangeError(format!(
                "port range {s:?} has a start greater than its end"
            )));
        }
        Ok(PortRange { lo, hi })
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.lo == self.hi {
            write!(f, "{}", self.lo)
        } else {
            write!(f, "{}-{}", self.lo, self.hi)
        }
    }
}

impl PortRange {
    /// `p` が範囲に入るかどうか。
    #[must_use]
    pub fn contains(&self, p: u16) -> bool {
        self.lo <= p && p <= self.hi
    }

    /// 範囲のポートを順に返す。
    pub fn ports(&self) -> impl Iterator<Item = u16> {
        self.lo..=self.hi
    }
}

impl Serialize for PortRange {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PortRange {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// エージェントに配るルール。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRule {
    /// ルールの ID。server が ULID から作る不透明な文字列。
    pub id: String,
    /// プロトコル。
    pub proto: Proto,
    /// エージェントがトンネルの中で待ち受けるポートの範囲。
    pub listen_port: PortRange,
    /// 宛先の `host:port`。範囲のルールでは先頭のポートに当たる。
    pub target: String,
    /// 有効かどうか。
    #[serde(default)]
    pub enabled: bool,
}

impl AgentRule {
    /// 範囲の中のポート `p` に当たる実効宛先 (Go の `EffectiveTarget`)。範囲の外か、宛先の形が
    /// 崩れているか、宛先のポートが 65535 を超えるなら `None`。
    #[must_use]
    pub fn effective_target(&self, p: u16) -> Option<(String, u16)> {
        if !self.listen_port.contains(p) {
            return None;
        }
        let (host, port) = split_target(&self.target)?;
        let eff = u32::from(port) + u32::from(p - self.listen_port.lo);
        let eff = u16::try_from(eff).ok()?;
        Some((host.to_owned(), eff))
    }
}

/// Go の `splitTarget`。IPv4 に写した IPv6 でない IPv6 のアドレスは拒む (Go の `net.ParseIP` と `To4`)。
fn split_target(target: &str) -> Option<(&str, u16)> {
    let (host, port) = split_host_port(target.as_bytes())?;
    // split_host_port は ASCII の区切りで切るので、どちらも target の str の境目に当たる
    let host = str::from_utf8(host).ok()?;
    let port = str::from_utf8(port).ok()?;
    if host.is_empty() {
        return None;
    }
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>()
        && v6.to_ipv4_mapped().is_none()
    {
        return None;
    }
    if !port.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    match port.parse::<u16>() {
        Ok(n) if n != 0 => Some((host, n)),
        _ => None,
    }
}

/// `null` を空の列として読む (Go の nil の slice は `null` で書かれる)。
pub(crate) fn null_as_empty<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

/// server がエージェントに配る全体状態。差分ではなく常に全体。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// 世代。
    #[serde(default)]
    pub generation: u64,
    /// wg の設定。
    #[serde(default)]
    pub wg: WgConfig,
    /// ルール。
    #[serde(default, deserialize_with = "null_as_empty")]
    pub rules: Vec<AgentRule>,
    /// その stream で server が選んだ版。legacy v0 の server は載せない。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_protocol_version: Option<i64>,
    /// server の capability。無いことと空の列を区別する。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_capabilities: Option<Vec<String>>,
    /// server がこのエージェントを無効にしているか。診断のためだけにある。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub agent_disabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_range_text_form() {
        assert_eq!(
            "2456".parse::<PortRange>().unwrap(),
            PortRange { lo: 2456, hi: 2456 }
        );
        assert_eq!(
            " 2456 - 2457".parse::<PortRange>().unwrap(),
            PortRange { lo: 2456, hi: 2457 }
        );
        for bad in ["0", "2457-2456", "", "65536", "+1", "1-"] {
            assert!(bad.parse::<PortRange>().is_err(), "{bad}");
        }
        assert_eq!(PortRange { lo: 1, hi: 3 }.to_string(), "1-3");
    }

    #[test]
    fn effective_target_offsets_into_the_range() {
        let r = AgentRule {
            id: "r_1".into(),
            proto: Proto::Tcp,
            listen_port: "2456-2458".parse().unwrap(),
            target: "192.168.1.10:3000".into(),
            enabled: true,
        };
        assert_eq!(
            r.effective_target(2457),
            Some(("192.168.1.10".into(), 3001))
        );
        assert_eq!(r.effective_target(2459), None);
        let edge = AgentRule {
            target: "h:65535".into(),
            ..r.clone()
        };
        assert_eq!(edge.effective_target(2457), None);
        let v6 = AgentRule {
            target: "[2001:db8::1]:80".into(),
            ..r
        };
        assert_eq!(v6.effective_target(2456), None);
    }

    #[test]
    fn null_rules_and_unknown_fields() {
        let st: State = serde_json::from_str(
            r#"{"generation":3,"wg":{"server_pubkey":"k","endpoint":"e:1","address":"10.200.0.2/24","mtu":1420,"keepalive":25,"udp_timeout":30,"udp_timeout_stream":120},"rules":null,"future":1}"#,
        )
        .unwrap();
        assert_eq!(st.rules, vec![]);
        assert_eq!(st.server_protocol_version, None);
        assert_eq!(st.server_capabilities, None);
    }

    #[test]
    fn capabilities_absent_and_empty_differ() {
        let st: State =
            serde_json::from_str(r#"{"server_protocol_version":1,"server_capabilities":[]}"#)
                .unwrap();
        assert_eq!(st.server_capabilities, Some(vec![]));
        let out = serde_json::to_string(&st).unwrap();
        assert!(out.contains(r#""server_capabilities":[]"#), "{out}");
        let none = serde_json::to_string(&State::default()).unwrap();
        assert!(
            !none.contains("server_capabilities") && !none.contains("agent_disabled"),
            "{none}"
        );
    }
}
