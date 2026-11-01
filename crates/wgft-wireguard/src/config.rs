//! Device の設定。v1 の agent が wireguard-go に渡す UAPI の設定と同じ情報を wgft の型で持つ。

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use crate::keys::{PrivateKey, PublicKey};

/// The smallest MTU that carries an IPv4 packet.
pub const MIN_MTU: u16 = 68;

/// The tunnel MTU of the v1 agent and server.
pub const DEFAULT_MTU: u16 = 1420;

/// The largest Unix time a device accepts, about 2^40 seconds; a larger one is a broken clock.
pub const MAX_UNIX_TIME: Duration = Duration::from_secs(1 << 40);

/// The largest packet count any queue limit may have.
pub const MAX_LIMIT_PACKETS: usize = 1 << 16;

/// The largest byte count any queue limit may have, 256 MiB.
pub const MAX_LIMIT_BYTES: usize = 256 << 20;

/// The persistent keepalive the v1 agent uses when the server sends none.
pub const DEFAULT_KEEPALIVE: Duration = Duration::from_secs(25);

/// The largest persistent keepalive, as `wg` accepts it.
pub const MAX_KEEPALIVE: Duration = Duration::from_secs(65535);

// WireGuard の論文の timer の既定値と、sanstun が上書きに課す上限
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);

/// An IPv4 network in CIDR form. Host bits are cleared when it is made, as `wg` does.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Prefix {
    addr: Ipv4Addr,
    len: u8,
}

impl Ipv4Prefix {
    /// Makes a prefix, clearing the bits past `len`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::PrefixLength`] when `len` is above 32.
    pub fn new(addr: Ipv4Addr, len: u8) -> Result<Self, ConfigError> {
        if len > 32 {
            return Err(ConfigError::PrefixLength(len));
        }
        Ok(Self {
            addr: Ipv4Addr::from_bits(u32::from(addr) & mask(len)),
            len,
        })
    }

    /// The prefix that holds exactly one address.
    #[must_use]
    pub const fn host(addr: Ipv4Addr) -> Self {
        Self { addr, len: 32 }
    }

    /// The network address.
    #[must_use]
    pub const fn addr(&self) -> Ipv4Addr {
        self.addr
    }

    /// The prefix length.
    #[must_use]
    #[expect(
        clippy::len_without_is_empty,
        reason = "the prefix length, not a container size"
    )]
    pub const fn len(&self) -> u8 {
        self.len
    }

    /// Whether the prefix holds `ip`.
    #[must_use]
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & mask(self.len) == u32::from(self.addr)
    }
}

pub(crate) const fn mask(len: u8) -> u32 {
    if len == 0 { 0 } else { u32::MAX << (32 - len) }
}

impl fmt::Debug for Ipv4Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

impl fmt::Display for Ipv4Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

impl FromStr for Ipv4Prefix {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = || ConfigError::Prefix(s.to_owned());
        let (addr, len) = match s.split_once('/') {
            Some((addr, len)) => (addr, len.parse::<u8>().map_err(|_| bad())?),
            None => (s, 32),
        };
        Self::new(addr.parse().map_err(|_| bad())?, len)
    }
}

/// One WireGuard peer.
#[derive(Debug, Clone)]
pub struct PeerConfig {
    /// The peer's public key.
    pub public_key: PublicKey,
    /// Where to send the first handshake. The device moves it when the peer roams.
    pub endpoint: Option<SocketAddr>,
    /// The inner addresses this peer may send from and that are routed to it.
    pub allowed_ips: Vec<Ipv4Prefix>,
    /// The persistent keepalive interval, 1 to 65535 seconds. As with wireguard-go, a peer with one
    /// and an endpoint is contacted as soon as the device starts, and the device starts a handshake
    /// whenever nothing has been sent to or received from the peer for one interval.
    pub persistent_keepalive: Option<Duration>,
    /// Which authenticated messages may move the endpoint.
    pub roaming: Roaming,
}

/// Which authenticated messages from a peer may move its endpoint to their source address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Roaming {
    /// WireGuard's rule: any accepted handshake or data message. For the peers of a server, whose
    /// endpoints are learned from the peers.
    Any,
    /// The agent's rule for its server: accepted data and keepalives, and the response to a
    /// handshake this side started, but not an initiation from the peer. The answer to an
    /// initiation still goes to its source. When the peer expires, the endpoint returns to the
    /// configured one. A replayed initiation therefore cannot pull the endpoint away, even after a
    /// restart has emptied sanstun's in-memory replay record.
    NotByInitiation,
}

/// Overrides of the protocol timers that sanstun lets a caller change. Unset fields keep the
/// values of the WireGuard paper. Tests shorten them; the agent leaves them unset.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProtocolTimers {
    /// `REKEY_TIMEOUT`, 5 seconds by default: the retry interval of an unanswered initiation.
    pub rekey_timeout: Option<Duration>,
    /// `KEEPALIVE_TIMEOUT`, 10 seconds by default: the delay of a passive keepalive.
    pub keepalive_timeout: Option<Duration>,
    /// `REKEY_ATTEMPT_TIME`, 90 seconds by default: how long to retry a handshake.
    pub rekey_attempt_time: Option<Duration>,
}

impl ProtocolTimers {
    /// The rekey timeout in effect.
    #[must_use]
    pub fn effective_rekey_timeout(&self) -> Duration {
        self.rekey_timeout.unwrap_or(REKEY_TIMEOUT)
    }

    /// The keepalive timeout in effect.
    #[must_use]
    pub fn effective_keepalive_timeout(&self) -> Duration {
        self.keepalive_timeout.unwrap_or(KEEPALIVE_TIMEOUT)
    }

    /// The keepalive timeout of the WireGuard paper.
    #[must_use]
    pub fn default_keepalive_timeout() -> Duration {
        KEEPALIVE_TIMEOUT
    }

    /// sanstun の上書きの前提 (0 でない、`REKEY_ATTEMPT_TIME` は 540 秒まで、`REKEY_TIMEOUT` と
    /// `KEEPALIVE_TIMEOUT` の和は 180 秒まで) を確かめる。外れた値は sanstun の debug の検査に当たる。
    fn validate(&self) -> Result<(), ConfigError> {
        for (name, value) in [
            ("rekey_timeout", self.rekey_timeout),
            ("keepalive_timeout", self.keepalive_timeout),
            ("rekey_attempt_time", self.rekey_attempt_time),
        ] {
            if value.is_some_and(|d| d.is_zero()) {
                return Err(ConfigError::Timer(name));
            }
        }
        if self
            .rekey_attempt_time
            .is_some_and(|d| d > REJECT_AFTER_TIME * 3)
        {
            return Err(ConfigError::Timer("rekey_attempt_time"));
        }
        if self
            .effective_rekey_timeout()
            .checked_add(self.effective_keepalive_timeout())
            .is_none_or(|sum| sum > REJECT_AFTER_TIME)
        {
            return Err(ConfigError::Timer("rekey_timeout + keepalive_timeout"));
        }
        Ok(())
    }
}

/// Upper bounds on everything the device holds between calls. Each queue drops what does not
/// fit and counts it in [`crate::Drops`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Outbound packets held per peer while a handshake is in progress.
    pub staged_packets: usize,
    /// Datagrams waiting for [`crate::Device::poll_transmit`].
    pub transmit_packets: usize,
    /// Total payload bytes of those datagrams.
    pub transmit_bytes: usize,
    /// Inner packets waiting for [`crate::Device::poll_packet`].
    pub deliver_packets: usize,
    /// Total bytes of those packets.
    pub deliver_bytes: usize,
    /// Events waiting for [`crate::Device::poll_event`].
    pub events: usize,
}

impl Limits {
    /// The byte bound of one peer's staged packets at `mtu`, or `None` on overflow.
    #[must_use]
    pub fn staged_bytes(&self, mtu: u16) -> Option<usize> {
        self.staged_packets.checked_mul(usize::from(mtu))
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            // wireguard-go と Linux の MAX_STAGED_PACKETS と同じ数
            staged_packets: 128,
            transmit_packets: 256,
            transmit_bytes: 512 * 1024,
            deliver_packets: 256,
            deliver_bytes: 512 * 1024,
            events: 64,
        }
    }
}

/// The configuration of a [`crate::Device`].
#[derive(Debug, Clone)]
pub struct DeviceConfig {
    /// This side's private key.
    pub private_key: PrivateKey,
    /// The tunnel MTU. Outbound packets longer than this are dropped.
    pub mtu: u16,
    /// The peers. The agent has exactly one, the server.
    pub peers: Vec<PeerConfig>,
    /// Queue bounds.
    pub limits: Limits,
    /// Timer overrides for tests.
    pub timers: ProtocolTimers,
}

impl DeviceConfig {
    /// Checks the limits, keepalives and timer overrides. [`crate::Device::new`] calls it.
    ///
    /// # Errors
    ///
    /// Returns the first [`ConfigError`] found.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.mtu < MIN_MTU {
            return Err(ConfigError::Mtu(self.mtu));
        }
        let l = &self.limits;
        for (name, v, max) in [
            ("staged_packets", l.staged_packets, MAX_LIMIT_PACKETS),
            ("transmit_packets", l.transmit_packets, MAX_LIMIT_PACKETS),
            ("transmit_bytes", l.transmit_bytes, MAX_LIMIT_BYTES),
            ("deliver_packets", l.deliver_packets, MAX_LIMIT_PACKETS),
            ("deliver_bytes", l.deliver_bytes, MAX_LIMIT_BYTES),
            ("events", l.events, MAX_LIMIT_PACKETS),
        ] {
            if v == 0 {
                return Err(ConfigError::ZeroLimit(name));
            }
            if v > max {
                return Err(ConfigError::LimitTooLarge(name));
            }
        }
        if l.staged_bytes(self.mtu).is_none_or(|b| b > MAX_LIMIT_BYTES) {
            return Err(ConfigError::LimitTooLarge("staged_packets"));
        }
        for p in &self.peers {
            if let Some(k) = p.persistent_keepalive
                && !(Duration::from_secs(1)..=MAX_KEEPALIVE).contains(&k)
            {
                return Err(ConfigError::Keepalive(k));
            }
        }
        self.timers.validate()
    }

    /// The v1 agent's configuration: one peer, the server, that may use only its own tunnel
    /// address, with MTU 1420. It matches the UAPI text the Go agent gives wireguard-go.
    ///
    /// `keepalive` must be 1 to 65535 seconds. Like Go's `tunnel.New`, the caller maps a keepalive
    /// of 0 or below one second from the server to [`DEFAULT_KEEPALIVE`].
    #[must_use]
    pub fn agent(
        private_key: PrivateKey,
        server_public_key: PublicKey,
        server_endpoint: Option<SocketAddr>,
        server_address: Ipv4Addr,
        keepalive: Duration,
    ) -> Self {
        Self {
            private_key,
            mtu: DEFAULT_MTU,
            peers: vec![PeerConfig {
                public_key: server_public_key,
                endpoint: server_endpoint,
                allowed_ips: vec![Ipv4Prefix::host(server_address)],
                persistent_keepalive: Some(keepalive),
                roaming: Roaming::NotByInitiation,
            }],
            limits: Limits::default(),
            timers: ProtocolTimers::default(),
        }
    }
}

/// The configuration cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// A prefix length above 32.
    PrefixLength(u8),
    /// Text that is not an IPv4 prefix.
    Prefix(String),
    /// The same public key appears twice.
    DuplicatePeer(PublicKey),
    /// The peer's public key is our own.
    OwnKey,
    /// The public key is a low-order point that would give an all-zero shared secret.
    LowOrderKey(PublicKey),
    /// The MTU is too small to carry an IPv4 header.
    Mtu(u16),
    /// A limit is zero.
    ZeroLimit(&'static str),
    /// A persistent keepalive outside 1 to 65535 seconds.
    Keepalive(Duration),
    /// A timer override that is zero or outside the protocol's bounds.
    Timer(&'static str),
    /// A limit above its upper bound.
    LimitTooLarge(&'static str),
    /// The Unix time is above [`MAX_UNIX_TIME`].
    UnixTime(Duration),
    /// The operating system gave no entropy for the seed.
    Entropy(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::PrefixLength(n) => write!(f, "prefix length {n} is above 32"),
            ConfigError::Prefix(s) => write!(f, "{s:?} is not an IPv4 prefix"),
            ConfigError::DuplicatePeer(k) => write!(f, "peer {k} is configured twice"),
            ConfigError::OwnKey => f.write_str("a peer has this device's own public key"),
            ConfigError::LowOrderKey(k) => write!(f, "peer key {k} is a low-order point"),
            ConfigError::Mtu(m) => write!(f, "MTU {m} is below the IPv4 minimum of 68"),
            ConfigError::ZeroLimit(name) => write!(f, "limit {name} is zero"),
            ConfigError::Keepalive(d) => {
                write!(
                    f,
                    "persistent keepalive {d:?} is outside 1 to 65535 seconds"
                )
            }
            ConfigError::LimitTooLarge(name) => write!(f, "limit {name} is above its bound"),
            ConfigError::UnixTime(d) => write!(f, "Unix time {}s is beyond 2^40 s", d.as_secs()),
            ConfigError::Entropy(e) => write!(f, "cannot read entropy for the seed: {e}"),
            ConfigError::Timer(name) => {
                write!(
                    f,
                    "timer override {name} is zero or outside the protocol bounds"
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_parses_and_masks() {
        let p: Ipv4Prefix = "10.200.0.7/24".parse().unwrap();
        assert_eq!(p.to_string(), "10.200.0.0/24");
        let h: Ipv4Prefix = "10.200.0.1".parse().unwrap();
        assert_eq!(h, Ipv4Prefix::host(Ipv4Addr::new(10, 200, 0, 1)));
        assert!(h.contains(Ipv4Addr::new(10, 200, 0, 1)));
        assert!(!h.contains(Ipv4Addr::new(10, 200, 0, 2)));
        let all: Ipv4Prefix = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains(Ipv4Addr::new(203, 0, 113, 9)));
        assert!("10.0.0.0/33".parse::<Ipv4Prefix>().is_err());
        assert!("10.0.0/8".parse::<Ipv4Prefix>().is_err());
        assert!("::1/128".parse::<Ipv4Prefix>().is_err());
    }

    #[test]
    fn agent_config_has_one_peer_with_the_server_host_route() {
        let key = PrivateKey::from_bytes([1; 32]);
        let server = PublicKey::from_bytes([2; 32]);
        let cfg = DeviceConfig::agent(
            key,
            server,
            Some("192.0.2.1:51820".parse().unwrap()),
            Ipv4Addr::new(10, 200, 0, 1),
            DEFAULT_KEEPALIVE,
        );
        assert_eq!(cfg.mtu, 1420);
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(
            cfg.peers[0].allowed_ips,
            vec!["10.200.0.1/32".parse().unwrap()]
        );
        assert_eq!(cfg.peers[0].persistent_keepalive, Some(DEFAULT_KEEPALIVE));
    }
}
