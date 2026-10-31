//! The WireGuard device layer of the wgft agent.
//!
//! [`Device`] is sans-IO: the caller passes in the current time, UDP datagrams that arrived and IP
//! packets to send through the tunnel, and takes out datagrams to send, packets to deliver,
//! [`Event`]s and the next wake-up time. The protocol core is sanstun, confined to one private
//! module; this crate's API uses only its own types.
//!
//! ```
//! use std::net::Ipv4Addr;
//! use std::time::{Duration, Instant};
//! use wgft_wireguard::{DeviceConfig, Device, PrivateKey, DEFAULT_KEEPALIVE};
//!
//! let agent_key = PrivateKey::generate([1; 32]);
//! let server_key = PrivateKey::generate([2; 32]).public_key();
//! let config = DeviceConfig::agent(
//!     agent_key,
//!     server_key,
//!     Some("192.0.2.1:51820".parse().unwrap()),
//!     Ipv4Addr::new(10, 200, 0, 1),
//!     DEFAULT_KEEPALIVE,
//! );
//! let now = Instant::now();
//! let mut device = Device::new(config, [3; 32], now, Duration::from_hours(500_000)).unwrap();
//!
//! // A peer with a persistent keepalive is contacted right away.
//! device.handle_timeout(device.poll_timeout().unwrap());
//! let initiation = device.poll_transmit().unwrap();
//! assert_eq!(initiation.to, "192.0.2.1:51820".parse().unwrap());
//! assert_eq!(initiation.payload.len(), 148);
//! ```

mod allowed_ips;
mod config;
mod device;
mod drops;
mod ip;
mod keys;
mod protocol;
mod queue;

pub use config::{
    ConfigError, DEFAULT_KEEPALIVE, DEFAULT_MTU, DeviceConfig, Ipv4Prefix, Limits, PeerConfig,
    ProtocolTimers,
};
pub use device::{Device, Event, Held, PeerStatus, Transmit};
pub use drops::{DropReason, Drops};
pub use keys::{KEY_LEN, KeyError, PrivateKey, PublicKey};
