//! The WireGuard device layer of the wgft agent.
//!
//! [`Device`] is sans-IO: the caller passes in the current time, UDP datagrams that arrived and IP
//! packets to send through the tunnel, and takes out datagrams to send, packets to deliver,
//! [`Event`]s and the next wake-up time. Data packets pass through buffers of the caller, so that
//! nothing is allocated or copied for them. The protocol core is sanstun, confined to one private
//! module; this crate's API uses only its own types.
//!
//! ```
//! use std::net::Ipv4Addr;
//! use std::time::{Duration, Instant};
//! use wgft_wireguard::{DeviceConfig, Device, PrivateKey, DEFAULT_KEEPALIVE};
//!
//! let agent_key = PrivateKey::generate(&[1; 32]);
//! let server_key = PrivateKey::generate(&[2; 32]).public_key();
//! let config = DeviceConfig::agent(
//!     agent_key,
//!     server_key,
//!     Some("192.0.2.1:51820".parse().unwrap()),
//!     Ipv4Addr::new(10, 200, 0, 1),
//!     DEFAULT_KEEPALIVE,
//! );
//! let now = Instant::now();
//! // Pass the unix_high_water persisted by the previous run, or zero.
//! let mut device = Device::new(config, now, Duration::ZERO).unwrap();
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
    ConfigError, DEFAULT_KEEPALIVE, DEFAULT_MTU, DeviceConfig, Ipv4Prefix, Limits, MAX_KEEPALIVE,
    MAX_LIMIT_BYTES, MAX_LIMIT_PACKETS, MAX_UNIX_TIME, MIN_MTU, PeerConfig, ProtocolTimers,
    Roaming,
};
pub use device::{Device, Event, Held, Outgoing, PeerStatus, Transmit};
/// The bytes a data message adds to the inner packet: the header and the tag.
pub const DATA_OVERHEAD: usize = protocol::DATA_OVERHEAD;
pub use drops::{DropReason, Drops};
pub use keys::{KEY_LEN, KeyError, PrivateKey, PublicKey};
pub use zeroize::Zeroizing;
