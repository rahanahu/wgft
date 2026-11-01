//! Async TCP, UDP and ping handles over the wgstack core.
//!
//! The core (`wgft-wgstack`) is sans-IO: its operations never wait and answer "not now" with
//! `WouldBlock`, and readiness changes come out as events. This crate turns them into futures on
//! one data plane thread: a handle tries the core's operation, and on `WouldBlock` registers its
//! task's waker in the [`Netstack`]'s waker table; the driver moves the wakers of the events it
//! polls out of the table and wakes them after releasing the netstack.
//!
//! - [`Netstack`]: the core and the waker table, the value the data plane drives
//! - [`Access`]: how the handles reach the netstack; [`LocalNetstack`] is one for a netstack on its
//!   own, and the agent's data plane provides another over its device and netstack
//! - [`TcpListener`], [`TcpStream`], [`UdpSocket`], [`UdpSender`], [`Ping`]: the handles
//! - [`LanSockets`] and [`LanHook`]: the table that pairs relayed connections with their LAN
//!   sockets for the core's boost hook
//!
//! The design is `docs/design/v2/wgstack-rs.md` ("データプレーンの駆動" and "handle の層で決めたこと").
//! The handles accept connections; the dial side is added later.

#![forbid(unsafe_code)]

mod access;
mod error;
mod lan;
mod netstack;
mod ping;
mod tcp;
mod udp;
mod wakers;

pub use access::{Access, LocalNetstack};
pub use lan::{LanHook, LanRegistration, LanSocket, LanSockets};
pub use netstack::{Netstack, NetstackError};
pub use ping::Ping;
pub use tcp::{Closing, TcpListener, TcpStream};
pub use udp::{UdpSender, UdpSocket};
