//! A thin Linux outer shell for the wgft WireGuard device: one UDP socket, one TUN device and a
//! tokio event loop around [`wgft_wireguard::Device`].
//!
//! The v2 prototype uses it to put the device in front of the kernel's TCP/IP stack until the
//! Rust wgstack exists. It is a lab tool and is not shipped. On other systems [`spawn`] returns
//! an [`std::io::ErrorKind::Unsupported`] error.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};
use wgft_wireguard::{DeviceConfig, Drops, Event, PeerStatus, Zeroizing};

#[cfg(target_os = "linux")]
mod linux;

/// The TUN device to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunSettings {
    /// The interface name, at most 15 bytes.
    pub name: String,
    /// This side's tunnel address.
    pub address: Ipv4Addr,
    /// The prefix length of the tunnel network. The kernel routes it through the TUN device.
    pub prefix_len: u8,
    /// The link MTU. Use the device's MTU.
    pub mtu: u16,
}

/// What the shell does with a packet the device decrypted, before it reaches the TUN device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Write the packet to the TUN device.
    Deliver,
    /// Discard the packet.
    Drop,
    /// Discard the packet and send this IPv4 packet back through the tunnel instead, as if it had
    /// come from the TUN device, for example a TCP reset for a port without a rule.
    Reply(Vec<u8>),
}

/// Decides each inbound packet. The kernel behind the TUN device would otherwise hand every
/// packet to the host's own services and, with forwarding on, to the LAN.
pub type InboundFilter = Box<dyn FnMut(&[u8]) -> Verdict + Send>;

/// An [`InboundFilter`] that delivers every packet, for lab tests of the device alone.
pub fn deliver_all() -> InboundFilter {
    Box::new(|_| Verdict::Deliver)
}

/// The state of the shell's peer and the device's drop counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status {
    /// The first configured peer, the server for the agent.
    pub peer: Option<PeerStatus>,
    /// Drops in the device.
    pub drops: Drops,
    /// The local address of the UDP socket.
    pub local: SocketAddr,
    /// Datagrams the socket refused to send.
    pub send_errors: u64,
    /// Packets the TUN device refused to take.
    pub tun_write_errors: u64,
    /// Inbound packets the filter dropped.
    pub filter_drops: u64,
    /// Inbound packets the filter answered with a reply.
    pub filter_replies: u64,
}

#[cfg_attr(
    not(target_os = "linux"),
    expect(dead_code, reason = "only the Linux event loop reads the commands")
)]
pub(crate) enum Command {
    Status(oneshot::Sender<Status>),
    SetEndpoint(SocketAddr),
    Rebind(SocketAddr, oneshot::Sender<io::Result<SocketAddr>>),
    Stop,
}

/// A running shell. Dropping it stops the loop as well.
#[derive(Debug)]
pub struct Handle {
    commands: mpsc::Sender<Command>,
    events: Option<mpsc::Receiver<Event>>,
    task: tokio::task::JoinHandle<io::Result<()>>,
}

fn stopped() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "the WireGuard shell has stopped")
}

impl Handle {
    /// The current status.
    ///
    /// # Errors
    ///
    /// Fails when the loop has stopped.
    pub async fn status(&self) -> io::Result<Status> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::Status(tx))
            .await
            .map_err(|_| stopped())?;
        rx.await.map_err(|_| stopped())
    }

    /// Points the first peer at a new endpoint.
    ///
    /// # Errors
    ///
    /// Fails when the loop has stopped.
    pub async fn set_endpoint(&self, endpoint: SocketAddr) -> io::Result<()> {
        self.commands
            .send(Command::SetEndpoint(endpoint))
            .await
            .map_err(|_| stopped())
    }

    /// Replaces the UDP socket with one bound to `listen`, keeping the device state, so the peer
    /// sees this side roam. Returns the new local address.
    ///
    /// # Errors
    ///
    /// Fails when the new socket cannot be bound or the loop has stopped.
    pub async fn rebind(&self, listen: SocketAddr) -> io::Result<SocketAddr> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::Rebind(listen, tx))
            .await
            .map_err(|_| stopped())?;
        rx.await.map_err(|_| stopped())?
    }

    /// Takes the event stream. Events that do not fit its buffer are dropped. Returns `None` after
    /// the first call.
    pub fn take_events(&mut self) -> Option<mpsc::Receiver<Event>> {
        self.events.take()
    }

    /// Stops the loop. Closing the TUN device removes its link, address and route.
    ///
    /// # Errors
    ///
    /// Returns the error that ended the loop, if one did.
    pub async fn stop(self) -> io::Result<()> {
        let _ = self.commands.send(Command::Stop).await;
        self.task
            .await
            .map_err(|e| io::Error::other(format!("the WireGuard shell task failed: {e}")))?
    }

    /// Whether the loop has ended.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

/// Creates the TUN device, configures its address, MTU and link state, binds the UDP socket to
/// `listen` and starts the event loop on the current tokio runtime. `filter` decides every
/// decrypted packet before it is written to the TUN device; outbound packets are not filtered.
///
/// `seed` must be fresh operating-system entropy and `unix` the wall clock since the Unix epoch;
/// see [`wgft_wireguard::Device::new`]. Needs `CAP_NET_ADMIN` and the `ip` command.
///
/// # Errors
///
/// Fails when the configuration is refused, the TUN device or the socket cannot be made, or the
/// link cannot be configured.
pub async fn spawn(
    config: DeviceConfig,
    tun: TunSettings,
    listen: SocketAddr,
    seed: Zeroizing<[u8; 32]>,
    unix: Duration,
    filter: InboundFilter,
) -> io::Result<Handle> {
    let device = wgft_wireguard::Device::new(config, seed, Instant::now(), unix)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let (commands, command_rx) = mpsc::channel(16);
    let (event_tx, events) = mpsc::channel(256);
    let task = start(device, &tun, listen, command_rx, event_tx, filter).await?;
    Ok(Handle {
        commands,
        events: Some(events),
        task,
    })
}

#[cfg(target_os = "linux")]
async fn start(
    device: wgft_wireguard::Device,
    tun: &TunSettings,
    listen: SocketAddr,
    commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
    filter: InboundFilter,
) -> io::Result<tokio::task::JoinHandle<io::Result<()>>> {
    let shell = linux::Shell::open(device, tun, listen, events, filter).await?;
    Ok(tokio::spawn(shell.run(commands)))
}

#[cfg(not(target_os = "linux"))]
#[expect(
    clippy::unused_async,
    reason = "the same signature as the Linux version"
)]
async fn start(
    _device: wgft_wireguard::Device,
    _tun: &TunSettings,
    _listen: SocketAddr,
    _commands: mpsc::Receiver<Command>,
    _events: mpsc::Sender<Event>,
    _filter: InboundFilter,
) -> io::Result<tokio::task::JoinHandle<io::Result<()>>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the WireGuard TUN shell runs only on Linux",
    ))
}
