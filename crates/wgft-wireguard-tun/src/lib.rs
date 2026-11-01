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
use wgft_wireguard::{DeviceConfig, Drops, Event, Ipv4Prefix, PeerStatus};

#[cfg(target_os = "linux")]
mod linux;

/// The routing table the shell uses by default.
pub const DEFAULT_TABLE: u32 = 5180;

/// The priority of the first of the shell's three routing rules by default. All come before the
/// main table's rule at 32766.
pub const DEFAULT_RULE_PRIORITY: u32 = 5180;

/// The TUN device to create and the routing around it.
///
/// The shell changes no route of the main table. The address goes on the link as a /32, so no
/// address band is routed to the tunnel. `routes` go into a table of their own that only traffic
/// from `address` uses, through the rule `from address lookup table` at `rule_priority`. The rule
/// `from address unreachable` at `rule_priority + 1` keeps traffic from the tunnel address to any
/// other destination off the main table. The rule `iif name blackhole` at `rule_priority + 2`
/// drops whatever arrives on the TUN device and is not for this host, so the tunnel never reaches
/// the LAN even with IPv4 forwarding on. The rules use `protocol kernel`, which systemd-networkd
/// leaves alone, and are removed when the shell stops. The shell refuses to start when the table
/// is not empty, a foreign rule holds one of the priorities, or the address is already on the
/// host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunSettings {
    /// The interface name, at most 15 bytes, without %, / or whitespace.
    pub name: String,
    /// This side's tunnel address.
    pub address: Ipv4Addr,
    /// The networks reached through the tunnel, for traffic from `address` only. The agent has
    /// one, the server's /32.
    pub routes: Vec<Ipv4Prefix>,
    /// The link MTU. Use the device's MTU.
    pub mtu: u16,
    /// The routing table for `routes`, from 1 to 252 or above 255.
    pub table: u32,
    /// The priority of the first rule, from 1 to 32763; the others follow it.
    pub rule_priority: u32,
}

impl TunSettings {
    /// The agent's settings: the server's tunnel address is the only route, in the default table
    /// at the default priorities.
    #[must_use]
    pub fn agent(name: &str, address: Ipv4Addr, server: Ipv4Addr, mtu: u16) -> Self {
        Self {
            name: name.to_owned(),
            address,
            routes: vec![Ipv4Prefix::host(server)],
            mtu,
            table: DEFAULT_TABLE,
            rule_priority: DEFAULT_RULE_PRIORITY,
        }
    }

    fn validate(&self) -> io::Result<()> {
        let bad = |what: String| Err(io::Error::new(io::ErrorKind::InvalidInput, what));
        let name = &self.name;
        if name.is_empty()
            || name.len() > 15
            || name
                .bytes()
                .any(|b| b == 0 || b == b'%' || b == b'/' || b.is_ascii_whitespace())
        {
            return bad(format!(
                "TUN name {name:?} must be 1 to 15 bytes without %, / or spaces"
            ));
        }
        if matches!(self.table, 0 | 253..=255) {
            return bad(format!(
                "routing table {} is reserved; use 1 to 252 or above 255",
                self.table
            ));
        }
        if !(1..=32763).contains(&self.rule_priority) {
            return bad(format!(
                "rule priority {} must be 1 to 32763",
                self.rule_priority
            ));
        }
        let [first, ..] = self.address.octets();
        if first == 0 || first == 127 || first >= 224 {
            return bad(format!(
                "tunnel address {} is not a unicast host address",
                self.address
            ));
        }
        if self.routes.is_empty() {
            return bad("no route through the tunnel".to_owned());
        }
        Ok(())
    }
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

/// Decides each inbound packet addressed to the tunnel address. The kernel behind the TUN device
/// would otherwise hand every such packet to any service listening on that address or on
/// 0.0.0.0. Packets for any other address are dropped before the filter and counted in
/// [`Status::wrong_destination`]. A panic in the filter drops the packet and is counted in
/// [`Status::filter_panics`]; the shell's panic hook prints at most one line a minute for such
/// panics. A build with `panic = "abort"` ends the process instead.
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
    /// Inbound packets dropped because the filter panicked.
    pub filter_panics: u64,
    /// Inbound packets for an address other than the tunnel address. The server never sends
    /// these; a count above zero is a sign of a compromised or broken server.
    pub wrong_destination: u64,
    /// The device's [`wgft_wireguard::Device::unix_high_water`]; persist it and pass it as the
    /// next `unix_floor`.
    pub unix_high_water: Duration,
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

    /// Resolves when the event loop has ended, by [`Handle::stop`] or by an error such as a TUN
    /// read failure. [`Handle::stop`] then returns the error. The agent rebuilds the tunnel.
    pub async fn finished(&self) {
        self.commands.closed().await;
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

/// Makes the device with [`wgft_wireguard::Device::new`], creates the TUN device, configures its
/// address, MTU, link state and routing as [`TunSettings`] describes, binds the UDP socket to
/// `listen` and starts the event loop on the current tokio runtime. `filter` decides every
/// decrypted packet for the tunnel address before it is written to the TUN device; outbound
/// packets are not filtered.
///
/// `unix_floor` is the persisted [`Status::unix_high_water`] of the previous run, or zero. Needs
/// `CAP_NET_ADMIN` and the `ip` command of iproute2 in a root-owned system directory.
///
/// # Errors
///
/// Fails when the configuration is refused, the TUN device or the socket cannot be made, or the
/// link cannot be configured.
pub async fn spawn(
    config: DeviceConfig,
    tun: TunSettings,
    listen: SocketAddr,
    unix_floor: Duration,
    filter: InboundFilter,
) -> io::Result<Handle> {
    tun.validate()?;
    let device = wgft_wireguard::Device::new(config, Instant::now(), unix_floor)
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

/// Binds a socket to the TUN device with `SO_BINDTODEVICE`, so it sends and receives only through
/// the tunnel. The agent applies it to its listeners and its ping socket. Needs `CAP_NET_RAW`.
///
/// # Errors
///
/// Fails when the kernel refuses the option, or on systems other than Linux.
#[cfg(target_os = "linux")]
pub fn bind_to_device(socket: &impl std::os::fd::AsFd, name: &str) -> io::Result<()> {
    linux::bind_to_device(socket, name)
}

/// Binds a socket to the TUN device; not supported on this system.
///
/// # Errors
///
/// Always fails with [`io::ErrorKind::Unsupported`].
#[cfg(not(target_os = "linux"))]
pub fn bind_to_device<S>(_socket: &S, _name: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SO_BINDTODEVICE exists only on Linux",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent() -> TunSettings {
        TunSettings::agent(
            "wgft0",
            Ipv4Addr::new(10, 200, 0, 2),
            Ipv4Addr::new(10, 200, 0, 1),
            1420,
        )
    }

    #[test]
    fn agent_settings_route_only_the_server() {
        let t = agent();
        assert_eq!(t.routes, vec!["10.200.0.1/32".parse().unwrap()]);
        assert_eq!(
            (t.table, t.rule_priority),
            (DEFAULT_TABLE, DEFAULT_RULE_PRIORITY)
        );
        assert!(t.validate().is_ok());
    }

    #[test]
    fn bad_settings_are_refused() {
        for name in ["", "tun%d", "a/b", "a b", "sixteen-bytes-xx"] {
            let mut t = agent();
            t.name = name.to_owned();
            assert!(t.validate().is_err(), "name {name:?}");
        }
        for table in [0, 253, 254, 255] {
            let mut t = agent();
            t.table = table;
            assert!(t.validate().is_err(), "table {table}");
        }
        for priority in [0, 32764, 32765, 32766] {
            let mut t = agent();
            t.rule_priority = priority;
            assert!(t.validate().is_err(), "priority {priority}");
        }
        for address in [
            "0.1.2.3",
            "127.0.0.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            let mut t = agent();
            t.address = address.parse().unwrap();
            assert!(t.validate().is_err(), "address {address}");
        }
        let mut t = agent();
        t.routes.clear();
        assert!(t.validate().is_err());
    }
}
