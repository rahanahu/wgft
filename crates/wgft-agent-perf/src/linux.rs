//! The measurement; see the crate documentation in `main.rs`.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};
use socket2::{Domain, Protocol, Socket, Type};
use wgft_wireguard::{
    DEFAULT_KEEPALIVE, DEFAULT_MTU, Device, DeviceConfig, Ipv4Prefix, Limits, PeerConfig,
    PrivateKey, ProtocolTimers, PublicKey, Roaming,
};

mod cpu;
mod error;
mod link;
mod measure;

use cpu::pin;
use error::Error;
use link::{Link, RxStamp};
use measure::{Plan, measure_recv, measure_send};

/// The agent's tunnel address and the server's, as in the device layer's own tests.
const AGENT_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 2);
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);
/// The buffer the data plane asks for.
const REQUESTED_BUFFER: usize = 7 << 20;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    /// Encrypt and send: the measured thread is the agent.
    Send,
    /// Receive and decrypt: the measured thread is the server end.
    Recv,
    /// Receive and decrypt a burst, then encrypt and send one 40-byte reply in the same wake-up:
    /// the measured thread is the server end, like a relayed TCP download that acknowledges once
    /// per wake-up.
    Answer,
}

#[derive(Debug, Parser)]
#[command(
    about = "Measure the agent's tunnel socket path on the host; run under perf stat --no-inherit"
)]
struct Args {
    #[arg(long, value_enum)]
    mode: Mode,
    /// Inner IPv4 packet length in bytes, 20 to the device layer's inner MTU. The default is the
    /// largest packet at the default tunnel MTU of 1420, which the device layer rounds down to a
    /// multiple of 16.
    #[arg(long, default_value_t = 1408)]
    size: usize,
    /// Packets to measure, rounded up to whole bursts.
    #[arg(long, default_value_t = 200_000)]
    packets: u64,
    /// Packets per burst. A burst must fit the receiving socket's buffer.
    #[arg(long, default_value_t = 64)]
    burst: usize,
    /// CPU for the measured thread.
    #[arg(long)]
    cpu_main: Option<usize>,
    /// CPU for the second thread.
    #[arg(long)]
    cpu_peer: Option<usize>,
    /// Use one `sendto` or `recvfrom` per datagram, as before the batching, instead of the data
    /// plane's batch store with `sendmmsg`, `recvmmsg`, UDP GSO and GRO.
    #[arg(long)]
    one_by_one: bool,
    /// What the measured receive side does about the kernel's receive times, for the cost of the
    /// receive queue control's signal: off, on (turned on once, never read), or batch (read once
    /// after every receive call). recv and answer modes only.
    #[arg(long, value_enum, default_value_t = RxStamp::Off)]
    rx_stamp: RxStamp,
}

pub(crate) fn main() -> ExitCode {
    match run(&Args::parse()) {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> Result<String, Error> {
    if args.size < 20 || args.size > usize::from(DEFAULT_MTU) || args.burst == 0 {
        return Err(Error::failed(format!(
            "size must be 20 to {DEFAULT_MTU} and burst above zero"
        )));
    }
    pin(args.cpu_main).map_err(|e| Error::context("cannot pin the measured thread", &e))?;
    let agent_key = PrivateKey::generate(&[0xa1; 32]);
    let server_key = PrivateKey::generate(&[0xb2; 32]);
    let agent_socket = open_socket().map_err(|e| Error::context("socket", &e))?;
    let server_socket = open_socket().map_err(|e| Error::context("socket", &e))?;
    let server_addr = server_socket.local_addr()?;
    let now = Instant::now();
    let agent = Device::new(
        DeviceConfig::agent(
            agent_key.clone(),
            server_key.public_key(),
            Some(server_addr),
            SERVER_IP,
            DEFAULT_KEEPALIVE,
        ),
        now,
        Duration::ZERO,
    )
    .map_err(|e| Error::failed(format!("{e:?}")))?;
    let server = Device::new(
        server_config(server_key, agent_key.public_key()),
        now,
        Duration::ZERO,
    )
    .map_err(|e| Error::failed(format!("{e:?}")))?;
    if args.size > agent.mtu() {
        return Err(Error::failed(format!(
            "size must be at most the inner MTU {}",
            agent.mtu()
        )));
    }
    let rx_stamp = match args.mode {
        Mode::Send => RxStamp::Off,
        Mode::Recv | Mode::Answer => args.rx_stamp,
    };
    let agent = Link::new(agent_socket, agent, !args.one_by_one, RxStamp::Off);
    let server = Link::new(server_socket, server, !args.one_by_one, rx_stamp);
    let packet = inner_packet(args.size, AGENT_IP, SERVER_IP);
    let bursts = args.packets.div_ceil(args.burst as u64);
    let plan = Plan {
        packet,
        reply: inner_packet(40, SERVER_IP, AGENT_IP),
        burst: args.burst,
        bursts,
        cpu_peer: args.cpu_peer,
    };
    let measured = match args.mode {
        Mode::Send => measure_send(agent, server, &plan)?,
        Mode::Recv => measure_recv(server, agent, &plan, false)?,
        Mode::Answer => measure_recv(server, agent, &plan, true)?,
    };
    let packets = bursts * args.burst as u64;
    Ok(format!(
        "RESULT mode={} size={} batch={} rx_stamp={} packets={packets} bytes={} cpu_ns={} user_ns={} sys_ns={} data_syscalls={} wake_syscalls={} stamp_syscalls={} peer_cpu_ns={}",
        match args.mode {
            Mode::Send => "send",
            Mode::Recv => "recv",
            Mode::Answer => "answer",
        },
        args.size,
        if args.one_by_one { "off" } else { "on" },
        match rx_stamp {
            RxStamp::Off => "off",
            RxStamp::On => "on",
            RxStamp::Batch => "batch",
        },
        packets * args.size as u64,
        measured.cpu.total.as_nanos(),
        measured.cpu.user.as_nanos(),
        measured.cpu.sys.as_nanos(),
        measured.calls.data,
        measured.calls.wake,
        measured.calls.stamp,
        measured.peer_cpu.total.as_nanos(),
    ))
}

fn server_config(key: PrivateKey, agent: PublicKey) -> DeviceConfig {
    DeviceConfig {
        private_key: key,
        mtu: DEFAULT_MTU,
        peers: vec![PeerConfig {
            public_key: agent,
            endpoint: None,
            allowed_ips: vec![Ipv4Prefix::host(AGENT_IP)],
            persistent_keepalive: None,
            roaming: Roaming::Any,
        }],
        limits: Limits::default(),
        timers: ProtocolTimers::default(),
    }
}

/// A valid inner IPv4 packet of `size` bytes from the agent to the server.
fn inner_packet(size: usize, src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let mut p = vec![0u8; size];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&u16::try_from(size).unwrap_or(u16::MAX).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let sum = p[..20]
        .as_chunks::<2>()
        .0
        .iter()
        .fold(0u32, |s, w| s + u32::from(u16::from_be_bytes(*w)));
    let sum = (sum & 0xffff) + (sum >> 16);
    let sum = !u16::try_from((sum & 0xffff) + (sum >> 16)).unwrap_or(0);
    p[10..12].copy_from_slice(&sum.to_be_bytes());
    for (i, b) in p[20..].iter_mut().enumerate() {
        *b = u8::try_from(i.wrapping_mul(7) & 0xff).unwrap_or(0);
    }
    p
}

/// A non-blocking UDP socket on the loopback, opened as the data plane opens its own.
fn open_socket() -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    let _ = socket.set_recv_buffer_size(REQUESTED_BUFFER);
    let _ = socket.set_send_buffer_size(REQUESTED_BUFFER);
    socket.bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())?;
    Ok(socket.into())
}
