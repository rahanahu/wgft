//! The measurement; see the crate documentation in `main.rs`.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};
use socket2::{Domain, Protocol, Socket, Type};
use wgft_wireguard::{
    DEFAULT_KEEPALIVE, DEFAULT_MTU, Device, DeviceConfig, Ipv4Prefix, Limits, PeerConfig,
    PrivateKey, ProtocolTimers, PublicKey, Roaming, Transmit,
};

/// The agent's tunnel address and the server's, as in the device layer's own tests.
const AGENT_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 2);
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);
/// The buffer the data plane asks for.
const REQUESTED_BUFFER: usize = 7 << 20;
const SETUP_LIMIT: Duration = Duration::from_secs(5);
const HAND_OFF_LIMIT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    /// Encrypt and send: the measured thread is the agent.
    Send,
    /// Receive and decrypt: the measured thread is the server end.
    Recv,
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
}

/// System calls the data path made, counted by the tool itself.
#[derive(Debug, Default, Clone, Copy)]
struct Syscalls {
    /// `sendto` and `recvfrom`, the final `WouldBlock` read included.
    data: u64,
    /// The readiness check once per burst, standing in for the data plane's `epoll_wait`.
    wake: u64,
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

fn run(args: &Args) -> Result<String, String> {
    if args.size < 20 || args.size > usize::from(DEFAULT_MTU) || args.burst == 0 {
        return Err(format!(
            "size must be 20 to {DEFAULT_MTU} and burst above zero"
        ));
    }
    pin(args.cpu_main).map_err(|e| format!("cannot pin the measured thread: {e}"))?;
    let agent_key = PrivateKey::generate(&[0xa1; 32]);
    let server_key = PrivateKey::generate(&[0xb2; 32]);
    let agent_socket = open_socket().map_err(|e| format!("socket: {e}"))?;
    let server_socket = open_socket().map_err(|e| format!("socket: {e}"))?;
    let server_addr = server_socket.local_addr().map_err(|e| e.to_string())?;
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
    .map_err(|e| format!("{e:?}"))?;
    let server = Device::new(
        server_config(server_key, agent_key.public_key()),
        now,
        Duration::ZERO,
    )
    .map_err(|e| format!("{e:?}"))?;
    if args.size > agent.mtu() {
        return Err(format!(
            "size must be at most the inner MTU {}",
            agent.mtu()
        ));
    }
    let agent = Link::new(agent_socket, agent);
    let server = Link::new(server_socket, server);
    let packet = inner_packet(args.size);
    let bursts = args.packets.div_ceil(args.burst as u64);
    let plan = Plan {
        packet,
        burst: args.burst,
        bursts,
        cpu_peer: args.cpu_peer,
    };
    let measured = match args.mode {
        Mode::Send => measure_send(agent, server, &plan)?,
        Mode::Recv => measure_recv(server, agent, &plan)?,
    };
    let packets = bursts * args.burst as u64;
    Ok(format!(
        "RESULT mode={} size={} packets={packets} bytes={} cpu_ns={} user_ns={} sys_ns={} data_syscalls={} wake_syscalls={}",
        match args.mode {
            Mode::Send => "send",
            Mode::Recv => "recv",
        },
        args.size,
        packets * args.size as u64,
        measured.cpu.total.as_nanos(),
        measured.cpu.user.as_nanos(),
        measured.cpu.sys.as_nanos(),
        measured.calls.data,
        measured.calls.wake,
    ))
}

struct Plan {
    packet: Vec<u8>,
    burst: usize,
    bursts: u64,
    cpu_peer: Option<usize>,
}

struct Measured {
    cpu: Cpu,
    calls: Syscalls,
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
fn inner_packet(size: usize) -> Vec<u8> {
    let mut p = vec![0u8; size];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&u16::try_from(size).unwrap_or(u16::MAX).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&AGENT_IP.octets());
    p[16..20].copy_from_slice(&SERVER_IP.octets());
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

/// Waits up to `timeout_ms` for `events` on the socket.
fn wait(socket: &UdpSocket, events: i16, timeout_ms: i32) -> std::io::Result<bool> {
    let mut fd = libc::pollfd {
        fd: socket.as_raw_fd(),
        events,
        revents: 0,
    };
    // SAFETY: fd is one valid pollfd that lives through the call and the count is 1.
    let n = unsafe { libc::poll(&raw mut fd, 1, timeout_ms) };
    if n < 0 {
        let e = std::io::Error::last_os_error();
        return if e.kind() == std::io::ErrorKind::Interrupted {
            Ok(false)
        } else {
            Err(e)
        };
    }
    Ok(n > 0)
}

fn pin(cpu: Option<usize>) -> std::io::Result<()> {
    let Some(cpu) = cpu else {
        return Ok(());
    };
    // SAFETY: a zeroed cpu_set_t is the empty set; CPU_SET writes within it for cpu below the
    // set's size, which the check guarantees; sched_setaffinity reads the set for the calling thread.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        if cpu >= 8 * size_of::<libc::cpu_set_t>() {
            return Err(std::io::Error::other("cpu number too large"));
        }
        libc::CPU_SET(cpu, &mut set);
        if libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &raw const set) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// The calling thread's CPU time.
#[derive(Debug, Clone, Copy)]
struct Cpu {
    total: Duration,
    user: Duration,
    sys: Duration,
}

impl Cpu {
    const ZERO: Self = Self {
        total: Duration::ZERO,
        user: Duration::ZERO,
        sys: Duration::ZERO,
    };

    fn plus(self, other: Self) -> Self {
        Self {
            total: self.total + other.total,
            user: self.user + other.user,
            sys: self.sys + other.sys,
        }
    }

    fn now() -> Self {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: ts is a valid timespec that lives through the call.
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &raw mut ts) };
        let tv = |sec: i64, sub: i64, per: u32| {
            Duration::new(
                u64::try_from(sec).unwrap_or(0),
                u32::try_from(sub).unwrap_or(0) * per,
            )
        };
        // SAFETY: a zeroed rusage is valid for getrusage to fill in.
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        // SAFETY: ru is a valid rusage that lives through the call.
        unsafe { libc::getrusage(libc::RUSAGE_THREAD, &raw mut ru) };
        Self {
            total: tv(ts.tv_sec, ts.tv_nsec, 1),
            user: tv(ru.ru_utime.tv_sec, ru.ru_utime.tv_usec, 1000),
            sys: tv(ru.ru_stime.tv_sec, ru.ru_stime.tv_usec, 1000),
        }
    }

    fn since(self, start: Self) -> Self {
        Self {
            total: self.total.saturating_sub(start.total),
            user: self.user.saturating_sub(start.user),
            sys: self.sys.saturating_sub(start.sys),
        }
    }
}

/// One end: a socket and the device layer on it.
struct Link {
    socket: UdpSocket,
    device: Device,
    /// Decrypted packets handed up so far.
    delivered: u64,
    buf: Vec<u8>,
}

impl Link {
    fn new(socket: UdpSocket, device: Device) -> Self {
        let buf = vec![0; device.max_transmit_len() + 64];
        Self {
            socket,
            device,
            delivered: 0,
            buf,
        }
    }

    /// The adapter to the device layer's encrypt side: one inner packet in.
    fn encrypt(&mut self, now: Instant, packet: &[u8]) {
        self.device.handle_packet(now, packet);
    }

    /// The adapter to the device layer's decrypt side: one datagram in, decrypted packets counted.
    fn decrypt(&mut self, now: Instant, from: SocketAddr, n: usize) {
        self.device.handle_datagram(now, from, &self.buf[..n]);
        while self.device.poll_packet().is_some() {
            self.delivered += 1;
        }
    }

    /// Sends every datagram the device layer has, one `sendto` each.
    fn send_pending(&mut self, calls: &mut Syscalls) -> std::io::Result<()> {
        while let Some(Transmit { to, payload }) = self.device.poll_transmit() {
            loop {
                match self.socket.send_to(&payload, to) {
                    Ok(_) => {
                        calls.data += 1;
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        wait(&self.socket, libc::POLLOUT, 100)?;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }

    /// Reads until the socket is empty, one `recvfrom` each and one for the `WouldBlock`.
    /// Returns the datagrams read.
    fn receive_all(&mut self, now: Instant, calls: &mut Syscalls) -> std::io::Result<u64> {
        let mut read = 0;
        loop {
            calls.data += 1;
            match self.socket.recv_from(&mut self.buf) {
                Ok((n, from)) => {
                    self.decrypt(now, from, n);
                    read += 1;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(read),
                Err(e) => return Err(e),
            }
        }
    }

    /// Runs the device's timer if it is due.
    fn tick(&mut self, now: Instant) {
        if self.device.poll_timeout().is_some_and(|t| t <= now) {
            self.device.handle_timeout(now);
        }
    }
}

/// The agent end sends and the server end receives, in both modes. In `send` mode the measured
/// thread is the agent, in `recv` mode the server end.
fn measure_send(mut agent: Link, server: Link, plan: &Plan) -> Result<Measured, String> {
    let stop = Arc::new(AtomicBool::new(false));
    let (delivered_tx, delivered_rx) = mpsc::channel::<u64>();
    let cpu_peer = plan.cpu_peer;
    let stop_peer = Arc::clone(&stop);
    let peer = thread::Builder::new()
        .name("peer".into())
        .spawn(move || {
            pin(cpu_peer).map_err(|e| format!("cannot pin the second thread: {e}"))?;
            let mut server = server;
            let mut calls = Syscalls::default();
            while !stop_peer.load(Ordering::Relaxed) {
                if !wait(&server.socket, libc::POLLIN, 20).map_err(|e| e.to_string())? {
                    continue;
                }
                let now = Instant::now();
                server
                    .receive_all(now, &mut calls)
                    .map_err(|e| e.to_string())?;
                server.send_pending(&mut calls).map_err(|e| e.to_string())?;
                if delivered_tx.send(server.delivered).is_err() {
                    break;
                }
            }
            Ok::<(), String>(())
        })
        .map_err(|e| e.to_string())?;
    let result = (|| {
        let mut calls = Syscalls::default();
        // 握手を済ませる。最初の packet が server に届くまで両側を回す
        let mut seen = 0;
        agent.encrypt(Instant::now(), &plan.packet);
        agent.send_pending(&mut calls).map_err(|e| e.to_string())?;
        let deadline = Instant::now() + SETUP_LIMIT;
        while seen < 1 {
            if Instant::now() > deadline {
                return Err("the handshake did not complete".to_string());
            }
            if wait(&agent.socket, libc::POLLIN, 5).map_err(|e| e.to_string())? {
                agent
                    .receive_all(Instant::now(), &mut calls)
                    .map_err(|e| e.to_string())?;
            }
            agent.tick(Instant::now());
            agent.send_pending(&mut calls).map_err(|e| e.to_string())?;
            while let Ok(n) = delivered_rx.try_recv() {
                seen = n;
            }
        }
        let mut calls = Syscalls::default();
        let mut target = seen;
        let mut cpu = Cpu::ZERO;
        for _ in 0..plan.bursts {
            let start = Cpu::now();
            let now = Instant::now();
            wait(&agent.socket, libc::POLLOUT, 0).map_err(|e| e.to_string())?;
            calls.wake += 1;
            for _ in 0..plan.burst {
                agent.encrypt(now, &plan.packet);
                agent.send_pending(&mut calls).map_err(|e| e.to_string())?;
            }
            cpu = cpu.plus(Cpu::now().since(start));
            target += plan.burst as u64;
            while seen < target {
                seen = delivered_rx.recv_timeout(HAND_OFF_LIMIT).map_err(|_| {
                    "datagrams were lost on the way to the second thread".to_string()
                })?;
            }
        }
        let drops = agent.device.drops().total();
        if drops != 0 {
            return Err(format!("the device layer dropped {drops} packets"));
        }
        Ok(Measured { cpu, calls })
    })();
    stop.store(true, Ordering::Relaxed);
    drop(delivered_rx);
    let joined = peer
        .join()
        .map_err(|_| "the second thread panicked".to_string())?;
    let measured = result?;
    joined?;
    Ok(measured)
}

enum Command {
    Burst(usize),
}

fn measure_recv(mut server: Link, agent: Link, plan: &Plan) -> Result<Measured, String> {
    let (command_tx, command_rx) = mpsc::channel::<Command>();
    let (sent_tx, sent_rx) = mpsc::channel::<()>();
    let cpu_peer = plan.cpu_peer;
    let packet = plan.packet.clone();
    let peer = thread::Builder::new()
        .name("peer".into())
        .spawn(move || sender_thread(agent, &packet, cpu_peer, &command_rx, &sent_tx))
        .map_err(|e| e.to_string())?;
    let result = (|| {
        let mut calls = Syscalls::default();
        // 握手を済ませる。相手が最初の packet を送り終えるまで、server の側を回す
        let deadline = Instant::now() + SETUP_LIMIT;
        loop {
            if Instant::now() > deadline {
                return Err("the handshake did not complete".to_string());
            }
            if wait(&server.socket, libc::POLLIN, 5).map_err(|e| e.to_string())? {
                server
                    .receive_all(Instant::now(), &mut calls)
                    .map_err(|e| e.to_string())?;
            }
            server.tick(Instant::now());
            server.send_pending(&mut calls).map_err(|e| e.to_string())?;
            if sent_rx.try_recv().is_ok() {
                break;
            }
        }
        server
            .receive_all(Instant::now(), &mut calls)
            .map_err(|e| e.to_string())?;
        if server.delivered != 1 {
            return Err(format!(
                "expected the first packet, delivered {}",
                server.delivered
            ));
        }
        let mut calls = Syscalls::default();
        let mut cpu = Cpu::ZERO;
        for _ in 0..plan.bursts {
            command_tx
                .send(Command::Burst(plan.burst))
                .map_err(|_| "the second thread stopped".to_string())?;
            sent_rx
                .recv_timeout(HAND_OFF_LIMIT)
                .map_err(|_| "the second thread did not finish a burst".to_string())?;
            // バッファに溜まった burst を読む区間だけを数える。待ちの間は CPU を使わない
            let start = Cpu::now();
            let now = Instant::now();
            wait(&server.socket, libc::POLLIN, 0).map_err(|e| e.to_string())?;
            calls.wake += 1;
            let read = server
                .receive_all(now, &mut calls)
                .map_err(|e| e.to_string())?;
            cpu = cpu.plus(Cpu::now().since(start));
            if read != plan.burst as u64 {
                return Err(format!(
                    "a burst delivered {read} of {} datagrams",
                    plan.burst
                ));
            }
        }
        let drops = server.device.drops().total();
        if drops != 0 {
            return Err(format!("the device layer dropped {drops} packets"));
        }
        Ok(Measured { cpu, calls })
    })();
    drop(command_tx);
    let joined = peer
        .join()
        .map_err(|_| "the second thread panicked".to_string())?;
    let measured = result?;
    joined?;
    Ok(measured)
}

/// The second thread of `recv` mode: the agent that encrypts a burst when told to.
fn sender_thread(
    mut agent: Link,
    packet: &[u8],
    cpu: Option<usize>,
    commands: &Receiver<Command>,
    sent: &Sender<()>,
) -> Result<(), String> {
    pin(cpu).map_err(|e| format!("cannot pin the second thread: {e}"))?;
    let mut calls = Syscalls::default();
    agent.encrypt(Instant::now(), packet);
    agent.send_pending(&mut calls).map_err(|e| e.to_string())?;
    let deadline = Instant::now() + SETUP_LIMIT;
    while !agent
        .device
        .has_session(&agent_peer(&agent), Instant::now())
    {
        if Instant::now() > deadline {
            return Err("the handshake did not complete".to_string());
        }
        if wait(&agent.socket, libc::POLLIN, 5).map_err(|e| e.to_string())? {
            agent
                .receive_all(Instant::now(), &mut calls)
                .map_err(|e| e.to_string())?;
        }
        agent.tick(Instant::now());
        agent.send_pending(&mut calls).map_err(|e| e.to_string())?;
    }
    agent.send_pending(&mut calls).map_err(|e| e.to_string())?;
    sent.send(()).map_err(|e| e.to_string())?;
    while let Ok(Command::Burst(n)) = commands.recv() {
        let now = Instant::now();
        for _ in 0..n {
            agent.encrypt(now, packet);
            agent.send_pending(&mut calls).map_err(|e| e.to_string())?;
        }
        if sent.send(()).is_err() {
            break;
        }
    }
    Ok(())
}

/// The server's public key as the agent knows it.
fn agent_peer(agent: &Link) -> PublicKey {
    agent
        .device
        .peers()
        .next()
        .expect("the agent has its server as a peer")
}
