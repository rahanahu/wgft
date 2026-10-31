//! A lab tool that runs the wgft WireGuard device over a Linux TUN device, for interop tests
//! against Linux WireGuard and wireguard-go. Not shipped.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use wgft_wireguard::{
    DeviceConfig, Event, Ipv4Prefix, Limits, PeerConfig, PrivateKey, ProtocolTimers, PublicKey,
    Zeroizing,
};
use wgft_wireguard_tun::{Handle, TunSettings};

/// Runs the wgft WireGuard device on a TUN device with one peer.
///
/// SIGUSR1 writes the status to stderr. SIGUSR2 moves the UDP socket to a new random port on the
/// same address, so the peer sees this side roam. SIGINT and SIGTERM stop it.
#[derive(Debug, Parser)]
#[command(name = "wgft-wireguard-tun", version)]
struct Args {
    /// The TUN device name.
    #[arg(long, default_value = "wgft-rs0")]
    tun: String,
    /// This side's tunnel address and prefix length, such as 10.200.0.2/24.
    #[arg(long)]
    address: String,
    /// The tunnel MTU.
    #[arg(long, default_value_t = 1420)]
    mtu: u16,
    /// A file holding this side's private key in base64.
    #[arg(long)]
    private_key_file: PathBuf,
    /// The peer's public key in base64.
    #[arg(long)]
    peer_public_key: String,
    /// The peer's endpoint, an IP address and port.
    #[arg(long)]
    endpoint: Option<SocketAddr>,
    /// An IPv4 prefix the peer may use; repeat for more.
    #[arg(long = "allowed-ip", required = true)]
    allowed_ips: Vec<Ipv4Prefix>,
    /// The persistent keepalive interval in seconds; 0 turns it off.
    #[arg(long, default_value_t = 25)]
    keepalive: u64,
    /// The local UDP address.
    #[arg(long, default_value = "0.0.0.0:0")]
    listen: SocketAddr,
    /// Overrides the handshake retry interval, 5000 by default, in milliseconds; for tests.
    #[arg(long)]
    rekey_timeout_ms: Option<u64>,
    /// Overrides the passive keepalive delay, 10000 by default, in milliseconds; for tests.
    #[arg(long)]
    keepalive_timeout_ms: Option<u64>,
    /// Overrides how long a handshake is retried, 90000 by default, in milliseconds; for tests.
    #[arg(long)]
    rekey_attempt_time_ms: Option<u64>,
}

fn build_config(args: &Args) -> Result<DeviceConfig, String> {
    let text = std::fs::read_to_string(&args.private_key_file)
        .map_err(|e| format!("read {}: {e}", args.private_key_file.display()))?;
    let private_key =
        PrivateKey::from_base64(text.trim()).map_err(|e| format!("private key: {e}"))?;
    let public_key =
        PublicKey::from_base64(&args.peer_public_key).map_err(|e| format!("peer key: {e}"))?;
    let ms = |v: Option<u64>| v.map(Duration::from_millis);
    Ok(DeviceConfig {
        private_key,
        mtu: args.mtu,
        peers: vec![PeerConfig {
            public_key,
            endpoint: args.endpoint,
            allowed_ips: args.allowed_ips.clone(),
            persistent_keepalive: Some(Duration::from_secs(args.keepalive))
                .filter(|d| !d.is_zero()),
        }],
        limits: Limits::default(),
        timers: ProtocolTimers {
            rekey_timeout: ms(args.rekey_timeout_ms),
            keepalive_timeout: ms(args.keepalive_timeout_ms),
            rekey_attempt_time: ms(args.rekey_attempt_time_ms),
        },
    })
}

fn tun_settings(args: &Args) -> Result<TunSettings, String> {
    let bad = || {
        format!(
            "address {:?} is not an IPv4 address with a prefix length",
            args.address
        )
    };
    let (addr, len) = args.address.split_once('/').ok_or_else(bad)?;
    Ok(TunSettings {
        name: args.tun.clone(),
        address: addr.parse().map_err(|_| bad())?,
        prefix_len: len.parse().ok().filter(|l| *l <= 32).ok_or_else(bad)?,
        mtu: args.mtu,
    })
}

fn log_event(event: &Event, start: Instant) {
    let at = start.elapsed().as_millis();
    match event {
        Event::HandshakeAccepted { peer } => {
            eprintln!("event at={at}ms handshake-accepted peer={peer}");
        }
        Event::SessionEstablished { peer, took } => eprintln!(
            "event at={at}ms session-established peer={peer} took={}ms",
            took.as_millis()
        ),
        Event::EndpointChanged { peer, endpoint } => {
            eprintln!("event at={at}ms endpoint-changed peer={peer} endpoint={endpoint}");
        }
        Event::PeerExpired { peer } => eprintln!("event at={at}ms peer-expired peer={peer}"),
    }
}

async fn print_status(handle: &Handle) {
    let Ok(status) = handle.status().await else {
        return;
    };
    let now = Instant::now();
    let mut line = format!("status local={}", status.local);
    if let Some(peer) = status.peer {
        if let Some(ep) = peer.endpoint {
            let _ = write!(line, " endpoint={ep}");
        }
        if let Some(at) = peer.last_handshake {
            let age = now.saturating_duration_since(at).as_millis();
            let _ = write!(line, " handshake_age_ms={age}");
        }
        let _ = write!(line, " rx={} tx={}", peer.rx_bytes, peer.tx_bytes);
    }
    for (reason, n) in status.drops.nonzero() {
        let _ = write!(line, " drop_{}={n}", reason.name());
    }
    let _ = write!(line, " send_errors={}", status.send_errors);
    eprintln!("{line}");
}

#[cfg(target_os = "linux")]
async fn serve(mut handle: Handle) -> std::io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let start = Instant::now();
    let mut events = handle.take_events().expect("events are taken once");
    let mut usr1 = signal(SignalKind::user_defined1())?;
    let mut usr2 = signal(SignalKind::user_defined2())?;
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    loop {
        tokio::select! {
            Some(event) = events.recv() => log_event(&event, start),
            _ = usr1.recv() => print_status(&handle).await,
            _ = usr2.recv() => {
                let status = handle.status().await?;
                let listen = SocketAddr::new(status.local.ip(), 0);
                let local = handle.rebind(listen).await?;
                eprintln!("rebound local={local}");
            }
            _ = term.recv() => break,
            _ = int.recv() => break,
            () = tokio::time::sleep(Duration::from_millis(200)), if handle.is_finished() => break,
        }
    }
    handle.stop().await
}

#[cfg(not(target_os = "linux"))]
async fn serve(handle: Handle) -> std::io::Result<()> {
    handle.stop().await
}

fn main() -> ExitCode {
    let args = Args::parse();
    let (config, tun) = match build_config(&args).and_then(|c| Ok((c, tun_settings(&args)?))) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("wgft-wireguard-tun: {e}");
            return ExitCode::from(2);
        }
    };
    let mut seed = Zeroizing::new([0u8; 32]);
    if let Err(e) = getrandom::fill(&mut seed[..]) {
        eprintln!("wgft-wireguard-tun: read entropy: {e}");
        return ExitCode::FAILURE;
    }
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("wgft-wireguard-tun: start runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(async {
        let handle = wgft_wireguard_tun::spawn(config, tun, args.listen, seed, unix).await?;
        let local = handle.status().await?.local;
        eprintln!("wgft-wireguard-tun: up tun={} local={local}", args.tun);
        serve(handle).await
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("wgft-wireguard-tun: {e}");
            ExitCode::FAILURE
        }
    }
}
