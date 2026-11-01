//! 中継の試験の相手。server の側の WireGuard の device をループバックの UDP で動かし、その上で台本の
//! TCP の client と ICMP の echo の応答を持つ。agent の側は本物のデータプレーンと Rust の wgstack の核で、
//! 試験は server がトンネルの中で agent のルールのポートへ接続する形を、カーネルの TCP/IP なしで作る。
//!
//! 台本の client は損失の無いループバックを前提にし、再送も窓の制御もしない。送るデータは相手の窓に
//! 収まる大きさにする。受けた segment には毎回 ACK を返す。

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use wgft_wgstack::Limits;
use wgft_wireguard::{
    Device, DeviceConfig, Ipv4Prefix, PeerConfig, PrivateKey, ProtocolTimers, PublicKey, Roaming,
};

use crate::dataplane::stack::{StackSettings, make};
use crate::dataplane::{Carry, Dataplane, Settings, clock};
use crate::tunnel::Stack;

pub(crate) const AGENT_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 2);
pub(crate) const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);

const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;
const FIN: u8 = 0x01;

/// 試験の核の表の大きさ。
pub(crate) fn limits() -> Limits {
    Limits {
        max_flows: 64,
        accept_queue: 16,
        syn_rows: 32,
        tw_rows: 256,
        ctl_slots: 64,
        ..Limits::default()
    }
}

/// 受けた TCP の segment。
#[derive(Debug, Clone)]
pub(crate) struct Seg {
    pub(crate) seq: u32,
    pub(crate) ack: u32,
    pub(crate) flags: u8,
    pub(crate) payload: Vec<u8>,
}

/// 台本の UDP の endpoint が受けた datagram の送信元のポートと中身。
type Datagram = (u16, Vec<u8>);

struct Inner {
    out: mpsc::UnboundedSender<Vec<u8>>,
    conns: Mutex<HashMap<u16, mpsc::UnboundedSender<Seg>>>,
    /// 台本の UDP の endpoint。受けた datagram を送信元のポートと中身で渡す。
    udp: Mutex<HashMap<u16, mpsc::UnboundedSender<Datagram>>>,
    /// echo の応答でない ICMP の packet (Port Unreachable など)。
    icmp: Mutex<Vec<Vec<u8>>>,
    next_port: AtomicU16,
}

/// The server side of a tunnel to an agent data plane, with a scripted TCP client.
pub(crate) struct Peer {
    inner: Arc<Inner>,
    task: JoinHandle<()>,
    /// The agent's data plane, its peer being this server.
    agent: Option<Dataplane<Stack>>,
    server_key: PrivateKey,
    endpoint: SocketAddr,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Peer {
    /// Starts a server device on loopback and an agent data plane with the Rust wgstack that
    /// points at it.
    pub(crate) async fn start() -> Peer {
        let (mut peer, agent_key) = Peer::server().await;
        let agent = DeviceConfig::agent(
            agent_key,
            peer.server_key.public_key(),
            Some(peer.endpoint),
            SERVER_IP,
            Duration::from_secs(25),
        );
        let settings = Settings {
            listen: "127.0.0.1:0".parse().unwrap(),
            ..Settings::default()
        };
        let stack = StackSettings {
            addr: AGENT_IP,
            limits: limits(),
        };
        let agent = Dataplane::start(agent, settings, Carry::first(Duration::ZERO), move |init| {
            make(stack, init)
        })
        .await
        .unwrap();
        peer.agent = Some(agent);
        peer
    }

    /// Starts only the server device on loopback, for an agent the test starts itself with the
    /// returned private key.
    pub(crate) async fn server() -> (Peer, PrivateKey) {
        let agent_key = PrivateKey::generate([0xa1; 32]);
        let server_key = PrivateKey::generate([0xb2; 32]);
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = sock.local_addr().unwrap();
        let server = DeviceConfig {
            private_key: server_key.clone(),
            mtu: 1420,
            peers: vec![PeerConfig {
                public_key: agent_key.public_key(),
                endpoint: None,
                allowed_ips: vec![Ipv4Prefix::host(AGENT_IP)],
                persistent_keepalive: None,
                roaming: Roaming::Any,
            }],
            limits: wgft_wireguard::Limits::default(),
            timers: ProtocolTimers::default(),
        };
        let device = Device::new(server, clock::now(), Duration::ZERO).unwrap();
        let (out, out_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner {
            out,
            conns: Mutex::new(HashMap::new()),
            udp: Mutex::new(HashMap::new()),
            icmp: Mutex::new(Vec::new()),
            next_port: AtomicU16::new(40000),
        });
        let task = tokio::spawn(serve(device, sock, out_rx, Arc::clone(&inner)));
        let peer = Peer {
            inner,
            task,
            agent: None,
            server_key,
            endpoint,
        };
        (peer, agent_key)
    }

    /// The server's public key.
    pub(crate) fn server_public_key(&self) -> PublicKey {
        self.server_key.public_key()
    }

    /// The server's UDP endpoint.
    pub(crate) fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    /// The agent's data plane.
    pub(crate) fn agent(&self) -> &Dataplane<Stack> {
        self.agent.as_ref().expect("the agent's data plane runs")
    }

    /// Stops the agent's data plane, as the agent does when it rebuilds the tunnel.
    pub(crate) async fn stop_agent(&mut self) {
        if let Some(a) = self.agent.take() {
            a.stop().await;
        }
    }

    /// A scripted UDP endpoint on the server's tunnel address, on a port of its own.
    pub(crate) fn udp(&self) -> UdpClient {
        let lport = self.inner.next_port.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::unbounded_channel();
        self.inner.udp.lock().unwrap().insert(lport, tx);
        UdpClient {
            inner: Arc::clone(&self.inner),
            lport,
            rx,
        }
    }

    /// The ICMP packets other than echo replies that came out of the tunnel so far.
    pub(crate) fn icmp_errors(&self) -> usize {
        self.inner.icmp.lock().unwrap().len()
    }

    /// Opens a connection from the server's tunnel address to the agent's `port`.
    ///
    /// # Errors
    ///
    /// Returns what came back instead of a SYN-ACK: a RST, or nothing within 5 seconds.
    pub(crate) async fn connect(&self, port: u16) -> Result<Client, Outcome> {
        let lport = self.inner.next_port.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::unbounded_channel();
        self.inner.conns.lock().unwrap().insert(lport, tx);
        let mut c = Client {
            inner: Arc::clone(&self.inner),
            lport,
            rport: port,
            rx,
            snd_nxt: 1000,
            rcv_nxt: 0,
            data: Vec::new(),
        };
        // MSS 1380。トンネルのハンドシェイクが済むまでの SYN は server の device で落ちうるので、答えが
        // 来るまで 200 ミリ秒ごとに送り直す
        let mut tries = 0;
        let s = loop {
            c.emit(SYN, &[2, 4, 0x05, 0x64], &[]);
            if let Some(s) = c.next(Duration::from_millis(200)).await {
                break s;
            }
            tries += 1;
            if tries == 25 {
                return Err(Outcome::Timeout);
            }
        };
        c.snd_nxt += 1;
        let mut first = Some(s);
        loop {
            let s = match first.take() {
                Some(s) => s,
                None => c
                    .next(Duration::from_secs(5))
                    .await
                    .ok_or(Outcome::Timeout)?,
            };
            if s.flags & RST != 0 {
                return Err(Outcome::Reset);
            }
            if s.flags & (SYN | ACK) == SYN | ACK {
                c.rcv_nxt = s.seq.wrapping_add(1);
                c.emit(ACK, &[], &[]);
                return Ok(c);
            }
        }
    }
}

/// How a read ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The peer sent a FIN.
    Eof,
    /// The peer sent a RST.
    Reset,
    /// Nothing came in time.
    Timeout,
}

/// A scripted TCP connection from the server into the tunnel.
pub(crate) struct Client {
    inner: Arc<Inner>,
    lport: u16,
    rport: u16,
    rx: mpsc::UnboundedReceiver<Seg>,
    snd_nxt: u32,
    rcv_nxt: u32,
    /// 受けて、まだ読まれていないデータ。
    data: Vec<u8>,
}

impl Drop for Client {
    fn drop(&mut self) {
        self.inner.conns.lock().unwrap().remove(&self.lport);
    }
}

impl Client {
    fn emit(&self, flags: u8, opts: &[u8], payload: &[u8]) {
        let p = tcp_packet(
            SERVER_IP,
            AGENT_IP,
            self.lport,
            self.rport,
            self.snd_nxt,
            if flags & ACK != 0 { self.rcv_nxt } else { 0 },
            flags,
            opts,
            payload,
        );
        let _ = self.inner.out.send(p);
    }

    async fn next(&mut self, wait: Duration) -> Option<Seg> {
        tokio::time::timeout(wait, self.rx.recv())
            .await
            .ok()
            .flatten()
    }

    /// Sends `data` in segments of at most 1000 bytes. The data must fit the peer's window.
    pub(crate) fn send(&mut self, data: &[u8]) {
        for chunk in data.chunks(1000) {
            self.emit(ACK | PSH, &[], chunk);
            self.snd_nxt = self
                .snd_nxt
                .wrapping_add(u32::try_from(chunk.len()).unwrap());
        }
    }

    /// Sends a FIN.
    pub(crate) fn finish(&mut self) {
        self.emit(FIN | ACK, &[], &[]);
        self.snd_nxt = self.snd_nxt.wrapping_add(1);
    }

    /// Sends a RST.
    pub(crate) fn reset(&mut self) {
        self.emit(RST | ACK, &[], &[]);
    }

    /// Reads until `n` bytes arrived, or returns how the stream ended first.
    pub(crate) async fn read_exact(&mut self, n: usize) -> Result<Vec<u8>, Outcome> {
        while self.data.len() < n {
            self.read_more(Duration::from_secs(5)).await?;
        }
        Ok(self.data.drain(..n).collect())
    }

    /// Reads everything up to the end of the stream and returns it with how the stream ended.
    pub(crate) async fn read_to_end(&mut self, wait: Duration) -> (Vec<u8>, Outcome) {
        loop {
            if let Err(o) = self.read_more(wait).await {
                return (std::mem::take(&mut self.data), o);
            }
        }
    }

    /// Waits for the next thing the peer sends after the data read so far: more data is kept and
    /// waited past; returns how the stream ended, or [`Outcome::Timeout`].
    pub(crate) async fn outcome(&mut self, wait: Duration) -> Outcome {
        self.read_to_end(wait).await.1
    }

    async fn read_more(&mut self, wait: Duration) -> Result<(), Outcome> {
        let s = self.next(wait).await.ok_or(Outcome::Timeout)?;
        if s.flags & RST != 0 {
            return Err(Outcome::Reset);
        }
        let _ = s.ack;
        if s.seq == self.rcv_nxt {
            self.rcv_nxt = self
                .rcv_nxt
                .wrapping_add(u32::try_from(s.payload.len()).unwrap());
            self.data.extend_from_slice(&s.payload);
            if s.flags & FIN != 0 {
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                self.emit(ACK, &[], &[]);
                return Err(Outcome::Eof);
            }
        }
        if !s.payload.is_empty() || s.flags & FIN != 0 {
            self.emit(ACK, &[], &[]);
        }
        Ok(())
    }
}

/// A scripted UDP endpoint on the server's side of the tunnel.
pub(crate) struct UdpClient {
    inner: Arc<Inner>,
    lport: u16,
    rx: mpsc::UnboundedReceiver<(u16, Vec<u8>)>,
}

impl Drop for UdpClient {
    fn drop(&mut self) {
        self.inner.udp.lock().unwrap().remove(&self.lport);
    }
}

impl UdpClient {
    /// Sends `data` as one datagram to the agent's `port`. It must fit the tunnel's MTU.
    pub(crate) fn send(&self, port: u16, data: &[u8]) {
        let _ = self
            .inner
            .out
            .send(udp_packet(SERVER_IP, AGENT_IP, self.lport, port, data));
    }

    /// The next datagram with its source port, or `None` after `wait`.
    pub(crate) async fn recv(&mut self, wait: Duration) -> Option<(u16, Vec<u8>)> {
        tokio::time::timeout(wait, self.rx.recv())
            .await
            .ok()
            .flatten()
    }
}

/// server の側の device を動かす task。
async fn serve(
    mut device: Device,
    sock: UdpSocket,
    mut out: mpsc::UnboundedReceiver<Vec<u8>>,
    inner: Arc<Inner>,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        let deadline = device.poll_timeout();
        tokio::select! {
            r = sock.recv_from(&mut buf) => {
                let Ok((n, from)) = r else { continue };
                device.handle_datagram(clock::now(), from, &buf[..n]);
                while let Some(p) = device.poll_packet() {
                    if let Some(reply) = route(&p, &inner) {
                        device.handle_packet(clock::now(), &reply);
                    }
                }
            }
            Some(p) = out.recv() => device.handle_packet(clock::now(), &p),
            () = crate::dataplane::clock::sleep_until(deadline.unwrap_or_else(|| clock::now() + Duration::from_secs(1))) => {
                device.handle_timeout(clock::now());
            }
        }
        while let Some(t) = device.poll_transmit() {
            let to: SocketAddr = t.to;
            let _ = sock.send_to(&t.payload, to).await;
        }
    }
}

/// 復号した packet を client に渡す。echo request には返す packet を返す。
fn route(p: &[u8], inner: &Inner) -> Option<Vec<u8>> {
    let ihl = usize::from(p.first()? & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([*p.get(2)?, *p.get(3)?]));
    let body = p.get(ihl..total)?;
    match p[9] {
        6 => {
            let dport = u16::from_be_bytes([body[2], body[3]]);
            let off = usize::from(body[12] >> 4) * 4;
            let seg = Seg {
                seq: u32::from_be_bytes(body[4..8].try_into().ok()?),
                ack: u32::from_be_bytes(body[8..12].try_into().ok()?),
                flags: body[13],
                payload: body.get(off..)?.to_vec(),
            };
            if let Some(tx) = inner.conns.lock().unwrap().get(&dport) {
                let _ = tx.send(seg);
            }
            None
        }
        17 => {
            let sport = u16::from_be_bytes([body[0], body[1]]);
            let dport = u16::from_be_bytes([body[2], body[3]]);
            if let Some(tx) = inner.udp.lock().unwrap().get(&dport) {
                let _ = tx.send((sport, body.get(8..)?.to_vec()));
            }
            None
        }
        1 if body.first() != Some(&8) && body.first() != Some(&0) => {
            inner.icmp.lock().unwrap().push(body.to_vec());
            None
        }
        1 if body.first() == Some(&8) => {
            let mut reply = body.to_vec();
            reply[0] = 0;
            reply[2..4].copy_from_slice(&[0, 0]);
            let sum = checksum(&reply, 0);
            reply[2..4].copy_from_slice(&sum.to_be_bytes());
            Some(ipv4(SERVER_IP, AGENT_IP, 1, &reply))
        }
        _ => None,
    }
}

fn checksum(data: &[u8], mut sum: u32) -> u16 {
    for c in data.chunks(2) {
        let w = u32::from(c[0]) << 8 | u32::from(*c.get(1).unwrap_or(&0));
        sum = sum.wrapping_add(w);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap()
}

fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, body: &[u8]) -> Vec<u8> {
    let total = 20 + body.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
    p[8] = 64;
    p[9] = proto;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let sum = checksum(&p[..20], 0);
    p[10..12].copy_from_slice(&sum.to_be_bytes());
    p[20..].copy_from_slice(body);
    p
}

#[expect(clippy::too_many_arguments, reason = "the fields of one TCP header")]
fn tcp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    opts: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let hlen = 20 + opts.len();
    let mut t = vec![0u8; hlen + payload.len()];
    t[0..2].copy_from_slice(&sport.to_be_bytes());
    t[2..4].copy_from_slice(&dport.to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = u8::try_from(hlen / 4).unwrap() << 4;
    t[13] = flags;
    t[14..16].copy_from_slice(&65535u16.to_be_bytes());
    t[20..hlen].copy_from_slice(opts);
    t[hlen..].copy_from_slice(payload);
    let mut pseudo = 0u32;
    for w in [src.octets(), dst.octets()] {
        pseudo += u32::from(u16::from_be_bytes([w[0], w[1]]));
        pseudo += u32::from(u16::from_be_bytes([w[2], w[3]]));
    }
    pseudo += 6 + u32::try_from(t.len()).unwrap();
    let sum = checksum(&t, pseudo);
    t[16..18].copy_from_slice(&sum.to_be_bytes());
    ipv4(src, dst, 6, &t)
}

fn udp_packet(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut u = vec![0u8; len];
    u[0..2].copy_from_slice(&sport.to_be_bytes());
    u[2..4].copy_from_slice(&dport.to_be_bytes());
    u[4..6].copy_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
    u[8..].copy_from_slice(payload);
    let mut pseudo = 0u32;
    for w in [src.octets(), dst.octets()] {
        pseudo += u32::from(u16::from_be_bytes([w[0], w[1]]));
        pseudo += u32::from(u16::from_be_bytes([w[2], w[3]]));
    }
    pseudo += 17 + u32::try_from(len).unwrap();
    let sum = checksum(&u, pseudo);
    u[6..8].copy_from_slice(&if sum == 0 { 0xffff } else { sum }.to_be_bytes());
    ipv4(src, dst, 17, &u)
}
