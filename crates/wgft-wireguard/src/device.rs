//! sans-IO の WireGuard の device。
//!
//! 入力は 3 種類だけで、どれも呼び手が今の時刻を渡す:
//! UDP で届いた datagram ([`Device::handle_datagram`])、トンネルへ送る IP の packet
//! ([`Device::handle_packet`])、timer ([`Device::handle_timeout`])。
//! 出力は送る datagram、トンネルの側へ渡す packet、event と、次に起こす時刻で、呼び手が
//! `poll_*` で取り出す。中にスレッド、実の時計、socket を持たない。
//!
//! sanstun の README の呼び手の責任のうち、次をここで果たす。
//! - 暗号鍵の経路表:送信は宛先からピアを選び、受信は復号した packet の送信元が送ってきた
//!   ピアの AllowedIPs に入るものだけを通す
//! - endpoint の更新:ハンドシェイクかデータを受け付けた後だけ、その datagram の送信元に移す
//! - 中身の検査:IPv4 のヘッダを確かめ、詰め物を全長で切る
//! - キューの上界:持つものはすべて件数とバイト数の上限を持ち、溢れたものは捨てて数える。
//!   暗号の処理はその呼び出しの中で済ませるので、暗号の処理を待つキューは無い
//! - 誤り:相手には何も返さず、[`Drops`] で数える

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::allowed_ips::AllowedIps;
use crate::config::{ConfigError, DeviceConfig, Limits};
use crate::drops::{DropReason, Drops};
use crate::ip::{IPV4_MIN_HEADER, parse_ipv4};
use crate::keys::PublicKey;
use crate::protocol::{DATA_OVERHEAD, Inbound, PADDING, PeerId, ProtoEvent, Protocol};
use crate::queue::{BoundedQueue, ByteLen};
use zeroize::Zeroizing;

/// The smallest MTU that carries an IPv4 packet.
const MIN_MTU: u16 = 68;

/// A UDP datagram for the caller to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transmit {
    /// Where to send it.
    pub to: SocketAddr,
    /// The WireGuard message.
    pub payload: Vec<u8>,
}

impl ByteLen for Transmit {
    fn byte_len(&self) -> usize {
        self.payload.capacity()
    }
}

/// Something that happened to a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A handshake with the peer was accepted: we answered its initiation or it answered ours.
    HandshakeAccepted {
        /// The peer.
        peer: PublicKey,
    },
    /// The first session with the peer since the device started or since the peer last
    /// expired was confirmed by traffic in both directions.
    SessionEstablished {
        /// The peer.
        peer: PublicKey,
        /// From the first initiation, retries included, or from the accepted initiation, to the
        /// confirmation.
        took: Duration,
    },
    /// An authenticated handshake or data message came from a new address, and the device now
    /// sends to that address.
    EndpointChanged {
        /// The peer.
        peer: PublicKey,
        /// The new endpoint.
        endpoint: SocketAddr,
    },
    /// The peer did not answer within the protocol's time limits, or its keys grew too old. Its
    /// sessions and waiting packets were dropped. A peer with a persistent keepalive is contacted
    /// again after one keepalive interval; any peer is contacted again when a packet is sent to it.
    PeerExpired {
        /// The peer.
        peer: PublicKey,
    },
}

/// The state of one peer, as `wg show` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerStatus {
    /// Where datagrams for the peer go.
    pub endpoint: Option<SocketAddr>,
    /// When the handshake of the session in use completed.
    pub last_handshake: Option<Instant>,
    /// Bytes of authenticated datagrams received from the peer.
    pub rx_bytes: u64,
    /// Bytes of datagrams queued for the peer.
    pub tx_bytes: u64,
}

/// What the device holds between calls. Every field stays within its [`Limits`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Held {
    /// Datagrams in the transmit queue.
    pub transmit_packets: usize,
    /// Their bytes.
    pub transmit_bytes: usize,
    /// Packets in the delivery queue.
    pub deliver_packets: usize,
    /// Their bytes.
    pub deliver_bytes: usize,
    /// Events in the event queue.
    pub events: usize,
    /// The largest number of staged packets of any peer.
    pub staged_packets_max: usize,
    /// The largest staged bytes of any peer.
    pub staged_bytes_max: usize,
}

#[derive(Debug)]
struct Peer {
    key: PublicKey,
    endpoint: Option<SocketAddr>,
    keepalive: Option<Duration>,
    /// ハンドシェイクを待つ送信の packet。
    staged: BoundedQueue<Vec<u8>>,
    /// persistent keepalive の期限。このピアへ送るか、このピアから認証した datagram を受けるたびに
    /// 間隔だけ先へ延ばす (wireguard-go の persistent keepalive の timer と同じ規則)。期限が来たときは、
    /// 使えるセッションが無いので、ハンドシェイクを始める。persistent keepalive を持たないピアには置かない。
    keepalive_at: Option<Instant>,
    rx_bytes: u64,
    tx_bytes: u64,
}

/// A sans-IO WireGuard device.
#[derive(Debug)]
pub struct Device {
    proto: Protocol,
    peers: Vec<Peer>,
    by_key: HashMap<PublicKey, PeerId>,
    routes: AllowedIps<PeerId>,
    mtu: usize,
    limits: Limits,
    transmits: BoundedQueue<Transmit>,
    packets: BoundedQueue<Vec<u8>>,
    events: VecDeque<Event>,
    drops: Drops,
    /// これまでに渡された最も新しい時刻。時刻が戻っても sanstun には戻さない。
    now: Instant,
}

impl Device {
    /// Makes a device.
    ///
    /// `seed` is the source of every key, index and nonce the device draws; give it 32 bytes of
    /// fresh operating-system entropy, never a reused value outside tests. `unix` is the wall
    /// clock time since the Unix epoch at `now`; handshake initiations carry it, so it must not go
    /// backwards across restarts or the peer drops them as replays.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for duplicate or invalid peer keys, a tiny MTU, a zero limit, a
    /// keepalive outside 1 to 65535 seconds or timer overrides outside the protocol's bounds.
    pub fn new(
        config: DeviceConfig,
        seed: Zeroizing<[u8; 32]>,
        now: Instant,
        unix: Duration,
    ) -> Result<Self, ConfigError> {
        if config.mtu < MIN_MTU {
            return Err(ConfigError::Mtu(config.mtu));
        }
        config.validate()?;
        let l = config.limits;
        let keys: Vec<_> = config
            .peers
            .iter()
            .map(|p| (p.public_key, p.persistent_keepalive))
            .collect();
        let proto = Protocol::new(&config.private_key, &keys, config.timers, seed, now, unix)?;
        let mtu = usize::from(config.mtu);
        let mut routes = AllowedIps::new();
        let mut by_key = HashMap::with_capacity(config.peers.len());
        let mut peers = Vec::with_capacity(config.peers.len());
        for (id, p) in config.peers.into_iter().enumerate() {
            for prefix in &p.allowed_ips {
                routes.insert(*prefix, id);
            }
            by_key.insert(p.public_key, id);
            let keepalive = p.persistent_keepalive;
            peers.push(Peer {
                key: p.public_key,
                endpoint: p.endpoint,
                keepalive,
                staged: BoundedQueue::new(l.staged_packets, l.staged_packets * mtu),
                keepalive_at: (keepalive.is_some() && p.endpoint.is_some()).then_some(now),
                rx_bytes: 0,
                tx_bytes: 0,
            });
        }
        Ok(Self {
            proto,
            peers,
            by_key,
            routes,
            mtu,
            limits: l,
            transmits: BoundedQueue::new(l.transmit_packets, l.transmit_bytes),
            packets: BoundedQueue::new(l.deliver_packets, l.deliver_bytes),
            events: VecDeque::new(),
            drops: Drops::default(),
            now,
        })
    }

    /// The longest datagram the device sends, for sizing receive buffers on the other side.
    #[must_use]
    pub fn max_transmit_len(&self) -> usize {
        // ハンドシェイクの開始 (148 バイト) より長い
        self.mtu.next_multiple_of(PADDING) + DATA_OVERHEAD
    }

    fn clock(&mut self, now: Instant) -> Instant {
        self.now = self.now.max(now);
        self.now
    }

    /// Handles a UDP datagram that arrived from `from`.
    pub fn handle_datagram(&mut self, now: Instant, from: SocketAddr, datagram: &[u8]) {
        let now = self.clock(now);
        let inbound = match self.proto.receive(now, from, datagram) {
            Ok(inbound) => inbound,
            Err(reason) => {
                self.drops.add(reason, 1);
                return;
            }
        };
        let rx = datagram.len() as u64;
        match inbound {
            Inbound::CookieReply(reply) => self.push_transmit(from, reply),
            Inbound::CookieStored => {}
            Inbound::InitiationAnswered { peer, response } => {
                self.accepted_from(peer, from, rx);
                self.push_event(Event::HandshakeAccepted {
                    peer: self.peers[peer].key,
                });
                self.send_to_peer(peer, response);
                self.drain_proto_events(peer, now);
            }
            Inbound::ResponseAccepted { peer, keepalive } => {
                self.accepted_from(peer, from, rx);
                self.push_event(Event::HandshakeAccepted {
                    peer: self.peers[peer].key,
                });
                self.send_to_peer(peer, keepalive);
                self.flush_staged(peer, now);
                self.drain_proto_events(peer, now);
            }
            Inbound::Keepalive { peer } => {
                self.accepted_from(peer, from, rx);
                self.flush_staged(peer, now);
                self.drain_proto_events(peer, now);
            }
            Inbound::Data { peer, plaintext } => {
                self.accepted_from(peer, from, rx);
                self.deliver(peer, &plaintext);
                self.flush_staged(peer, now);
                self.drain_proto_events(peer, now);
            }
        }
    }

    /// 認証した datagram の後だけ endpoint を動かす。
    fn accepted_from(&mut self, peer: PeerId, from: SocketAddr, rx: u64) {
        let now = self.now;
        let p = &mut self.peers[peer];
        p.rx_bytes = p.rx_bytes.saturating_add(rx);
        p.keepalive_at = p.keepalive.map(|interval| now + interval);
        if p.endpoint != Some(from) {
            p.endpoint = Some(from);
            let event = Event::EndpointChanged {
                peer: p.key,
                endpoint: from,
            };
            self.push_event(event);
        }
    }

    fn deliver(&mut self, peer: PeerId, plaintext: &[u8]) {
        let Some(header) = parse_ipv4(plaintext) else {
            self.drops.add(DropReason::InvalidInnerPacket, 1);
            return;
        };
        if self.routes.lookup(header.src) != Some(peer) {
            self.drops.add(DropReason::DisallowedSource, 1);
            return;
        }
        // 詰め物を除いた長さの新しいバッファに写す。復号のバッファは datagram の長さで、相手は
        // 短い packet を長い詰め物で送れるので、そのまま持つと容量がキューの上限を超える
        if !self.packets.push(plaintext[..header.total_len].to_vec()) {
            self.drops.add(DropReason::DeliverOverflow, 1);
        }
    }

    /// Handles an IP packet from the tunnel side, to be encrypted for the peer whose allowed IPs
    /// hold its destination.
    pub fn handle_packet(&mut self, now: Instant, packet: &[u8]) {
        let now = self.clock(now);
        let Some(header) = parse_ipv4(packet) else {
            self.drops.add(DropReason::InvalidInnerPacket, 1);
            return;
        };
        if header.total_len > self.mtu {
            self.drops.add(DropReason::TooBig, 1);
            return;
        }
        let Some(peer) = self.routes.lookup(header.dst) else {
            self.drops.add(DropReason::NoRoute, 1);
            return;
        };
        if self.peers[peer].endpoint.is_none() {
            self.drops.add(DropReason::NoEndpoint, 1);
            return;
        }
        let packet = packet[..header.total_len].to_vec();
        if self.peers[peer].staged.is_empty() {
            match self.proto.encapsulate(peer, now, &packet) {
                Ok(Some(datagram)) => {
                    self.send_to_peer(peer, datagram);
                    return;
                }
                Ok(None) => {}
                Err(reason) => {
                    self.drops.add(reason, 1);
                    return;
                }
            }
        }
        // セッションが無いか、先に待っている packet がある。順を保って待たせ、ハンドシェイクを始める
        let evicted = self.peers[peer].staged.push_evicting(packet);
        self.drops.add(DropReason::StagedOverflow, evicted as u64);
        if let Some(initiation) = self.proto.initiate(peer, now) {
            self.send_to_peer(peer, initiation);
        }
        self.flush_staged(peer, now);
    }

    fn flush_staged(&mut self, peer: PeerId, now: Instant) {
        while let Some(packet) = self.peers[peer].staged.pop() {
            match self.proto.encapsulate(peer, now, &packet) {
                Ok(Some(datagram)) => self.send_to_peer(peer, datagram),
                Ok(None) => {
                    self.peers[peer].staged.unpop(packet);
                    return;
                }
                Err(reason) => self.drops.add(reason, 1),
            }
        }
    }

    /// Advances the timers to `now`: handshake retries, rekeying, keepalives and expiry.
    pub fn handle_timeout(&mut self, now: Instant) {
        let now = self.clock(now);
        for peer in 0..self.peers.len() {
            self.proto.handle_timeout(peer, now);
            self.drain_proto_events(peer, now);
            // sanstun は使えるセッションがある間、persistent keepalive を間隔ごとに送り、その送信が
            // この期限を延ばす。sanstun を先に進めた後でも期限が来ているのは、間隔の間なにも送って
            // いない、つまり使えるセッションが無いときだけである。応答の側のセッションが 180 秒で切れた
            // 後もここで始める
            let p = &mut self.peers[peer];
            if let (Some(at), Some(interval)) = (p.keepalive_at, p.keepalive)
                && at <= now
            {
                p.keepalive_at = Some(now + interval);
                if p.endpoint.is_some()
                    && let Some(initiation) = self.proto.initiate(peer, now)
                {
                    self.send_to_peer(peer, initiation);
                }
            }
        }
    }

    fn drain_proto_events(&mut self, peer: PeerId, now: Instant) {
        while let Some(event) = self.proto.poll_event(peer, now) {
            match event {
                ProtoEvent::SendInitiation(d) | ProtoEvent::SendKeepalive(d) => {
                    self.send_to_peer(peer, d);
                }
                ProtoEvent::Established { took } => self.push_event(Event::SessionEstablished {
                    peer: self.peers[peer].key,
                    took,
                }),
                ProtoEvent::Expired { used } => {
                    let p = &mut self.peers[peer];
                    let lost = p.staged.clear();
                    if let (Some(interval), Some(_)) = (p.keepalive, p.endpoint) {
                        p.keepalive_at = Some(now + interval);
                    }
                    let key = p.key;
                    self.drops.add(DropReason::NoSession, lost as u64);
                    // 一度も使わなかったトンネル (ハンドシェイクを始めも受けもしていない) の期限切れは
                    // 知らせない。sanstun は作成から 540 秒で切るので、そのまま知らせると待つだけの
                    // ピアについて 9 分ごとに event が出る
                    if used {
                        self.push_event(Event::PeerExpired { peer: key });
                    }
                }
            }
        }
    }

    fn send_to_peer(&mut self, peer: PeerId, payload: Vec<u8>) {
        let Some(to) = self.peers[peer].endpoint else {
            self.drops.add(DropReason::NoEndpoint, 1);
            return;
        };
        let len = payload.len() as u64;
        if self.transmits.push(Transmit { to, payload }) {
            let now = self.now;
            let p = &mut self.peers[peer];
            p.tx_bytes = p.tx_bytes.saturating_add(len);
            p.keepalive_at = p.keepalive.map(|interval| now + interval);
        } else {
            self.drops.add(DropReason::TransmitOverflow, 1);
        }
    }

    fn push_transmit(&mut self, to: SocketAddr, payload: Vec<u8>) {
        if !self.transmits.push(Transmit { to, payload }) {
            self.drops.add(DropReason::TransmitOverflow, 1);
        }
    }

    fn push_event(&mut self, event: Event) {
        if self.events.len() >= self.limits.events {
            self.events.pop_front();
            self.drops.add(DropReason::EventOverflow, 1);
        }
        self.events.push_back(event);
    }

    /// The next datagram to send.
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.transmits.pop()
    }

    /// The next decrypted packet for the tunnel side. It is a well formed IPv4 packet without
    /// padding, from an address in its peer's allowed IPs.
    pub fn poll_packet(&mut self) -> Option<Vec<u8>> {
        self.packets.pop()
    }

    /// The next event.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// When to call [`Device::handle_timeout`] next. Calling it earlier is harmless.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        (0..self.peers.len())
            .flat_map(|peer| [self.proto.poll_timeout(peer), self.peers[peer].keepalive_at])
            .flatten()
            .min()
    }

    /// Points the peer at a new endpoint, as the control plane does after resolving the server's
    /// name again. Returns `false` for an unknown key.
    pub fn set_endpoint(&mut self, now: Instant, peer: &PublicKey, endpoint: SocketAddr) -> bool {
        let now = self.clock(now);
        let Some(&id) = self.by_key.get(peer) else {
            return false;
        };
        let p = &mut self.peers[id];
        let first = p.endpoint.is_none();
        p.endpoint = Some(endpoint);
        if first && p.keepalive.is_some() {
            p.keepalive_at = Some(now);
        }
        true
    }

    /// The state of a peer, or `None` for an unknown key.
    #[must_use]
    pub fn peer_status(&self, peer: &PublicKey, now: Instant) -> Option<PeerStatus> {
        let &id = self.by_key.get(peer)?;
        let p = &self.peers[id];
        Some(PeerStatus {
            endpoint: p.endpoint,
            last_handshake: self.proto.last_handshake(id, now.max(self.now)),
            rx_bytes: p.rx_bytes,
            tx_bytes: p.tx_bytes,
        })
    }

    /// Encrypts `packet` for the peer as it is, without the checks of [`Device::handle_packet`],
    /// so a fuzz target can send arbitrary inner packets. Not part of the API.
    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn encapsulate_unchecked(
        &mut self,
        now: Instant,
        peer: &PublicKey,
        packet: &[u8],
    ) -> Option<Vec<u8>> {
        let now = self.clock(now);
        let &id = self.by_key.get(peer)?;
        self.proto.encapsulate(id, now, packet).ok().flatten()
    }

    /// The configured peers' keys, in configuration order.
    pub fn peers(&self) -> impl Iterator<Item = PublicKey> {
        self.peers.iter().map(|p| p.key)
    }

    /// Counts of everything dropped so far.
    #[must_use]
    pub fn drops(&self) -> &Drops {
        &self.drops
    }

    /// What the device holds now.
    #[must_use]
    pub fn held(&self) -> Held {
        Held {
            transmit_packets: self.transmits.len(),
            transmit_bytes: self.transmits.bytes(),
            deliver_packets: self.packets.len(),
            deliver_bytes: self.packets.bytes(),
            events: self.events.len(),
            staged_packets_max: self.peers.iter().map(|p| p.staged.len()).max().unwrap_or(0),
            staged_bytes_max: self
                .peers
                .iter()
                .map(|p| p.staged.bytes())
                .max()
                .unwrap_or(0),
        }
    }

    /// The configured limits.
    #[must_use]
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// The tunnel MTU.
    #[must_use]
    pub fn mtu(&self) -> usize {
        self.mtu
    }
}

const _: () = assert!(IPV4_MIN_HEADER <= MIN_MTU as usize);

#[cfg(test)]
#[path = "device_tests.rs"]
mod tests;
