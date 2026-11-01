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
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::allowed_ips::AllowedIps;
use crate::config::{ConfigError, DeviceConfig, Limits, MAX_UNIX_TIME, MIN_MTU, Roaming};
use crate::drops::{DropReason, Drops};
use crate::ip::{IPV4_MIN_HEADER, parse_ipv4};
use crate::keys::PublicKey;
use crate::protocol::{DATA_OVERHEAD, Inbound, PeerId, ProtoEvent, Protocol, inner_mtu};
use crate::queue::{BoundedQueue, ByteLen};
use zeroize::Zeroizing;

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

struct Peer {
    key: PublicKey,
    endpoint: Option<SocketAddr>,
    /// 設定した endpoint。`Roaming::NotByInitiation` のピアは期限切れでここへ戻る。
    configured_endpoint: Option<SocketAddr>,
    roaming: Roaming,
    keepalive: Option<Duration>,
    /// ハンドシェイクを待つ送信の packet。
    staged: BoundedQueue<Vec<u8>>,
    /// persistent keepalive の期限。このピアへ送るか、このピアから認証した datagram を受けるたびに
    /// 間隔だけ先へ延ばす (wireguard-go の persistent keepalive の timer と同じ規則)。期限が来たときは、
    /// 使えるセッションが無いので、ハンドシェイクを始める。persistent keepalive を持たないピアには置かない。
    keepalive_at: Option<Instant>,
    /// 最後にハンドシェイクの開始か応答を送った時刻。device が始める開始は、ここから `REKEY_TIMEOUT` を
    /// 空ける (論文の 6.1 節、wireguard-go の `lastSentHandshake`)。
    handshake_sent_at: Option<Instant>,
    /// 接続の期限切れ (再試行の打ち切り) の後、データを持たない開始 ([`Device::start_handshake`] と
    /// keepalive の期限) を控える終わりの時刻。
    paused_until: Option<Instant>,
    /// 間隔か休止で控えた開始の要求。時刻が来たら `handle_timeout` が行う。`bool` はデータの送信の要求か。
    deferred: Option<(Instant, bool)>,
    rx_bytes: u64,
    tx_bytes: u64,
}

/// A sans-IO WireGuard device.
pub struct Device {
    proto: Protocol,
    peers: Vec<Peer>,
    by_key: HashMap<PublicKey, PeerId>,
    routes: AllowedIps<PeerId>,
    mtu: usize,
    /// `REKEY_TIMEOUT`。device が始めるハンドシェイクの開始の間隔の下限。
    rekey_timeout: Duration,
    limits: Limits,
    transmits: BoundedQueue<Transmit>,
    packets: BoundedQueue<Vec<u8>>,
    events: VecDeque<Event>,
    drops: Drops,
    /// これまでに渡された最も新しい時刻。時刻が戻っても sanstun には戻さない。
    now: Instant,
    /// 作成の時刻と、そのときの Unix 時刻。ハンドシェイクの開始の印の上限を求める。
    start: Instant,
    unix_at_start: Duration,
}

// 平文を持つキューを出さず、数だけを出す
impl fmt::Debug for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Device")
            .field("peers", &self.peers.len())
            .field("mtu", &self.mtu)
            .field("held", &self.held())
            .field("drops", &self.drops.total())
            .finish_non_exhaustive()
    }
}

impl Device {
    /// Makes a device for production use.
    ///
    /// It draws the seed for every key, index and nonce from the operating system and reads the
    /// wall clock once. Handshake initiations carry a timestamp that the peer requires to grow
    /// across restarts, so the device stamps them from `max(wall clock, unix_floor + 1 s)`.
    /// `unix_floor` is the caller's persisted [`Device::unix_high_water`] of the previous run, or
    /// zero; persisting it keeps initiations acceptable after the wall clock went back.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for duplicate or invalid peer keys, a tiny MTU, limits that are
    /// zero or too large, a keepalive outside 1 to 65535 seconds, timer overrides outside the
    /// protocol's bounds, a Unix time beyond [`MAX_UNIX_TIME`] or missing entropy.
    pub fn new(
        config: DeviceConfig,
        now: Instant,
        unix_floor: Duration,
    ) -> Result<Self, ConfigError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut seed[..]).map_err(|e| ConfigError::Entropy(e.to_string()))?;
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let unix = wall.max(unix_floor.saturating_add(Duration::from_secs(1)));
        Self::build(config, seed, now, unix)
    }

    /// Makes a device from a caller's seed and Unix time, for deterministic tests and fuzzing.
    /// Reusing a seed repeats keys and nonces; never use this in production.
    ///
    /// # Errors
    ///
    /// As for [`Device::new`], except missing entropy.
    #[cfg(any(test, feature = "deterministic"))]
    pub fn with_seed(
        config: DeviceConfig,
        seed: Zeroizing<[u8; 32]>,
        now: Instant,
        unix: Duration,
    ) -> Result<Self, ConfigError> {
        Self::build(config, seed, now, unix)
    }

    fn build(
        config: DeviceConfig,
        seed: Zeroizing<[u8; 32]>,
        now: Instant,
        unix: Duration,
    ) -> Result<Self, ConfigError> {
        if unix > MAX_UNIX_TIME {
            return Err(ConfigError::UnixTime(unix));
        }
        config.validate()?;
        let l = config.limits;
        let staged_bytes = l.staged_bytes(config.mtu).unwrap_or(usize::MAX);
        let keys: Vec<_> = config
            .peers
            .iter()
            .map(|p| (p.public_key, p.persistent_keepalive))
            .collect();
        let proto = Protocol::new(&config.private_key, &keys, config.timers, seed, now, unix)?;
        // sanstun の詰め物への手当て (sanstun_compat::inner_mtu)
        let mtu = inner_mtu(config.mtu);
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
                configured_endpoint: p.endpoint,
                roaming: p.roaming,
                keepalive,
                staged: BoundedQueue::new(l.staged_packets, staged_bytes),
                keepalive_at: (keepalive.is_some() && p.endpoint.is_some()).then_some(now),
                handshake_sent_at: None,
                paused_until: None,
                deferred: None,
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
            rekey_timeout: config.timers.effective_rekey_timeout(),
            limits: l,
            transmits: BoundedQueue::new(l.transmit_packets, l.transmit_bytes),
            packets: BoundedQueue::new(l.deliver_packets, l.deliver_bytes),
            events: VecDeque::new(),
            drops: Drops::default(),
            now,
            start: now,
            unix_at_start: unix,
        })
    }

    /// The Unix time the device would stamp on a handshake initiation now: an upper bound of every
    /// stamp it has sent. Pass a persisted value as `unix_floor` to the next [`Device::new`].
    ///
    /// Save it on a clean shutdown. While running, save `unix_high_water() + interval` every
    /// `interval`, so that the saved value stays above every stamp until the next save; a plain
    /// periodic save of `unix_high_water()` is not a floor after a crash.
    #[must_use]
    pub fn unix_high_water(&self) -> Duration {
        self.unix_at_start + self.now.saturating_duration_since(self.start)
    }

    /// The longest datagram the device sends, for sizing receive buffers on the other side. It is
    /// [`Device::mtu`] plus 32 bytes of header and tag, never more than the configured MTU plus 32.
    #[must_use]
    pub fn max_transmit_len(&self) -> usize {
        // ハンドシェイクの開始 (148 バイト) より長い。mtu は 16 の倍数なので詰め物で伸びない (inner_mtu)
        self.mtu + DATA_OVERHEAD
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
                if self.peers[peer].roaming == Roaming::Any {
                    self.accepted_from(peer, from, rx);
                    self.send_to_peer(peer, response);
                } else {
                    // 開始は古いものの再送でありうる (sanstun の再送の記録はプロセスの中だけにある)。
                    // endpoint は動かさず、応答だけを送信元へ返す
                    self.counted_from(peer, rx);
                    self.send_to(peer, from, response);
                }
                self.peers[peer].handshake_sent_at = Some(now);
                self.push_event(Event::HandshakeAccepted {
                    peer: self.peers[peer].key,
                });
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

    /// 認証した datagram を数え、keepalive の期限を延ばす。
    fn counted_from(&mut self, peer: PeerId, rx: u64) {
        let now = self.now;
        let p = &mut self.peers[peer];
        p.rx_bytes = p.rx_bytes.saturating_add(rx);
        p.keepalive_at = p.keepalive.map(|interval| now + interval);
    }

    /// 認証した datagram の後だけ endpoint を動かす。
    fn accepted_from(&mut self, peer: PeerId, from: SocketAddr, rx: u64) {
        self.counted_from(peer, rx);
        let p = &mut self.peers[peer];
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
        self.initiate(peer, now, true);
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

    /// ハンドシェイクを始める。前の開始か応答から `REKEY_TIMEOUT` が経っていないか、データを持たない
    /// 要求 (`data` が偽) が期限切れの後の休止の中なら、始めずに要求を控え、許される時刻に
    /// `handle_timeout` で行う。開始を送る待ち行列に入れたら `true`。
    fn initiate(&mut self, peer: PeerId, now: Instant, data: bool) -> bool {
        let p = &mut self.peers[peer];
        if p.endpoint.is_none() {
            return false;
        }
        let mut allowed = p.handshake_sent_at.map(|t| t + self.rekey_timeout);
        if !data {
            allowed = allowed.max(p.paused_until);
        }
        if let Some(at) = allowed
            && now < at
        {
            // データの要求を先に控えていれば、それより遅くしない
            p.deferred = Some(match p.deferred {
                Some((earlier, true)) => (earlier.min(at), true),
                _ => (at, data),
            });
            return false;
        }
        p.deferred = None;
        let Some(initiation) = self.proto.initiate(peer, now) else {
            return false;
        };
        self.peers[peer].handshake_sent_at = Some(now);
        self.send_to_peer(peer, initiation);
        true
    }

    /// Advances the timers to `now`: handshake retries, rekeying, keepalives and expiry.
    pub fn handle_timeout(&mut self, now: Instant) {
        let now = self.clock(now);
        for peer in 0..self.peers.len() {
            self.proto.handle_timeout(peer, now);
            self.drain_proto_events(peer, now);
            // sanstun の passive keepalive への手当て (sanstun_compat::PassiveKeepalive)
            if self.proto.passive_keepalive(peer, now) {
                self.drain_proto_events(peer, now);
            }
            // sanstun は使えるセッションがある間、persistent keepalive を間隔ごとに送り、その送信が
            // この期限を延ばす。sanstun を先に進めた後でも期限が来ているのは、間隔の間なにも送って
            // いない、つまり使えるセッションが無いときだけである。応答の側のセッションが 180 秒で切れた
            // 後もここで始める
            let p = &mut self.peers[peer];
            if let (Some(at), Some(interval)) = (p.keepalive_at, p.keepalive)
                && at <= now
            {
                p.keepalive_at = Some(now + interval);
                self.initiate(peer, now, false);
            }
            // 控えた要求。その間にセッションができていれば (相手が始めたハンドシェイクなど) 捨てる
            if let Some((at, data)) = self.peers[peer].deferred
                && at <= now
            {
                self.peers[peer].deferred = None;
                if !self.proto.has_session(peer, now) {
                    self.initiate(peer, now, data);
                }
            }
        }
    }

    fn drain_proto_events(&mut self, peer: PeerId, now: Instant) {
        while let Some(event) = self.proto.poll_event(peer, now) {
            match event {
                ProtoEvent::SendInitiation(d) => {
                    self.peers[peer].handshake_sent_at = Some(now);
                    self.send_to_peer(peer, d);
                }
                ProtoEvent::SendKeepalive(d) => self.send_to_peer(peer, d),
                ProtoEvent::Established { took } => self.push_event(Event::SessionEstablished {
                    peer: self.peers[peer].key,
                    took,
                }),
                ProtoEvent::Expired { used } => {
                    let p = &mut self.peers[peer];
                    let lost = p.staged.clear();
                    let mut reset = None;
                    if p.roaming == Roaming::NotByInitiation && p.endpoint != p.configured_endpoint
                    {
                        p.endpoint = p.configured_endpoint;
                        reset = p.endpoint;
                    }
                    if let (Some(interval), Some(_)) = (p.keepalive, p.endpoint) {
                        p.keepalive_at = Some(now + interval);
                    }
                    // 再試行を打ち切った後は、データを持たない開始を keepalive の間隔だけ控える
                    // (論文の 6.1 節: 打ち切りの後は新しいデータまで始めない)。期限は keepalive の
                    // 期限と同じなので、その時に 1 つだけ始める。控えた要求も休止の後へ送る
                    if used && let Some(interval) = p.keepalive {
                        p.paused_until = Some(now + interval);
                    }
                    let key = p.key;
                    self.drops.add(DropReason::NoSession, lost as u64);
                    // 一度も使わなかったトンネル (ハンドシェイクを始めも受けもしていない) の期限切れは
                    // 知らせない。sanstun は作成から 540 秒で切るので、そのまま知らせると待つだけの
                    // ピアについて 9 分ごとに event が出る
                    if used {
                        self.push_event(Event::PeerExpired { peer: key });
                    }
                    if let Some(endpoint) = reset {
                        self.push_event(Event::EndpointChanged {
                            peer: key,
                            endpoint,
                        });
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
        self.send_to(peer, to, payload);
    }

    fn send_to(&mut self, peer: PeerId, to: SocketAddr, payload: Vec<u8>) {
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
            .flat_map(|peer| {
                let p = &self.peers[peer];
                [
                    self.proto.poll_timeout(peer),
                    p.keepalive_at,
                    p.deferred.map(|(at, _)| at),
                ]
            })
            .flatten()
            .min()
    }

    /// Points the peer at a new endpoint, as the control plane does after resolving the server's
    /// name again. It also becomes the configured endpoint that `Roaming::NotByInitiation` returns
    /// to. Returns `false` for an unknown key.
    pub fn set_endpoint(&mut self, now: Instant, peer: &PublicKey, endpoint: SocketAddr) -> bool {
        let now = self.clock(now);
        let Some(&id) = self.by_key.get(peer) else {
            return false;
        };
        let p = &mut self.peers[id];
        let first = p.endpoint.is_none();
        p.endpoint = Some(endpoint);
        p.configured_endpoint = Some(endpoint);
        if first && p.keepalive.is_some() {
            p.keepalive_at = Some(now);
        }
        true
    }

    /// Whether the device can encrypt a packet for the peer now, without waiting for a handshake.
    ///
    /// The data plane pulls packets from the layer above only while this holds, so that packets do
    /// not pile up in the bounded queue of packets waiting for a handshake. It errs on the side of
    /// `false`: it is `false` during the last `KEEPALIVE_TIMEOUT` of a session this side answered,
    /// where sending still works, and then [`Device::start_handshake`] replaces the session early.
    /// It ignores the per-session message limit of about 2^64, past which a packet still waits for
    /// the handshake that the limit starts. Returns `false` for an unknown key.
    #[must_use]
    pub fn has_session(&self, peer: &PublicKey, now: Instant) -> bool {
        let Some(&id) = self.by_key.get(peer) else {
            return false;
        };
        self.proto.has_session(id, now.max(self.now))
    }

    /// Asks for a handshake with the peer, for a caller that wants a session before it has a
    /// packet to send, and queues the initiation for [`Device::poll_transmit`]. Returns `true` when
    /// an initiation was queued.
    ///
    /// It keeps the protocol's pacing: no initiation within `REKEY_TIMEOUT` of the last initiation
    /// or response to the peer, and none for one keepalive interval after the peer expired because
    /// it did not answer. A request that the pacing holds back returns `false` and is carried out
    /// by [`Device::handle_timeout`] when it is allowed, unless a session exists by then;
    /// [`Device::poll_timeout`] includes that time. It also returns `false` and does nothing when
    /// a handshake is already in progress, the peer has no endpoint or the key is unknown.
    pub fn start_handshake(&mut self, now: Instant, peer: &PublicKey) -> bool {
        let now = self.clock(now);
        let Some(&id) = self.by_key.get(peer) else {
            return false;
        };
        self.initiate(id, now, false)
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

    /// The largest inner packet the device sends: the configured MTU rounded down to a multiple of
    /// 16, so that padding never makes a data message carry more than the configured MTU. Give the
    /// layer above this value.
    #[must_use]
    pub fn mtu(&self) -> usize {
        self.mtu
    }
}

const _: () = assert!(IPV4_MIN_HEADER <= MIN_MTU as usize);

#[cfg(test)]
#[path = "device_tests.rs"]
mod tests;
