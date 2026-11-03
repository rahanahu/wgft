//! sanstun を使う唯一の module。
//!
//! WireGuard のプロトコルの核 (ハンドシェイク、暗号、セッション、timer) は sanstun が持つ。
//! この module は sanstun の型を外に出さず、wgft の型 (鍵、ピアの番号、バイト列、
//! [`DropReason`]) だけで device の層と話す。sanstun の README の「Caller responsibilities」
//! のうち、ハンドシェイクの振り分け (設定した鍵だけを受ける) と受信の index からピアを引く
//! 表はここで果たし、暗号鍵の経路表、endpoint の更新、中身の検査、キューの上界は
//! `device` の module が果たす。誤りは [`DropReason`] に写して呼び手が数えるだけで、相手には
//! 何も返さない。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sanstun::{
    Committed, Decrypted, Error as SanstunError, Event as SanstunEvent, Interface,
    PendingDecapsulate, PendingEncapsulate, Received, ReceivedMessage, StaticSecret, Tunnel,
    TunnelConfig, TunnelId,
};
use zeroize::Zeroizing;

use crate::config::{ConfigError, ProtocolTimers, REJECT_AFTER_TIME};
use crate::drops::DropReason;
use crate::keys::{PrivateKey, PublicKey};

/// Device の中のピアの番号。設定の並びの位置。
pub(crate) type PeerId = usize;

/// データの message のヘッダの長さ (type、receiver、counter)。
const DATA_HEADER_LEN: usize = 16;
/// ヘッダと認証 tag を合わせた、データの message の上乗せ。
pub(crate) const DATA_OVERHEAD: usize = DATA_HEADER_LEN + 16;
// sanstun 0.1.0 の振る舞いへの手当ては、この module の子の sanstun_compat に集める
#[path = "sanstun_compat.rs"]
mod sanstun_compat;

use sanstun_compat::PassiveKeepalive;
pub(crate) use sanstun_compat::{PADDING, inner_mtu};

/// 秘密鍵を sanstun の型へ写す。写しは Zeroizing の中に直接作り、stack に裸の写しを残さない。
fn static_secret(private: &PrivateKey) -> StaticSecret {
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(private.as_bytes());
    StaticSecret::from(bytes)
}

pub(crate) fn derive_public_key(private: &PrivateKey) -> PublicKey {
    let secret = static_secret(private);
    PublicKey::from_bytes(sanstun::PublicKey::from(&secret).to_bytes())
}

/// 受け付けた datagram の中身。
#[derive(Debug)]
pub(crate) enum Inbound {
    /// 負荷が高く、cookie を求める返事。datagram の送信元へ返す。ピアは認証していない。
    CookieReply(Vec<u8>),
    /// ピアのハンドシェイクの開始に答えた。応答は datagram の送信元へ返す。
    InitiationAnswered { peer: PeerId, response: Vec<u8> },
    /// こちらが始めたハンドシェイクが完了した。確認の keepalive を datagram の送信元へ送る。
    ResponseAccepted { peer: PeerId, keepalive: Vec<u8> },
    /// cookie を受け取った。次の開始に使う。
    CookieStored,
    /// 認証し、再送の検査を通ったデータ。平文は呼び手の buffer の先頭の `len` byte で、詰め物を含む。
    Data { peer: PeerId, len: usize },
    /// 認証した keepalive。
    Keepalive { peer: PeerId },
}

/// ピアの timer と状態の変化から出る仕事。
#[derive(Debug)]
pub(crate) enum ProtoEvent {
    /// ハンドシェイクの開始 (再送と鍵の更新を含む) を endpoint へ送る。
    SendInitiation(Vec<u8>),
    /// keepalive を endpoint へ送る。
    SendKeepalive(Vec<u8>),
    /// このピアとの最初のセッションが確かめられた。`took` はハンドシェイクにかかった時間。
    Established { took: Duration },
    /// 接続が期限切れになった。状態は捨て、新しいトンネルに取り替えた。`used` は、そのトンネルが
    /// ハンドシェイクを始めたか受けたかである。
    Expired { used: bool },
}

/// [`Protocol::begin`] の結果。
#[derive(Debug)]
pub(crate) enum Begun {
    /// ハンドシェイク、cookie、またはそれへの返事。この呼び出しの中で済んだ。
    Done(Inbound),
    /// 復号の前の検査を通ったデータの message。
    Open(OpenJob),
}

/// 復号を待つデータの message。sanstun の復号の前の検査 (セッションがあり、番号が再送の窓の先の検査を
/// 通る) を通った。持つのはセッションの鍵の写しと index と番号だけで、復号はほかの状態に触れないので、
/// どのスレッドで行ってもよい。鍵の写しは drop で 0 に戻る。
///
/// 再送の窓の本当の検査は [`Protocol::commit`] で、datagram の届いた順に行う。同じ番号の写しを同じ
/// バッチで復号しても、受け付けるのは最初の 1 つだけである。
pub(crate) struct OpenJob {
    pending: PendingDecapsulate,
    peer: PeerId,
    tunnel: TunnelId,
}

impl std::fmt::Debug for OpenJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenJob")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl OpenJob {
    /// `datagram` を呼び手の buffer `out` に復号する。`out` は datagram の長さから 16 byte を引いた長さが
    /// 要り、足りなければ復号を始めずに不正な message とする。ほかの状態に触れない。
    pub(crate) fn open(self, datagram: &[u8], out: &mut [u8]) -> Opened {
        let Self {
            pending,
            peer,
            tunnel,
        } = self;
        // datagram は sanstun が読んだデータの message なので、header と tag の 32 byte 以上ある
        let Some(buffer) = out.get_mut(..datagram.len().saturating_sub(DATA_HEADER_LEN)) else {
            return Opened {
                decrypted: Err(DropReason::Malformed),
                len: 0,
                peer,
                tunnel,
            };
        };
        let mut len = 0;
        let decrypted = pending.decrypt(datagram, buffer).map(|_, n| len = n);
        Opened {
            decrypted: Ok(decrypted),
            len,
            peer,
            tunnel,
        }
    }
}

/// [`OpenJob::open`] の結果。[`Protocol::commit`] に渡すまで、平文はまだ受け付けていない。
pub(crate) struct Opened {
    decrypted: Result<Decrypted<()>, DropReason>,
    /// 平文の長さ。詰め物を含み、復号できなければ 0。
    len: usize,
    peer: PeerId,
    tunnel: TunnelId,
}

impl std::fmt::Debug for Opened {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opened")
            .field("peer", &self.peer)
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl Opened {
    /// 呼び手の buffer の先頭で平文を持つ長さ。詰め物を含み、復号できなかったときは 0。
    pub(crate) fn len(&self) -> usize {
        self.len
    }
}

/// 番号を取った暗号化の仕事。セッションの鍵の写しと index と番号だけを持ち、暗号化はほかの状態に
/// 触れないので、どのスレッドで行ってもよい。鍵の写しは drop で 0 に戻る。
pub(crate) struct SealJob {
    pending: PendingEncapsulate,
    /// 暗号化した datagram の長さ。
    len: usize,
}

impl std::fmt::Debug for SealJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealJob")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl SealJob {
    /// 暗号化した datagram の長さ。呼び手の buffer はこの長さが要る。
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// `packet` を呼び手の buffer `out` に暗号化し、書いた長さを返す。`out` が [`SealJob::len`] より短いと
    /// `Err` で、取った番号は使わずに飛ばす (Linux の WireGuard と同じく、番号は使い回さない)。
    pub(crate) fn seal(self, packet: &[u8], out: &mut [u8]) -> Result<usize, DropReason> {
        Ok(self
            .pending
            .encrypt(packet, out)
            .map_err(|e| map_error(&e))?
            .len())
    }
}

struct PeerProto {
    remote: sanstun::PublicKey,
    keepalive: Option<Duration>,
    tunnel: Tunnel,
    /// このトンネルでハンドシェイクを始めたか受けたか。
    used: bool,
    /// sanstun の passive keepalive への手当て。sanstun の送信の記録が進む呼び出しで `on_send` を呼ぶ。
    passive: PassiveKeepalive,
}

pub(crate) struct Protocol {
    interface: Interface,
    timers: ProtocolTimers,
    peers: Vec<PeerProto>,
    /// ハンドシェイクの振り分け: 開始の message の静的公開鍵からピアを引く。
    by_key: HashMap<sanstun::PublicKey, PeerId>,
    /// 受信の index (の上位の部分) からピアを引く。
    by_tunnel: HashMap<TunnelId, PeerId>,
}

impl std::fmt::Debug for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Protocol")
            .field("peers", &self.peers.len())
            .finish_non_exhaustive()
    }
}

fn map_error(e: &SanstunError) -> DropReason {
    match e {
        SanstunError::InvalidPacket => DropReason::Malformed,
        SanstunError::InvalidMac
        | SanstunError::InvalidAeadTag
        | SanstunError::WrongKey
        | SanstunError::WrongIndex
        | SanstunError::LowOrderPoint => DropReason::Unauthenticated,
        SanstunError::ReplayedHandshakeInitiation
        | SanstunError::DuplicateCounter
        | SanstunError::InvalidCounter => DropReason::Replayed,
        SanstunError::RateLimited => DropReason::RateLimited,
        SanstunError::NoCurrentSession
        | SanstunError::ConnectionExpired
        | SanstunError::UnexpectedPacket => DropReason::NoSession,
        SanstunError::DestinationBufferTooSmall { .. } | SanstunError::EmptyPlaintext => {
            DropReason::Internal
        }
    }
}

impl Protocol {
    pub(crate) fn new(
        private_key: &PrivateKey,
        peers: &[(PublicKey, Option<Duration>)],
        timers: ProtocolTimers,
        seed: Zeroizing<[u8; 32]>,
        now: Instant,
        unix: Duration,
    ) -> Result<Self, ConfigError> {
        let secret = static_secret(private_key);
        let mut interface =
            Interface::new(seed, now, sanstun_compat::stamp_base(unix)).with_static_private(secret);
        let own = interface.static_public();
        let mut list = Vec::with_capacity(peers.len());
        let mut by_key = HashMap::with_capacity(peers.len());
        let mut by_tunnel = HashMap::with_capacity(peers.len());
        for (id, &(key, keepalive)) in peers.iter().enumerate() {
            let remote = sanstun::PublicKey::from(*key.as_bytes());
            if remote == own {
                return Err(ConfigError::OwnKey);
            }
            if by_key.insert(remote, id).is_some() {
                return Err(ConfigError::DuplicatePeer(key));
            }
            let tunnel = new_tunnel(&mut interface, remote, keepalive, timers, now)
                .map_err(|_| ConfigError::LowOrderKey(key))?;
            by_tunnel.insert(tunnel.id(), id);
            list.push(PeerProto {
                remote,
                keepalive,
                tunnel,
                used: false,
                passive: PassiveKeepalive::default(),
            });
        }
        Ok(Self {
            interface,
            timers,
            peers: list,
            by_key,
            by_tunnel,
        })
    }

    fn peer_by_tunnel(&self, id: TunnelId) -> Result<PeerId, DropReason> {
        self.by_tunnel
            .get(&id)
            .copied()
            .ok_or(DropReason::UnknownPeer)
    }

    /// 届いた datagram を検査する。データの message は、復号の前の検査 (セッションと再送の窓の先の検査) を
    /// 通ったら、復号の仕事 [`OpenJob`] を返す。復号は呼び手が [`OpenJob::open`] で行い、結果を
    /// [`Protocol::commit`] に渡す。ほかの message はこの呼び出しの中で済ませる。
    pub(crate) fn begin(
        &mut self,
        now: Instant,
        src: SocketAddr,
        datagram: &[u8],
    ) -> Result<Begun, DropReason> {
        let message = match self
            .interface
            .receive(src, datagram, now)
            .map_err(|e| map_error(&e))?
        {
            Received::SendCookieReply(reply) => {
                return Ok(Begun::Done(Inbound::CookieReply(reply.to_vec())));
            }
            Received::Message(message) => message,
        };
        match message {
            ReceivedMessage::HandshakeInitiation(init) => {
                // 誰でも鍵の対を作れるので、設定に無い鍵にはトンネルを作らない
                let peer = *self
                    .by_key
                    .get(&init.peer_static_public())
                    .ok_or(DropReason::UnknownPeer)?;
                let response = self.peers[peer]
                    .tunnel
                    .handle_handshake_initiation(init, now)
                    .map_err(|e| map_error(&e))?;
                self.peers[peer].used = true;
                self.peers[peer].passive.on_send();
                Ok(Begun::Done(Inbound::InitiationAnswered {
                    peer,
                    response: response.to_vec(),
                }))
            }
            ReceivedMessage::HandshakeResponse(response) => {
                let peer = self.peer_by_tunnel(response.tunnel_id())?;
                let keepalive = self.peers[peer]
                    .tunnel
                    .handle_handshake_response(response, now)
                    .map_err(|e| map_error(&e))?;
                self.peers[peer].passive.on_send();
                Ok(Begun::Done(Inbound::ResponseAccepted {
                    peer,
                    keepalive: keepalive.to_vec(),
                }))
            }
            ReceivedMessage::CookieReply(reply) => {
                let peer = self.peer_by_tunnel(reply.tunnel_id())?;
                self.peers[peer]
                    .tunnel
                    .handle_cookie_reply(reply, now)
                    .map_err(|e| map_error(&e))?;
                Ok(Begun::Done(Inbound::CookieStored))
            }
            ReceivedMessage::TransportData(data) => {
                let tunnel_id = data.tunnel_id();
                let peer = self.peer_by_tunnel(tunnel_id)?;
                let pending = self.peers[peer]
                    .tunnel
                    .begin_decapsulate(data, now)
                    .map_err(|e| map_error(&e))?;
                Ok(Begun::Open(OpenJob {
                    pending,
                    peer,
                    tunnel: tunnel_id,
                }))
            }
        }
    }

    /// 復号した結果を受け付ける。再送の窓の検査とセッションの確かめは、ここで datagram の届いた順に
    /// 行う ([`OpenJob`])。
    pub(crate) fn commit(&mut self, now: Instant, opened: Opened) -> Result<Inbound, DropReason> {
        let Opened {
            decrypted,
            peer,
            tunnel,
            len: _,
        } = opened;
        let decrypted = decrypted?;
        let p = &mut self.peers[peer];
        // 復号の間にトンネルを取り替えていれば、古いトンネルの message である。1 つずつ扱う道では、
        // 取り替えた後の datagram は index を引けずに捨てるので、同じ理由で捨てる
        if p.tunnel.id() != tunnel {
            return Err(DropReason::UnknownPeer);
        }
        match p
            .tunnel
            .commit_decapsulate(decrypted, now)
            .map_err(|e| map_error(&e))?
        {
            Committed::Data { len, .. } => {
                p.passive.on_data(now);
                Ok(Inbound::Data { peer, len })
            }
            Committed::Keepalive => Ok(Inbound::Keepalive { peer }),
        }
    }

    /// 暗号に要る `out` の長さ。詰め物と header と tag を含む。
    pub(crate) const fn sealed_len(packet_len: usize) -> usize {
        packet_len.next_multiple_of(PADDING) + DATA_OVERHEAD
    }

    /// `packet` を呼び手の buffer `out` に暗号化し、書いた長さを返す。セッションが無ければ `Ok(None)`。
    /// `out` は [`Protocol::sealed_len`] より短くてはならない。短ければ `Err` で、暗号の番号は使わない。
    pub(crate) fn encapsulate_into(
        &mut self,
        peer: PeerId,
        now: Instant,
        packet: &[u8],
        out: &mut [u8],
    ) -> Result<Option<usize>, DropReason> {
        if out.len() < Self::sealed_len(packet.len()) {
            return Err(DropReason::Internal);
        }
        let Some(job) = self.begin_seal(peer, now, packet.len())? else {
            return Ok(None);
        };
        Ok(Some(job.seal(packet, out)?))
    }

    /// `len` byte の packet の暗号の番号を取り、暗号化の仕事 [`SealJob`] を返す。セッションが無ければ
    /// `Ok(None)`。番号はこの呼び出しの順に付くので、呼び手は返した仕事の datagram をこの順に送る。
    pub(crate) fn begin_seal(
        &mut self,
        peer: PeerId,
        now: Instant,
        len: usize,
    ) -> Result<Option<SealJob>, DropReason> {
        let p = &mut self.peers[peer];
        match p.tunnel.begin_encapsulate(now) {
            Ok(pending) => {
                p.passive.on_send();
                Ok(Some(SealJob {
                    pending,
                    len: Self::sealed_len(len),
                }))
            }
            Err(SanstunError::NoCurrentSession | SanstunError::ConnectionExpired) => Ok(None),
            Err(e) => Err(map_error(&e)),
        }
    }

    /// `packet` を新しい buffer に暗号化する。ハンドシェイクを待っていた packet を送るときの、
    /// 定常の経路ではない道で使う。セッションが無ければ `Ok(None)`。
    pub(crate) fn encapsulate(
        &mut self,
        peer: PeerId,
        now: Instant,
        packet: &[u8],
    ) -> Result<Option<Vec<u8>>, DropReason> {
        let mut out = vec![0u8; Self::sealed_len(packet.len())];
        Ok(self
            .encapsulate_into(peer, now, packet, &mut out)?
            .map(|len| {
                out.truncate(len);
                out
            }))
    }

    /// ハンドシェイクを始める。進行中なら `None`。
    pub(crate) fn initiate(&mut self, peer: PeerId, now: Instant) -> Option<Vec<u8>> {
        let p = &mut self.peers[peer];
        let initiation = p.tunnel.initiate_handshake(now)?;
        p.used = true;
        p.passive.on_send();
        Some(initiation.to_vec())
    }

    pub(crate) fn handle_timeout(&mut self, peer: PeerId, now: Instant) {
        self.peers[peer].tunnel.handle_timeout(now);
    }

    /// 次に [`Protocol::handle_timeout`] か [`Protocol::passive_keepalive`] を呼ぶ時刻。
    pub(crate) fn poll_timeout(&self, peer: PeerId) -> Option<Instant> {
        let p = &self.peers[peer];
        let passive = p
            .passive
            .deadline(self.timers.effective_keepalive_timeout());
        match (p.tunnel.poll_timeout(), passive) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// passive keepalive を WireGuard の規則の時刻に送らせる ([`PassiveKeepalive::force`])。呼び手は
    /// 先に [`Protocol::handle_timeout`] を同じ `now` で呼び、出た event を取り出してから呼ぶ。`true` を
    /// 返したら、呼び手は出た event を取り出す。
    pub(crate) fn passive_keepalive(&mut self, peer: PeerId, now: Instant) -> bool {
        let usable = self.has_session(peer, now);
        let keepalive_timeout = self.timers.effective_keepalive_timeout();
        let p = &mut self.peers[peer];
        p.passive
            .force(&mut p.tunnel, now, keepalive_timeout, usable)
    }

    /// ピアの次の仕事。期限切れはここで新しいトンネルに取り替える。
    pub(crate) fn poll_event(&mut self, peer: PeerId, now: Instant) -> Option<ProtoEvent> {
        let event = self.peers[peer].tunnel.poll_event()?;
        Some(match event {
            SanstunEvent::SendHandshakeInitiation(d) => {
                self.peers[peer].used = true;
                self.peers[peer].passive.on_send();
                ProtoEvent::SendInitiation(d.to_vec())
            }
            SanstunEvent::SendKeepalive(d) => {
                self.peers[peer].passive.on_send();
                ProtoEvent::SendKeepalive(d.to_vec())
            }
            SanstunEvent::Established {
                started_at,
                confirmed_at,
            } => ProtoEvent::Established {
                took: confirmed_at.saturating_duration_since(started_at),
            },
            SanstunEvent::ConnectionExpired => {
                let used = self.peers[peer].used;
                // 期限の切れたトンネルはハンドシェイクを受けないので、使っていなくても取り替える
                self.renew(peer, now);
                ProtoEvent::Expired { used }
            }
        })
    }

    /// 期限の切れたトンネルを同じ設定の新しいものに替える。index も新しくなる。
    fn renew(&mut self, peer: PeerId, now: Instant) {
        let p = &self.peers[peer];
        let (remote, keepalive, old) = (p.remote, p.keepalive, p.tunnel.id());
        // 鍵は new で確かめたので、ここでは失敗しない。失敗したら古いトンネルを残す
        if let Ok(tunnel) = new_tunnel(&mut self.interface, remote, keepalive, self.timers, now) {
            self.by_tunnel.remove(&old);
            self.by_tunnel.insert(tunnel.id(), peer);
            self.peers[peer].tunnel = tunnel;
            self.peers[peer].used = false;
            self.peers[peer].passive.on_send();
        }
    }

    /// 今のセッションでデータを暗号にできるか。sanstun はこの判定を公開しないので、sanstun が送信に
    /// 使うセッションの条件 (今のセッションがあり、期限切れでなく、開始の側なら `KEEPALIVE_TIMEOUT` を
    /// 残している) を、公開の値から写す。sanstun はセッションの役を公開しないので、応答の側にも開始の側の
    /// 条件を当てる。このため応答の側のセッションの最後の `KEEPALIVE_TIMEOUT` の間は偽を返す。
    /// 送信の数の上限 (2^64 から 2^13 を引いた数) は見ない。真を返した後に暗号にできなかった packet は、
    /// device がハンドシェイクを待つ待ち行列に入れる。
    pub(crate) fn has_session(&self, peer: PeerId, now: Instant) -> bool {
        let tunnel = &self.peers[peer].tunnel;
        let keepalive_timeout = self.timers.effective_keepalive_timeout();
        !tunnel.is_expired()
            && tunnel
                .time_since_last_handshake(now)
                .is_some_and(|age| age + keepalive_timeout <= REJECT_AFTER_TIME)
    }

    /// 今のセッションのハンドシェイクが済んだ時刻。
    pub(crate) fn last_handshake(&self, peer: PeerId, now: Instant) -> Option<Instant> {
        self.peers[peer]
            .tunnel
            .time_since_last_handshake(now)
            .map(|age| now.checked_sub(age).unwrap_or(now))
    }
}

fn new_tunnel(
    interface: &mut Interface,
    remote: sanstun::PublicKey,
    keepalive: Option<Duration>,
    timers: ProtocolTimers,
    now: Instant,
) -> Result<Tunnel, SanstunError> {
    let mut config = TunnelConfig::default();
    if let Some(interval) = keepalive {
        config = config.with_persistent_keepalive(interval);
    }
    let mut tunnel = interface.new_tunnel(remote, config, now)?;
    // sanstun は 2 つの和が 180 秒以下であることを、設定するたびに今の値で確かめる。和は
    // ProtocolTimers::validate で確かめたので、途中の和も超えない順に設定する
    let keepalive_first =
        timers.effective_keepalive_timeout() <= ProtocolTimers::default_keepalive_timeout();
    if keepalive_first && let Some(t) = timers.keepalive_timeout {
        tunnel.set_keepalive_timeout(t);
    }
    if let Some(t) = timers.rekey_timeout {
        tunnel.set_rekey_timeout(t);
    }
    if !keepalive_first && let Some(t) = timers.keepalive_timeout {
        tunnel.set_keepalive_timeout(t);
    }
    if let Some(t) = timers.rekey_attempt_time {
        tunnel.set_rekey_attempt_time(t);
    }
    Ok(tunnel)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 開始の message の TAI64N の印の秒。sanstun の相手として受け、認証した開始から読む。
    fn stamped_seconds(unix: Duration) -> u64 {
        let now = Instant::now();
        let agent = PrivateKey::generate(&[0xa1; 32]);
        let server = PrivateKey::generate(&[0xb2; 32]);
        let mut proto = Protocol::new(
            &agent,
            &[(server.public_key(), None)],
            ProtocolTimers::default(),
            Zeroizing::new([1; 32]),
            now,
            unix,
        )
        .unwrap();
        let initiation = proto.initiate(0, now).unwrap();
        let mut responder = Interface::new(Zeroizing::new([2; 32]), now, unix)
            .with_static_private(static_secret(&server));
        let agent_public = sanstun::PublicKey::from(*agent.public_key().as_bytes());
        let _tunnel = responder
            .new_tunnel(agent_public, TunnelConfig::default(), now)
            .unwrap();
        let src = "192.0.2.2:40000".parse().unwrap();
        match responder.receive(src, &initiation, now).unwrap() {
            Received::Message(ReceivedMessage::HandshakeInitiation(init)) => {
                u64::try_from(init.timestamp() >> 32).unwrap()
            }
            other => panic!("expected an initiation, got {other:?}"),
        }
    }

    #[test]
    fn initiations_carry_the_standard_tai64n_label() {
        // Linux の WireGuard と wireguard-go の印の秒は 2^62 + 10 + Unix 時刻 (秒)
        for secs in [1_700_000_000, 1_800_000_123] {
            assert_eq!(
                stamped_seconds(Duration::from_secs(secs)),
                (1 << 62) + 10 + secs
            );
        }
    }
}
