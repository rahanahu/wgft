//! 駆動の task。1 回の起床の順と送り出しの規則は `docs/design/v2/wgstack-rs.md` の「1 回の起床」に従う。
//!
//! 1. ソケットから datagram を読み、device の層に渡し、復号した packet を上の層に渡す
//! 2. 時刻の来た timer を回す
//! 3. 送り出す ([`pump`])
//! 4. device の event を channel に流し、上の層の waker を借用を返した後に起こし、ログの行を出す
//! 5. device の層と上の層の早い方の時刻で timer を張り直す

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use wgft_wireguard::{Device, Event, PublicKey, Transmit};

use super::{Command, Local, Settings, SocketBuffers, Status, Upper, clock, duration_to_nanos};

/// 受ける datagram の buffer と、復号の行き先の長さ。UDP の datagram の最大の長さで、起動の時に 1 回だけ
/// 確保する。メモリの上界の `device` の項が数える ([`crate::memory`])。
const DATAGRAM_BUF: usize = u16::MAX as usize;
const _: () = assert!(DATAGRAM_BUF == crate::relay::UDP_BUF);

/// 送り出しの先。製品はソケットで、試験は記録する。
pub(super) trait Sink {
    /// 1 つの datagram を送る。`WouldBlock` は書けないことを示し、datagram は呼び手が持ち続ける。
    fn send(&mut self, to: SocketAddr, payload: &[u8]) -> io::Result<()>;
}

impl Sink for &UdpSocket {
    fn send(&mut self, to: SocketAddr, payload: &[u8]) -> io::Result<()> {
        self.try_send_to(payload, to).map(|_| ())
    }
}

/// ソケットが受け付けなかった datagram。
#[derive(Debug)]
pub(super) enum Pending {
    /// device の層のキューから引いた datagram。
    Queued(Transmit),
    /// 暗号化して [`Outbox`] の `sealed` に置いた datagram の送り先と長さ。
    Sealed { to: SocketAddr, len: usize },
}

/// 起床をまたいで持つ送り出しの状態。
#[derive(Debug)]
pub(super) struct Outbox {
    /// 上の層が packet を書く buffer。MTU の長さ。
    buf: Vec<u8>,
    /// device の層が packet を暗号化して書く buffer。device の層が送る最大の datagram の長さ。
    /// `pending` が `Sealed` の間は書き換えない。
    sealed: Vec<u8>,
    /// ソケットが受け付けなかった datagram。高々 1 つで、これがある間は何も引かない。
    pub(super) pending: Option<Pending>,
    /// `WouldBlock` 以外の理由で送れず捨てた datagram の数。
    pub(super) send_errors: u64,
}

impl Outbox {
    pub(super) fn new(mtu: usize, max_datagram: usize) -> Self {
        Self {
            buf: vec![0; mtu],
            sealed: vec![0; max_datagram],
            pending: None,
            send_errors: 0,
        }
    }

    /// `sealed` の先頭の `len` byte を `to` へ送る。ソケットが受け付けなければ控えて `false`。
    fn send_sealed(&mut self, to: SocketAddr, len: usize, sink: &mut impl Sink) -> bool {
        match sink.send(to, &self.sealed[..len]) {
            Ok(()) => true,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.pending = Some(Pending::Sealed { to, len });
                false
            }
            Err(_) => {
                self.send_errors += 1;
                true
            }
        }
    }

    /// 控えた datagram と device の層の送る datagram を、ソケットが受け付ける間すべて送る。待ち行列が
    /// 空になれば `true`。
    fn drain(&mut self, device: &mut Device, sink: &mut impl Sink) -> bool {
        let mut held = match self.pending.take() {
            Some(Pending::Sealed { to, len }) => {
                if !self.send_sealed(to, len, sink) {
                    return false;
                }
                None
            }
            Some(Pending::Queued(t)) => Some(t),
            None => None,
        };
        loop {
            let Some(t) = held.take().or_else(|| device.poll_transmit()) else {
                return true;
            };
            match sink.send(t.to, &t.payload) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.pending = Some(Pending::Queued(t));
                    return false;
                }
                Err(_) => self.send_errors += 1,
            }
        }
    }
}

/// 送り出しの規則。
///
/// - 先に device の層の datagram をすべて送る
/// - device の層がピアとのセッションを持ち、送る datagram の待ち行列が空の間だけ、上の層から packet を
///   1 つずつ引き、device の層で暗号にして送る。これを `cap` まで繰り返す
/// - セッションが無ければ引かず、device の層にハンドシェイクを始めさせる。device の層は開始の間隔
///   (`REKEY_TIMEOUT`) と再試行の打ち切りの後の休止を守り、控えた開始は自分の timer で送るので、
///   起きるたびに頼んでよい。データの packet は休止の中でも開始を促すが、ここではセッションの無い間
///   packet を引かないのでその道を使わず、打ち切りの後は送るものがあっても keepalive の間隔を待つ。
///   server が始めたハンドシェイクには device の層がすぐ答える
/// - ソケットが書けなければ引かない
///
/// `cap` で止まったときだけ `true` を返す。上の層にまだ送るものがあるかもしれないので、呼び手は
/// 他の仕事に順を譲った後にすぐ起きる。
pub(super) fn pump<U: Upper>(
    device: &mut Device,
    upper: &mut U,
    peer: &PublicKey,
    now: Instant,
    outbox: &mut Outbox,
    sink: &mut impl Sink,
    cap: usize,
) -> bool {
    if !outbox.drain(device, sink) {
        return false;
    }
    let mut pulled = 0;
    loop {
        if !device.has_session(peer, now) {
            if device.start_handshake(now, peer) {
                outbox.drain(device, sink);
            }
            return false;
        }
        if pulled == cap {
            return true;
        }
        let Some(len) = upper.poll_transmit(now, &mut outbox.buf) else {
            return false;
        };
        pulled += 1;
        // 上の層は buf より長い長さを返さない。返したら捨てる。暗号文は outbox の buffer に直接書く
        if let Some(packet) = outbox.buf.get(..len)
            && let Some(out) = device.handle_packet(now, packet, &mut outbox.sealed)
            && !outbox.send_sealed(out.to, out.len, sink)
        {
            return false;
        }
        if !outbox.drain(device, sink) {
            return false;
        }
    }
}

/// ソケットから `cap` までの datagram を読み、device の層と上の層に渡す。読み切れなかったら `true`。
/// 受信の誤りは数えて読み続ける (仕様 tunnel.md の受信の goroutine の停止)。
fn receive<U: Upper>(
    local: &Local<U>,
    socket: &UdpSocket,
    buf: &mut [u8],
    plain: &mut [u8],
    now: Instant,
    cap: usize,
    receive_errors: &mut u64,
) -> bool {
    let mut guard = local.0.borrow();
    let inner = &mut *guard;
    for _ in 0..cap {
        match socket.try_recv_from(buf) {
            Ok((n, from)) => {
                // 復号は plain に直接行い、上の層には plain を借用で渡す
                if let Some(len) = inner.device.handle_datagram(now, from, &buf[..n], plain) {
                    inner.upper.handle_packet(now, &plain[..len]);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return false,
            Err(_) => *receive_errors += 1,
        }
    }
    true
}

fn earliest(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// 止める命令で駆動の task が終わった後に、最後の送り出しに要るもの。
pub(super) struct Rest {
    socket: UdpSocket,
    outbox: Outbox,
    peer: PublicKey,
}

/// 最後の送り出しで引く packet の上限。中継の task を落とした後の RST は核の制御の輪に入るので、輪の
/// 大きさで足りる。
const FINAL_PACKETS: usize = 4096;

impl Rest {
    /// 駆動の task が終わり、local の task を落とした後に、上の層に残った出力 (中継の接続を切った RST
    /// など) を 1 回だけ送り出す。セッションが無いか、ソケットが書けなければ送らずに終える。
    pub(super) fn flush<U: Upper>(mut self, local: &Local<U>) {
        let mut guard = local.0.borrow();
        let inner = &mut *guard;
        let now = clock::now();
        pump(
            &mut inner.device,
            &mut inner.upper,
            &self.peer,
            now,
            &mut self.outbox,
            &mut &self.socket,
            FINAL_PACKETS,
        );
    }
}

/// 駆動の task。命令の channel が閉じるか止める命令で、最後の送り出しに要るものを返す。上の層の中の
/// panic の後と、ソケットの準備を待てなくなったときに誤りを返す。
pub(super) async fn drive<U: Upper>(
    local: Local<U>,
    socket: UdpSocket,
    mut commands: mpsc::Receiver<Command<U>>,
    events: mpsc::Sender<Event>,
    high_water: &Arc<AtomicU64>,
    settings: Settings,
    buffers: SocketBuffers,
) -> io::Result<Rest> {
    let (peer, mtu, max_datagram) = {
        let inner = local.0.inner.borrow();
        let peer =
            inner.device.peers().next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "the device has no peer")
            })?;
        (peer, inner.device.mtu(), inner.device.max_transmit_len())
    };
    let local_addr = socket
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    let mut rx_buf = vec![0u8; DATAGRAM_BUF];
    // 復号の行き先。最大の datagram でも足りる長さ
    let mut plain = vec![0u8; DATAGRAM_BUF];
    let mut outbox = Outbox::new(mtu, max_datagram);
    let mut receive_errors = 0u64;
    let mut wakers = Vec::new();
    loop {
        if local.is_poisoned() {
            return Err(io::Error::other(
                "a panic inside the TCP/IP core ended this tunnel generation",
            ));
        }
        let now = clock::now();
        let mut more = receive(
            &local,
            &socket,
            &mut rx_buf,
            &mut plain,
            now,
            settings.max_datagrams_per_wake,
            &mut receive_errors,
        );
        let deadline = {
            let mut guard = local.0.borrow();
            let inner = &mut *guard;
            if inner.device.poll_timeout().is_some_and(|t| t <= now) {
                inner.device.handle_timeout(now);
            }
            if inner.upper.poll_timeout().is_some_and(|t| t <= now) {
                inner.upper.handle_timeout(now);
            }
            more |= pump(
                &mut inner.device,
                &mut inner.upper,
                &peer,
                now,
                &mut outbox,
                &mut &socket,
                settings.max_packets_per_wake,
            );
            while let Some(event) = inner.device.poll_event() {
                // 受け手が遅ければ捨てる。駆動の task を event の受け手に止めさせない
                let _ = events.try_send(event);
            }
            inner.upper.poll_wakers(&mut wakers);
            while let Some(line) = inner.upper.poll_log() {
                crate::logf!("{line}");
            }
            high_water.store(
                duration_to_nanos(inner.device.unix_high_water()),
                Ordering::Relaxed,
            );
            earliest(inner.device.poll_timeout(), inner.upper.poll_timeout())
        };
        for waker in wakers.drain(..) {
            waker.wake();
        }
        let blocked = outbox.pending.is_some();
        if more {
            // 上限で止めたので、同じスレッドの中継の task (accept と読み書き) に順を譲ってから続ける。下の
            // select の中では譲れない。ソケットが読める間は読める枝がすぐに選ばれ、task は coop の予算を
            // 使い切るまで起床を繰り返すので、その間に核の accept の待ち行列が溢れる
            tokio::task::yield_now().await;
        }
        tokio::select! {
            ready = socket.readable() => ready?,
            ready = socket.writable(), if blocked => ready?,
            () = clock::sleep_until_some(deadline) => {}
            () = local.0.wake.woken() => {}
            () = std::future::ready(()), if more => {}
            command = commands.recv() => match command {
                None | Some(Command::Stop) => break,
                Some(Command::Status(reply)) => {
                    let inner = local.0.inner.borrow();
                    let now = clock::now();
                    let _ = reply.send(Status {
                        peer: inner.device.peer_status(&peer, now),
                        drops: *inner.device.drops(),
                        held: inner.device.held(),
                        local: local_addr,
                        send_errors: outbox.send_errors,
                        receive_errors,
                        socket_buffers: buffers.clone(),
                        unix_high_water: inner.device.unix_high_water(),
                    });
                }
                Some(Command::SetEndpoint(endpoint)) => {
                    local.0.borrow().device.set_endpoint(clock::now(), &peer, endpoint);
                }
                Some(Command::Run(job)) => job(&local),
            },
        }
    }
    Ok(Rest {
        socket,
        outbox,
        peer,
    })
}
