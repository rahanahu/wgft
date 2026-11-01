//! 駆動の task。1 回の起床の順と送り出しの規則は `docs/design/v2/wgstack-rs.md` の「1 回の起床」に、
//! バッチの規則は `docs/design/v2/agent-throughput.md` の「バッチの作りの規則」に従う。
//!
//! 1 回の起床は、受信の相と送信の相を 1 回ずつ行い、どちらも起床の始めから [`WAKE_BUDGET`] が経ったら
//! 次のバッチを始めない。
//!
//! 1. 受信の相:受信のバッチ ([`receive_batch`]) を、ソケットが空になるか予算が尽きるまで繰り返す。
//!    バッチはソケットから datagram の列を読み、device の層で平文の領域に復号し、UDP の packet を先に、
//!    残りを読んだ順に上の層に渡す
//! 2. 時刻の来た timer を回す
//! 3. 送信の相:送信のバッチ ([`send_batch`]) を、上の層に送るものが無くなるか予算が尽きるまで繰り返す。
//!    バッチは上の層から packet の列を引き、UDP を先に暗号化して送る。最初のバッチは、受信の相が予算を
//!    使い切っていても予算の半分に合わせる
//! 4. 起床の終わりに、device の event を channel に流し、上の層の waker を借用を返した後に起こし、
//!    ログの行を出し、device の層と上の層の早い方の時刻で timer を張り直す
//!
//! バッチの枠の数は、前のバッチで測った 1 つあたりの時間から、残りの予算に収まる数にする。バッチを
//! 満たすために待つことも、timer を張ることもしない。

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Waker;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use wgft_wireguard::{Device, Event, PublicKey, Transmit};

use super::batch::{
    Pace, RX_SLOT, RxBatch, RxMeta, TxBatch, WAKE_BUDGET, each_packet, rx_store, tx_store,
};
use super::{Command, Local, Settings, SocketBuffers, Status, Upper, clock, duration_to_nanos};
use crate::batching::Batching;

const _: () = assert!(RX_SLOT == crate::relay::UDP_BUF);

/// 送り出しの先。製品はソケットで、試験は記録する。
pub(super) trait Sink {
    /// 1 つの datagram を送る。`WouldBlock` は書けないことを示し、datagram は呼び手が持ち続ける。
    fn send(&mut self, to: SocketAddr, payload: &[u8]) -> io::Result<()>;

    /// バッチの message を `tx.next` から順に送り、送れた message の数を返す。誤りは 1 つも送れなかった
    /// ことを示す。既定は 1 つずつ送り、[`Sink::gso`] が偽のときだけ正しい。
    fn send_batch(&mut self, tx: &mut TxBatch) -> io::Result<usize> {
        send_each(self, tx)
    }

    /// 同じ長さの datagram の並びを 1 つの message (UDP の GSO) で送れるか。
    fn gso(&self) -> bool {
        false
    }
}

/// バッチの message を 1 つずつ送る。message はどれも datagram 1 つである。
fn send_each<S: Sink + ?Sized>(sink: &mut S, tx: &TxBatch) -> io::Result<usize> {
    let mut sent = 0;
    for k in tx.next..tx.n_msgs {
        let (to, payload) = tx.datagram(usize::from(tx.msgs[k].first));
        match sink.send(to, payload) {
            Ok(()) => sent += 1,
            Err(e) if sent == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok(sent)
}

/// 受信の元。製品はソケットである。
pub(super) trait Source {
    /// 最大 `vlen` の枠に datagram を読み、埋めた枠の数を返す。読むものが無ければ `WouldBlock`。
    fn recv(&mut self, rx: &mut RxBatch, vlen: usize) -> io::Result<usize>;
}

/// WireGuard の UDP のソケットと、そこで使える送受信の形。
pub(super) struct Io<'a> {
    socket: &'a UdpSocket,
    /// UDP の GSO を使う。Linux でバッチが有効で、カーネルが GSO を持つときだけ真である。
    gso: bool,
}

impl<'a> Io<'a> {
    /// `socket` の上の送受信。Linux でバッチが有効なら UDP の GRO を有効にし、GSO の有無を調べる。
    /// `recvmmsg` と `sendmmsg` を使うかは、バッチの置き場が見出しを持つかで決まる。
    pub(super) fn new(socket: &'a UdpSocket, batching: Batching) -> Self {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let on = batching.running().is_on();
            let fd = socket.as_raw_fd();
            if on {
                // 有効にできなければ、datagram は 1 つずつ届き、制御の message は付かない
                let _ = wgft_udp_batch::sys::enable_gro(fd);
            }
            let gso = on && batching.slots() > 1 && wgft_udp_batch::sys::has_gso(fd);
            Self { socket, gso }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = batching;
            Self { socket, gso: false }
        }
    }
}

impl Sink for Io<'_> {
    fn send(&mut self, to: SocketAddr, payload: &[u8]) -> io::Result<()> {
        self.socket.try_send_to(payload, to).map(|_| ())
    }

    fn send_batch(&mut self, tx: &mut TxBatch) -> io::Result<usize> {
        #[cfg(target_os = "linux")]
        if tx.batched() {
            use std::os::fd::AsRawFd;
            let fd = self.socket.as_raw_fd();
            return self
                .socket
                .try_io(tokio::io::Interest::WRITABLE, || tx.send(fd));
        }
        send_each(self, tx)
    }

    fn gso(&self) -> bool {
        self.gso
    }
}

impl Source for Io<'_> {
    fn recv(&mut self, rx: &mut RxBatch, vlen: usize) -> io::Result<usize> {
        #[cfg(target_os = "linux")]
        if rx.batched() {
            use std::os::fd::AsRawFd;
            let fd = self.socket.as_raw_fd();
            // 枠より少なく読めたら、ソケットの待ち行列は空になった。それを `WouldBlock` として try_io に
            // 返し、準備の印を消させる。消さないと次の select がすぐに解け、空の読みのためだけに起床する。
            // try_io は閉包を呼ぶ前の印の世代だけを消すので、その間に届いた datagram の印は残る
            let mut short = None;
            let got = self.socket.try_io(tokio::io::Interest::READABLE, || {
                let n = rx.recv(fd, vlen)?;
                if n > 0 && n < vlen {
                    short = Some(n);
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                Ok(n)
            });
            return match (got, short) {
                (_, Some(n)) => Ok(n),
                (got, None) => got,
            };
        }
        let _ = vlen;
        let (n, from) = self.socket.try_recv_from(&mut rx.data[..RX_SLOT])?;
        rx.meta[0] = RxMeta {
            from: Some(from),
            len: u32::try_from(n).unwrap_or(0),
            seg: 0,
        };
        Ok(1)
    }
}

/// 起床をまたいで持つ送り出しの状態。
#[derive(Debug)]
pub(super) struct Outbox {
    /// 送信のバッチの置き場。送り切っていない message がある間は、何も引かず、暗号文の枠を書き換えない。
    pub(super) tx: TxBatch,
    /// ソケットが受け付けなかった、device の層のキューから引いた datagram。高々 1 つで、これがある間は
    /// 何も引かない。
    pub(super) queued: Option<Transmit>,
    /// `WouldBlock` 以外の理由で送れず捨てた datagram の数。
    pub(super) send_errors: u64,
    /// カーネルが UDP の GSO の message を拒んだ。このソケットでは以後 1 つずつ送る。
    gso_refused: bool,
}

impl Outbox {
    pub(super) fn new(batching: Batching, mtu: usize, max_datagram: usize) -> Self {
        Self {
            tx: tx_store(batching, mtu, max_datagram),
            queued: None,
            send_errors: 0,
            gso_refused: false,
        }
    }

    /// 送り切っていないものがあるか。
    pub(super) fn is_blocked(&self) -> bool {
        self.tx.is_pending() || self.queued.is_some()
    }

    /// バッチの残りの message を送る。送り切れば `true`。
    fn flush_batch(&mut self, sink: &mut impl Sink) -> bool {
        while self.tx.is_pending() {
            match sink.send_batch(&mut self.tx) {
                Ok(n) => self.tx.next += n.clamp(1, self.tx.n_msgs - self.tx.next),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return false,
                Err(e) if self.tx.msgs[self.tx.next].count > 1 && gso_refusal(&e) => {
                    // 経路の MTU を超える segment や checksum の offload の無い装置では、カーネルが GSO を
                    // 拒む。同じ datagram を 1 つずつ送り直し、このソケットでは GSO を使わない
                    if !self.gso_refused {
                        crate::logf!(
                            "tunnel: the kernel refused UDP segmentation offload on the WireGuard socket: {e}; sending one datagram per message on this socket"
                        );
                    }
                    self.gso_refused = true;
                    self.tx.lay_out_without_gso();
                }
                Err(_) => {
                    self.send_errors += u64::from(self.tx.msgs[self.tx.next].count);
                    self.tx.next += 1;
                }
            }
        }
        self.tx.clear();
        true
    }

    /// 送り切っていないバッチ、控えた datagram、device の層の送る datagram を、ソケットが受け付ける間
    /// この順にすべて送る。すべて送れば `true`。
    fn drain(&mut self, device: &mut Device, sink: &mut impl Sink) -> bool {
        if !self.flush_batch(sink) {
            return false;
        }
        let mut held = self.queued.take();
        loop {
            let Some(t) = held.take().or_else(|| device.poll_transmit()) else {
                return true;
            };
            match sink.send(t.to, &t.payload) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.queued = Some(t);
                    return false;
                }
                Err(_) => self.send_errors += 1,
            }
        }
    }
}

/// カーネルが UDP の GSO の message を拒んだ誤りか。`EIO` は checksum の offload の無い装置、`EINVAL` は
/// 経路の MTU を超える segment で返る。
fn gso_refusal(e: &io::Error) -> bool {
    #[cfg(unix)]
    {
        matches!(e.raw_os_error(), Some(libc::EIO | libc::EINVAL))
    }
    #[cfg(not(unix))]
    {
        let _ = e;
        false
    }
}

/// 送信のバッチの終わり方。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Sent {
    /// 引ける数だけ引いて送った。上の層にまだ送るものがあるかもしれない。
    Full,
    /// 上の層に送るものが無いか、セッションが無い。
    Idle,
    /// ソケットが書けない。書けるようになるまで何も引かない。
    Blocked,
}

/// 送信のバッチを 1 つ行い、引いた packet の数と終わり方を返す。
///
/// - 先に、送り切っていないバッチと device の層の datagram をすべて送る
/// - device の層がピアとのセッションを持ち、送るものが残っていない間だけ、上の層から `vlen` までの
///   packet を引き、UDP の packet を先に、残りを引いた順に device の層で暗号化して送る。暗号化の順が
///   送る順で、WireGuard の番号もその順に付く
/// - セッションが無ければ引かず、device の層にハンドシェイクを始めさせる。device の層は開始の間隔
///   (`REKEY_TIMEOUT`) と再試行の打ち切りの後の休止を守り、控えた開始は自分の timer で送るので、
///   起きるたびに頼んでよい。server が始めたハンドシェイクには device の層がすぐ答える
/// - ソケットが書けなければ引かない
pub(super) fn send_batch<U: Upper>(
    device: &mut Device,
    upper: &mut U,
    peer: &PublicKey,
    now: Instant,
    outbox: &mut Outbox,
    sink: &mut impl Sink,
    vlen: usize,
) -> (usize, Sent) {
    if !outbox.drain(device, sink) {
        return (0, Sent::Blocked);
    }
    if !device.has_session(peer, now) {
        if device.start_handshake(now, peer) {
            outbox.drain(device, sink);
        }
        return (0, Sent::Idle);
    }
    let tx = &mut outbox.tx;
    let vlen = vlen.clamp(1, tx.slots());
    let mut pulled = 0;
    while pulled < vlen {
        let Some(len) = upper.poll_transmit(now, tx.packet_slot(pulled)) else {
            break;
        };
        tx.set_len(pulled, len);
        pulled += 1;
    }
    // UDP の中継の datagram を TCP の segment の後ろに並べない
    for udp in [true, false] {
        for i in 0..pulled {
            if tx.is_udp_slot(i) != udp {
                continue;
            }
            let (packet, sealed) = tx.seal_slot(i);
            // 上の層は buf より長い長さを返さない。返したら seal_slot が切り詰め、device の層が捨てる
            if let Some(out) = device.handle_packet(now, packet, sealed) {
                tx.push_sealed(out.to, out.len);
            }
        }
    }
    let gso = sink.gso() && !outbox.gso_refused;
    outbox.tx.lay_out(0, gso);
    let state = if !outbox.drain(device, sink) {
        Sent::Blocked
    } else if pulled == vlen {
        Sent::Full
    } else {
        Sent::Idle
    };
    (pulled, state)
}

/// 上の層から `limit` までの packet を、バッチの枠の数ずつ引いて送る。`limit` で止まったときだけ
/// `true` を返す。止めるときの最後の送り出しと試験が使う。
pub(super) fn pump<U: Upper>(
    device: &mut Device,
    upper: &mut U,
    peer: &PublicKey,
    now: Instant,
    outbox: &mut Outbox,
    sink: &mut impl Sink,
    limit: usize,
) -> bool {
    let mut left = limit;
    loop {
        if left == 0 {
            return true;
        }
        let vlen = left.min(outbox.tx.slots());
        let (pulled, state) = send_batch(device, upper, peer, now, outbox, sink, vlen);
        left -= pulled.min(left);
        if state != Sent::Full {
            return false;
        }
    }
}

/// 受信のバッチを 1 つ行い、埋めた枠の数と、順を譲っていた時間を返す。読むものが無ければ 0。受信の
/// 誤りは数えて 0 を返す (仕様 tunnel.md の受信の goroutine の停止)。
///
/// 読んだ datagram をすべて復号してから、UDP の packet を先に上の層に渡す。残りの packet もあれば、
/// 起こす waker を起こして順を譲り、中継の task が UDP の datagram を先に運べるようにしてから、残りを
/// 読んだ順に渡す。核に渡す TCP の segment の順は変えない。
pub(super) async fn receive_batch<U: Upper>(
    local: &Local<U>,
    source: &mut impl Source,
    rx: &mut RxBatch,
    now: Instant,
    vlen: usize,
    receive_errors: &mut u64,
    wakers: &mut Vec<Waker>,
) -> io::Result<(usize, Duration)> {
    let n = match source.recv(rx, vlen) {
        Ok(n) => n,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok((0, Duration::ZERO)),
        Err(_) => {
            *receive_errors += 1;
            return Ok((0, Duration::ZERO));
        }
    };
    let (end, udp, others) = {
        let mut guard = local.0.borrow();
        let inner = &mut *guard;
        let end = decrypt(&mut inner.device, rx, n, now);
        let upper = &mut inner.upper;
        let (udp, others) = each_packet(&rx.plain[..end], true, |p| upper.handle_packet(now, p));
        (end, udp, others)
    };
    if others == 0 {
        return Ok((n, Duration::ZERO));
    }
    let mut yielded = Duration::ZERO;
    if udp > 0 {
        local.0.borrow().upper.poll_wakers(wakers);
        for waker in wakers.drain(..) {
            waker.wake();
        }
        let before = clock::now();
        yield_local().await;
        yielded = clock::now().saturating_duration_since(before);
        if local.is_poisoned() {
            return Err(io::Error::other(
                "a panic inside the TCP/IP core ended this tunnel generation",
            ));
        }
    }
    let mut guard = local.0.borrow();
    let upper = &mut guard.upper;
    each_packet(&rx.plain[..end], false, |p| upper.handle_packet(now, p));
    Ok((n, yielded))
}

/// 埋めた `n` 個の枠の datagram を、GRO がまとめた列は segment ごとに、device の層で平文の領域に
/// 詰めて復号する。平文の領域の使った長さを返す。平文は暗号文より短いので、領域は足りる。
fn decrypt(device: &mut Device, rx: &mut RxBatch, n: usize, now: Instant) -> usize {
    rx.decrypt_each(n, |from, datagram, out| {
        device
            .handle_datagram(now, from, datagram, out)
            .unwrap_or(0)
    })
}

/// 同じスレッドの起きている task に順を譲る。自分を LocalSet の run queue の後ろに並べ直すだけで、
/// `tokio::task::yield_now` と違って I/O の driver の park (epoll_wait) を待たない。LocalSet は tick ごとに
/// 実行環境に戻るので、I/O の知らせは止まらない。
async fn yield_local() {
    let mut yielded = false;
    std::future::poll_fn(|cx| {
        if yielded {
            return std::task::Poll::Ready(());
        }
        yielded = true;
        cx.waker().wake_by_ref();
        std::task::Poll::Pending
    })
    .await;
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
    gso: bool,
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
        let mut io = Io {
            socket: &self.socket,
            gso: self.gso,
        };
        pump(
            &mut inner.device,
            &mut inner.upper,
            &self.peer,
            now,
            &mut self.outbox,
            &mut io,
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
    high_water: Arc<AtomicU64>,
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
    let batching = settings.batching.running();
    // バッチの置き場は起動の時に 1 回だけ確保する。メモリの上界の `batch` の項が数える
    let mut rx = rx_store(batching, max_datagram);
    let mut rx_pace = Pace::default();
    let mut tx_pace = Pace::default();
    let mut outbox = Outbox::new(batching, mtu, max_datagram);
    let mut io = Io::new(&socket, batching);
    let mut receive_errors = 0u64;
    let mut wakers = Vec::new();
    loop {
        if local.is_poisoned() {
            return Err(io::Error::other(
                "a panic inside the TCP/IP core ended this tunnel generation",
            ));
        }
        let start = clock::now();
        let mut now = start;
        let elapsed = |now: Instant| now.saturating_duration_since(start);
        // 受信の相:ソケットが空になるか、予算が尽きるまでバッチを読む。核の出力は送信の相でまとめて
        // 引くので、ACK は起床ごとに 1 回の割で作られる
        let mut rx_more = false;
        loop {
            let left = WAKE_BUDGET.saturating_sub(elapsed(now));
            let vlen = rx_pace.units(left, rx.slots());
            let (n, yielded) = receive_batch(
                &local,
                &mut io,
                &mut rx,
                now,
                vlen,
                &mut receive_errors,
                &mut wakers,
            )
            .await?;
            let after = clock::now();
            // 中継の task に譲っていた時間は、このバッチの仕事ではない
            let took = after.saturating_duration_since(now).saturating_sub(yielded);
            rx_pace.record(took, n);
            now = after;
            if n < vlen {
                break;
            }
            if elapsed(now) >= WAKE_BUDGET {
                rx_more = true;
                break;
            }
        }
        // 送信の相:最初のバッチは、受信の相が予算を使い切っても予算の半分に合わせる。送る向きが
        // 受ける向きに飢えないためである
        let tx_more = {
            let mut guard = local.0.borrow();
            let inner = &mut *guard;
            if inner.device.poll_timeout().is_some_and(|t| t <= now) {
                inner.device.handle_timeout(now);
            }
            if inner.upper.poll_timeout().is_some_and(|t| t <= now) {
                inner.upper.handle_timeout(now);
            }
            let mut first = true;
            loop {
                let left = WAKE_BUDGET.saturating_sub(elapsed(now));
                let share = if first {
                    left.max(WAKE_BUDGET / 2)
                } else {
                    left
                };
                first = false;
                let vlen = tx_pace.units(share, outbox.tx.slots());
                let (pulled, state) = send_batch(
                    &mut inner.device,
                    &mut inner.upper,
                    &peer,
                    now,
                    &mut outbox,
                    &mut io,
                    vlen,
                );
                let after = clock::now();
                tx_pace.record(after.saturating_duration_since(now), pulled);
                now = after;
                if state != Sent::Full {
                    break false;
                }
                if elapsed(now) >= WAKE_BUDGET {
                    break true;
                }
            }
        };
        let more = rx_more || tx_more;
        let deadline = {
            let mut guard = local.0.borrow();
            let inner = &mut *guard;
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
        let blocked = outbox.is_blocked();
        let command = if more {
            // 予算で止めたので、同じスレッドの中継の task (accept と読み書き) に順を譲ってから、待たずに次の
            // 起床を始める。命令だけは見る。I/O の driver を待つ所 (select) には戻らない。Linux の NAPI が
            // 予算を使い切った poll を割り込みに戻さずに続けるのと同じ考えで、起床ごとの epoll_wait と準備の
            // 登録をしない。select の中では譲れない。ソケットが読める間は読める枝がすぐに選ばれ、task は coop
            // の予算を使い切るまで起床を繰り返すので、その間に核の accept の待ち行列が溢れる
            yield_local().await;
            match commands.try_recv() {
                Ok(command) => Some(command),
                Err(mpsc::error::TryRecvError::Empty) => continue,
                Err(mpsc::error::TryRecvError::Disconnected) => None,
            }
        } else {
            tokio::select! {
                ready = socket.readable() => {
                    ready?;
                    continue;
                }
                ready = socket.writable(), if blocked => {
                    ready?;
                    continue;
                }
                () = clock::sleep_until_some(deadline) => continue,
                () = local.0.wake.woken() => continue,
                command = commands.recv() => command,
            }
        };
        match command {
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
                local
                    .0
                    .borrow()
                    .device
                    .set_endpoint(clock::now(), &peer, endpoint);
            }
            Some(Command::Run(job)) => job(&local),
        }
    }
    let gso = io.gso;
    Ok(Rest {
        socket,
        outbox,
        peer,
        gso,
    })
}
