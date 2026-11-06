//! Hash S の front の駆動 (試作)。区画 0 を実行し、WireGuard の device を 1 人で持つ。
//!
//! 1 回の起床は今の Inline の駆動 ([`super::super::driver`]) と同じ順で、違いは次だけである。
//!
//! - 受信の相:復号した packet のうち UDP を先に区画 0 の核に渡すのは Inline と同じ。残りは R0 の鍵で振り分け、
//!   区画 0 の packet はその場で核に渡し、ほかの区画の packet はその区画のバッチに詰める。受信のバッチの終わりに
//!   バッチを区画に渡し、答えを生む packet の数 (上限 [`PIGGYBACK_MAX`]) の在庫を相乗りで付ける。中身の無い ACK
//!   には付けない ([`super::needs_reply`])
//! - 在庫の求めに応える:区画が求めた数だけ予約し、輪で渡して起こす。セッションが無ければハンドシェイクを始める
//! - 送信の相:区画 0 の核の出力を Inline と同じく device で暗号化して送る。予約の通し番号を引いた packet の数だけ
//!   進め (1 つの packet は高々 1 つの番号を使う)、相の終わりに公開する
//! - 起床の終わり:Inline と同じ (device の event、waker、ログ、timer)

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Waker;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use wgft_wireguard::{Device, Event, PublicKey};

use super::super::batch::{BATCH_TIME, Pace, RxBatch, WAKE_BUDGET, each_packet, rx_store};
use super::super::driver::{
    Io, ONE_SLOT_CAP, Outbox, Rest, Sent, Sink, Source, decrypt, finish_wake,
};
use super::super::{Command, Local, Settings, SocketBuffers, Status, Upper, clock};
use super::steer::{Route, Steer};
use super::{Batch, Hub, Item, PIGGYBACK_MAX};

/// N = 1 の今のトンネルの番号。
const TUNNEL: u16 = 0;

/// front が持つ Hash S の状態。
#[derive(Debug)]
pub(crate) struct Front {
    pub(crate) hub: Arc<Hub>,
    pub(crate) steer: Steer,
    peer: PublicKey,
    /// トンネルの予約の通し番号。
    rseq: u64,
    /// 区画ごとの詰めている途中のバッチ。番号 0 は使わない。
    cur: Vec<Option<Box<Batch>>>,
    /// 区画ごとの、前に device に足した送った byte の累計。
    seen_bytes: Vec<u64>,
}

impl Front {
    pub(crate) fn new(hub: Arc<Hub>, steer: Steer, peer: PublicKey) -> Self {
        let parts = hub.parts();
        Self {
            hub,
            steer,
            peer,
            rseq: 0,
            cur: (0..parts).map(|_| None).collect(),
            seen_bytes: vec![0; parts],
        }
    }

    /// 番号を 1 つ予約する。セッション、endpoint が無いか、ハンドシェイクを待つ packet があれば `None`。
    pub(crate) fn reserve(&mut self, device: &mut Device, now: Instant) -> Option<Item> {
        let (seal, to) = device.reserve_seal(now, &self.peer)?;
        self.rseq += 1;
        Some(Item {
            tunnel: TUNNEL,
            seal,
            rseq: self.rseq,
            at: now,
            to,
        })
    }

    /// front 自身の送りで `n` 個までの番号を使った。
    fn used(&mut self, n: usize) {
        self.rseq += n as u64;
    }

    /// 今の予約の通し番号を公開する。
    pub(crate) fn publish(&self) {
        self.hub.tunnels[usize::from(TUNNEL)]
            .published
            .store(self.rseq, Ordering::Release);
    }

    /// 区画 `k` の詰めている途中のバッチに `p` を足す。バッチが満ちたら渡して次を取る。空きのバッチが無ければ
    /// 捨てて数える。
    pub(crate) fn stage(&mut self, k: usize, p: &[u8], device: &mut Device, now: Instant) {
        loop {
            if self.cur[k].is_none() {
                let Some(b) = self.hub.links[k].to_front.pop() else {
                    super::count(&self.hub.counts.lane_drops, 1);
                    return;
                };
                self.cur[k] = Some(b);
            }
            let Some(b) = self.cur[k].as_mut() else {
                return;
            };
            if b.push(p) {
                super::count(&self.hub.counts.front_staged, 1);
                return;
            }
            if b.packets() == 0 {
                // 空のバッチに入らない packet は MTU を超える。起きないが捨てて数える
                super::count(&self.hub.counts.lane_drops, 1);
                return;
            }
            self.ship(k, device, now);
        }
    }

    /// 区画 `k` の詰めている途中のバッチを渡して起こす。答えを生む packet の数 (上限 [`PIGGYBACK_MAX`]) の在庫を
    /// 付ける。
    fn ship(&mut self, k: usize, device: &mut Device, now: Instant) {
        let Some(mut b) = self.cur[k].take() else {
            return;
        };
        let n = b.replies().min(PIGGYBACK_MAX).min(b.stock_room());
        for _ in 0..n {
            let Some(it) = self.reserve(device, now) else {
                break;
            };
            if b.push_stock(it).is_err() {
                break;
            }
            super::count(&self.hub.counts.piggybacked, 1);
        }
        self.send_to(k, b);
    }

    fn send_to(&self, k: usize, b: Box<Batch>) {
        let link = &self.hub.links[k];
        // バッチは区画ごとに輪の容量の数だけで、front が 1 つを持つ間は輪は満ちない
        if let Err(mut b) = link.to_part.push(b) {
            b.clear();
            let _ = link.to_front.push(b);
            return;
        }
        link.bell.ring();
    }

    /// 詰めたバッチをすべて渡し、予約の番号を公開する。
    pub(crate) fn ship_all(&mut self, device: &mut Device, now: Instant) {
        for k in 1..self.cur.len() {
            if self.cur[k].as_ref().is_some_and(|b| !b.is_empty()) {
                self.ship(k, device, now);
            }
        }
        self.publish();
    }

    /// 区画の在庫の求めに応える。セッションが無ければハンドシェイクを始め、求めを残す。
    pub(crate) fn serve(&mut self, device: &mut Device, now: Instant) {
        for k in 1..self.cur.len() {
            let want = self.hub.links[k].demand.take();
            if want == 0 {
                continue;
            }
            let mut left = want as usize;
            while left > 0 {
                if !device.has_session(&self.peer, now) {
                    device.start_handshake(now, &self.peer);
                    break;
                }
                let mut b = match self.cur[k].take() {
                    Some(b) => b,
                    None => match self.hub.links[k].to_front.pop() {
                        Some(b) => b,
                        None => break,
                    },
                };
                let mut added = 0;
                while left > 0 && b.stock_room() > 0 {
                    let Some(it) = self.reserve(device, now) else {
                        break;
                    };
                    if b.push_stock(it).is_err() {
                        break;
                    }
                    left -= 1;
                    added += 1;
                }
                super::count(&self.hub.counts.refilled, added);
                if b.is_empty() {
                    b.clear();
                    let _ = self.hub.links[k].to_front.push(b);
                    break;
                }
                self.send_to(k, b);
                if added == 0 {
                    break;
                }
            }
            self.hub.links[k]
                .demand
                .put_back(u32::try_from(left).unwrap_or(u32::MAX));
        }
        self.publish();
    }

    /// 区画が送った byte を device の数えに足し、区画の送信の誤りの和を返す。区画の数えは区画だけが書き、front は
    /// 状態の読み出しの時に読むだけである (front と区画が同じ cache line に書かない)。
    fn collect_sent(&mut self, device: &mut Device) -> u64 {
        let mut errors = 0;
        for (k, l) in self.hub.links.iter().enumerate().skip(1) {
            let total = l.stats.sent_bytes.load(Ordering::Relaxed);
            device.add_sent_bytes(&self.peer, total.saturating_sub(self.seen_bytes[k]));
            self.seen_bytes[k] = total;
            errors += l.stats.send_errors.load(Ordering::Relaxed);
        }
        errors
    }
}

/// 受信のバッチを 1 つ行う (Inline の `receive_batch` に振り分けを足したもの)。
#[expect(
    clippy::too_many_arguments,
    reason = "the Inline receive batch's inputs and the front"
)]
async fn receive_batch<U: Upper>(
    local: &Local<U>,
    device: &mut Device,
    front: &mut Front,
    source: &mut impl Source,
    rx: &mut RxBatch,
    now: Instant,
    vlen: usize,
    receive_errors: &mut u64,
    wakers: &mut Vec<Waker>,
) -> io::Result<(usize, Duration)> {
    let n = match source.recv(rx, vlen) {
        Ok(n) => n,
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            return Ok((0, Duration::ZERO));
        }
        Err(_) => {
            *receive_errors += 1;
            return Ok((0, Duration::ZERO));
        }
    };
    let (end, udp, others) = {
        let mut guard = local.0.borrow();
        let end = decrypt(device, rx, n, now);
        let upper = &mut *guard;
        let (udp, others) = each_packet(&rx.plain[..end], true, |p| upper.handle_packet(now, p));
        (end, udp, others)
    };
    if others == 0 {
        return Ok((n, Duration::ZERO));
    }
    let mut yielded = Duration::ZERO;
    if udp > 0 {
        local.0.borrow().poll_wakers(wakers);
        for waker in wakers.drain(..) {
            waker.wake();
        }
        let before = clock::now();
        tokio::task::yield_now().await;
        yielded = clock::now().saturating_duration_since(before);
        if local.is_poisoned() {
            return Err(io::Error::other(
                "a panic inside the TCP/IP core ended this tunnel generation",
            ));
        }
    }
    {
        let mut guard = local.0.borrow();
        let upper = &mut *guard;
        each_packet(&rx.plain[..end], false, |p| {
            match front.steer.inbound(TUNNEL, p) {
                Route::Part(0) => upper.handle_packet(now, p),
                Route::Part(k) => front.stage(k, p, device, now),
                Route::TcpFragment => super::count(&front.hub.counts.tcp_fragments, 1),
            }
        });
    }
    front.ship_all(device, now);
    Ok((n, yielded))
}

/// 送信のバッチを 1 つ行う (Inline の `send_batch` に、番号の使用と UDP の時刻の記録を足したもの)。
fn send_batch<U: Upper>(
    device: &mut Device,
    upper: &mut U,
    front: &mut Front,
    now: Instant,
    outbox: &mut Outbox,
    sink: &mut impl Sink,
    vlen: usize,
) -> (usize, Sent) {
    let peer = front.peer;
    if !outbox.drain(device, sink) {
        return (0, Sent::Blocked);
    }
    if !device.has_session(&peer, now) {
        if device.start_handshake(now, &peer) {
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
    front.used(pulled);
    for udp in [true, false] {
        for i in 0..pulled {
            if tx.is_udp_slot(i) != udp {
                continue;
            }
            let (packet, sealed) = tx.seal_slot(i);
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

/// 送信の相 (Inline の `send_phase` と同じ規則)。
#[expect(
    clippy::too_many_arguments,
    reason = "the Inline send phase's inputs and the front"
)]
fn send_phase<U: Upper>(
    local: &Local<U>,
    device: &mut Device,
    front: &mut Front,
    outbox: &mut Outbox,
    io: &mut Io<'_>,
    pace: &mut Pace,
    start: Instant,
    timed: bool,
    now: &mut Instant,
) -> bool {
    let mut guard = local.0.borrow();
    let upper = &mut *guard;
    if device.poll_timeout().is_some_and(|t| t <= *now) {
        device.handle_timeout(*now);
    }
    if upper.poll_timeout().is_some_and(|t| t <= *now) {
        upper.handle_timeout(*now);
    }
    let mut tx_done = 0;
    loop {
        let vlen = if timed {
            pace.units(BATCH_TIME, outbox.tx.slots())
        } else {
            1
        };
        let (pulled, state) = send_batch(device, upper, front, *now, outbox, io, vlen);
        tx_done += pulled;
        if timed {
            let after = clock::now();
            pace.record(after.saturating_duration_since(*now), pulled);
            *now = after;
        }
        if state != Sent::Full {
            return false;
        }
        if spent(start, timed, *now, tx_done) {
            return true;
        }
    }
}

fn spent(start: Instant, timed: bool, now: Instant, done: usize) -> bool {
    if timed {
        now.saturating_duration_since(start) >= WAKE_BUDGET
    } else {
        done >= ONE_SLOT_CAP
    }
}

/// front の駆動の task。Inline の `drive` と同じく、止める命令で最後の送り出しに要るものを返す。
#[expect(
    clippy::too_many_arguments,
    reason = "the Inline driver's inputs and the front"
)]
pub(in crate::dataplane) async fn drive<U: Upper>(
    local: Local<U>,
    device: &mut Device,
    front: &mut Front,
    socket: UdpSocket,
    mut commands: mpsc::Receiver<Command<U>>,
    events: mpsc::Sender<Event>,
    high_water: &Arc<AtomicU64>,
    settings: Settings,
    buffers: SocketBuffers,
) -> io::Result<Rest> {
    let peer = front.peer;
    let (mtu, max_datagram) = (device.mtu(), device.max_transmit_len());
    let local_addr = socket
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    let batching = settings.batching.running();
    let mut rx = rx_store(batching, max_datagram);
    let timed = rx.batched();
    let mut rx_pace = Pace::default();
    let mut tx_pace = Pace::default();
    let mut outbox = Outbox::new(batching, mtu, max_datagram);
    let mut io = Io::new(&socket, batching);
    let mut receive_errors = 0u64;
    let mut wakers = Vec::new();
    let hub = Arc::clone(&front.hub);
    loop {
        if local.is_poisoned() {
            return Err(io::Error::other(
                "a panic inside the TCP/IP core ended this tunnel generation",
            ));
        }
        if hub.is_ending() {
            return Err(io::Error::other(
                "a partition thread of this tunnel generation ended",
            ));
        }
        // 知らせの回数は起床の始めに読む。この起床の間に区画が在庫を求めて起こせば、眠らずに続ける
        let seen = hub.front_bell.prepare();
        let start = clock::now();
        let tb = super::t0();
        super::count(&hub.counts.front_wakes, 1);
        let mut now = start;
        let mut rx_more = false;
        let trx = super::t0();
        let mut rx_done = 0;
        loop {
            let vlen = if timed {
                rx_pace.units(BATCH_TIME, rx.slots())
            } else {
                1
            };
            let (n, yielded) = receive_batch(
                &local,
                device,
                front,
                &mut io,
                &mut rx,
                now,
                vlen,
                &mut receive_errors,
                &mut wakers,
            )
            .await?;
            rx_done += n;
            if timed {
                let after = clock::now();
                let took = after.saturating_duration_since(now).saturating_sub(yielded);
                rx_pace.record(took, n);
                now = after;
            }
            if n < vlen {
                break;
            }
            if spent(start, timed, now, rx_done) {
                rx_more = true;
                break;
            }
        }
        super::t1(&hub.counts.front_ns_rx, trx);
        let ts = super::t0();
        front.serve(device, now);
        super::t1(&hub.counts.front_ns_serve, ts);
        let ttx = super::t0();
        let tx_more = send_phase(
            &local,
            device,
            front,
            &mut outbox,
            &mut io,
            &mut tx_pace,
            start,
            timed,
            &mut now,
        );
        front.publish();
        super::t1(&hub.counts.front_ns_tx, ttx);
        let more = rx_more || tx_more;
        let deadline = finish_wake(&local, device, &events, high_water, &mut wakers);
        for waker in wakers.drain(..) {
            waker.wake();
        }
        let blocked = outbox.is_blocked();
        if more {
            tokio::task::yield_now().await;
        }
        // 眠りの印を立てられなければ、この起床の間に知らせがあった。命令が飢えないよう select は通る
        super::t1(&hub.counts.front_ns_busy, tb);
        let rung = !hub.front_bell.sleep(seen);
        tokio::select! {
            ready = socket.readable() => ready?,
            ready = socket.writable(), if blocked => ready?,
            () = clock::sleep_until_some(deadline) => {}
            () = local.0.wake.woken() => {}
            () = hub.front_bell.notifier().0.notified() => {}
            () = std::future::ready(()), if more || rung => {}
            command = commands.recv() => match command {
                None | Some(Command::Stop) => break,
                Some(Command::Status(reply)) => {
                    let now = clock::now();
                    let part_errors = front.collect_sent(device);
                    let _ = reply.send(Status {
                        peer: device.peer_status(&peer, now),
                        drops: *device.drops(),
                        held: device.held(),
                        local: local_addr,
                        send_errors: outbox.send_errors + part_errors,
                        receive_errors,
                        receive_truncated: rx.truncated,
                        socket_buffers: buffers.clone(),
                        unix_high_water: device.unix_high_water(),
                    });
                }
                Some(Command::SetEndpoint(endpoint)) => {
                    device.set_endpoint(clock::now(), &peer, endpoint);
                }
                Some(Command::Run(job)) => job(&local),
            },
        }
        if !rung {
            hub.front_bell.awake();
        }
    }
    front.collect_sent(device);
    let gso = io.gso;
    let _ = io;
    Ok(Rest::new(socket, outbox, peer, gso))
}
