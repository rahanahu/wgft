//! Hash S の区画の駆動 (試作)。区画 1 から P - 1 のスレッドで、今の核と中継を動かす。
//!
//! 1 回の起床:
//!
//! 1. front から受けたバッチの packet を核に渡し、添えられた在庫を自分の在庫に足し、空にしたバッチを返す
//! 2. 時刻の来た timer を回し、ほかの区画が boost の枠を欲しがっていれば需要の無い保有者の枠を返す
//! 3. 送信の相:核から packet を引き、在庫で暗号化し、複製したソケットから `sendmmsg` で送る。在庫が足りなければ
//!    平文を送信の枠に残して front に求め、届いてから暗号化する。暗号化の前と `sendmmsg` の直前に遅れを確かめ、
//!    上限を超えた在庫を捨てて暗号化し直す。`EAGAIN` で送れなかった datagram の在庫は捨て、書けるようになったら
//!    新しい在庫で暗号化し直す。予約から送るまでに `.await` を置かない。UDP が働いている間は 1 回の送りの byte を
//!    B / (P - 1) までにする
//! 4. 起床の終わりに waker を起こし、ログを出し、boost の枠を返す
//!
//! 区画のソケットは front のソケットの複製で、書けることだけを待つ (読める知らせで全区画が起きないため)。

use std::collections::VecDeque;
use std::io;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::Waker;
use std::time::{Duration, Instant};

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

use super::super::batch::{BATCH_TIME, Pace, TxBatch, WAKE_BUDGET};
use super::super::{Command, Local, Upper, clock};
use super::{Freshness, Hub, Item, STOCK_CAP};

/// 区画の送りの状態。
pub(crate) struct PartSend {
    pub(crate) k: usize,
    pub(crate) hub: Arc<Hub>,
    pub(crate) tx: TxBatch,
    /// 区画の在庫。予約の順 (通し番号の順) に並ぶ。
    pub(crate) stock: VecDeque<Item>,
    /// 暗号化した datagram ごとの、使った在庫の通し番号と予約の時刻と元の packet の枠。
    seals: Vec<(u64, Instant, usize)>,
    /// 引いた packet の数。
    pulled: usize,
    /// 在庫を待つ平文:(最初の packet の枠、その datagram の枠)。
    pub(crate) reseal_from: Option<(usize, usize)>,
    gso: bool,
    gso_refused: bool,
    /// ソケットが `EAGAIN` を返し、書けるようになるのを待つ。
    pub(crate) write_blocked: bool,
}

impl std::fmt::Debug for PartSend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartSend")
            .field("k", &self.k)
            .field("stock", &self.stock.len())
            .field("pulled", &self.pulled)
            .field("reseal_from", &self.reseal_from)
            .finish_non_exhaustive()
    }
}

/// 送りの終わり方。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PartSent {
    /// 引ける数だけ引いて送った。
    Full,
    /// 送るものが無い。
    Idle,
    /// 在庫を求めて待つ。
    Starved,
    /// ソケットが書けない。
    Blocked,
}

/// datagram を送る先。製品は複製したソケットで、試験は記録する。
pub(crate) trait PartSink {
    /// バッチの message を `tx.next` から送り、送れた message の数を返す。`WouldBlock` は書けない。
    fn send(&mut self, tx: &mut TxBatch) -> io::Result<usize>;
}

/// 複製したソケット。書けることだけを待つ。
pub(crate) struct PartSocket(pub(crate) AsyncFd<std::net::UdpSocket>);

impl PartSink for PartSocket {
    fn send(&mut self, tx: &mut TxBatch) -> io::Result<usize> {
        let fd = self.0.get_ref().as_raw_fd();
        self.0.try_io(Interest::WRITABLE, |_| tx.send(fd))
    }
}

impl PartSend {
    pub(crate) fn new(k: usize, hub: Arc<Hub>, tx: TxBatch, gso: bool) -> Self {
        let slots = tx.slots();
        Self {
            k,
            hub,
            tx,
            stock: VecDeque::with_capacity(STOCK_CAP),
            seals: vec![(0, Instant::now(), 0); slots],
            pulled: 0,
            reseal_from: None,
            gso,
            gso_refused: false,
            write_blocked: false,
        }
    }

    /// front から受けた在庫を足す。上限を超えたら古いものから捨てて数える。
    pub(crate) fn add_stock(&mut self, it: Item) {
        if self.stock.len() == STOCK_CAP {
            self.stock.pop_front();
            self.hub.counts.overflow_drops.fetch_add(1, Ordering::Relaxed);
        }
        self.stock.push_back(it);
    }

    /// 遅れか時間の上限を超えた在庫を先頭から捨てる (暗号化の前の確かめ)。
    fn drop_stale(&mut self, now: Instant) {
        while let Some(it) = self.stock.front() {
            match self.hub.fresh(it, now) {
                Freshness::Fresh => return,
                Freshness::Lagging => {
                    self.hub.counts.lag_drops.fetch_add(1, Ordering::Relaxed);
                }
                Freshness::Old => {
                    self.hub.counts.age_drops.fetch_add(1, Ordering::Relaxed);
                }
            }
            self.stock.pop_front();
        }
    }

    /// packet の枠 `p0` からの平文を、datagram の枠 `s0` から在庫で暗号化する。在庫が足りなければ front に求め、
    /// 偽を返す (平文は残る)。
    fn seal(&mut self, p0: usize, s0: usize, now: Instant) -> bool {
        self.drop_stale(now);
        let need = self.pulled - p0;
        if self.stock.len() < need {
            let ask = u32::try_from(need).unwrap_or(u32::MAX);
            self.hub.links[self.k]
                .demand
                .ask(ask, &self.hub.front_bell);
            self.hub.counts.requests.fetch_add(1, Ordering::Relaxed);
            self.reseal_from = Some((p0, s0));
            return false;
        }
        self.tx.n_sealed = s0;
        self.tx.n_msgs = self.tx.next;
        for i in p0..self.pulled {
            let Some(it) = self.stock.pop_front() else {
                break;
            };
            let j = self.tx.n_sealed;
            let (packet, out) = self.tx.seal_slot(i);
            // 長さは MTU 以下で、枠は暗号文の最大の長さなので失敗しない。失敗すれば packet を捨てる
            if let Some(len) = it.seal.seal(packet, out) {
                self.tx.push_sealed(it.to, len);
                self.seals[j] = (it.rseq, it.at, i);
            }
        }
        self.reseal_from = None;
        let gso = self.gso && !self.gso_refused;
        self.tx.lay_out(s0, gso);
        true
    }

    /// まだ送っていない最初の datagram の在庫が `sendmmsg` の直前の確かめを通るか。通らなければ送っていない
    /// datagram の在庫を捨て、平文を在庫の待ちに戻す。
    fn recheck(&mut self, now: Instant) -> bool {
        if !self.tx.is_pending() {
            return true;
        }
        let j0 = usize::from(self.tx.msgs[self.tx.next].first);
        let (rseq, at, p0) = self.seals[j0];
        let published = self.hub.tunnels[0].published.load(Ordering::Acquire);
        let stale = published.saturating_sub(rseq) > super::LAG_LIMIT
            || now.saturating_duration_since(at) > super::STOCK_MAX_AGE;
        if !stale {
            return true;
        }
        let dropped = (self.tx.n_sealed - j0) as u64;
        self.hub
            .counts
            .lag_reseals
            .fetch_add(dropped, Ordering::Relaxed);
        self.tx.n_sealed = j0;
        self.tx.n_msgs = self.tx.next;
        self.reseal_from = Some((p0, j0));
        false
    }

    /// 送り残しを送る。送り切れば真。`EAGAIN` なら送れなかった datagram の在庫を捨て、平文を在庫の待ちに戻す。
    fn flush(&mut self, sink: &mut impl PartSink, now: Instant) -> Result<bool, PartSent> {
        while self.tx.is_pending() {
            if !self.recheck(now) {
                // 暗号化し直す。在庫が足りなければ待つ
                let (p0, s0) = self.reseal_from.unwrap_or((self.pulled, self.tx.n_sealed));
                if !self.seal(p0, s0, now) {
                    return Err(PartSent::Starved);
                }
                continue;
            }
            match sink.send(&mut self.tx) {
                Ok(0) => return Err(self.blocked()),
                Ok(n) => {
                    let n = n.min(self.tx.n_msgs - self.tx.next);
                    let sent: usize = self.tx.msgs[self.tx.next..self.tx.next + n]
                        .iter()
                        .map(|m| usize::from(m.count))
                        .sum();
                    let bytes: u64 = self.tx.msgs[self.tx.next..self.tx.next + n]
                        .iter()
                        .map(|m| {
                            let first = usize::from(m.first);
                            (first..first + usize::from(m.count))
                                .map(|j| u64::from(self.tx.out[j].len))
                                .sum::<u64>()
                        })
                        .sum();
                    self.tx.next += n;
                    let link = &self.hub.links[self.k];
                    link.sent_bytes.fetch_add(bytes, Ordering::Relaxed);
                    self.hub
                        .counts
                        .part_sent
                        .fetch_add(sent as u64, Ordering::Relaxed);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Err(self.blocked()),
                Err(e) if self.tx.msgs[self.tx.next].count > 1 && gso_refusal(&e) => {
                    if !self.gso_refused {
                        crate::logf!(
                            "tunnel: the kernel refused a UDP GSO send on partition {}: {e}; sending one datagram per message from now on",
                            self.k
                        );
                    }
                    self.gso_refused = true;
                    self.tx.lay_out_without_gso();
                }
                Err(_) => {
                    let c = u64::from(self.tx.msgs[self.tx.next].count);
                    self.hub.links[self.k]
                        .send_errors
                        .fetch_add(c, Ordering::Relaxed);
                    self.tx.next += 1;
                }
            }
        }
        self.tx.clear();
        self.pulled = 0;
        Ok(true)
    }

    /// 書けない:送れなかった datagram の在庫を捨て、平文を在庫の待ちに戻す。
    fn blocked(&mut self) -> PartSent {
        let j0 = usize::from(self.tx.msgs[self.tx.next].first);
        let p0 = self.seals[j0].2;
        let dropped = (self.tx.n_sealed - j0) as u64;
        self.hub
            .counts
            .eagain_drops
            .fetch_add(dropped, Ordering::Relaxed);
        self.tx.n_sealed = j0;
        self.tx.n_msgs = self.tx.next;
        self.reseal_from = Some((p0, j0));
        self.write_blocked = true;
        PartSent::Blocked
    }

    /// 送信のバッチを 1 つ行い、引いた packet の数と終わり方を返す。
    pub(crate) fn send_batch<U: Upper>(
        &mut self,
        upper: &mut U,
        sink: &mut impl PartSink,
        now: Instant,
        vlen: usize,
    ) -> (usize, PartSent) {
        if self.write_blocked {
            return (0, PartSent::Blocked);
        }
        // 在庫を待つ平文があれば先に暗号化して送る
        if let Some((p0, s0)) = self.reseal_from {
            if !self.seal(p0, s0, now) {
                return (0, PartSent::Starved);
            }
        }
        if self.tx.is_pending() {
            match self.flush(sink, now) {
                Ok(_) => {}
                Err(s) => return (0, s),
            }
        }
        let cap = self.hub.send_cap(now);
        let vlen = vlen.clamp(1, self.tx.slots());
        let mut pulled = 0;
        let mut bytes = 0;
        while pulled < vlen && bytes < cap {
            let Some(len) = upper.poll_transmit(now, self.tx.packet_slot(pulled)) else {
                break;
            };
            self.tx.set_len(pulled, len);
            pulled += 1;
            bytes += len;
        }
        if pulled == 0 {
            return (0, PartSent::Idle);
        }
        self.pulled = pulled;
        if !self.seal(0, 0, now) {
            return (pulled, PartSent::Starved);
        }
        match self.flush(sink, now) {
            Ok(_) if pulled == vlen => (pulled, PartSent::Full),
            Ok(_) => (pulled, PartSent::Idle),
            Err(s) => (pulled, s),
        }
    }

    /// 試験が使う:核から引いて在庫で暗号化し、送らずに止める。
    #[cfg(test)]
    pub(crate) fn pull_and_seal<U: Upper>(&mut self, upper: &mut U, now: Instant, vlen: usize) -> bool {
        let mut pulled = 0;
        while pulled < vlen.min(self.tx.slots()) {
            let Some(len) = upper.poll_transmit(now, self.tx.packet_slot(pulled)) else {
                break;
            };
            self.tx.set_len(pulled, len);
            pulled += 1;
        }
        self.pulled = pulled;
        self.seal(0, 0, now)
    }

    /// 試験が使う:送り残しを送る。
    #[cfg(test)]
    pub(crate) fn flush_for_test(&mut self, sink: &mut impl PartSink, now: Instant) -> Result<bool, PartSent> {
        self.flush(sink, now)
    }

    /// ソケットが書けずに待つか。
    pub(crate) fn is_blocked(&self) -> bool {
        self.write_blocked
    }
}

/// カーネルが UDP の GSO の message を拒んだ誤りか (Inline と同じ判定)。
fn gso_refusal(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::EIO | libc::EINVAL))
}

/// front から受けたバッチをすべて核に渡し、在庫を足し、空にしたバッチを返す。渡した packet の数を返す。
pub(crate) fn take_lane<U: Upper>(local: &Local<U>, send: &mut PartSend, now: Instant) -> usize {
    let hub = Arc::clone(&send.hub);
    let link = &hub.links[send.k];
    let mut n = 0;
    while let Some(mut b) = link.to_part.pop() {
        {
            let mut guard = local.0.borrow();
            b.each(|p| guard.handle_packet(now, p));
        }
        n += b.packets();
        for it in b.stock.drain(..) {
            send.add_stock(it);
        }
        b.clear();
        let _ = link.to_front.push(b);
    }
    n
}

/// 区画の駆動の task。止める命令か、世代の終わりの印で終わる。核の中の panic の後は誤りを返す。
pub(in crate::dataplane) async fn drive<U: Upper>(
    local: Local<U>,
    send: &mut PartSend,
    sink: &mut PartSocket,
    mut commands: mpsc::Receiver<Command<U>>,
) -> io::Result<()> {
    let hub = Arc::clone(&send.hub);
    let k = send.k;
    let mut pace = Pace::default();
    let mut wakers: Vec<Waker> = Vec::new();
    loop {
        if local.is_poisoned() {
            return Err(io::Error::other(
                "a panic inside the TCP/IP core ended this tunnel generation",
            ));
        }
        if hub.is_ending() {
            return Ok(());
        }
        let start = clock::now();
        let mut now = start;
        take_lane(&local, send, now);
        let mut more = false;
        let deadline = {
            let mut guard = local.0.borrow();
            let upper = &mut *guard;
            if upper.poll_timeout().is_some_and(|t| t <= now) {
                upper.handle_timeout(now);
            }
            upper.release_wanted(now);
            let mut done = 0;
            loop {
                let vlen = pace.units(BATCH_TIME, send.tx.slots());
                let (pulled, state) = send.send_batch(upper, sink, now, vlen);
                done += pulled;
                let after = clock::now();
                pace.record(after.saturating_duration_since(now), pulled);
                now = after;
                if state != PartSent::Full {
                    break;
                }
                if now.saturating_duration_since(start) >= WAKE_BUDGET {
                    more = true;
                    break;
                }
            }
            let _ = done;
            if upper.take_boost_wanted() {
                hub.ring_others(k);
            }
            upper.sync_boost();
            upper.poll_wakers(&mut wakers);
            while let Some(line) = upper.poll_log() {
                crate::logf!("{line}");
            }
            upper.poll_timeout()
        };
        for waker in wakers.drain(..) {
            waker.wake();
        }
        if more {
            tokio::task::yield_now().await;
        }
        let link = &hub.links[k];
        link.bell.sleep();
        if link.to_part.has_items() || hub.is_ending() {
            link.bell.awake();
            continue;
        }
        let blocked = send.is_blocked();
        tokio::select! {
            () = link.bell.notifier().0.notified() => {}
            () = local.0.wake.woken() => {}
            () = clock::sleep_until_some(deadline) => {}
            ready = sink.0.writable(), if blocked => {
                send.write_blocked = false;
                if let Ok(mut g) = ready {
                    g.retain_ready();
                }
            }
            () = std::future::ready(()), if more => {}
            command = commands.recv() => match command {
                None | Some(Command::Stop) => {
                    link.bell.awake();
                    return Ok(());
                }
                Some(Command::Run(job)) => job(&local),
                Some(Command::Status(_) | Command::SetEndpoint(_)) => {}
            },
        }
        link.bell.awake();
    }
}

/// 止める時の最後の送り出し:中継の task を落とした後に核に残った出力 (中継の接続を切る RST) を、front に在庫を
/// 求めて送る。front は区画がすべて止まるまで止まらない。在庫かソケットを `FINAL_WAIT` より長く待てば諦める。
pub(in crate::dataplane) async fn final_flush<U: Upper>(
    local: &Local<U>,
    send: &mut PartSend,
    sink: &mut PartSocket,
) {
    const FINAL_WAIT: Duration = Duration::from_millis(500);
    const FINAL_PACKETS: usize = 4096;
    let hub = Arc::clone(&send.hub);
    let k = send.k;
    let deadline = tokio::time::Instant::now() + FINAL_WAIT;
    let mut left = FINAL_PACKETS;
    while left > 0 && !hub.is_ending() {
        let now = clock::now();
        take_lane(local, send, now);
        let (pulled, state) = {
            let mut guard = local.0.borrow();
            let vlen = send.tx.slots();
            send.send_batch(&mut *guard, sink, now, vlen)
        };
        left = left.saturating_sub(pulled);
        match state {
            PartSent::Full => {}
            PartSent::Idle => return,
            PartSent::Starved => {
                let link = &hub.links[k];
                link.bell.sleep();
                if !link.to_part.has_items() {
                    let woke =
                        tokio::time::timeout_at(deadline, link.bell.notifier().0.notified()).await;
                    if woke.is_err() {
                        link.bell.awake();
                        return;
                    }
                }
                link.bell.awake();
            }
            PartSent::Blocked => {
                match tokio::time::timeout_at(deadline, sink.0.writable()).await {
                    Ok(Ok(mut g)) => {
                        send.write_blocked = false;
                        g.retain_ready();
                    }
                    _ => return,
                }
            }
        }
    }
}
