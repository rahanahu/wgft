//! 飽和の門の後ろの送りの手伝い (gated send) の試作。`WGFT_AGENT_EXPERIMENTAL_GATED_SEND=1` の実験の設定で、
//! Linux でバッチの枠が最大で、利用可能な CPU が 3 以上の時だけ作る。
//!
//! - 持ち主 (駆動の task) は今の Inline の道のまま、TCP の核、WireGuard の状態と counter の予約を持つ。
//!   門 ([`Gate`]) が開いているか手伝いに束がある間だけ、TCP の packet の束の封じると `sendmmsg` を手伝いの
//!   スレッドに渡す。UDP の中継の datagram は持ち主が封じて送る
//! - 持ち主は手伝いを待たない。置き場は [`JOBS`] 個で、どれも手伝いにある時だけ核から引くのを止める
//! - 手伝いはソケットの複製をどの epoll にも登録せず、`EAGAIN` の後だけ `poll` で書けるのを待つ
//! - 門が閉じていて手伝いに束が無い間、持ち主は [`super::driver`] の今の送信のバッチを呼ぶ。手伝いは
//!   眠ったままで、起床も受け渡しも無い

// 手伝いを作るのは Linux だけで、ほかの OS の製品の build は作る道を持たない (試験は作る)
#![cfg_attr(
    all(not(target_os = "linux"), not(test)),
    expect(dead_code, reason = "the helper is made on Linux only")
)]

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread::{self, JoinHandle, Thread};
use std::time::Instant;

use wgft_handoff::{Handoff, Next, Signal};
use wgft_wireguard::SealJob;

pub(super) use wgft_handoff::gate::Gate;

use super::batch::{TxBatch, tx_store};
use crate::batching::Batching;

/// 置き場の数。持ち主が 1 つを満たす間に手伝いが 1 つを送る。
pub(super) const JOBS: usize = 2;

/// 手伝いが空の時に渡す束の TCP の packet の最小の数。これ未満は持ち主が自分で封じて送る。手伝いの起床を
/// 32 packet に 1 回以下にする (起床の予算)。
pub(super) const HANDOFF_MIN: usize = 32;

/// 手伝いのスレッドのスタック。
pub(crate) const STACK: usize = 128 << 10;

/// `EAGAIN` の後に書けるのを待つ 1 回の長さ。止める印をこの間隔で見る。
#[cfg(target_os = "linux")]
const WRITABLE_WAIT_MS: i32 = 50;

/// 手伝いに渡す 1 つの束。
#[derive(Debug)]
pub(super) struct Job {
    /// 核が書いた packet と、封じた datagram。持ち主が封じた UDP は封じた枠の先頭にある。
    pub(super) tx: TxBatch,
    /// 封じる packet の枠の番号と、その予約。予約の順に並ぶ。
    pub(super) seals: Vec<(u16, SealJob)>,
    /// 持ち主が送り終えた封じた枠の数。手伝いはこの枠から並べて送る。
    pub(super) first: usize,
    /// 同じ長さの並びを UDP の GSO の 1 つの message にまとめる。
    pub(super) gso: bool,
}

impl Job {
    fn new(batching: Batching, mtu: usize, max_datagram: usize) -> Self {
        let tx = tx_store(batching, mtu, max_datagram);
        let seals = Vec::with_capacity(tx.slots());
        Self {
            tx,
            seals,
            first: 0,
            gso: false,
        }
    }

    pub(super) fn clear(&mut self) {
        self.tx.clear();
        self.seals.clear();
        self.first = 0;
    }
}

/// 手伝いを作る時に確保する byte:置き場と予約の列、スタック。メモリの上界の `batch` の項に足す。
pub(crate) fn bytes(slots: usize, on: bool, mtu: usize, max_datagram: usize) -> usize {
    let job = wgft_udp_batch::tx_store_bytes(slots, on, mtu, max_datagram)
        + slots * size_of::<(u16, SealJob)>();
    JOBS * job + STACK
}

/// 手伝いを起こす:park と unpark。許可を残すので、眠る前に起こしても次の park がすぐ戻る。
#[derive(Debug, Default)]
pub(super) struct Park(OnceLock<Thread>);

impl Signal for Park {
    fn signal(&self) {
        if let Some(t) = self.0.get() {
            t.unpark();
        }
    }
}

/// 持ち主を起こす:tokio の `Notify`。待つ task が無ければ許可を 1 つ残す。
#[derive(Debug, Default)]
pub(super) struct OwnerBell(tokio::sync::Notify);

impl Signal for OwnerBell {
    fn signal(&self) {
        self.0.notify_one();
    }
}

type Shared = Handoff<Job, Park, OwnerBell>;

/// 手伝いが送る先。製品はソケットの複製で、試験は記録する。
pub(super) trait HelperSink: Send + 'static {
    /// バッチの message を `tx.next` から送り、送れた message の数を返す。
    fn send_batch(&mut self, tx: &mut TxBatch) -> io::Result<usize>;
    /// 書けるようになるのを少しの間待つ。書けるなら `true`。
    fn wait_writable(&mut self) -> io::Result<bool>;
}

/// 製品の送り先:WireGuard の UDP のソケットの複製。どの epoll にも登録しない。
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(super) struct DupSocket(pub(super) std::os::fd::OwnedFd);

#[cfg(target_os = "linux")]
impl HelperSink for DupSocket {
    fn send_batch(&mut self, tx: &mut TxBatch) -> io::Result<usize> {
        use std::os::fd::AsRawFd;
        tx.send(self.0.as_raw_fd())
    }

    fn wait_writable(&mut self) -> io::Result<bool> {
        use std::os::fd::AsRawFd;
        wgft_udp_batch::sys::wait_writable(self.0.as_raw_fd(), WRITABLE_WAIT_MS)
    }
}

/// 手伝いと持ち主が共有する数と印。
#[derive(Debug, Default)]
struct Stats {
    send_errors: AtomicU64,
    gso_refused: AtomicBool,
}

/// 観測の build と試験の数。
#[cfg(any(test, feature = "lab-observe"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HelperCounters {
    /// 門の切り替わり。
    pub transitions: u64,
    /// 手伝いに渡した束と packet。
    pub jobs: u64,
    pub packets: u64,
    /// 門が開いているか手伝いに束がある間に、持ち主が自分で送った packet。
    pub owner_packets: u64,
    /// 持ち主が眠っている手伝いを起こした数と、手伝いが待っている持ち主を起こした数。
    pub helper_wakes: u64,
    pub owner_wakes: u64,
    /// 持ち主が置き場を待った数。
    pub waits: u64,
}

/// 持ち主の側の手伝い。止める時と落とす時に手伝いのスレッドを止めて join する。
#[derive(Debug)]
pub(super) struct Helper {
    shared: Arc<Shared>,
    stats: Arc<Stats>,
    /// 持ち主が持つ空いた置き場。
    free: Vec<Job>,
    /// 手伝いに渡して返っていない置き場の数。持ち主だけが数える。
    outstanding: usize,
    /// 置き場が無くて待ちの印を立てた。
    waiting: bool,
    thread: Option<JoinHandle<()>>,
    pub(super) gate: Gate,
    #[cfg(any(test, feature = "lab-observe"))]
    pub(super) counters: HelperCounters,
}

impl Helper {
    /// 置き場を確保し、手伝いのスレッドを作る。
    pub(super) fn spawn(
        batching: Batching,
        mtu: usize,
        max_datagram: usize,
        sink: impl HelperSink,
    ) -> io::Result<Self> {
        let free: Vec<Job> = (0..JOBS)
            .map(|_| Job::new(batching, mtu, max_datagram))
            .collect();
        let shared = Arc::new(Shared::new(JOBS, Park::default(), OwnerBell::default()));
        let stats = Arc::new(Stats::default());
        let thread = {
            let (shared, stats) = (Arc::clone(&shared), Arc::clone(&stats));
            thread::Builder::new()
                .name("wgft-send".to_owned())
                .stack_size(STACK)
                .spawn(move || run(&shared, &stats, sink))?
        };
        Ok(Self {
            shared,
            stats,
            free,
            outstanding: 0,
            waiting: false,
            thread: Some(thread),
            gate: Gate::new(),
            #[cfg(any(test, feature = "lab-observe"))]
            counters: HelperCounters::default(),
        })
    }

    /// 送りの束が手伝いを通る状態か:門が開いているか、手伝いに束がある。偽なら持ち主は Inline の道を使う。
    pub(super) fn engaged(&self) -> bool {
        self.gate.is_open() || self.outstanding > 0
    }

    pub(super) fn outstanding(&self) -> usize {
        self.outstanding
    }

    /// 手伝いが返した置き場を引き取る。
    fn collect(&mut self) {
        while self.outstanding > 0 {
            let Some(job) = self.shared.collect() else {
                return;
            };
            self.outstanding -= 1;
            self.free.push(job);
        }
    }

    /// 空いた置き場を 1 つ取る。無ければ待ちの印を立てて `None` を返し、持ち主は [`Helper::notified`] を待つ。
    pub(super) fn take(&mut self) -> Option<Job> {
        self.collect();
        if let Some(job) = self.free.pop() {
            self.waiting = false;
            return Some(job);
        }
        if let Some(job) = self.shared.want() {
            self.outstanding -= 1;
            self.waiting = false;
            return Some(job);
        }
        #[cfg(any(test, feature = "lab-observe"))]
        if !self.waiting {
            self.counters.waits += 1;
        }
        self.waiting = true;
        None
    }

    /// 使わなかった置き場を戻す。
    pub(super) fn put_back(&mut self, mut job: Job) {
        job.clear();
        self.free.push(job);
    }

    /// 束を手伝いに渡す。
    pub(super) fn submit(&mut self, job: Job) {
        #[cfg(any(test, feature = "lab-observe"))]
        {
            self.counters.jobs += 1;
            self.counters.packets += job.seals.len() as u64;
        }
        // 置き場の数は輪の容量と同じなので、渡す輪は溢れない
        let res = self.shared.submit(job);
        debug_assert!(res.is_ok(), "more jobs than the ring holds");
        if let Err(job) = res {
            self.free.push(job);
            return;
        }
        self.outstanding += 1;
    }

    /// 置き場を待っている。
    pub(super) fn is_waiting(&self) -> bool {
        self.waiting
    }

    /// 手伝いが置き場を返すか死ぬのを待つ。
    pub(super) async fn notified(&self) {
        self.shared.owner_signal().0.notified().await;
    }

    pub(super) fn is_dead(&self) -> bool {
        self.shared.is_dead()
    }

    /// 手伝いが送れずに捨てた datagram の数。
    pub(super) fn send_errors(&self) -> u64 {
        self.stats.send_errors.load(Ordering::Relaxed)
    }

    pub(super) fn gso_refused(&self) -> bool {
        self.stats.gso_refused.load(Ordering::Relaxed)
    }

    /// 起床の終わりに門を進める。`cut` は送信の相が時間の予算で切れて送るものが残ったか。
    pub(super) fn end_wake(&mut self, start: Instant, end: Instant, cut: bool) {
        let shared = &self.shared;
        if self
            .gate
            .end_wake(start, end, cut, || shared.busy_ns())
            .is_some()
        {
            #[cfg(any(test, feature = "lab-observe"))]
            {
                self.counters.transitions += 1;
            }
        }
    }

    /// 観測の build と試験の数。
    #[cfg(any(test, feature = "lab-observe"))]
    pub(super) fn counters(&self) -> HelperCounters {
        HelperCounters {
            helper_wakes: self.shared.counters.helper_signals.load(Ordering::Relaxed),
            owner_wakes: self.shared.counters.owner_signals.load(Ordering::Relaxed),
            ..self.counters
        }
    }

    /// 手伝いに渡した束を送り終えさせ、スレッドを止めて join する。最後の送り出しを Inline で行う前に呼び、
    /// 手伝いの束を後の送りに追い越させない。
    pub(super) fn finish(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        self.shared.stop();
        let _ = thread.join();
        self.collect();
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        self.finish();
    }
}

/// 手伝いのスレッドの本体。
fn run(shared: &Shared, stats: &Stats, mut sink: impl HelperSink) {
    /// 終わり方によらず (panic の巻き戻しを含む)、死んだ印を立てて持ち主を起こす。
    struct Dead<'a>(&'a Shared);
    impl Drop for Dead<'_> {
        fn drop(&mut self) {
            self.0.mark_dead();
        }
    }
    let _dead = Dead(shared);
    let _ = shared.helper_signal().0.set(thread::current());
    while let Next::Job(mut job) = shared.next(thread::park) {
        let start = Instant::now();
        seal_and_send(&mut job, &mut sink, stats, || shared.is_stopping());
        let took = Instant::now().saturating_duration_since(start);
        shared.add_busy(u64::try_from(took.as_nanos()).unwrap_or(u64::MAX));
        job.clear();
        shared.give_back(job);
    }
}

/// 予約の順に封じ、GSO の message に並べ、送り切る。`EAGAIN` では書けるまで待ち、止める印が立てば
/// 残りを数えて捨てる。
fn seal_and_send(
    job: &mut Job,
    sink: &mut impl HelperSink,
    stats: &Stats,
    stopping: impl Fn() -> bool,
) {
    let Job {
        tx,
        seals,
        first,
        gso,
    } = job;
    for (slot, seal) in seals.drain(..) {
        let (packet, out) = tx.seal_slot(usize::from(slot));
        let to = seal.to();
        match seal.seal(packet, out) {
            Ok(len) => tx.push_sealed(to, len),
            Err(_) => {
                stats.send_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    let gso = *gso && !stats.gso_refused.load(Ordering::Relaxed);
    tx.lay_out(*first, gso);
    while tx.is_pending() {
        match sink.send_batch(tx) {
            Ok(0) => wait_or_drop(tx, sink, stats, &stopping),
            Ok(n) => tx.next += n.min(tx.n_msgs - tx.next),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                wait_or_drop(tx, sink, stats, &stopping);
            }
            Err(e) if tx.msgs[tx.next].count > 1 && super::driver::gso_refusal(&e) => {
                if !stats.gso_refused.swap(true, Ordering::Relaxed) {
                    let m = tx.msgs[tx.next];
                    crate::logf!(
                        "tunnel: the kernel refused a UDP GSO send of {} datagrams of {} bytes on the WireGuard socket: {e}; sending one datagram per message on this socket from now on",
                        m.count,
                        m.seg
                    );
                }
                tx.lay_out_without_gso();
            }
            Err(_) => {
                stats
                    .send_errors
                    .fetch_add(u64::from(tx.msgs[tx.next].count), Ordering::Relaxed);
                tx.next += 1;
            }
        }
    }
}

/// 書けるまで待つ。止める印が立つか待ちが失敗すれば、残りの message を数えて捨てる。
fn wait_or_drop(
    tx: &mut TxBatch,
    sink: &mut impl HelperSink,
    stats: &Stats,
    stopping: &impl Fn() -> bool,
) {
    loop {
        if stopping() {
            break;
        }
        match sink.wait_writable() {
            Ok(true) => return,
            Ok(false) => {}
            Err(_) => break,
        }
    }
    let left: u64 = tx.msgs[tx.next..tx.n_msgs]
        .iter()
        .map(|m| u64::from(m.count))
        .sum();
    stats.send_errors.fetch_add(left, Ordering::Relaxed);
    tx.next = tx.n_msgs;
}
