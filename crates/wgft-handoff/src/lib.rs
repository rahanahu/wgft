//! 飽和の門の後ろの送りの手伝い (gated send) の、データプレーンのスレッド (持ち主) と手伝いのスレッドの間の
//! 受け渡しと、門 ([`gate::Gate`])。
//!
//! - [`Handoff`] は、持ち主から手伝いへ送りの束を渡す輪と、空にした束を返す輪の 2 本を持つ。束の数は輪の
//!   容量と同じで、起動の時に作った束だけが回るので、輪は溢れない
//! - 手伝いは渡す輪が空の時だけ眠りの印を立てて眠る。持ち主は束を入れた時に印を見て、立っていれば 1 回だけ
//!   起こす。持ち主は束が無くて待つ時だけ待ちの印を立て、手伝いは束を返した時に印を見て 1 回だけ起こす。
//!   印と回数を 1 つの語に置く event count なので、起こし損ねも、印の無い相手への起こしも無い
//! - 持ち主は手伝いを待たない。束を入れたら次の仕事に進む
//!
//! どれも unsafe を使わない。輪の枠は錠で包むが、書き手と読み手は別の枠を触るので錠は取り合わない。
//! 錠は所有の安全な受け渡しのためだけにあり、取るのは束 1 つごとに 1 回である。
//!
//! loom の模型は、この crate の型そのものを `--cfg loom` の試験の build で loom の同期の型に替えて確かめる
//! (`RUSTFLAGS="--cfg loom" cargo test -p wgft-handoff --release --lib`)。眠りと起こしは [`Signal`] で外から
//! 渡す。製品の手伝いは `std::thread` の park と unpark、持ち主は tokio の `Notify`、模型は loom の `Notify`。

#![forbid(unsafe_code)]

pub mod gate;

#[cfg(all(loom, test))]
mod loom_tests;

#[cfg(all(loom, test))]
use loom::sync::Mutex;
#[cfg(all(loom, test))]
use loom::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

#[cfg(not(all(loom, test)))]
use std::sync::Mutex;
#[cfg(not(all(loom, test)))]
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use std::sync::PoisonError;

/// 眠っている相手を起こす。製品と模型で中身が違う。起こす前に眠りに入っていなくても、次の眠りが
/// すぐ戻る (許可を残す) ものでなければならない。
pub trait Signal {
    fn signal(&self);
}

/// 1 つの値を自分の cache line に置く (隣の line を先読みする CPU のために 128 byte)。
#[derive(Debug, Default)]
#[repr(align(128))]
struct Line<T>(T);

impl<T> std::ops::Deref for Line<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

/// 容量の決まった 1 対 1 の輪。書き手と読み手はそれぞれ 1 つのスレッドだけである。
struct Ring<T> {
    slots: Box<[Mutex<Option<T>>]>,
    /// 読み手が次に読む位置。読み手だけが書く。
    head: Line<AtomicUsize>,
    /// 書き手が次に書く位置。書き手だけが書く。
    tail: Line<AtomicUsize>,
}

impl<T> Ring<T> {
    fn new(cap: usize) -> Self {
        Self {
            slots: (0..cap.max(1)).map(|_| Mutex::new(None)).collect(),
            head: Line(AtomicUsize::new(0)),
            tail: Line(AtomicUsize::new(0)),
        }
    }

    /// 書き手:`v` を足す。満ちていれば `v` を返す。
    fn push(&self, v: T) -> Result<(), T> {
        let t = self.tail.load(Ordering::Relaxed);
        let h = self.head.load(Ordering::Acquire);
        if t.wrapping_sub(h) >= self.slots.len() {
            return Err(v);
        }
        *self.slots[t % self.slots.len()]
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(v);
        self.tail.store(t.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// 読み手:最も古い値を取る。
    fn pop(&self) -> Option<T> {
        let h = self.head.load(Ordering::Relaxed);
        let t = self.tail.load(Ordering::Acquire);
        if h == t {
            return None;
        }
        let v = self.slots[h % self.slots.len()]
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.head.store(h.wrapping_add(1), Ordering::Release);
        v
    }
}

/// 起床の数。`counters` の feature の build と試験だけが持つ。
#[cfg(any(test, feature = "counters"))]
#[derive(Debug, Default)]
pub struct Counters {
    /// 持ち主が眠っている手伝いを起こした数。
    pub helper_signals: AtomicU64,
    /// 手伝いが待っている持ち主を起こした数。
    pub owner_signals: AtomicU64,
    /// 手伝いが眠りに入った数 (起こされて戻った数と同じ)。
    pub helper_sleeps: AtomicU64,
}

/// 手伝いの次の仕事。
#[derive(Debug)]
pub enum Next<T> {
    /// 送る束。
    Job(T),
    /// 止める印が立った。渡す輪に残る束は無い (持ち主が止める前に渡すのを止める)。
    Stop,
}

/// 手伝いの側の状態の語:眠りの印、止める印、持ち主が束を渡すたびに進む回数。
const SLEEP: u64 = 1;
const STOP: u64 = 2;
const HELPER_EPOCH: u64 = 4;
/// 持ち主の側の状態の語:待ちの印、手伝いが束を返すたびに進む回数。
const WAIT: u64 = 1;
const OWNER_EPOCH: u64 = 2;

/// 持ち主と手伝いが共有する受け渡し。`H` は手伝いを、`O` は持ち主を起こす。
///
/// 眠る側は「状態の語を読む → 輪を確かめる → 読んだ語のままなら印を立てる (compare_exchange)」の順で眠り、
/// 起こす側は「輪に入れる → 語の回数を進める (fetch_add) → 進める前の語に印があれば下ろして起こす」の順で
/// 起こす。1 つの語への読み書きだけで決まるので、起こし損ないも、印の無い相手への起こしも無い。
pub struct Handoff<T, H, O> {
    to_helper: Ring<T>,
    to_owner: Ring<T>,
    helper_state: Line<AtomicU64>,
    owner_state: Line<AtomicU64>,
    dead: AtomicBool,
    /// 手伝いが束を封じて送った時間の累計 (ns)。門が窓ごとに 1 回読む。
    busy_ns: Line<AtomicU64>,
    helper: H,
    owner: O,
    #[cfg(any(test, feature = "counters"))]
    pub counters: Counters,
}

impl<T, H, O> std::fmt::Debug for Handoff<T, H, O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handoff")
            .field("cap", &self.to_helper.slots.len())
            .finish_non_exhaustive()
    }
}

impl<T, H: Signal, O: Signal> Handoff<T, H, O> {
    /// 束を `cap` 個まで運ぶ受け渡し。
    pub fn new(cap: usize, helper: H, owner: O) -> Self {
        Self {
            to_helper: Ring::new(cap),
            to_owner: Ring::new(cap),
            helper_state: Line(AtomicU64::new(0)),
            owner_state: Line(AtomicU64::new(0)),
            dead: AtomicBool::new(false),
            busy_ns: Line(AtomicU64::new(0)),
            helper,
            owner,
            #[cfg(any(test, feature = "counters"))]
            counters: Counters::default(),
        }
    }

    /// 手伝いを起こす信号。
    pub fn helper_signal(&self) -> &H {
        &self.helper
    }

    /// 持ち主を起こす信号。
    pub fn owner_signal(&self) -> &O {
        &self.owner
    }

    // ---- 持ち主の側 ----

    /// 持ち主:束を手伝いに渡す。手伝いが眠りの印を立てていれば 1 回だけ起こす。
    ///
    /// # Errors
    ///
    /// 輪が満ちていれば `job` を返す (束の数が容量と同じなら起きない)。
    pub fn submit(&self, job: T) -> Result<(), T> {
        self.to_helper.push(job)?;
        let prev = self.helper_state.fetch_add(HELPER_EPOCH, Ordering::AcqRel);
        if prev & SLEEP != 0 {
            self.wake_helper();
        }
        Ok(())
    }

    fn wake_helper(&self) {
        self.helper_state.fetch_and(!SLEEP, Ordering::AcqRel);
        #[cfg(any(test, feature = "counters"))]
        self.counters.helper_signals.fetch_add(1, Ordering::Relaxed);
        self.helper.signal();
    }

    /// 持ち主:手伝いが返した束を 1 つ取る。待ちの印は立てない。
    pub fn collect(&self) -> Option<T> {
        self.to_owner.pop()
    }

    /// 持ち主:束が要る。返った束があれば取り、無ければ待ちの印を立てて `None` を返す。`None` の後、
    /// 持ち主は `O` の信号を待つ。束が返るか手伝いが死ぬと、手伝いが 1 回だけ起こす。
    pub fn want(&self) -> Option<T> {
        loop {
            let s = self.owner_state.load(Ordering::Acquire);
            if let Some(job) = self.to_owner.pop() {
                if s & WAIT != 0 {
                    // 前に立てた印を下ろす。手伝いが同時に下ろして起こしても、持ち主の次の待ちがすぐ解けるだけ
                    self.owner_state.fetch_and(!WAIT, Ordering::AcqRel);
                }
                return Some(job);
            }
            if self
                .owner_state
                .compare_exchange(s, s | WAIT, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return None;
            }
        }
    }

    /// 持ち主:手伝いを止める。手伝いは渡された束を送り終えてから [`Next::Stop`] を受ける。
    pub fn stop(&self) {
        let prev = self.helper_state.fetch_or(STOP, Ordering::AcqRel);
        if prev & SLEEP != 0 {
            self.wake_helper();
        }
    }

    /// 止める印が立っている。手伝いが書けるのを待つ間に見る。
    pub fn is_stopping(&self) -> bool {
        self.helper_state.load(Ordering::Acquire) & STOP != 0
    }

    /// 手伝いのスレッドが終わった (panic を含む)。
    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
    }

    /// 手伝いが封じて送った時間の累計 (ns)。
    pub fn busy_ns(&self) -> u64 {
        self.busy_ns.load(Ordering::Relaxed)
    }

    // ---- 手伝いの側 ----

    /// 手伝い:次の仕事を待つ。渡す輪が空なら眠りの印を立て、`wait` で眠る。`wait` は
    /// [`Signal::signal`] の許可を消費して戻る (許可が先にあればすぐ戻る)。
    pub fn next(&self, wait: impl Fn()) -> Next<T> {
        loop {
            let s = self.helper_state.load(Ordering::Acquire);
            if let Some(job) = self.to_helper.pop() {
                return Next::Job(job);
            }
            if s & STOP != 0 {
                return Next::Stop;
            }
            // 読んだ後に束が渡されるか止められていれば、語が変わっていて印を立てない
            if self
                .helper_state
                .compare_exchange(s, s | SLEEP, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            #[cfg(any(test, feature = "counters"))]
            self.counters.helper_sleeps.fetch_add(1, Ordering::Relaxed);
            wait();
            // 起こされたか、まれに理由なく戻った。どちらも印を下ろして確かめ直す
            self.helper_state.fetch_and(!SLEEP, Ordering::AcqRel);
        }
    }

    /// 手伝い:空にした束を返す。持ち主が待ちの印を立てていれば 1 回だけ起こす。
    pub fn give_back(&self, job: T) {
        // 束の数は輪の容量と同じなので、返す輪は溢れない
        let pushed = self.to_owner.push(job);
        debug_assert!(pushed.is_ok(), "more jobs than the ring holds");
        let prev = self.owner_state.fetch_add(OWNER_EPOCH, Ordering::AcqRel);
        if prev & WAIT != 0 {
            self.owner_state.fetch_and(!WAIT, Ordering::AcqRel);
            #[cfg(any(test, feature = "counters"))]
            self.counters.owner_signals.fetch_add(1, Ordering::Relaxed);
            self.owner.signal();
        }
    }

    /// 手伝い:封じて送った時間を足す。
    pub fn add_busy(&self, ns: u64) {
        self.busy_ns.fetch_add(ns, Ordering::Relaxed);
    }

    /// 手伝い:終わる (panic で巻き戻る時を含む)。持ち主を必ず起こす。
    pub fn mark_dead(&self) {
        self.dead.store(true, Ordering::Release);
        self.owner_state.fetch_add(OWNER_EPOCH, Ordering::AcqRel);
        self.owner.signal();
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU32;
    use std::thread;
    use std::time::{Duration, Instant};

    /// park と unpark の信号。製品の手伝いと同じ形。
    #[derive(Default)]
    struct Park(std::sync::OnceLock<thread::Thread>);

    impl Signal for Park {
        fn signal(&self) {
            if let Some(t) = self.0.get() {
                t.unpark();
            }
        }
    }

    #[derive(Default)]
    struct Count(AtomicU32);

    impl Signal for Count {
        fn signal(&self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn the_ring_is_fifo_and_bounded() {
        let r = Ring::new(2);
        r.push(1).unwrap();
        r.push(2).unwrap();
        assert_eq!(r.push(3), Err(3));
        assert_eq!(r.pop(), Some(1));
        r.push(3).unwrap();
        assert_eq!((r.pop(), r.pop(), r.pop()), (Some(2), Some(3), None));
    }

    /// 起きている手伝いへ渡しても起こさない。眠りの印がある時だけ 1 回起こす。待っていない持ち主は
    /// 起こさない。
    #[test]
    fn signals_go_only_to_a_sleeper() {
        let h: Handoff<u32, Count, Count> = Handoff::new(2, Count::default(), Count::default());
        h.submit(1).unwrap();
        assert_eq!(h.helper.0.load(Ordering::Relaxed), 0);
        assert!(matches!(h.next(|| unreachable!()), Next::Job(1)));
        h.give_back(1);
        assert_eq!(
            h.owner.0.load(Ordering::Relaxed),
            0,
            "the owner was not waiting"
        );
        assert_eq!(h.want(), Some(1));
        assert_eq!(h.want(), None);
        h.give_back(7);
        assert_eq!(h.owner.0.load(Ordering::Relaxed), 1, "the owner waited");
        // 眠りの印を手で立てた状態 (眠りに入る直前) に渡すと起こす
        h.helper_state.fetch_or(SLEEP, Ordering::SeqCst);
        h.submit(2).unwrap();
        assert_eq!(h.helper.0.load(Ordering::Relaxed), 1);
        assert_eq!(h.counters.helper_signals.load(Ordering::Relaxed), 1);
        assert_eq!(h.counters.owner_signals.load(Ordering::Relaxed), 1);
    }

    /// 手伝いが panic で終わっても、待っている持ち主は起こされ、死んだことを知る。
    #[test]
    fn a_dying_helper_wakes_the_owner() {
        let h: Handoff<u32, Count, Count> = Handoff::new(2, Count::default(), Count::default());
        assert_eq!(h.want(), None);
        h.mark_dead();
        assert!(h.is_dead());
        assert_eq!(h.owner.0.load(Ordering::Relaxed), 1);
    }

    /// 本物のスレッドで 64 packet の束を流し、束あたりの起床を数える。構造の不変条件として、起床は
    /// 束ごとに手伝いと持ち主で高々 1 回ずつである。手伝いが遅い時と速い時の値を出す。
    #[test]
    #[expect(clippy::cast_precision_loss, reason = "a ratio for the report")]
    fn wake_ups_per_batch_at_full_load() {
        for (name, owner_us, helper_us) in [("helper slower", 5, 20), ("helper faster", 20, 5)] {
            let (jobs, helper_signals, owner_signals) = run_full_load(owner_us, helper_us);
            let per_batch = (helper_signals + owner_signals) as f64 / jobs as f64;
            eprintln!(
                "{name}: {jobs} batches of 64 packets, helper wakes {helper_signals}, owner wakes {owner_signals}, {per_batch:.3} per batch, {:.1} per 1000 packets",
                per_batch * 1000.0 / 64.0
            );
            assert!(helper_signals <= jobs && owner_signals <= jobs);
        }
    }

    fn spin(us: u64) {
        let end = Instant::now() + Duration::from_micros(us);
        while Instant::now() < end {
            std::hint::spin_loop();
        }
    }

    fn run_full_load(owner_us: u64, helper_us: u64) -> (u64, u64, u64) {
        const JOBS: u64 = 400;
        let h = Arc::new(Handoff::<u64, Park, Park>::new(
            2,
            Park::default(),
            Park::default(),
        ));
        h.owner_signal().0.set(thread::current()).unwrap();
        let helper = {
            let h = Arc::clone(&h);
            thread::spawn(move || {
                h.helper_signal().0.set(thread::current()).unwrap();
                let mut last = None;
                while let Next::Job(j) = h.next(thread::park) {
                    assert!(last.is_none_or(|l| j > l), "FIFO");
                    last = Some(j);
                    spin(helper_us);
                    h.give_back(j);
                }
            })
        };
        let mut free = 2u64;
        for j in 0..JOBS {
            if free == 0 {
                loop {
                    if h.want().is_some() {
                        break;
                    }
                    thread::park();
                }
                free += 1;
            }
            while h.collect().is_some() {
                free += 1;
            }
            spin(owner_us);
            h.submit(j).unwrap();
            free -= 1;
        }
        h.stop();
        helper.join().unwrap();
        (
            JOBS,
            h.counters.helper_signals.load(Ordering::Relaxed),
            h.counters.owner_signals.load(Ordering::Relaxed),
        )
    }
}
