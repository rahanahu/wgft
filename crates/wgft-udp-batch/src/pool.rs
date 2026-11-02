//! The crypto workers: a few threads, started once per tunnel generation, that run parts of one
//! batch while the data-plane thread runs another part and waits. The rules are in
//! `docs/design/v2/agent-throughput.md` (暗号を並べて行う段).
//!
//! - 1 回の受け渡し:持ち主のスレッド (データプレーンのスレッド) は、バッチの仕事を作業者の数より 1 つ
//!   多い部分に分け、作業者ごとの枠に 1 つずつ置いて起こし、残りの 1 つを自分で行う。終わったら、まだ
//!   どの作業者も取っていない部分を取り戻して自分で行い、作業者が取った部分の終わりを待つ。眠っている
//!   作業者を待たないので、起床の遅れはバッチを長くしない
//! - 同期:バッチごとに枠ごとの錠を数回取り、作業者を起こし、終わりを知らせるだけで、packet ごとには
//!   何もしない
//! - 持ち物:部分 (`T`) は持ち主と作業者の間を値で動く。作業者が借用を持つことは無いので unsafe は要らない
//! - panic:作業者の中の panic は毒の印を付け、[`Pool::run`] は以後 [`Poisoned`] を返す。呼び手は
//!   その世代を終える

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle, Thread};

/// A part of a batch that a worker can run.
pub trait Run: Send + 'static {
    /// Does the work. It allocates nothing and does not block.
    fn run(&mut self);

    /// Whether the part has nothing to do: the pool neither offers it to a worker nor runs it, so
    /// no worker is woken for it.
    fn is_idle(&self) -> bool {
        false
    }
}

/// A worker panicked; the pool runs nothing more.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poisoned;

impl fmt::Display for Poisoned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a crypto worker panicked")
    }
}

impl std::error::Error for Poisoned {}

/// The stack of one worker. A worker runs only the crypto of its part and a loop around it.
pub const WORKER_STACK: usize = 128 << 10;

/// What one worker's thread holds beyond its stack, as an allowance: the thread's own state in the
/// standard library and the C library (thread-local storage, the thread's control block).
pub const THREAD_STATE: usize = 4 << 10;

/// The most workers. Two workers already reach most of what moving the crypto off the data-plane
/// thread can give (`docs/design/v2/agent-throughput.md`), and each one adds a wake-up per batch.
pub const MAX_WORKERS: usize = 2;

/// The number of crypto workers for this host, read once at start: [`MAX_WORKERS`] when the process
/// may use more CPUs than that, else none. Rust's count follows the CPU affinity and the cgroup CPU
/// quota. One worker is not used: on the host it ended a received batch no sooner than the owner
/// alone, because the batch waited for the worker to wake.
#[must_use]
pub fn worker_count() -> usize {
    workers_for(thread::available_parallelism().map_or(1, std::num::NonZero::get))
}

/// [`worker_count`] for `cpus` CPUs.
#[must_use]
pub const fn workers_for(cpus: usize) -> usize {
    if cpus > MAX_WORKERS { MAX_WORKERS } else { 0 }
}

/// One worker's place. Each sits on its own cache lines, so that the owner and the workers do not
/// share a line they write.
#[repr(align(128))]
struct Slot<T> {
    /// A part offered to the worker. The worker or the owner takes it.
    todo: Mutex<Option<T>>,
    /// The part the worker finished.
    done: Mutex<Option<T>>,
}

struct Shared<T> {
    slots: Box<[Slot<T>]>,
    owner: Thread,
    /// Workers that reached their loop. [`Pool::new`] waits for all of them, so that what a thread
    /// allocates as it starts happens before the pool is used.
    started: std::sync::atomic::AtomicUsize,
    stop: AtomicBool,
    poisoned: AtomicBool,
}

/// The bytes a pool of `workers` workers for parts `T` holds: each worker's stack and thread state,
/// and the places the owner and the workers share.
#[must_use]
pub const fn bytes<T: Run>(workers: usize) -> usize {
    let workers = if workers < MAX_WORKERS {
        workers
    } else {
        MAX_WORKERS
    };
    // Arc の 2 つの数と共有の値、作業者ごとの枠と join の handle
    2 * size_of::<usize>()
        + size_of::<Shared<T>>()
        + workers
            * (WORKER_STACK + THREAD_STATE + size_of::<Slot<T>>() + size_of::<JoinHandle<()>>())
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // 錠を持つ間は take と置き換えだけで、panic しない
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The workers of one tunnel generation. Make it on the thread that calls [`Pool::run`]; dropping it
/// stops and joins the workers.
pub struct Pool<T: Run> {
    shared: Arc<Shared<T>>,
    workers: Box<[JoinHandle<()>]>,
}

impl<T: Run> fmt::Debug for Pool<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pool")
            .field("workers", &self.workers.len())
            .finish_non_exhaustive()
    }
}

/// Marks the pool poisoned and wakes the owner if the worker unwinds out of a part.
struct PanicGuard<'a, T>(&'a Shared<T>);

impl<T> Drop for PanicGuard<'_, T> {
    fn drop(&mut self) {
        if thread::panicking() {
            self.0.poisoned.store(true, Ordering::Release);
            self.0.owner.unpark();
        }
    }
}

fn work<T: Run>(shared: &Shared<T>, me: usize) {
    let slot = &shared.slots[me];
    shared.started.fetch_add(1, Ordering::AcqRel);
    shared.owner.unpark();
    loop {
        thread::park();
        if shared.stop.load(Ordering::Acquire) {
            return;
        }
        // 持ち主が先に取り戻していれば何も無い。起こされずに起きたときも同じ
        let Some(mut part) = lock(&slot.todo).take() else {
            continue;
        };
        let guard = PanicGuard(shared);
        part.run();
        drop(guard);
        *lock(&slot.done) = Some(part);
        shared.owner.unpark();
    }
}

impl<T: Run> Pool<T> {
    /// Starts `workers` threads, at most [`MAX_WORKERS`], with [`WORKER_STACK`] bytes of stack each.
    /// The calling thread becomes the owner that [`Pool::run`] must be called from.
    ///
    /// # Errors
    ///
    /// The error of a thread that could not start; the threads already started are stopped.
    pub fn new(workers: usize) -> std::io::Result<Self> {
        let workers = workers.min(MAX_WORKERS);
        let shared = Arc::new(Shared {
            slots: (0..workers)
                .map(|_| Slot {
                    todo: Mutex::new(None),
                    done: Mutex::new(None),
                })
                .collect(),
            owner: thread::current(),
            started: std::sync::atomic::AtomicUsize::new(0),
            stop: AtomicBool::new(false),
            poisoned: AtomicBool::new(false),
        });
        let mut handles = Vec::with_capacity(workers);
        for me in 0..workers {
            let s = Arc::clone(&shared);
            let spawned = thread::Builder::new()
                .name("wgft-crypto".into())
                .stack_size(WORKER_STACK)
                .spawn(move || work(&s, me));
            match spawned {
                Ok(h) => handles.push(h),
                Err(e) => {
                    let _ = Self {
                        shared,
                        workers: handles.into_boxed_slice(),
                    };
                    return Err(e);
                }
            }
        }
        // 作業者がそれぞれ待ちの loop に着くまで待つ。スレッドの始まりの確保をここで済ませる
        while shared.started.load(Ordering::Acquire) < workers {
            thread::park();
        }
        Ok(Self {
            shared,
            workers: handles.into_boxed_slice(),
        })
    }

    /// The number of workers.
    #[must_use]
    pub fn workers(&self) -> usize {
        self.workers.len()
    }

    /// Runs the parts in `parts` and puts them back in place: `parts[0]` on this thread, `parts[i]`
    /// for `i` from 1 offered to worker `i - 1`, taken back and run here if that worker has not
    /// started it once `parts[0]` is done. Returns once every part is done. Empty places are
    /// skipped; places beyond the workers run here.
    ///
    /// # Errors
    ///
    /// [`Poisoned`] once a worker panicked: a part it held is lost and the pool runs nothing more.
    pub fn run(&self, parts: &mut [Option<T>]) -> Result<(), Poisoned> {
        let Some((first, rest)) = parts.split_first_mut() else {
            return Ok(());
        };
        let offered = self.offer(rest)?;
        if let Some(part) = first.as_mut().filter(|p| !p.is_idle()) {
            part.run();
        }
        self.collect(rest, offered)
    }

    /// Offers `parts[i]` to worker `i` and returns at once; places beyond the workers run here
    /// first. Pass the result to [`Pool::collect`] with the same places.
    ///
    /// # Errors
    ///
    /// [`Poisoned`] once a worker panicked.
    pub fn offer(&self, parts: &mut [Option<T>]) -> Result<Offered, Poisoned> {
        let shared = &*self.shared;
        if shared.poisoned.load(Ordering::Acquire) {
            return Err(Poisoned);
        }
        debug_assert_eq!(
            thread::current().id(),
            shared.owner.id(),
            "the pool runs on the thread that made it"
        );
        let n = parts.len().min(self.workers.len());
        // することの無い部分は渡さず、作業者を起こさない
        let mut offered = Offered([false; MAX_WORKERS]);
        for (i, place) in parts[..n].iter_mut().enumerate() {
            if place.as_ref().is_some_and(|p| !p.is_idle())
                && let Some(part) = place.take()
            {
                let slot = &shared.slots[i];
                debug_assert!(
                    lock(&slot.todo).is_none() && lock(&slot.done).is_none(),
                    "one batch is with the workers at a time"
                );
                *lock(&slot.todo) = Some(part);
                offered.0[i] = true;
                self.workers[i].thread().unpark();
            }
        }
        for part in parts[n..].iter_mut().flatten() {
            if !part.is_idle() {
                part.run();
            }
        }
        Ok(offered)
    }

    /// Puts the parts [`Pool::offer`] offered back in place: a part no worker has started runs
    /// here, a started one is waited for.
    ///
    /// # Errors
    ///
    /// [`Poisoned`] once a worker panicked: a part it held is lost.
    pub fn collect(&self, parts: &mut [Option<T>], offered: Offered) -> Result<(), Poisoned> {
        let shared = &*self.shared;
        debug_assert_eq!(
            thread::current().id(),
            shared.owner.id(),
            "the pool runs on the thread that made it"
        );
        let mut waiting = offered.0;
        let mut any = false;
        for (i, place) in parts.iter_mut().enumerate().take(MAX_WORKERS) {
            if !waiting[i] {
                continue;
            }
            if let Some(mut part) = lock(&shared.slots[i].todo).take() {
                part.run();
                *place = Some(part);
                waiting[i] = false;
            } else {
                // 作業者が取った。偽の起床と、前のバッチで残った起こしは、下の確かめで読み飛ばす
                any = true;
            }
        }
        while any {
            any = false;
            for (i, place) in parts.iter_mut().enumerate().take(MAX_WORKERS) {
                if !waiting[i] {
                    continue;
                }
                if let Some(part) = lock(&shared.slots[i].done).take() {
                    *place = Some(part);
                    waiting[i] = false;
                } else {
                    any = true;
                }
            }
            if any {
                if shared.poisoned.load(Ordering::Acquire) {
                    return Err(Poisoned);
                }
                thread::park();
            }
        }
        Ok(())
    }
}

/// Which places [`Pool::offer`] handed to workers.
#[derive(Clone, Copy, Debug, Default)]
pub struct Offered([bool; MAX_WORKERS]);

#[cfg(feature = "test-hooks")]
impl<T: Run> Pool<T> {
    /// Marks the pool poisoned, as a worker's panic does, for tests of the callers' handling.
    pub fn poison(&self) {
        self.shared.poisoned.store(true, Ordering::Release);
    }
}

impl<T: Run> Drop for Pool<T> {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        for h in &self.workers {
            h.thread().unpark();
        }
        for h in std::mem::take(&mut self.workers) {
            // panic した作業者の join は Err を返す。毒の印で知らせ済みである
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    #[derive(Debug, Default)]
    struct Count {
        ran: usize,
        by: Option<thread::ThreadId>,
        panic: bool,
        sleep: Duration,
    }

    impl Run for Count {
        fn run(&mut self) {
            thread::sleep(self.sleep);
            assert!(!self.panic, "the part panics");
            self.ran += 1;
            self.by = Some(thread::current().id());
        }
    }

    #[test]
    fn every_part_runs_once_and_comes_back_in_place() {
        for workers in 0..=MAX_WORKERS {
            let pool = Pool::<Count>::new(workers).unwrap();
            assert_eq!(pool.workers(), workers);
            for round in 0..200 {
                let mut parts: Vec<Option<Count>> = (0..=MAX_WORKERS + 1)
                    .map(|_| Some(Count::default()))
                    .collect();
                if round % 3 == 0 {
                    parts[1] = None;
                }
                pool.run(&mut parts).unwrap();
                for (i, p) in parts.iter().enumerate() {
                    match p {
                        Some(c) => assert_eq!(c.ran, 1, "part {i}"),
                        None => assert!(i == 1 && round % 3 == 0),
                    }
                }
            }
        }
    }

    #[derive(Debug)]
    struct Idle;

    impl Run for Idle {
        fn run(&mut self) {
            panic!("an idle part is not run");
        }

        fn is_idle(&self) -> bool {
            true
        }
    }

    #[test]
    fn idle_parts_wake_no_worker_and_stay_in_place() {
        let pool = Pool::<Idle>::new(MAX_WORKERS).unwrap();
        let mut parts: Vec<Option<Idle>> = (0..=MAX_WORKERS).map(|_| Some(Idle)).collect();
        pool.run(&mut parts).unwrap();
        assert!(parts.iter().all(Option::is_some));
        for s in &pool.shared.slots {
            assert!(lock(&s.todo).is_none() && lock(&s.done).is_none());
        }
    }

    #[test]
    fn a_slow_part_on_a_worker_is_waited_for() {
        let pool = Pool::<Count>::new(1).unwrap();
        let mut parts = [
            Some(Count::default()),
            Some(Count {
                sleep: Duration::from_millis(30),
                ..Count::default()
            }),
        ];
        // 作業者が取るまで持ち主の部分を長くする
        parts[0].as_mut().unwrap().sleep = Duration::from_millis(5);
        pool.run(&mut parts).unwrap();
        assert!(parts.iter().all(|p| p.as_ref().unwrap().ran == 1));
    }

    #[test]
    fn a_panicking_worker_poisons_the_pool() {
        let pool = Pool::<Count>::new(1).unwrap();
        let mut parts = [
            Some(Count {
                sleep: Duration::from_millis(50),
                ..Count::default()
            }),
            Some(Count {
                panic: true,
                ..Count::default()
            }),
        ];
        // 持ち主の部分を長くして、作業者に取らせる。持ち主が先に取り戻すと、panic は持ち主で起きる
        let got = pool.run(&mut parts);
        assert_eq!(got, Err(Poisoned));
        assert!(parts[1].is_none(), "the part the worker held is lost");
        let mut again = [Some(Count::default())];
        assert_eq!(pool.run(&mut again), Err(Poisoned));
    }

    #[test]
    fn a_worker_panic_on_an_offered_part_poisons_the_collect() {
        let pool = Pool::<Count>::new(1).unwrap();
        let mut parts = [Some(Count {
            panic: true,
            ..Count::default()
        })];
        let offered = pool.offer(&mut parts).unwrap();
        // 作業者が取るまで待ってから取り戻す。取り戻せた部分はここで panic するので、取られたことを確かめる
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while lock(&pool.shared.slots[0].todo).is_some() {
            assert!(
                std::time::Instant::now() < deadline,
                "the worker took the part"
            );
            thread::yield_now();
        }
        assert_eq!(pool.collect(&mut parts, offered), Err(Poisoned));
        assert!(parts[0].is_none());
        let mut again = [Some(Count::default())];
        assert!(matches!(pool.offer(&mut again), Err(Poisoned)));
    }

    #[test]
    fn dropping_the_pool_joins_its_workers() {
        static STARTED: AtomicUsize = AtomicUsize::new(0);
        struct Mark;
        impl Run for Mark {
            fn run(&mut self) {
                STARTED.fetch_add(1, Ordering::Relaxed);
            }
        }
        let pool = Pool::<Mark>::new(MAX_WORKERS).unwrap();
        let mut parts: Vec<Option<Mark>> = (0..=MAX_WORKERS).map(|_| Some(Mark)).collect();
        pool.run(&mut parts).unwrap();
        drop(pool);
        assert_eq!(STARTED.load(Ordering::Relaxed), MAX_WORKERS + 1);
    }

    #[test]
    fn the_workers_come_with_a_cpu_left_for_the_owner() {
        assert_eq!(
            (1..=5).map(workers_for).collect::<Vec<_>>(),
            [0, 0, 2, 2, 2]
        );
        assert!(worker_count() <= MAX_WORKERS);
    }
}
