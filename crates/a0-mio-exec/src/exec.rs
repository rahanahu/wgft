//! 単一スレッドの実行器。task の置き場、run queue、std の Waker、mio の待ちの 1 回の起床を持ちます。
//!
//! 1 回の起床 (tick) の順:
//! 1. 別スレッドから起こされた task を受け箱から run queue へ移す
//! 2. run queue が空になるか上限 (`cap`) に届くまで poll する。poll の中で起こされた task も同じ tick で
//!    回る (tokio の LocalSet の 1 tick と同じ)。[`yield_now`] で譲った task だけは OS の待ちの後に回す
//!    (tokio の `yield_now` の defer と同じ)
//! 3. run queue と譲りの列が空でなければ待たずに、空ならタイマーの最も早い期限まで mio の `Poll::poll` で待つ
//! 4. I/O の event を準備の印にし、待つ task を起こす。期限の来たタイマーを起こす。譲った task を起こす

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use mio::{Events, Token};

use crate::io::IoTable;
use crate::timer::Timers;

/// mio の `Waker` の token。I/O の token は slot と世代を詰めた値で、これと重ならない。
pub(crate) const WAKER_TOKEN: Token = Token(usize::MAX);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TaskRef {
    slot: u32,
    generation: u32,
}

type BoxFuture = Pin<Box<dyn Future<Output = ()>>>;

enum State {
    Free,
    Idle(BoxFuture),
    /// poll の最中。future は呼び手の手元にある。
    Running,
    /// poll の最中に abort された。poll の後に落とす。
    AbortedWhileRunning,
}

struct Entry {
    generation: u32,
    state: State,
    waker: Option<Arc<TaskWaker>>,
}

/// 別スレッドと分け合う部分。
struct Remote {
    inbox: Mutex<Vec<TaskRef>>,
    /// 受け箱に積んだ印。tick ごとの錠を省く。
    has_inbox: AtomicBool,
    /// 実行器が `Poll::poll` で寝ている (寝ようとしている) 間だけ真。
    sleeping: AtomicBool,
    waker: mio::Waker,
    remote_wakes: AtomicU64,
    mio_wakes: AtomicU64,
}

struct TaskWaker {
    task: TaskRef,
    /// run queue に入っている間は真。同じ task を 2 度積まない。
    queued: AtomicBool,
    remote: Arc<Remote>,
}

thread_local! {
    static CURRENT: RefCell<Option<Rc<Core>>> = const { RefCell::new(None) };
    /// 今のスレッドの実行器の `Remote` の番地。同じスレッドからの起こしを見分ける。
    static CURRENT_REMOTE: Cell<usize> = const { Cell::new(0) };
    /// poll の中の panic の後に落とす future の印。`JoinHandle` に panic を知らせる。
    static DROPPING_PANICKED: Cell<bool> = const { Cell::new(false) };
    /// [`yield_now`] で譲った task。OS の待ちの後に起こす。
    static DEFERRED: RefCell<Vec<Waker>> = const { RefCell::new(Vec::new()) };
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if self.queued.swap(true, Ordering::AcqRel) {
            return;
        }
        let here = CURRENT_REMOTE.with(Cell::get) == Arc::as_ptr(&self.remote) as usize;
        if here {
            // 同じスレッド:原子の操作 1 回と run queue への push だけで、syscall を出さない
            CURRENT.with(|c| {
                if let Some(core) = c.borrow().as_ref() {
                    core.ready.borrow_mut().push_back(self.task);
                }
            });
            return;
        }
        self.remote.remote_wakes.fetch_add(1, Ordering::Relaxed);
        self.remote
            .inbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(self.task);
        self.remote.has_inbox.store(true, Ordering::SeqCst);
        // 寝ている時だけ eventfd (Linux) を鳴らす。起きていれば次の tick の始めに受け箱を見る
        if self.remote.sleeping.load(Ordering::SeqCst) {
            self.remote.mio_wakes.fetch_add(1, Ordering::Relaxed);
            let _ = self.remote.waker.wake();
        }
    }
}

/// 実行器の数え。
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub ticks: u64,
    pub polls: u64,
    pub max_polls_per_tick: u64,
    pub os_waits: u64,
    pub os_waits_nonzero_timeout: u64,
    pub io_events: u64,
    pub timers_fired: u64,
    pub panics: u64,
    pub remote_wakes: u64,
    pub mio_wakes: u64,
}

pub(crate) struct Core {
    tasks: RefCell<Vec<Entry>>,
    free: RefCell<Vec<u32>>,
    ready: RefCell<VecDeque<TaskRef>>,
    remote: Arc<Remote>,
    pub(crate) timers: RefCell<Timers>,
    pub(crate) io: RefCell<IoTable>,
    pub(crate) registry: mio::Registry,
    stats: Cell<Stats>,
    /// 1 tick に poll する task の上限。
    cap: usize,
    /// task の poll を catch_unwind で包むか (測定の比べのためだけの切り替え)。
    isolate: bool,
}

pub(crate) fn with_core<R>(f: impl FnOnce(&Core) -> R) -> R {
    CURRENT.with(|c| {
        let c = c.borrow();
        let core = c
            .as_ref()
            .expect("a0-mio-exec: called outside the executor's thread");
        f(core)
    })
}

pub(crate) fn try_with_core<R>(f: impl FnOnce(&Core) -> R) -> Option<R> {
    CURRENT.with(|c| c.borrow().as_ref().map(|core| f(core)))
}

/// 実行器。作ったスレッドでだけ使う。
pub struct Exec {
    poll: mio::Poll,
    events: Events,
    core: Rc<Core>,
}

impl fmt::Debug for Exec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Exec").finish_non_exhaustive()
    }
}

impl Exec {
    /// 実行器を作り、このスレッドの今の実行器にする。
    ///
    /// # Errors
    ///
    /// mio の `Poll` か `Waker` を作れなければ誤りを返す。
    pub fn new(cap: usize) -> io::Result<Self> {
        Self::with_isolation(cap, true)
    }

    /// `isolate` が偽なら task の poll を catch_unwind で包まない (測定の比べのためだけ)。
    ///
    /// # Errors
    ///
    /// mio の `Poll` か `Waker` を作れなければ誤りを返す。
    pub fn with_isolation(cap: usize, isolate: bool) -> io::Result<Self> {
        let poll = mio::Poll::new()?;
        let waker = mio::Waker::new(poll.registry(), WAKER_TOKEN)?;
        let registry = poll.registry().try_clone()?;
        let core = Rc::new(Core {
            tasks: RefCell::new(Vec::new()),
            free: RefCell::new(Vec::new()),
            ready: RefCell::new(VecDeque::new()),
            remote: Arc::new(Remote {
                inbox: Mutex::new(Vec::new()),
                has_inbox: AtomicBool::new(false),
                sleeping: AtomicBool::new(false),
                waker,
                remote_wakes: AtomicU64::new(0),
                mio_wakes: AtomicU64::new(0),
            }),
            timers: RefCell::new(Timers::default()),
            io: RefCell::new(IoTable::default()),
            registry,
            stats: Cell::new(Stats::default()),
            cap: cap.max(1),
            isolate,
        });
        CURRENT.with(|c| *c.borrow_mut() = Some(Rc::clone(&core)));
        CURRENT_REMOTE.with(|c| c.set(Arc::as_ptr(&core.remote) as usize));
        Ok(Self {
            poll,
            events: Events::with_capacity(256),
            core,
        })
    }

    /// 今までの数え。
    pub fn stats(&self) -> Stats {
        let mut s = self.core.stats.get();
        s.remote_wakes = self.core.remote.remote_wakes.load(Ordering::Relaxed);
        s.mio_wakes = self.core.remote.mio_wakes.load(Ordering::Relaxed);
        s
    }

    /// 生きている task の数。
    pub fn live_tasks(&self) -> usize {
        self.core
            .tasks
            .borrow()
            .iter()
            .filter(|e| !matches!(e.state, State::Free))
            .count()
    }

    /// `main` を task として立て、終わるまで回す。`main` の中の panic は `Err` になる。
    ///
    /// # Errors
    ///
    /// `main` が panic したか abort されたら [`JoinError`] を返す。
    pub fn block_on<T: 'static>(
        &mut self,
        main: impl Future<Output = T> + 'static,
    ) -> Result<T, JoinError> {
        let handle = spawn(main);
        loop {
            if let Some(r) = handle.state.result.borrow_mut().take() {
                return r;
            }
            let state = Rc::clone(&handle.state);
            self.tick_until(&|| state.result.borrow().is_some());
        }
    }

    /// 1 回の起床。
    pub fn tick(&mut self) {
        self.tick_until(&|| false);
    }

    /// 1 回の起床。poll の相の後に `done` が真なら OS の待ちに入らずに戻る。
    fn tick_until(&mut self, done: &dyn Fn() -> bool) {
        let core = &self.core;
        let mut st = core.stats.get();
        st.ticks += 1;
        // 1. 受け箱
        if core.remote.has_inbox.swap(false, Ordering::SeqCst) {
            let mut inbox = core
                .remote
                .inbox
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            core.ready.borrow_mut().extend(inbox.drain(..));
        }
        // 2. 上限つきの poll
        let mut polled = 0u64;
        for _ in 0..core.cap {
            let Some(t) = core.ready.borrow_mut().pop_front() else {
                break;
            };
            if poll_task(core, t, &mut st) {
                polled += 1;
            }
        }
        st.polls += polled;
        st.max_polls_per_tick = st.max_polls_per_tick.max(polled);
        if done() {
            core.stats.set(st);
            return;
        }
        // 3. 待つ時間
        let idle = core.ready.borrow().is_empty() && DEFERRED.with(|d| d.borrow().is_empty());
        let mut timeout = if idle {
            core.timers
                .borrow_mut()
                .next_deadline()
                .map(|d| d.saturating_duration_since(Instant::now()))
        } else {
            Some(Duration::ZERO)
        };
        if timeout != Some(Duration::ZERO) {
            core.remote.sleeping.store(true, Ordering::SeqCst);
            // 印を立てた後に受け箱を見直す。立てる前に積まれた起こしは eventfd を鳴らしていない
            if core.remote.has_inbox.load(Ordering::SeqCst) {
                timeout = Some(Duration::ZERO);
            }
        }
        st.os_waits += 1;
        if timeout != Some(Duration::ZERO) {
            st.os_waits_nonzero_timeout += 1;
        }
        // 4. OS の待ち
        let r = self.poll.poll(&mut self.events, timeout);
        core.remote.sleeping.store(false, Ordering::SeqCst);
        if let Err(e) = r
            && e.kind() != io::ErrorKind::Interrupted
        {
            panic!("a0-mio-exec: poll failed: {e}");
        }
        for ev in &self.events {
            if ev.token() == WAKER_TOKEN {
                continue;
            }
            st.io_events += 1;
            core.io.borrow_mut().dispatch(ev);
        }
        // 5. タイマー
        st.timers_fired += core.timers.borrow_mut().fire(Instant::now());
        // 6. 譲った task
        DEFERRED.with(|d| {
            for w in d.borrow_mut().drain(..) {
                w.wake();
            }
        });
        core.stats.set(st);
    }
}

impl Exec {
    /// 止める手順:残った task を (panic を隔てて) 落とす。落とす中で立った task も落とす。実行器は
    /// 残るので、呼び手はこの後に送り出し (RST の flush) をしてよい。
    pub fn shutdown(&mut self) {
        loop {
            let live: Vec<(u32, BoxFuture)> = {
                let mut tasks = self.core.tasks.borrow_mut();
                tasks
                    .iter_mut()
                    .enumerate()
                    .filter_map(
                        |(i, e)| match std::mem::replace(&mut e.state, State::Free) {
                            State::Idle(f) => Some((u32::try_from(i).unwrap_or(u32::MAX), f)),
                            other => {
                                e.state = other;
                                None
                            }
                        },
                    )
                    .collect()
            };
            if live.is_empty() {
                break;
            }
            for (slot, f) in live {
                let _ = catch_unwind(AssertUnwindSafe(|| drop(f)));
                release(&self.core, slot);
            }
        }
        self.core.ready.borrow_mut().clear();
        DEFERRED.with(|d| d.borrow_mut().clear());
    }
}

impl Drop for Exec {
    fn drop(&mut self) {
        self.shutdown();
        CURRENT.with(|c| *c.borrow_mut() = None);
        CURRENT_REMOTE.with(|c| c.set(0));
    }
}

fn release(core: &Core, slot: u32) {
    let mut tasks = core.tasks.borrow_mut();
    let e = &mut tasks[slot as usize];
    e.state = State::Free;
    e.generation = e.generation.wrapping_add(1);
    e.waker = None;
    core.free.borrow_mut().push(slot);
}

/// task を 1 回 poll する。古い起こし (落ちた task) なら偽を返す。
fn poll_task(core: &Core, t: TaskRef, st: &mut Stats) -> bool {
    let (mut fut, waker) = {
        let mut tasks = core.tasks.borrow_mut();
        let Some(e) = tasks.get_mut(t.slot as usize) else {
            return false;
        };
        if e.generation != t.generation {
            return false;
        }
        let State::Idle(f) = std::mem::replace(&mut e.state, State::Running) else {
            return false;
        };
        let w = e.waker.clone().expect("a live task has a waker");
        (f, w)
    };
    // poll の前に印を下ろす。poll の中の起こし (譲り) は次の tick に積まれる
    waker.queued.store(false, Ordering::Release);
    let std_waker = Waker::from(Arc::clone(&waker));
    let mut cx = Context::from_waker(&std_waker);
    let outcome = if core.isolate {
        catch_unwind(AssertUnwindSafe(|| fut.as_mut().poll(&mut cx)))
    } else {
        Ok(fut.as_mut().poll(&mut cx))
    };
    match outcome {
        Ok(Poll::Pending) => {
            let mut tasks = core.tasks.borrow_mut();
            let e = &mut tasks[t.slot as usize];
            if matches!(e.state, State::AbortedWhileRunning) {
                drop(tasks);
                drop(fut);
                release(core, t.slot);
            } else {
                e.state = State::Idle(fut);
            }
        }
        Ok(Poll::Ready(())) => {
            drop(fut);
            release(core, t.slot);
        }
        Err(_) => {
            st.panics += 1;
            // task の持ち物 (ソケット、枠、handle) を落とす。落とす中の panic も隔てる
            DROPPING_PANICKED.with(|p| p.set(true));
            let _ = catch_unwind(AssertUnwindSafe(|| drop(fut)));
            DROPPING_PANICKED.with(|p| p.set(false));
            release(core, t.slot);
        }
    }
    true
}

/// task の終わり方。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinError {
    Cancelled,
    Panicked,
}

struct JoinState<T> {
    result: RefCell<Option<Result<T, JoinError>>>,
    waker: RefCell<Option<Waker>>,
    task: Cell<TaskRef>,
}

impl<T> JoinState<T> {
    fn finish(&self, r: Result<T, JoinError>) {
        let mut slot = self.result.borrow_mut();
        if slot.is_none() {
            *slot = Some(r);
            drop(slot);
            if let Some(w) = self.waker.borrow_mut().take() {
                w.wake();
            }
        }
    }
}

/// 立てた task の結果を待つ口。落としても task は止めない (tokio と同じ)。
pub struct JoinHandle<T> {
    state: Rc<JoinState<T>>,
}

impl<T> fmt::Debug for JoinHandle<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinHandle").finish_non_exhaustive()
    }
}

impl<T> JoinHandle<T> {
    /// task を止める。持ち物はすぐに落ちる (poll の最中なら poll の後)。
    pub fn abort(&self) {
        abort(self.state.task.get());
    }

    pub fn is_finished(&self) -> bool {
        self.state.result.borrow().is_some()
    }
}

impl<T> Future for JoinHandle<T> {
    type Output = Result<T, JoinError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(r) = self.state.result.borrow_mut().take() {
            return Poll::Ready(r);
        }
        *self.state.waker.borrow_mut() = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// task の future を包み、終わり、abort、panic を `JoinHandle` に知らせる。
struct Wrapped<F: Future> {
    fut: F,
    state: Rc<JoinState<F::Output>>,
}

impl<F: Future> Future for Wrapped<F> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        // 安全:fut は Wrapped と共に Box の中で固定され、ここから動かさない
        let this = unsafe { self.get_unchecked_mut() };
        let fut = unsafe { Pin::new_unchecked(&mut this.fut) };
        match fut.poll(cx) {
            Poll::Ready(v) => {
                this.state.finish(Ok(v));
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<F: Future> Drop for Wrapped<F> {
    fn drop(&mut self) {
        let e = if DROPPING_PANICKED.with(Cell::get) {
            JoinError::Panicked
        } else {
            JoinError::Cancelled
        };
        self.state.finish(Err(e));
    }
}

/// 今のスレッドの実行器に task を立てる (tokio の `spawn_local` に当たる)。
///
/// # Panics
///
/// 実行器の外で呼ぶと panic する。
pub fn spawn<F>(fut: F) -> JoinHandle<F::Output>
where
    F: Future + 'static,
    F::Output: 'static,
{
    with_core(|core| {
        let state = Rc::new(JoinState {
            result: RefCell::new(None),
            waker: RefCell::new(None),
            task: Cell::new(TaskRef {
                slot: 0,
                generation: 0,
            }),
        });
        let boxed: BoxFuture = Box::pin(Wrapped {
            fut,
            state: Rc::clone(&state),
        });
        let mut tasks = core.tasks.borrow_mut();
        let slot = core.free.borrow_mut().pop().unwrap_or_else(|| {
            tasks.push(Entry {
                generation: 0,
                state: State::Free,
                waker: None,
            });
            u32::try_from(tasks.len() - 1).expect("fewer than 2^32 tasks")
        });
        let e = &mut tasks[slot as usize];
        let t = TaskRef {
            slot,
            generation: e.generation,
        };
        e.state = State::Idle(boxed);
        e.waker = Some(Arc::new(TaskWaker {
            task: t,
            queued: AtomicBool::new(true),
            remote: Arc::clone(&core.remote),
        }));
        state.task.set(t);
        core.ready.borrow_mut().push_back(t);
        JoinHandle { state }
    })
}

fn abort(t: TaskRef) {
    let fut = with_core(|core| {
        let mut tasks = core.tasks.borrow_mut();
        let e = tasks.get_mut(t.slot as usize)?;
        if e.generation != t.generation {
            return None;
        }
        match std::mem::replace(&mut e.state, State::Free) {
            State::Idle(f) => Some(f),
            State::Running => {
                e.state = State::AbortedWhileRunning;
                None
            }
            other => {
                e.state = other;
                None
            }
        }
    });
    if let Some(f) = fut {
        // 借用の外で落とす。落とす中で別の task を立てても止めてもよい
        drop(f);
        with_core(|core| release(core, t.slot));
    }
}

/// 1 回だけ順を譲る (tokio の `yield_now` に当たる)。OS の待ち (I/O の event) を 1 回見た後に回る。
pub async fn yield_now() {
    let mut yielded = false;
    std::future::poll_fn(|cx| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            DEFERRED.with(|d| d.borrow_mut().push(cx.waker().clone()));
            Poll::Pending
        }
    })
    .await;
}
