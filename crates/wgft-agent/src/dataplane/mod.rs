//! データプレーン。トンネルの世代ごとに 1 つの OS のスレッドを立て、tokio の current-thread の実行環境で
//! WireGuard の device の層 (`wgft_wireguard::Device`)、上の層 ([`Upper`]、Rust の wgstack の核)、
//! WireGuard の UDP のソケットを動かす。TUN は使わない。
//!
//! 規則の正本は `docs/design/v2/wgstack-rs.md` の「データプレーンの駆動」で、この module はそれを実装する。
//! 足した規則と決めた値は `docs/design/v2/agent-parity.md` の「データプレーンのスレッドと送る経路」に書く。
//!
//! - 所有:device の層と上の層は 1 つの `Rc` の値 ([`Local`] が指す) にまとめ、駆動の task と、同じ
//!   スレッドの local の task だけが触る。ソケットは駆動の task が持つ。制御プレーンは容量の決まった
//!   channel で命令を送る ([`Dataplane`])
//! - 毒の印:上の層を借用している間に巻き戻しが起きたら印を付け、駆動の task はそれを見てスレッドを
//!   終える。上の層の状態は途中で壊れているかもしれないので、その世代の [`Upper::Budget`] は取り出さない
//! - 世代:[`Dataplane::stop`] は実行環境を止めてスレッドを join し、ハンドシェイクの時刻の高い水位と
//!   上の層の `Budget` を [`Carry`] で返す。[`Generations`] はそれを次の世代に渡し、スレッドがどの理由で
//!   終わっても [`Generations::exited`] で知らせる

pub(crate) mod clock;
mod driver;
mod socket;
pub(crate) mod stack;
#[cfg(test)]
mod tests;

use std::cell::{Cell, RefCell, RefMut};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Waker;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};
use wgft_wireguard::{Device, DeviceConfig, Drops, Event, Held, PeerStatus};

pub(crate) use socket::{REQUIRED, SocketBuffers};

/// The layer above the WireGuard device: the TCP/IP core that ends the tunnel's traffic.
///
/// It is sans-IO, as `docs/design/v2/wgstack-rs.md` describes the Rust wgstack: time, packets
/// and operations go in; packets, the next wake-up time, wakers and log lines come out. Every
/// time is on the data plane's [`clock`].
pub trait Upper: 'static {
    /// What the layer hands from one tunnel generation to the next, such as the memory budget.
    type Budget: Send + 'static;

    /// Takes a packet the device decrypted and checked.
    fn handle_packet(&mut self, now: Instant, packet: &[u8]);

    /// Runs the timers that are due.
    fn handle_timeout(&mut self, now: Instant);

    /// Writes the next packet to send into `buf`, which is at least the tunnel MTU long, and
    /// returns its length. The data plane calls it only while the device has a session with the
    /// peer and nothing waiting to be sent.
    fn poll_transmit(&mut self, now: Instant, buf: &mut [u8]) -> Option<usize>;

    /// When to call [`Upper::handle_timeout`] next.
    fn poll_timeout(&self) -> Option<Instant>;

    /// Moves the wakers of handles whose readiness changed into `wake`. The data plane wakes them
    /// after it has released the layer.
    fn poll_wakers(&mut self, wake: &mut Vec<Waker>);

    /// The next log line, without a timestamp.
    fn poll_log(&mut self) -> Option<String>;

    /// Closes everything and returns the budget for the next generation.
    fn close(self, now: Instant) -> Self::Budget;
}

/// What the data plane passes to the factory of the layer above, on the data plane thread.
#[derive(Debug)]
pub struct UpperInit<B> {
    /// The time of creation.
    pub now: Instant,
    /// The tunnel MTU.
    pub mtu: usize,
    /// The previous generation's budget, or `None` when the previous one ended in a panic or
    /// there was none; the layer then makes a new one.
    pub budget: Option<B>,
}

/// A failed factory of the layer above, with the budget it was given, so that the next attempt
/// keeps it.
#[derive(Debug)]
pub struct UpperError<B> {
    /// Why the layer could not be made.
    pub error: io::Error,
    /// The budget the factory took, or `None` when it had none or lost it.
    pub budget: Option<B>,
}

/// What one tunnel generation hands to the next.
#[derive(Debug)]
pub struct Carry<B> {
    /// [`Device::unix_high_water`] of the previous generations, or the persisted floor. The next
    /// device stamps its handshake initiations later than this.
    pub unix_high_water: Duration,
    /// The previous generation's budget.
    pub budget: Option<B>,
}

impl<B> Carry<B> {
    /// The carry of the first generation: the persisted floor and no budget.
    #[must_use]
    pub fn first(unix_floor: Duration) -> Self {
        Self {
            unix_high_water: unix_floor,
            budget: None,
        }
    }
}

/// How the data plane runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// The local address of the WireGuard UDP socket.
    pub listen: SocketAddr,
    /// The most packets taken from the layer above in one wake-up.
    pub max_packets_per_wake: usize,
    /// The most datagrams read from the socket in one wake-up.
    pub max_datagrams_per_wake: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([0, 0, 0, 0], 0)),
            max_packets_per_wake: 64,
            max_datagrams_per_wake: 64,
        }
    }
}

/// The state of the data plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// The peer, the server for the agent. Its times are on the data plane's [`clock`].
    pub peer: Option<PeerStatus>,
    /// Drops in the device.
    pub drops: Drops,
    /// What the device holds.
    pub held: Held,
    /// The local address of the UDP socket.
    pub local: SocketAddr,
    /// Datagrams the socket refused to send, other than for a full buffer.
    pub send_errors: u64,
    /// Receive errors the data plane counted and skipped.
    pub receive_errors: u64,
    /// The socket's buffers, measured when it was opened.
    pub socket_buffers: SocketBuffers,
    /// The device's [`Device::unix_high_water`].
    pub unix_high_water: Duration,
}

struct Inner<U> {
    device: Device,
    upper: U,
}

/// データプレーンのスレッドの上の、device の層と上の層。
struct Shared<U> {
    inner: RefCell<Inner<U>>,
    poisoned: Cell<bool>,
    /// 出力を生みうる操作の後に鳴らし、駆動の task を起こす。
    wake: Wake,
}

/// 駆動の task を起こす知らせ。同じスレッドの中だけで使うので、錠を持たない。待つ者がいない間の知らせは
/// 印として残り、次の待ちがすぐに解ける。
#[derive(Default)]
pub(crate) struct Wake {
    woken: Cell<bool>,
    waker: Cell<Option<Waker>>,
}

impl Wake {
    /// 駆動の task を起こす。
    pub(crate) fn wake(&self) {
        self.woken.set(true);
        if let Some(w) = self.waker.take() {
            w.wake();
        }
    }

    /// 前の待ちの後に [`Wake::wake`] が呼ばれていれば解ける。待つのは駆動の task 1 つだけである。
    pub(crate) async fn woken(&self) {
        std::future::poll_fn(|cx| {
            if self.woken.replace(false) {
                return std::task::Poll::Ready(());
            }
            let w = self.waker.take();
            match w {
                Some(w) if w.will_wake(cx.waker()) => self.waker.set(Some(w)),
                _ => self.waker.set(Some(cx.waker().clone())),
            }
            std::task::Poll::Pending
        })
        .await;
    }
}

impl<U> Shared<U> {
    /// 借用する。借用の中で巻き戻しが起きたら毒の印を付けて駆動の task を起こす。
    fn borrow(&self) -> Borrow<'_, U> {
        Borrow {
            inner: self.inner.borrow_mut(),
            shared: self,
            panicking: std::thread::panicking(),
        }
    }
}

struct Borrow<'a, U> {
    inner: RefMut<'a, Inner<U>>,
    shared: &'a Shared<U>,
    /// 借用の前から巻き戻しの途中だったか。巻き戻しで落ちる handle の `Drop` が借用するときは、
    /// 核の中の panic ではないので印を付けない。
    panicking: bool,
}

impl<U> Deref for Borrow<'_, U> {
    type Target = Inner<U>;
    fn deref(&self) -> &Inner<U> {
        &self.inner
    }
}

impl<U> DerefMut for Borrow<'_, U> {
    fn deref_mut(&mut self) -> &mut Inner<U> {
        &mut self.inner
    }
}

impl<U> Drop for Borrow<'_, U> {
    fn drop(&mut self) {
        if !self.panicking && std::thread::panicking() {
            self.shared.poisoned.set(true);
            self.shared.wake.wake();
        }
    }
}

/// Access to the layer above from the data plane thread, for the handle layer and the relay tasks
/// that run there as local tasks.
pub struct Local<U>(Rc<Shared<U>>);

impl<U> Clone for Local<U> {
    fn clone(&self) -> Self {
        Self(Rc::clone(&self.0))
    }
}

impl<U> fmt::Debug for Local<U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Local")
            .field("poisoned", &self.0.poisoned.get())
            .finish_non_exhaustive()
    }
}

impl<U> Local<U> {
    /// Calls `f` with the layer above, for an operation that cannot produce output, such as a
    /// read of its state. A panic inside `f` ends the generation.
    ///
    /// # Panics
    ///
    /// Panics when called from inside another `with` or `operate`, which hold the same borrow.
    pub fn with<R>(&self, f: impl FnOnce(&mut U) -> R) -> R {
        let mut guard = self.0.borrow();
        f(&mut guard.upper)
    }

    /// Calls `f` with the layer above for an operation that may produce output, such as a write,
    /// a close or a read that opens the window, and then wakes the driver to send it.
    ///
    /// # Panics
    ///
    /// As for [`Local::with`].
    pub fn operate<R>(&self, f: impl FnOnce(&mut U) -> R) -> R {
        let r = self.with(f);
        self.0.wake.wake();
        r
    }

    /// Whether a panic inside the layer above has ended this generation.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.0.poisoned.get()
    }
}

type Job<U> = Box<dyn FnOnce(&Local<U>) + Send>;

enum Command<U> {
    Status(oneshot::Sender<Status>),
    SetEndpoint(SocketAddr),
    Run(Job<U>),
    Stop,
}

/// スレッドが返すもの。
struct Exit<B> {
    unix_high_water: Duration,
    budget: Option<B>,
}

/// A failed start, with the carry to keep for the next attempt.
#[derive(Debug)]
pub struct StartError<B> {
    /// Why it failed.
    pub error: io::Error,
    /// The carry that was passed in, or a carry without a budget when the layer above had taken
    /// it before the failure.
    pub carry: Carry<B>,
}

/// A running data plane generation. Dropping it stops the thread without waiting for it.
pub struct Dataplane<U: Upper> {
    commands: mpsc::Sender<Command<U>>,
    events: Option<mpsc::Receiver<Event>>,
    thread: Option<std::thread::JoinHandle<Exit<U::Budget>>>,
    high_water: Arc<AtomicU64>,
    local: SocketAddr,
    socket_buffers: SocketBuffers,
}

impl<U: Upper> fmt::Debug for Dataplane<U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dataplane")
            .field("local", &self.local)
            .field("finished", &self.commands.is_closed())
            .finish_non_exhaustive()
    }
}

fn stopped() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "the data plane has stopped")
}

fn duration_to_nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

impl<U: Upper> Dataplane<U> {
    /// Makes the device, opens the UDP socket at `settings.listen`, logs the socket buffer warning
    /// when the buffers fall short, and starts the data plane thread. `make` builds the layer
    /// above on that thread.
    ///
    /// The device must have exactly one peer: the data plane asks it about the session with that
    /// peer before taking packets from the layer above.
    ///
    /// # Errors
    ///
    /// Fails when the configuration is refused, the socket cannot be opened or the thread cannot
    /// start; the error carries the carry back.
    pub async fn start<F>(
        config: DeviceConfig,
        settings: Settings,
        carry: Carry<U::Budget>,
        make: F,
    ) -> Result<Self, StartError<U::Budget>>
    where
        F: FnOnce(UpperInit<U::Budget>) -> Result<U, UpperError<U::Budget>> + Send + 'static,
    {
        let fail = |error: io::Error, carry| StartError { error, carry };
        if config.peers.len() != 1 {
            return Err(fail(
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the data plane needs exactly one WireGuard peer",
                ),
                carry,
            ));
        }
        let device = match Device::new(config, clock::now(), carry.unix_high_water) {
            Ok(d) => d,
            Err(e) => {
                return Err(fail(
                    io::Error::new(io::ErrorKind::InvalidInput, e.to_string()),
                    carry,
                ));
            }
        };
        let (socket, buffers) = match socket::open(settings.listen) {
            Ok(s) => s,
            Err(e) => {
                let error = io::Error::new(
                    e.kind(),
                    format!("open the WireGuard UDP socket on {}: {e}", settings.listen),
                );
                return Err(fail(error, carry));
            }
        };
        socket::warn(&buffers);
        let local = match socket.local_addr() {
            Ok(a) => a,
            Err(e) => return Err(fail(e, carry)),
        };
        let floor = carry.unix_high_water;
        let high_water = Arc::new(AtomicU64::new(duration_to_nanos(device.unix_high_water())));
        let (commands, command_rx) = mpsc::channel(16);
        let (event_tx, events) = mpsc::channel(256);
        let (ready_tx, ready) = oneshot::channel();
        let thread_high_water = Arc::clone(&high_water);
        let buffers_for_thread = buffers.clone();
        let budget = carry.budget;
        let spawned = std::thread::Builder::new()
            .name("wgft-dataplane".to_owned())
            .spawn(move || {
                run_thread(
                    device,
                    socket,
                    buffers_for_thread,
                    settings,
                    budget,
                    make,
                    command_rx,
                    event_tx,
                    thread_high_water,
                    ready_tx,
                )
            });
        let thread = match spawned {
            Ok(t) => t,
            Err(e) => {
                // 閉包と一緒に予算も落ちた
                return Err(fail(e, Carry::first(floor)));
            }
        };
        match ready.await {
            Ok(Ok(())) => Ok(Self {
                commands,
                events: Some(events),
                thread: Some(thread),
                high_water,
                local,
                socket_buffers: buffers,
            }),
            Ok(Err((error, budget))) => {
                let _ = join(thread).await;
                Err(StartError {
                    error,
                    carry: Carry {
                        unix_high_water: floor,
                        budget,
                    },
                })
            }
            Err(_) => {
                let _ = join(thread).await;
                Err(fail(
                    io::Error::other("the data plane thread ended while starting"),
                    Carry::first(floor),
                ))
            }
        }
    }

    /// The local address of the UDP socket.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// The socket's buffers, measured when it was opened.
    #[must_use]
    pub fn socket_buffers(&self) -> &SocketBuffers {
        &self.socket_buffers
    }

    /// The device's latest [`Device::unix_high_water`], kept up to date after every wake-up.
    #[must_use]
    pub fn unix_high_water(&self) -> Duration {
        Duration::from_nanos(self.high_water.load(Ordering::Relaxed))
    }

    /// A handle for the control plane's tasks: status, endpoint changes and jobs on the data plane
    /// thread. It does not keep the thread alive.
    #[must_use]
    pub fn handle(&self) -> Handle<U> {
        Handle {
            commands: self.commands.clone(),
        }
    }

    /// The current status.
    ///
    /// # Errors
    ///
    /// Fails when the thread has ended.
    pub async fn status(&self) -> io::Result<Status> {
        status(&self.commands).await
    }

    /// Points the peer at a new endpoint.
    ///
    /// # Errors
    ///
    /// Fails when the thread has ended.
    pub async fn set_endpoint(&self, endpoint: SocketAddr) -> io::Result<()> {
        set_endpoint(&self.commands, endpoint).await
    }

    /// Runs `f` on the data plane thread, between two wake-ups of the driver, and returns its
    /// result. `f` may spawn local tasks with `tokio::task::spawn_local`. A panic in `f` ends the
    /// generation.
    ///
    /// # Errors
    ///
    /// Fails when the thread has ended or ends before `f` returns.
    pub async fn call<R, F>(&self, f: F) -> io::Result<R>
    where
        R: Send + 'static,
        F: FnOnce(&Local<U>) -> R + Send + 'static,
    {
        call(&self.commands, f).await
    }

    /// Takes the device's event stream. Events that do not fit its buffer are dropped. Returns
    /// `None` after the first call.
    pub fn take_events(&mut self) -> Option<mpsc::Receiver<Event>> {
        self.events.take()
    }

    /// Resolves when the thread has ended or is ending, for any reason: [`Dataplane::stop`], a
    /// panic in the layer above, or a fatal socket error.
    pub async fn finished(&self) {
        self.commands.closed().await;
    }

    /// Whether the thread has ended or is ending.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.commands.is_closed()
    }

    /// Stops the runtime, joins the thread, closes the layer above and returns what the next
    /// generation needs. After a panic in the layer above, the carry has no budget.
    pub async fn stop(mut self) -> Carry<U::Budget> {
        let _ = self.commands.send(Command::Stop).await;
        let last = self.unix_high_water();
        let exit = match self.thread.take() {
            Some(t) => join(t).await,
            None => None,
        };
        match exit {
            Some(exit) => Carry {
                unix_high_water: exit.unix_high_water.max(last),
                budget: exit.budget,
            },
            None => Carry::first(last.max(Duration::from_nanos(
                self.high_water.load(Ordering::Relaxed),
            ))),
        }
    }
}

/// A handle on a running data plane generation, for the control plane's tasks. Cloning it is
/// cheap; it fails every call once the generation's thread has ended.
pub struct Handle<U: Upper> {
    commands: mpsc::Sender<Command<U>>,
}

impl<U: Upper> Clone for Handle<U> {
    fn clone(&self) -> Self {
        Self {
            commands: self.commands.clone(),
        }
    }
}

impl<U: Upper> fmt::Debug for Handle<U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handle")
            .field("finished", &self.commands.is_closed())
            .finish_non_exhaustive()
    }
}

impl<U: Upper> Handle<U> {
    /// As [`Dataplane::status`].
    ///
    /// # Errors
    ///
    /// Fails when the thread has ended.
    pub async fn status(&self) -> io::Result<Status> {
        status(&self.commands).await
    }

    /// As [`Dataplane::set_endpoint`].
    ///
    /// # Errors
    ///
    /// Fails when the thread has ended.
    pub async fn set_endpoint(&self, endpoint: SocketAddr) -> io::Result<()> {
        set_endpoint(&self.commands, endpoint).await
    }

    /// As [`Dataplane::call`].
    ///
    /// # Errors
    ///
    /// Fails when the thread has ended or ends before `f` returns.
    pub async fn call<R, F>(&self, f: F) -> io::Result<R>
    where
        R: Send + 'static,
        F: FnOnce(&Local<U>) -> R + Send + 'static,
    {
        call(&self.commands, f).await
    }

    /// Resolves when the generation's thread has ended or is ending, for any reason.
    pub async fn finished(&self) {
        self.commands.closed().await;
    }

    /// Whether the generation's thread has ended or is ending.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.commands.is_closed()
    }
}

async fn status<U: Upper>(commands: &mpsc::Sender<Command<U>>) -> io::Result<Status> {
    let (tx, rx) = oneshot::channel();
    commands
        .send(Command::Status(tx))
        .await
        .map_err(|_| stopped())?;
    rx.await.map_err(|_| stopped())
}

async fn set_endpoint<U: Upper>(
    commands: &mpsc::Sender<Command<U>>,
    endpoint: SocketAddr,
) -> io::Result<()> {
    commands
        .send(Command::SetEndpoint(endpoint))
        .await
        .map_err(|_| stopped())
}

async fn call<U, R, F>(commands: &mpsc::Sender<Command<U>>, f: F) -> io::Result<R>
where
    U: Upper,
    R: Send + 'static,
    F: FnOnce(&Local<U>) -> R + Send + 'static,
{
    let (tx, rx) = oneshot::channel();
    let job: Job<U> = Box::new(move |local| {
        let _ = tx.send(f(local));
    });
    commands
        .send(Command::Run(job))
        .await
        .map_err(|_| stopped())?;
    rx.await.map_err(|_| stopped())
}

/// スレッドを join する。panic で終わったスレッドは 1 行を出して `None` を返す。
async fn join<B: Send + 'static>(thread: std::thread::JoinHandle<Exit<B>>) -> Option<Exit<B>> {
    let exit = tokio::task::spawn_blocking(move || thread.join().ok())
        .await
        .ok()
        .flatten();
    if exit.is_none() {
        crate::logf!(
            "tunnel: the data plane thread ended with a panic; the next tunnel starts with a new memory budget"
        );
    }
    exit
}

type Ready<B> = oneshot::Sender<Result<(), (io::Error, Option<B>)>>;

#[expect(
    clippy::too_many_arguments,
    reason = "everything the thread takes over from the caller"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "the thread owns what it is given"
)]
fn run_thread<U, F>(
    device: Device,
    socket: std::net::UdpSocket,
    buffers: SocketBuffers,
    settings: Settings,
    budget: Option<U::Budget>,
    make: F,
    commands: mpsc::Receiver<Command<U>>,
    events: mpsc::Sender<Event>,
    high_water: Arc<AtomicU64>,
    ready: Ready<U::Budget>,
) -> Exit<U::Budget>
where
    U: Upper,
    F: FnOnce(UpperInit<U::Budget>) -> Result<U, UpperError<U::Budget>>,
{
    let unix_high_water = device.unix_high_water();
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let error = io::Error::new(e.kind(), format!("start the data plane runtime: {e}"));
            let _ = ready.send(Err((error, budget)));
            return Exit {
                unix_high_water,
                budget: None,
            };
        }
    };
    let socket = {
        let _guard = runtime.enter();
        tokio::net::UdpSocket::from_std(socket)
    };
    let socket = match socket {
        Ok(s) => s,
        Err(e) => {
            let _ = ready.send(Err((e, budget)));
            return Exit {
                unix_high_water,
                budget: None,
            };
        }
    };
    let mtu = device.mtu();
    let upper = match make(UpperInit {
        now: clock::now(),
        mtu,
        budget,
    }) {
        Ok(u) => u,
        Err(UpperError { error, budget }) => {
            let _ = ready.send(Err((error, budget)));
            return Exit {
                unix_high_water,
                budget: None,
            };
        }
    };
    let shared = Rc::new(Shared {
        inner: RefCell::new(Inner { device, upper }),
        poisoned: Cell::new(false),
        wake: Wake::default(),
    });
    let _ = ready.send(Ok(()));
    let tasks = tokio::task::LocalSet::new();
    let ended = tasks.block_on(
        &runtime,
        driver::drive(
            Local(Rc::clone(&shared)),
            socket,
            commands,
            events,
            &high_water,
            settings,
            buffers,
        ),
    );
    let rest = match ended {
        Ok(rest) => Some(rest),
        Err(e) => {
            crate::logf!("tunnel: the data plane stopped: {e}");
            None
        }
    };
    // local の task を実行環境の中で落とす。task が持つ handle の `Drop` は上の層を借用し、中継の接続を
    // 切る RST を核に積みうる。止める命令で終わったときは、それを 1 回だけ送り出す
    {
        let _guard = runtime.enter();
        drop(tasks);
        if let Some(rest) = rest
            && !shared.poisoned.get()
        {
            rest.flush(&Local(Rc::clone(&shared)));
        }
    }
    drop(runtime);
    let unix_high_water = shared.inner.borrow().device.unix_high_water();
    high_water.fetch_max(duration_to_nanos(unix_high_water), Ordering::Relaxed);
    let budget = match Rc::try_unwrap(shared) {
        Ok(s) if !s.poisoned.get() => {
            let Inner { upper, .. } = s.inner.into_inner();
            Some(upper.close(clock::now()))
        }
        _ => None,
    };
    Exit {
        unix_high_water,
        budget,
    }
}

/// The data plane generations of one tunnel. It holds the [`Carry`] between generations, also
/// while a rebuild waits for its retry.
pub struct Generations<U: Upper> {
    current: Option<Dataplane<U>>,
    carry: Option<Carry<U::Budget>>,
}

impl<U: Upper> fmt::Debug for Generations<U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Generations")
            .field("current", &self.current)
            .field(
                "unix_high_water",
                &self.carry.as_ref().map(|c| c.unix_high_water),
            )
            .finish_non_exhaustive()
    }
}

impl<U: Upper> Generations<U> {
    /// No generation yet; the first device stamps its initiations later than `unix_floor`.
    #[must_use]
    pub fn new(unix_floor: Duration) -> Self {
        Self {
            current: None,
            carry: Some(Carry::first(unix_floor)),
        }
    }

    /// Stops the current generation, if any, and starts the next one with the carry.
    ///
    /// # Errors
    ///
    /// As for [`Dataplane::start`]; the carry stays for the next attempt.
    pub async fn start<F>(
        &mut self,
        config: DeviceConfig,
        settings: Settings,
        make: F,
    ) -> io::Result<()>
    where
        F: FnOnce(UpperInit<U::Budget>) -> Result<U, UpperError<U::Budget>> + Send + 'static,
    {
        self.stop().await;
        let carry = self
            .carry
            .take()
            .unwrap_or_else(|| Carry::first(Duration::ZERO));
        match Dataplane::start(config, settings, carry, make).await {
            Ok(d) => {
                self.current = Some(d);
                Ok(())
            }
            Err(e) => {
                self.carry = Some(e.carry);
                Err(e.error)
            }
        }
    }

    /// Raises the floor of the next device's handshake stamps to at least `unix_floor`, such as
    /// the high water mark persisted in the data directory.
    pub fn raise_floor(&mut self, unix_floor: Duration) {
        let carry = self
            .carry
            .get_or_insert_with(|| Carry::first(Duration::ZERO));
        carry.unix_high_water = carry.unix_high_water.max(unix_floor);
    }

    /// Stops the current generation and keeps its carry.
    pub async fn stop(&mut self) {
        if let Some(d) = self.current.take() {
            let next = d.stop().await;
            let floor = self
                .carry
                .as_ref()
                .map_or(Duration::ZERO, |c| c.unix_high_water);
            self.carry = Some(Carry {
                unix_high_water: next.unix_high_water.max(floor),
                budget: next.budget,
            });
        }
    }

    /// The running generation.
    #[must_use]
    pub fn current(&self) -> Option<&Dataplane<U>> {
        self.current.as_ref()
    }

    /// The running generation, for taking its events.
    pub fn current_mut(&mut self) -> Option<&mut Dataplane<U>> {
        self.current.as_mut()
    }

    /// The Unix time stamped on handshake initiations so far: the running device's, or the carry's.
    #[must_use]
    pub fn unix_high_water(&self) -> Duration {
        let carried = self
            .carry
            .as_ref()
            .map_or(Duration::ZERO, |c| c.unix_high_water);
        self.current
            .as_ref()
            .map_or(carried, |d| d.unix_high_water().max(carried))
    }

    /// Whether the carry holds a budget for the next generation.
    #[must_use]
    pub fn has_budget(&self) -> bool {
        self.carry.as_ref().is_some_and(|c| c.budget.is_some())
    }

    /// Resolves when the running generation's thread ends for any reason; never without one. The
    /// caller then rebuilds the tunnel with [`Generations::start`].
    pub async fn exited(&self) {
        match &self.current {
            Some(d) => d.finished().await,
            None => std::future::pending().await,
        }
    }
}
