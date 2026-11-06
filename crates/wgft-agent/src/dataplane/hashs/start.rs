//! Hash S の世代の始めと終わり (試作)。
//!
//! front のスレッド (区画 0) と区画 1 から P - 1 のスレッドを立てる。boost の枠は前の世代の `Budget` から作る
//! 集まり ([`BoostPool`]) で分け合い、止める時に区画の `Budget` を集まりに返して 1 つの `Budget` に戻す。どれかの
//! スレッドが終わると ([`EndGuard`])、全員を起こして世代を終える。

use std::cell::{Cell, RefCell};
use std::io;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, oneshot};
use wgft_netstack::{LanHook, LanSocket, Netstack};
use wgft_wgstack::{BoostPool, Budget, Partition};
use wgft_wireguard::{Device, DeviceConfig, Event};

use super::super::batch::tx_store;
use super::super::stack::{StackSettings, make_part};
use super::super::{
    Carry, Command, Dataplane, Exit, Generations, Local, Settings, Shared, SocketBuffers,
    StartError, Wake, clock, duration_to_nanos, socket,
};
use super::Hub;
use super::front::Front;
use super::part::{PartSend, PartSocket};
use super::steer::Steer;

type Stack<T> = Netstack<LanHook<T>>;

/// 落ちる時に世代を終える。スレッドがどの理由で終わっても (panic を含む) 全員を起こす (L6)。区画が止める命令で
/// 終わった時だけは外し、front が区画の最後の送り出しに在庫を渡し続けられるようにする。
struct EndGuard(Arc<Hub>, bool);

impl Drop for EndGuard {
    fn drop(&mut self) {
        if self.1 {
            self.0.end();
        }
    }
}

fn random_seed() -> io::Result<[u8; 64]> {
    let mut seed = [0u8; 64];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut seed)
        .map_err(|_| io::Error::other("no randomness for the TCP/IP seed"))?;
    Ok(seed)
}

impl<T: LanSocket + 'static> Dataplane<Stack<T>> {
    /// Starts a Hash S generation of `parts` (2 or more) partitions: the front thread runs
    /// partition 0 and owns the device and the socket; partitions 1 to P - 1 run on their own
    /// threads (prototype).
    ///
    /// # Errors
    ///
    /// As for [`Dataplane::start`].
    pub(crate) async fn start_hashs(
        config: DeviceConfig,
        settings: Settings,
        carry: Carry<Budget>,
        stack: StackSettings,
        parts: usize,
    ) -> Result<Self, StartError<Budget>> {
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
        let floor = carry.unix_high_water;
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
        let budget = match carry.budget {
            Some(b) => b,
            None => match Budget::new() {
                Ok(b) => b,
                Err(e) => {
                    return Err(fail(
                        io::Error::other(format!("allocate the TCP/IP memory budget: {e}")),
                        Carry::first(floor),
                    ));
                }
            },
        };
        let pool = match BoostPool::new(budget) {
            Ok(p) => Arc::new(p),
            Err(budget) => {
                return Err(fail(
                    io::Error::other("share the boost slots between the partitions"),
                    Carry {
                        unix_high_water: floor,
                        budget: Some(budget),
                    },
                ));
            }
        };
        let shared_seed = match random_seed() {
            Ok(s) => s,
            Err(e) => return Err(fail(e, Carry::first(floor))),
        };
        let batching = settings.batching.running();
        let (mtu, max_datagram) = (device.mtu(), device.max_transmit_len());
        let hub = Arc::new(Hub::new(
            parts,
            1,
            batching.slots() * max_datagram,
            clock::now(),
        ));
        let mut steer = Steer::new(parts, stack.addr);
        if super::no_tcp_on_zero() {
            steer = steer.without_tcp_on_zero();
        }
        let peer = device.peers().next();
        let high_water = Arc::new(AtomicU64::new(duration_to_nanos(device.unix_high_water())));
        let (commands, command_rx) = mpsc::channel(16);
        let (event_tx, events) = mpsc::channel(256);

        // 区画 1 から P - 1
        let mut part_cmds = Vec::new();
        let mut part_threads = Vec::new();
        let mut readies = Vec::new();
        let mut started = Ok(());
        for k in 1..parts {
            let sock = match socket.try_clone() {
                Ok(s) => s,
                Err(e) => {
                    started = Err(e);
                    break;
                }
            };
            let (tx, rx) = mpsc::channel(16);
            let (ready_tx, ready) = oneshot::channel();
            let (hub, pool) = (Arc::clone(&hub), Arc::clone(&pool));
            let part = Partition {
                index: u16::try_from(k).unwrap_or(u16::MAX),
                count: u16::try_from(parts).unwrap_or(u16::MAX),
                shared_seed,
            };
            let spawned = std::thread::Builder::new()
                .name(format!("wgft-dp-part{k}"))
                .spawn(move || {
                    run_part::<T>(
                        k,
                        hub,
                        sock,
                        stack,
                        settings,
                        mtu,
                        max_datagram,
                        part,
                        pool,
                        rx,
                        ready_tx,
                    )
                });
            match spawned {
                Ok(t) => {
                    part_cmds.push(tx);
                    part_threads.push(t);
                    readies.push(ready);
                }
                Err(e) => {
                    started = Err(e);
                    break;
                }
            }
        }

        // front (区画 0)
        let (ready_tx, ready) = oneshot::channel();
        let thread_high_water = Arc::clone(&high_water);
        let buffers_for_thread = buffers.clone();
        let front_pool = Arc::clone(&pool);
        let front_hub = Arc::clone(&hub);
        let part0 = Partition {
            index: 0,
            count: u16::try_from(parts).unwrap_or(u16::MAX),
            shared_seed,
        };
        let thread = match (&started, peer) {
            (Ok(()), Some(peer)) => std::thread::Builder::new()
                .name("wgft-dataplane".to_owned())
                .spawn(move || {
                    run_front::<T>(
                        device,
                        socket,
                        buffers_for_thread,
                        settings,
                        stack,
                        part0,
                        front_pool,
                        Front::new(front_hub, steer, peer),
                        command_rx,
                        event_tx,
                        thread_high_water,
                        ready_tx,
                    )
                })
                .map_err(Some),
            (Ok(()), None) => Err(None),
            (Err(_), _) => Err(None),
        };
        let mut error = match (&thread, started) {
            (Ok(_), Ok(())) => None,
            (_, Err(e)) => Some(e),
            (Err(Some(_)), Ok(())) => Some(io::Error::other("start the data plane thread")),
            (Err(None), Ok(())) => Some(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the device has no peer",
            )),
        };
        if error.is_none() {
            if let Ok(Err(e)) | Err(e) = ready
                .await
                .map_err(|_| io::Error::other("the data plane thread ended while starting"))
            {
                error = Some(e);
            }
        }
        for r in readies {
            if error.is_some() {
                break;
            }
            match r.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => error = Some(e),
                Err(_) => error = Some(io::Error::other("a partition thread ended while starting")),
            }
        }
        let dp = Self {
            commands,
            events: Some(events),
            thread: thread.ok(),
            high_water,
            local,
            socket_buffers: buffers,
            parts: part_cmds,
            part_threads,
            rejoin: Some(Box::new(move |budgets| {
                for b in budgets.into_iter().flatten() {
                    pool.put_back(b);
                }
                Arc::try_unwrap(pool).ok().and_then(BoostPool::into_budget)
            })),
        };
        if let Some(error) = error {
            hub.end();
            let carry = dp.stop().await;
            return Err(StartError {
                error,
                carry: Carry {
                    unix_high_water: carry.unix_high_water.max(floor),
                    budget: carry.budget,
                },
            });
        }
        crate::logf!(
            "tunnel: the data plane runs {parts} partitions (Hash S prototype){}",
            if super::no_tcp_on_zero() && parts >= 3 {
                "; no TCP on partition 0"
            } else {
                ""
            }
        );
        Ok(dp)
    }
}

/// 複製したソケットを、書けることだけを待つ形で今の実行環境の reactor に登録する。
///
/// tokio 1.54 は I/O の安全の理由で `with_interest` を非推奨にし、unsafe の `register_with_interest` を勧める。
/// データプレーンの unsafe は `wgft-udp-batch` の `sys.rs` だけに置く規則なので、試作は非推奨の安全な口を使う。
/// 包む値は fd を持ち続ける `std::net::UdpSocket` で、`as_raw_fd` は同じ fd を返し続ける (非推奨の理由に
/// 当たらない)。
#[expect(
    deprecated,
    reason = "the safe registration; the data plane keeps unsafe in sys.rs only"
)]
fn writable_only(sock: std::net::UdpSocket) -> io::Result<AsyncFd<std::net::UdpSocket>> {
    AsyncFd::with_interest(sock, Interest::WRITABLE)
}

impl<T: LanSocket + 'static> Generations<Stack<T>> {
    /// Stops the current generation, if any, and starts a Hash S generation of `parts`
    /// partitions with the carry (prototype).
    ///
    /// # Errors
    ///
    /// As for [`Generations::start`].
    pub(crate) async fn start_hashs(
        &mut self,
        config: DeviceConfig,
        settings: Settings,
        stack: StackSettings,
        parts: usize,
    ) -> io::Result<()> {
        self.stop().await;
        let carry = self
            .carry
            .take()
            .unwrap_or_else(|| Carry::first(Duration::ZERO));
        match Dataplane::start_hashs(config, settings, carry, stack, parts).await {
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
}

type Ready = oneshot::Sender<io::Result<()>>;

/// 区画 `k` のスレッド。核と中継を動かし、終わる時に区画の `Budget` を返す。
#[expect(
    clippy::too_many_arguments,
    reason = "everything the thread takes over"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "the thread owns what it is given"
)]
fn run_part<T: LanSocket + 'static>(
    k: usize,
    hub: Arc<Hub>,
    sock: std::net::UdpSocket,
    stack: StackSettings,
    settings: Settings,
    mtu: usize,
    max_datagram: usize,
    part: Partition,
    pool: Arc<BoostPool>,
    commands: mpsc::Receiver<Command<Stack<T>>>,
    ready: Ready,
) -> Option<Budget> {
    let mut end = EndGuard(Arc::clone(&hub), true);
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = ready.send(Err(e));
            return None;
        }
    };
    let afd = {
        let _guard = runtime.enter();
        sock.set_nonblocking(true)
            .and_then(|()| writable_only(sock))
    };
    let afd = match afd {
        Ok(a) => a,
        Err(e) => {
            let _ = ready.send(Err(e));
            return None;
        }
    };
    let upper = match make_part::<T>(stack, clock::now(), mtu, part, &pool) {
        Ok(u) => u,
        Err(e) => {
            let _ = ready.send(Err(e));
            return None;
        }
    };
    drop(pool);
    let shared = Rc::new(Shared {
        inner: RefCell::new(upper),
        poisoned: Cell::new(false),
        wake: Wake::default(),
    });
    let batching = settings.batching.running();
    let tx = tx_store(batching, mtu, max_datagram);
    let gso = {
        use std::os::fd::AsRawFd;
        tx.slots() > 1 && wgft_udp_batch::sys::has_gso(afd.get_ref().as_raw_fd())
    };
    let mut send = PartSend::new(k, Arc::clone(&hub), tx, gso);
    let mut sink = PartSocket(afd);
    let _ = ready.send(Ok(()));
    let tasks = tokio::task::LocalSet::new();
    let ended = tasks.block_on(
        &runtime,
        super::part::drive(Local(Rc::clone(&shared)), &mut send, &mut sink, commands),
    );
    let clean = match ended {
        Ok(()) => !hub.is_ending(),
        Err(e) => {
            crate::logf!("tunnel: data plane partition {k} stopped: {e}");
            false
        }
    };
    if !clean {
        hub.end();
    }
    // 中継の task を実行環境の中で落とす。task が持つ handle の `Drop` は中継の接続を切る RST を核に積む。止める
    // 命令で終わった時は、front に在庫を求めてそれを送り出す (front は区画が止まるまで止まらない)
    {
        let _guard = runtime.enter();
        drop(tasks);
    }
    if clean && !shared.poisoned.get() {
        runtime.block_on(super::part::final_flush(
            &Local(Rc::clone(&shared)),
            &mut send,
            &mut sink,
        ));
    }
    end.1 = !clean;
    drop(runtime);
    drop(send);
    match Rc::try_unwrap(shared) {
        Ok(s) if !s.poisoned.get() => {
            let upper = s.inner.into_inner();
            Some(super::super::Upper::close(upper, clock::now()))
        }
        _ => None,
    }
}

/// front のスレッド。区画 0 の核と device と外側のソケットを持つ。
#[expect(
    clippy::too_many_arguments,
    reason = "everything the thread takes over"
)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "the thread owns what it is given"
)]
fn run_front<T: LanSocket + 'static>(
    device: Device,
    socket: std::net::UdpSocket,
    buffers: SocketBuffers,
    settings: Settings,
    stack: StackSettings,
    part: Partition,
    pool: Arc<BoostPool>,
    mut front: Front,
    commands: mpsc::Receiver<Command<Stack<T>>>,
    events: mpsc::Sender<Event>,
    high_water: Arc<AtomicU64>,
    ready: Ready,
) -> Exit<Budget> {
    let hub = Arc::clone(&front.hub);
    let _end = EndGuard(Arc::clone(&hub), true);
    let mut device = device;
    let unix_high_water = device.unix_high_water();
    let ready_cell = Cell::new(Some(ready));
    let ready_send = |r: io::Result<()>| {
        if let Some(t) = ready_cell.take() {
            let _ = t.send(r);
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            ready_send(Err(e));
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
            ready_send(Err(e));
            return Exit {
                unix_high_water,
                budget: None,
            };
        }
    };
    let upper = match make_part::<T>(stack, clock::now(), device.mtu(), part, &pool) {
        Ok(u) => u,
        Err(e) => {
            ready_send(Err(e));
            return Exit {
                unix_high_water,
                budget: None,
            };
        }
    };
    drop(pool);
    let shared = Rc::new(Shared {
        inner: RefCell::new(upper),
        poisoned: Cell::new(false),
        wake: Wake::default(),
    });
    ready_send(Ok(()));
    let tasks = tokio::task::LocalSet::new();
    let ended = tasks.block_on(
        &runtime,
        super::front::drive(
            Local(Rc::clone(&shared)),
            &mut device,
            &mut front,
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
    hub.end();
    {
        let _guard = runtime.enter();
        drop(tasks);
        if let Some(rest) = rest
            && !shared.poisoned.get()
        {
            rest.flush(&Local(Rc::clone(&shared)), &mut device);
        }
    }
    drop(runtime);
    crate::logf!("tunnel: {}", hub.counts.line());
    let unix_high_water = device.unix_high_water();
    high_water.fetch_max(
        duration_to_nanos(unix_high_water),
        std::sync::atomic::Ordering::Relaxed,
    );
    let budget = match Rc::try_unwrap(shared) {
        Ok(s) if !s.poisoned.get() => {
            let upper = s.inner.into_inner();
            Some(super::super::Upper::close(upper, clock::now()))
        }
        _ => None,
    };
    Exit {
        unix_high_water,
        budget,
    }
}
