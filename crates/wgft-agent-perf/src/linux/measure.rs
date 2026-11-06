//! The two measuring loops. In both, the agent end sends and the server end receives; `send` mode
//! measures the agent, `recv` mode the server end. A second thread plays the other end and hands
//! off to the measured thread over a channel once per burst.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use libc::{POLLIN, POLLOUT};

use super::cpu::{Cpu, pin, wait};
use super::error::Error;
use super::link::{Link, Syscalls};

const SETUP_LIMIT: Duration = Duration::from_secs(5);
const HAND_OFF_LIMIT: Duration = Duration::from_secs(5);

pub(super) struct Plan {
    pub(super) packet: Vec<u8>,
    /// The packet the server end sends back once per burst in `answer` mode.
    pub(super) reply: Vec<u8>,
    pub(super) burst: usize,
    pub(super) bursts: u64,
    pub(super) cpu_peer: Option<usize>,
}

pub(super) struct Measured {
    pub(super) cpu: Cpu,
    pub(super) calls: Syscalls,
}

/// Waits for the second thread, then returns the measured thread's result before the second
/// thread's, so that the first failure is the one reported.
fn finish(
    peer: thread::JoinHandle<Result<(), Error>>,
    result: Result<Measured, Error>,
) -> Result<Measured, Error> {
    let joined = peer
        .join()
        .map_err(|_| Error::failed("the second thread panicked"))?;
    let measured = result?;
    joined?;
    Ok(measured)
}

/// Fails the run when the device layer dropped anything.
fn no_drops(link: &Link) -> Result<(), Error> {
    let drops = link.device.drops().total();
    if drops == 0 {
        Ok(())
    } else {
        Err(Error::failed(format!(
            "the device layer dropped {drops} packets"
        )))
    }
}

pub(super) fn measure_send(mut agent: Link, server: Link, plan: &Plan) -> Result<Measured, Error> {
    let stop = Arc::new(AtomicBool::new(false));
    let (delivered_tx, delivered_rx) = mpsc::channel::<u64>();
    let cpu_peer = plan.cpu_peer;
    let stop_peer = Arc::clone(&stop);
    let peer = thread::Builder::new().name("peer".into()).spawn(move || {
        pin(cpu_peer).map_err(|e| Error::context("cannot pin the second thread", &e))?;
        let mut server = server;
        let mut calls = Syscalls::default();
        while !stop_peer.load(Ordering::Relaxed) {
            if !wait(&server.socket, POLLIN, 20)? {
                continue;
            }
            let now = Instant::now();
            server.receive_all(now, &mut calls)?;
            server.send_pending(&mut calls)?;
            if delivered_tx.send(server.delivered).is_err() {
                break;
            }
        }
        Ok::<(), Error>(())
    })?;
    let result = (|| {
        let mut calls = Syscalls::default();
        // 握手を済ませる。最初の packet が server に届くまで両側を回す
        let mut seen = 0;
        agent.encrypt(Instant::now(), &plan.packet);
        agent.send_pending(&mut calls)?;
        let deadline = Instant::now() + SETUP_LIMIT;
        while seen < 1 {
            if Instant::now() > deadline {
                return Err(Error::failed("the handshake did not complete"));
            }
            if wait(&agent.socket, POLLIN, 5)? {
                agent.receive_all(Instant::now(), &mut calls)?;
            }
            agent.tick(Instant::now());
            agent.send_pending(&mut calls)?;
            while let Ok(n) = delivered_rx.try_recv() {
                seen = n;
            }
        }
        let mut calls = Syscalls::default();
        let mut target = seen;
        let mut cpu = Cpu::ZERO;
        for _ in 0..plan.bursts {
            let start = Cpu::now();
            let now = Instant::now();
            wait(&agent.socket, POLLOUT, 0)?;
            calls.wake += 1;
            agent.tick(now);
            for _ in 0..plan.burst {
                agent.encrypt(now, &plan.packet);
                if agent.send_each() {
                    agent.send_pending(&mut calls)?;
                }
            }
            agent.send_pending(&mut calls)?;
            agent.end_wake();
            cpu = cpu.plus(Cpu::now().since(start));
            target += plan.burst as u64;
            while seen < target {
                seen = delivered_rx.recv_timeout(HAND_OFF_LIMIT).map_err(|_| {
                    Error::failed("datagrams were lost on the way to the second thread")
                })?;
            }
        }
        no_drops(&agent)?;
        Ok(Measured { cpu, calls })
    })();
    stop.store(true, Ordering::Relaxed);
    drop(delivered_rx);
    finish(peer, result)
}

enum Command {
    Burst(usize),
}

/// `recv` mode, and with `answer` the `answer` mode: each measured wake-up also sends one reply.
pub(super) fn measure_recv(
    mut server: Link,
    agent: Link,
    plan: &Plan,
    answer: bool,
) -> Result<Measured, Error> {
    let (command_tx, command_rx) = mpsc::channel::<Command>();
    let (sent_tx, sent_rx) = mpsc::channel::<()>();
    let cpu_peer = plan.cpu_peer;
    let packet = plan.packet.clone();
    let peer = thread::Builder::new()
        .name("peer".into())
        .spawn(move || sender_thread(agent, &packet, cpu_peer, &command_rx, &sent_tx))?;
    let result = (|| {
        let mut calls = Syscalls::default();
        // 握手を済ませる。相手が最初の packet を送り終えるまで、server の側を回す
        let deadline = Instant::now() + SETUP_LIMIT;
        loop {
            if Instant::now() > deadline {
                return Err(Error::failed("the handshake did not complete"));
            }
            if wait(&server.socket, POLLIN, 5)? {
                server.receive_all(Instant::now(), &mut calls)?;
            }
            server.tick(Instant::now());
            server.send_pending(&mut calls)?;
            if sent_rx.try_recv().is_ok() {
                break;
            }
        }
        server.receive_all(Instant::now(), &mut calls)?;
        if server.delivered != 1 {
            return Err(Error::failed(format!(
                "expected the first packet, delivered {}",
                server.delivered
            )));
        }
        let mut calls = Syscalls::default();
        let mut cpu = Cpu::ZERO;
        for _ in 0..plan.bursts {
            command_tx
                .send(Command::Burst(plan.burst))
                .map_err(|_| Error::failed("the second thread stopped"))?;
            sent_rx
                .recv_timeout(HAND_OFF_LIMIT)
                .map_err(|_| Error::failed("the second thread did not finish a burst"))?;
            // バッファに溜まった burst を読む区間だけを数える。待ちの間は CPU を使わない
            let start = Cpu::now();
            let now = Instant::now();
            wait(&server.socket, POLLIN, 0)?;
            calls.wake += 1;
            let read = server.receive_all(now, &mut calls)?;
            server.tick(now);
            if answer {
                // 受けたのと同じ起床で答える。core が接続ごとに起床ごと 1 つ返す ACK に当たる
                server.encrypt(now, &plan.reply);
                server.send_pending(&mut calls)?;
            }
            server.end_wake();
            cpu = cpu.plus(Cpu::now().since(start));
            if read != plan.burst as u64 {
                return Err(Error::failed(format!(
                    "a burst delivered {read} of {} datagrams",
                    plan.burst
                )));
            }
        }
        no_drops(&server)?;
        Ok(Measured { cpu, calls })
    })();
    drop(command_tx);
    finish(peer, result)
}

/// The second thread of `recv` mode: the agent that encrypts a burst when told to.
fn sender_thread(
    mut agent: Link,
    packet: &[u8],
    cpu: Option<usize>,
    commands: &Receiver<Command>,
    sent: &Sender<()>,
) -> Result<(), Error> {
    pin(cpu).map_err(|e| Error::context("cannot pin the second thread", &e))?;
    let mut calls = Syscalls::default();
    agent.encrypt(Instant::now(), packet);
    agent.send_pending(&mut calls)?;
    let deadline = Instant::now() + SETUP_LIMIT;
    while !agent
        .device
        .has_session(&agent.server_key(), Instant::now())
    {
        if Instant::now() > deadline {
            return Err(Error::failed("the handshake did not complete"));
        }
        if wait(&agent.socket, POLLIN, 5)? {
            agent.receive_all(Instant::now(), &mut calls)?;
        }
        agent.tick(Instant::now());
        agent.send_pending(&mut calls)?;
    }
    agent.send_pending(&mut calls)?;
    sent.send(()).map_err(|e| Error::failed(e.to_string()))?;
    while let Ok(Command::Burst(n)) = commands.recv() {
        let now = Instant::now();
        // `answer` mode の返事を読み捨てる。読むのは測る区間の外で、無ければ何もしない
        agent.receive_all(now, &mut calls)?;
        for _ in 0..n {
            agent.encrypt(now, packet);
            if agent.send_each() {
                agent.send_pending(&mut calls)?;
            }
        }
        agent.send_pending(&mut calls)?;
        if sent.send(()).is_err() {
            break;
        }
    }
    Ok(())
}
