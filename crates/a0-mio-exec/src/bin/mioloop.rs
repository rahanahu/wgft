//! 問い 3:mio の上の小さな loop の形。UDP のソケット 1 つと TCP の stream 1 本を edge-triggered で登録し、
//! タイマーのヒープを `Poll::poll` の timeout にし、別スレッドの命令を mio の `Waker` で受け、run queue に
//! 上限を置き、task の poll ごとに catch_unwind で隔て、止める時に task の持ち物を落としてから送り出す。

use std::cell::{Cell, RefCell};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use a0_mio_exec::{Async, Exec, JoinError, sleep, sleep_until, spawn, timeout_at, yield_now};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CAP: usize = 32;
const BURSTS: usize = 50;
const PER_BURST: usize = 100;
const TCP_BYTES: usize = 4 << 20;
const COMMANDS: u32 = 1000;

enum Command {
    Ping(#[allow(dead_code)] u32),
    Stop,
}

/// task の持ち物の代わり。落ちると「RST」を送り出しの箱に積む (中継の handle の Drop に当たる)。
struct Conn {
    id: usize,
    outbox: Rc<RefCell<Vec<String>>>,
    dropped: Rc<Cell<usize>>,
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.dropped.set(self.dropped.get() + 1);
        self.outbox.borrow_mut().push(format!("RST {}", self.id));
    }
}

fn tcp_echo_server() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let mut buf = vec![0u8; 65536];
        loop {
            match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => s.write_all(&buf[..n]).unwrap(),
            }
        }
    });
    addr
}

#[allow(clippy::too_many_lines)]
fn main() {
    std::panic::set_hook(Box::new(|info| {
        eprintln!(
            "    (panic caught by the executor: {})",
            info.payload().downcast_ref::<&str>().unwrap_or(&"?")
        );
    }));
    let mut exec = Exec::new(CAP).unwrap();
    let udp = Rc::new(
        Async::new(mio::net::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap()).unwrap(),
    );
    let udp_addr = udp.get_ref().local_addr().unwrap();

    // 相手の UDP:datagram を束で送り、最後に送り出し (RST) を受ける
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let peer_tx = peer.try_clone().unwrap();
    let sender = std::thread::spawn(move || {
        for b in 0..BURSTS {
            for i in 0..PER_BURST {
                peer_tx
                    .send_to(
                        &u32::try_from(b * PER_BURST + i).unwrap().to_be_bytes(),
                        udp_addr,
                    )
                    .unwrap();
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        // 終わりの印。受け手がこれを読めば、起こしは失われていない (失った datagram はカーネルの捨て)
        std::thread::sleep(Duration::from_millis(20));
        peer_tx.send_to(b"END", udp_addr).unwrap();
    });

    // 制御プレーンの代わり:別スレッドから tokio の mpsc で命令を送る
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<Command>(16);
    let control = std::thread::spawn(move || {
        for i in 0..COMMANDS {
            cmd_tx.blocking_send(Command::Ping(i)).unwrap();
            if i % 50 == 0 {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        // 他の検査が終わるのを待ってから止める
        std::thread::sleep(Duration::from_millis(400));
        cmd_tx.blocking_send(Command::Stop).unwrap();
    });

    let tcp_addr = tcp_echo_server();
    let outbox: Rc<RefCell<Vec<String>>> = Rc::default();
    let dropped: Rc<Cell<usize>> = Rc::default();
    let report: Rc<RefCell<Vec<String>>> = Rc::default();

    let started = Instant::now();
    let main = {
        let udp = Rc::clone(&udp);
        let outbox = Rc::clone(&outbox);
        let dropped = Rc::clone(&dropped);
        let report = Rc::clone(&report);
        async move {
            // 1. UDP:edge-triggered。印が立ったら WouldBlock まで読み切り、印を消してから待つ
            let udp_task = {
                let udp = Rc::clone(&udp);
                spawn(async move {
                    let mut buf = [0u8; 64];
                    let (mut got, mut drains, mut seen) =
                        (0usize, 0usize, vec![false; BURSTS * PER_BURST]);
                    let mut end = false;
                    while !end {
                        udp.ready(a0_mio_exec::io::READABLE).await;
                        drains += 1;
                        loop {
                            match udp.try_io(a0_mio_exec::io::READABLE, |s| s.recv_from(&mut buf)) {
                                Ok((4, _)) => {
                                    let k =
                                        u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
                                    assert!(!seen[k]);
                                    seen[k] = true;
                                    got += 1;
                                }
                                Ok((3, _)) => end = true,
                                Ok(_) => {}
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                                Err(e) => panic!("{e}"),
                            }
                        }
                    }
                    format!(
                        "udp: END marker seen; {got} of {} datagrams in {drains} readiness edges (missing ones are kernel drops)",
                        BURSTS * PER_BURST
                    )
                })
            };

            // 2. TCP:非同期の connect に期限 (dial の形)、split して 4 MiB を往復
            let tcp_task = spawn(async move {
                let s = timeout_at(
                    Instant::now() + Duration::from_secs(2),
                    Async::<mio::net::TcpStream>::connect(tcp_addr),
                )
                .await
                .expect("connect timed out")
                .unwrap();
                let (mut rd, mut wr) = tokio::io::split(s);
                let w = spawn(async move {
                    let data: Vec<u8> = (0..TCP_BYTES).map(|i| (i % 251) as u8).collect();
                    wr.write_all(&data).await.unwrap();
                    wr.shutdown().await.unwrap();
                });
                let mut back = Vec::with_capacity(TCP_BYTES);
                rd.read_to_end(&mut back).await.unwrap();
                w.await.unwrap();
                assert!(back.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8));
                format!(
                    "tcp: {} bytes echoed through AsyncRead/AsyncWrite + tokio::io::split",
                    back.len()
                )
            });

            // 3. タイマー:1000 個の期限、早く終わったものと最大の遅れ
            let timer_task = spawn(async {
                let early = Rc::new(Cell::new(0u32));
                let late = Rc::new(Cell::new(Duration::ZERO));
                let mut hs = Vec::new();
                for i in 0..1000u64 {
                    let (early, late) = (Rc::clone(&early), Rc::clone(&late));
                    hs.push(spawn(async move {
                        let at = Instant::now() + Duration::from_micros(1000 + (i * 7919) % 49_000);
                        sleep_until(at).await;
                        let now = Instant::now();
                        if now < at {
                            early.set(early.get() + 1);
                        }
                        late.set(late.get().max(now - at));
                    }));
                }
                for h in hs {
                    h.await.unwrap();
                }
                format!(
                    "timers: 1000 deadlines 1-50 ms, early {}, max late {:?}",
                    early.get(),
                    late.get()
                )
            });

            // 4. run queue の上限:500 の task が 10 回ずつ譲る間も、I/O と命令が進む
            let storm = spawn(async {
                let mut hs = Vec::new();
                for _ in 0..500 {
                    hs.push(spawn(async {
                        for _ in 0..10 {
                            yield_now().await;
                        }
                    }));
                }
                for h in hs {
                    h.await.unwrap();
                }
                "yield storm: 500 tasks x 10 yields done".to_owned()
            });

            // 5. panic の隔て:持ち物を持った task が panic し、持ち物が落ち、他は続く
            let before = dropped.get();
            let bad = spawn({
                let c = Conn {
                    id: 9000,
                    outbox: Rc::clone(&outbox),
                    dropped: Rc::clone(&dropped),
                };
                async move {
                    let _c = c;
                    sleep(Duration::from_millis(5)).await;
                    panic!("bug in one relay task");
                }
            });
            let r = bad.await;
            assert_eq!(r, Err(JoinError::Panicked));
            report.borrow_mut().push(format!(
                "panic: join -> {r:?}; its resources dropped: {}",
                dropped.get() - before
            ));
            outbox.borrow_mut().clear();

            // 6. 止める時に落ちる「中継の接続」:100 本、永遠に待つ
            for id in 0..100 {
                let c = Conn {
                    id,
                    outbox: Rc::clone(&outbox),
                    dropped: Rc::clone(&dropped),
                };
                spawn(async move {
                    let _c = c;
                    std::future::pending::<()>().await;
                });
            }

            for (name, t) in [
                ("udp", udp_task),
                ("tcp", tcp_task),
                ("timers", timer_task),
                ("storm", storm),
            ] {
                match timeout_at(Instant::now() + Duration::from_secs(5), t).await {
                    Ok(r) => report.borrow_mut().push(r.unwrap()),
                    Err(_) => report
                        .borrow_mut()
                        .push(format!("{name}: DID NOT FINISH within 5 s")),
                }
            }

            // 7. 命令:別スレッドの送り手が起こす。Stop で抜ける
            let mut pings = 0;
            let mut ticks = 0;
            let mut next = Instant::now() + Duration::from_millis(50);
            loop {
                tokio::select! {
                    c = cmd_rx.recv() => match c {
                        Some(Command::Ping(_)) => pings += 1,
                        Some(Command::Stop) | None => break,
                    },
                    () = sleep_until(next) => {
                        ticks += 1;
                        next += Duration::from_millis(50);
                    }
                }
            }
            report.borrow_mut().push(format!("commands: {pings} pings then Stop from another thread; {ticks} periodic timer ticks meanwhile"));
        }
    };
    exec.block_on(main).unwrap();
    let run_time = started.elapsed();
    let s = exec.stats();

    // 止める手順:task を落とし (持ち物の Drop が RST を積む)、その後に 1 回だけ送り出す
    let before = dropped.get();
    exec.shutdown();
    let rst = outbox.borrow_mut().split_off(0);
    for m in &rst {
        udp.get_ref().send_to(m.as_bytes(), peer_addr).unwrap();
    }
    peer.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut got_rst = 0;
    let mut b = [0u8; 64];
    while let Ok((n, _)) = peer.recv_from(&mut b) {
        if b[..n].starts_with(b"RST") {
            got_rst += 1;
        }
    }
    sender.join().unwrap();
    control.join().unwrap();

    println!("mio loop on a0-mio-exec (cap {CAP} polls per tick)");
    println!("{:-<100}", "");
    for line in report.borrow().iter() {
        println!("{line}");
    }
    println!(
        "shutdown: {} tasks dropped, {} RST queued, peer received {got_rst} after the flush",
        dropped.get() - before,
        rst.len()
    );
    println!("live tasks after shutdown: {}", exec.live_tasks());
    println!("run {run_time:.1?}; {s:?}");
}
