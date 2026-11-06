//! 問い 1:tokio の API は、tokio の実行環境の無いスレッドで、自前の実行器と std の Waker に poll されて
//! 動くか。probe ごとに新しい実行器を作り、結果を ok、panic、hang (500 ms の期限) で出す。

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant};

use a0_mio_exec::{Exec, JoinError, spawn, timeout_at};

static LAST_PANIC: Mutex<Option<String>> = Mutex::new(None);

type Probe = fn() -> Pin<Box<dyn Future<Output = String>>>;

fn run(name: &str, probe: Probe) {
    *LAST_PANIC.lock().unwrap() = None;
    let mut exec = Exec::new(64).unwrap();
    let out = exec.block_on(async move {
        let h = spawn(probe());
        match timeout_at(
            Instant::now() + Duration::from_millis(500),
            &mut Box::pin(h),
        )
        .await
        {
            Ok(Ok(s)) => format!("ok    | {s}"),
            Ok(Err(JoinError::Panicked)) => format!(
                "PANIC | {}",
                LAST_PANIC.lock().unwrap().clone().unwrap_or_default()
            ),
            Ok(Err(JoinError::Cancelled)) => "cancelled".to_owned(),
            Err(_) => "HANG  | no result within 500 ms".to_owned(),
        }
    });
    let out = out.unwrap_or_else(|e| format!("main task failed: {e:?}"));
    println!("{name:<44} | {out}");
}

/// 1 回の poll の中で、Pending までに recv できた数を数える (coop の予算の有無を見る)。
async fn recv_in_one_poll(rx: &mut tokio::sync::mpsc::Receiver<u32>) -> usize {
    std::future::poll_fn(|cx| {
        let mut n = 0;
        loop {
            match rx.poll_recv(cx) {
                Poll::Ready(Some(_)) => n += 1,
                Poll::Ready(None) | Poll::Pending => return Poll::Ready(n),
            }
        }
    })
    .await
}

fn coop_under_tokio() -> usize {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        tokio::task::spawn_local(async {
            let (tx, mut rx) = tokio::sync::mpsc::channel(2000);
            for i in 0..1000 {
                tx.try_send(i).unwrap();
            }
            recv_in_one_poll(&mut rx).await
        })
        .await
        .unwrap()
    })
}

#[allow(clippy::too_many_lines)]
fn main() {
    std::panic::set_hook(Box::new(|info| {
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_default();
        *LAST_PANIC.lock().unwrap() = Some(msg.replace('\n', " "));
    }));
    println!("tokio API probes on a0-mio-exec (no tokio runtime on this thread)");
    println!("{:-<120}", "");

    // --- macros ---
    run("select! (unbiased, random start)", || {
        Box::pin(async {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<u32>(4);
            let (mut a, mut b) = (0, 0);
            for _ in 0..200 {
                tx.try_send(1).unwrap();
                tokio::select! {
                    v = rx.recv() => { a += v.unwrap(); }
                    () = std::future::ready(()) => { b += 1; while rx.try_recv().is_ok() {} }
                }
            }
            format!("both branches chosen: recv {a}, ready {b} of 200")
        })
    });
    run("select! biased; + try_join! + join! + pin!", || {
        Box::pin(async {
            let x = async { Ok::<_, ()>(1) };
            let y = async { Ok::<_, ()>(2) };
            let (p, q) = tokio::try_join!(x, y).unwrap();
            let (r, s) = tokio::join!(async { 3 }, async { 4 });
            let f = async { 5 };
            tokio::pin!(f);
            let t = tokio::select! { biased; v = &mut f => v, () = std::future::pending() => 0 };
            format!("sum {}", p + q + r + s + t)
        })
    });

    // --- tokio::sync ---
    run("sync::mpsc woken from another thread", || {
        Box::pin(async {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<u32>(16);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(30));
                tx.blocking_send(42).unwrap();
            });
            let t = Instant::now();
            let v = rx.recv().await.unwrap();
            format!("got {v} after {:?}", t.elapsed())
        })
    });
    run("sync::mpsc bounded send waits for room", || {
        Box::pin(async {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<u32>(1);
            tx.send(1).await.unwrap();
            let h = spawn(async move {
                tx.send(2).await.unwrap();
                "sent"
            });
            a0_mio_exec::yield_now().await;
            let first = rx.recv().await.unwrap();
            let second = rx.recv().await.unwrap();
            format!("{first},{second}, sender {}", h.await.unwrap())
        })
    });
    run("sync::oneshot from another thread", || {
        Box::pin(async {
            let (tx, rx) = tokio::sync::oneshot::channel::<&str>();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                tx.send("hi").unwrap();
            });
            rx.await.unwrap().to_owned()
        })
    });
    run("sync::watch wait_for from another thread", || {
        Box::pin(async {
            let (tx, mut rx) = tokio::sync::watch::channel(0u32);
            std::thread::spawn(move || {
                for i in 1..=3 {
                    std::thread::sleep(Duration::from_millis(10));
                    tx.send(i).unwrap();
                }
            });
            let v = *rx.wait_for(|v| *v == 3).await.unwrap();
            format!("saw {v}")
        })
    });
    run(
        "sync::Notify one (stored permit), waiters, x-thread",
        || {
            Box::pin(async {
                let n = Arc::new(tokio::sync::Notify::new());
                n.notify_one();
                n.notified().await; // 前に鳴らした知らせが残る
                let mut hs = Vec::new();
                for _ in 0..3 {
                    let n = Arc::clone(&n);
                    hs.push(spawn(async move {
                        let mut f = std::pin::pin!(n.notified());
                        f.as_mut().enable();
                        f.await;
                    }));
                }
                a0_mio_exec::yield_now().await;
                n.notify_waiters();
                for h in hs {
                    h.await.unwrap();
                }
                let n2 = Arc::clone(&n);
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(10));
                    n2.notify_one();
                });
                n.notified().await;
                "stored permit, 3 waiters, cross-thread: all woke".to_owned()
            })
        },
    );
    run("sync::Semaphore acquire waits, release wakes", || {
        Box::pin(async {
            let s = Arc::new(tokio::sync::Semaphore::new(1));
            let p = Arc::clone(&s).acquire_owned().await.unwrap();
            let s2 = Arc::clone(&s);
            let h = spawn(async move {
                let _p = s2.acquire().await.unwrap();
                "acquired"
            });
            a0_mio_exec::yield_now().await;
            let waiting = !h.is_finished();
            drop(p);
            let r = h.await.unwrap();
            s.close();
            let closed = s.acquire().await.is_err();
            format!("waited={waiting}, then {r}; closed -> err={closed}")
        })
    });

    // --- coop の予算 ---
    run("coop: mpsc recv in one poll (1000 queued)", || {
        Box::pin(async {
            let (tx, mut rx) = tokio::sync::mpsc::channel(2000);
            for i in 0..1000 {
                tx.try_send(i).unwrap();
            }
            let here = recv_in_one_poll(&mut rx).await;
            let tokio = std::thread::spawn(coop_under_tokio).join().unwrap();
            format!("a0: {here} before Pending; tokio current_thread+LocalSet: {tokio}")
        })
    });
    run("task::consume_budget x1000", || {
        Box::pin(async {
            let mut pend = 0;
            let mut f = std::pin::pin!(async {
                for _ in 0..1000 {
                    tokio::task::consume_budget().await;
                }
            });
            std::future::poll_fn(|cx| match f.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(()),
                Poll::Pending => {
                    pend += 1;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await;
            format!("returned Pending {pend} times (budget is unconstrained)")
        })
    });
    run("task::yield_now (tokio's)", || {
        Box::pin(async {
            let mut polls = 0;
            let mut f = std::pin::pin!(tokio::task::yield_now());
            std::future::poll_fn(|cx| {
                polls += 1;
                f.as_mut().poll(cx)
            })
            .await;
            format!("completed after {polls} polls (woken immediately, no defer)")
        })
    });

    // --- tokio::io ---
    run("io::duplex + AsyncReadExt/AsyncWriteExt", || {
        Box::pin(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut a, mut b) = tokio::io::duplex(64);
            let h = spawn(async move {
                a.write_all(&[7u8; 1000]).await.unwrap();
                a.shutdown().await.unwrap();
            });
            let mut v = Vec::new();
            b.read_to_end(&mut v).await.unwrap();
            h.await.unwrap();
            format!("{} bytes through a 64-byte pipe", v.len())
        })
    });

    // --- tokio::time ---
    run("time::Instant::now", || {
        Box::pin(async { format!("{:?}", tokio::time::Instant::now().elapsed()) })
    });
    run("time::sleep", || {
        Box::pin(async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            String::new()
        })
    });
    run("time::timeout around a ready future", || {
        Box::pin(async {
            let _ = tokio::time::timeout(Duration::from_secs(1), async { 1 }).await;
            String::new()
        })
    });
    run("time::interval", || {
        Box::pin(async {
            let mut i = tokio::time::interval(Duration::from_millis(10));
            i.tick().await;
            String::new()
        })
    });

    // --- tokio::net ---
    run("net::UdpSocket::from_std", || {
        Box::pin(async {
            let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            s.set_nonblocking(true).unwrap();
            match tokio::net::UdpSocket::from_std(s) {
                Ok(_) => "registered".to_owned(),
                Err(e) => format!("error: {e}"),
            }
        })
    });
    run("net::TcpSocket::new_v4 (no connect)", || {
        Box::pin(async {
            tokio::net::TcpSocket::new_v4()
                .map(|_| "created".to_owned())
                .unwrap_or_else(|e| e.to_string())
        })
    });
    run("net::TcpStream::connect", || {
        Box::pin(async {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let _ = tokio::net::TcpStream::connect(l.local_addr().unwrap()).await;
            String::new()
        })
    });

    // --- task ---
    run("tokio::spawn", || {
        Box::pin(async {
            let _ = tokio::spawn(async {});
            String::new()
        })
    });
    run("task::spawn_local", || {
        Box::pin(async {
            let _ = tokio::task::spawn_local(async {});
            String::new()
        })
    });
    run("task::JoinSet::new + spawn_local", || {
        Box::pin(async {
            let mut js = tokio::task::JoinSet::new();
            js.spawn_local(async {});
            String::new()
        })
    });
    run("task::spawn_blocking", || {
        Box::pin(async {
            let _ = tokio::task::spawn_blocking(|| {});
            String::new()
        })
    });
    run("runtime::Handle::try_current", || {
        Box::pin(async {
            format!(
                "{:?}",
                tokio::runtime::Handle::try_current()
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            )
        })
    });

    // --- 実行環境に入ったが回さない (dp のスレッドに tokio の Handle を enter した場合) ---
    run("entered-but-undriven runtime: time::sleep", || {
        Box::pin(async {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let _g = rt.enter();
            tokio::time::sleep(Duration::from_millis(10)).await;
            "fired".to_owned()
        })
    });
    run("entered-but-undriven runtime: UdpSocket recv", || {
        Box::pin(async {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let _g = rt.enter();
            let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let me = s.local_addr().unwrap();
            std::net::UdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .send_to(b"x", me)
                .unwrap();
            std::thread::sleep(Duration::from_millis(5));
            let mut b = [0u8; 8];
            let r = s.try_recv_from(&mut b).map(|x| x.0);
            println!("    (entered-but-undriven: a datagram is queued; try_recv_from -> {r:?})");
            let n = s.recv_from(&mut b).await.unwrap().0;
            format!("try_recv_from {r:?}; recv_from {n}")
        })
    });

    // --- 名前の解決の直しの形:制御プレーンの Handle で spawn し、dp は watch と自前の期限で待つ ---
    run("control-plane Handle::spawn + watch (resolver fix)", || {
        Box::pin(async {
            let (htx, hrx) = std::sync::mpsc::channel();
            let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
            let ctl = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                htx.send(rt.handle().clone()).unwrap();
                rt.block_on(async {
                    let _ = stop_rx.await;
                });
            });
            let handle: tokio::runtime::Handle = hrx.recv().unwrap();
            let sem = Arc::new(tokio::sync::Semaphore::new(1));
            let (tx, mut rx) = tokio::sync::watch::channel(None::<String>);
            // resolve.rs の join と同じ形:許可を待つ task を立て、OS のスレッドで引き、watch で配る
            handle.spawn(async move {
                let permit = sem.acquire_owned().await.unwrap();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(20));
                    let _ = tx.send(Some("10.0.0.1".to_owned()));
                    drop(permit);
                });
            });
            let got = timeout_at(
                Instant::now() + Duration::from_secs(1),
                rx.wait_for(Option::is_some),
            )
            .await
            .map(|v| v.unwrap().clone());
            let _ = stop_tx.send(());
            ctl.join().unwrap();
            format!("{got:?}")
        })
    });
}
