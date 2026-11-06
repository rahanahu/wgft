//! 微ベンチ (agent の利得ではない):同じ玩具の loop を、自前の実行器と tokio の current_thread + LocalSet
//! で回し、起こし 1 回あたり、UDP の往復 1 回あたり、タイマーの作りと取り消し 1 回あたりの時間を比べる。

use std::cell::RefCell;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::rc::Rc;
use std::task::{Poll, Waker};
use std::time::{Duration, Instant};

use a0_mio_exec::{Async, Exec, spawn};

const HANDOFFS: u32 = 2_000_000;
const ROUND_TRIPS: u32 = 100_000;
const TIMERS: u32 = 200_000;
const RUNS: usize = 5;

/// 2 つの task が順番を渡し合う。渡すたびに相手を起こす (起こし 1 回と poll 1 回)。
#[derive(Default)]
struct Baton {
    turn: u8,
    wakers: [Option<Waker>; 2],
}

async fn player(b: Rc<RefCell<Baton>>, me: u8, n: u32) {
    for _ in 0..n {
        poll_fn(|cx| {
            let mut s = b.borrow_mut();
            if s.turn == me {
                Poll::Ready(())
            } else {
                s.wakers[me as usize] = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await;
        let mut s = b.borrow_mut();
        s.turn = 1 - me;
        if let Some(w) = s.wakers[1 - me as usize].take() {
            drop(s);
            w.wake();
        }
    }
}

fn handoff_a0(isolate: bool) -> Duration {
    let mut e = Exec::with_isolation(64, isolate).unwrap();
    e.block_on(async {
        let b = Rc::new(RefCell::new(Baton::default()));
        let t = Instant::now();
        let x = spawn(player(Rc::clone(&b), 0, HANDOFFS / 2));
        let y = spawn(player(b, 1, HANDOFFS / 2));
        x.await.unwrap();
        y.await.unwrap();
        t.elapsed()
    })
    .unwrap()
}

fn tokio_local<F: Future>(f: F) -> F::Output {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    tokio::task::LocalSet::new().block_on(&rt, f)
}

fn handoff_tokio() -> Duration {
    tokio_local(async {
        let b = Rc::new(RefCell::new(Baton::default()));
        let t = Instant::now();
        let x = tokio::task::spawn_local(player(Rc::clone(&b), 0, HANDOFFS / 2));
        let y = tokio::task::spawn_local(player(b, 1, HANDOFFS / 2));
        x.await.unwrap();
        y.await.unwrap();
        t.elapsed()
    })
}

fn udp_a0() -> Duration {
    let mut e = Exec::new(64).unwrap();
    e.block_on(async {
        let a = Rc::new(
            Async::new(mio::net::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap()).unwrap(),
        );
        let b = Rc::new(
            Async::new(mio::net::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap()).unwrap(),
        );
        let (aa, ba) = (
            a.get_ref().local_addr().unwrap(),
            b.get_ref().local_addr().unwrap(),
        );
        let echo = spawn({
            let b = Rc::clone(&b);
            async move {
                let mut buf = [0u8; 64];
                for _ in 0..ROUND_TRIPS {
                    let (n, _) = b.recv_from(&mut buf).await.unwrap();
                    b.send_to(&buf[..n], aa).await.unwrap();
                }
            }
        });
        let t = Instant::now();
        let mut buf = [0u8; 64];
        for _ in 0..ROUND_TRIPS {
            a.send_to(b"ping", ba).await.unwrap();
            a.recv_from(&mut buf).await.unwrap();
        }
        echo.await.unwrap();
        t.elapsed()
    })
    .unwrap()
}

fn udp_tokio() -> Duration {
    tokio_local(async {
        let a = Rc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let b = Rc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (aa, ba) = (a.local_addr().unwrap(), b.local_addr().unwrap());
        let echo = tokio::task::spawn_local({
            let b = Rc::clone(&b);
            async move {
                let mut buf = [0u8; 64];
                for _ in 0..ROUND_TRIPS {
                    let (n, _) = b.recv_from(&mut buf).await.unwrap();
                    b.send_to(&buf[..n], aa).await.unwrap();
                }
            }
        });
        let t = Instant::now();
        let mut buf = [0u8; 64];
        for _ in 0..ROUND_TRIPS {
            a.send_to(b"ping", ba).await.unwrap();
            a.recv_from(&mut buf).await.unwrap();
        }
        echo.await.unwrap();
        t.elapsed()
    })
}

/// 中継の写しの「読みごとに 200 ms の期限を作り、すぐ捨てる」形:作る、1 回 poll して登録する、落とす。
async fn churn<S: Future<Output = ()>>(make: impl Fn() -> S) -> Duration {
    let t = Instant::now();
    for _ in 0..TIMERS {
        let mut s = pin!(make());
        poll_fn(|cx| {
            let _ = s.as_mut().poll(cx);
            Poll::Ready(())
        })
        .await;
    }
    t.elapsed()
}

fn timers_a0() -> (Duration, usize) {
    let mut e = Exec::new(64).unwrap();
    e.block_on(async {
        let d = churn(|| a0_mio_exec::sleep(Duration::from_millis(200))).await;
        (d, a0_mio_exec::timer::heap_len())
    })
    .unwrap()
}

fn timers_tokio() -> Duration {
    tokio_local(async { churn(|| tokio::time::sleep(Duration::from_millis(200))).await })
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

fn per(d: Duration, n: u32) -> f64 {
    d.as_secs_f64() * 1e9 / f64::from(n)
}

fn main() {
    let mut rows: Vec<(&str, Vec<f64>)> = vec![
        ("handoff a0 (catch_unwind)", vec![]),
        ("handoff a0 (no catch_unwind)", vec![]),
        ("handoff tokio current_thread+LocalSet", vec![]),
        ("udp round trip a0 (mio)", vec![]),
        ("udp round trip tokio", vec![]),
        ("timer create+register+drop a0", vec![]),
        ("timer create+register+drop tokio", vec![]),
    ];
    let mut heap = 0;
    for _ in 0..RUNS {
        rows[0].1.push(per(handoff_a0(true), HANDOFFS));
        rows[1].1.push(per(handoff_a0(false), HANDOFFS));
        rows[2].1.push(per(handoff_tokio(), HANDOFFS));
        rows[3].1.push(per(udp_a0(), ROUND_TRIPS));
        rows[4].1.push(per(udp_tokio(), ROUND_TRIPS));
        let (d, h) = timers_a0();
        heap = h;
        rows[5].1.push(per(d, TIMERS));
        rows[6].1.push(per(timers_tokio(), TIMERS));
    }
    println!(
        "micro benchmark, release, median of {RUNS} runs (ns per operation); not an agent gain"
    );
    for (name, v) in &rows {
        let mut s = v.clone();
        s.sort_by(f64::total_cmp);
        println!(
            "{name:<40} {:>9.1}   (min {:.1}, max {:.1})",
            median(v.clone()),
            s[0],
            s[s.len() - 1]
        );
    }
    println!("a0 timer heap entries left after the churn (lazy deletion): {heap} of {TIMERS}");
}
