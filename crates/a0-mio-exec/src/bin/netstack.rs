//! 問い 2:wgft-netstack の handle の future (std の Future、waker の表) は、変えずに自前の実行器で動くか。
//!
//! 試験の道具 (wgft-netstack の tests/common) の核の作りと台本の TCP の相手をそのまま使い、駆動だけを自前の
//! タイマーで書き直す。時計は実時間。

#[allow(dead_code, unreachable_pub, clippy::all, clippy::pedantic)]
#[path = "../../../wgft-netstack/tests/common/mod.rs"]
mod common;

use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use a0_mio_exec::{Exec, JoinError, sleep, sleep_until, spawn, timeout_at, yield_now};
use common::{A, B, End, Peers, TcpPeer, clock, netstack, pattern};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wgft_netstack::{Access, Ping, TcpListener, UdpSocket};

fn sa(ip: std::net::Ipv4Addr, port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(ip, port)
}

/// tests/common の `drive` と同じ順の駆動。待ちだけを自前のタイマーにする。
async fn drive<X: End, Y: End>(x: X, y: Y) {
    let mut buf = vec![0u8; 65536];
    let mut wakers = Vec::new();
    loop {
        let now = clock();
        x.timers(now);
        y.timers(now);
        loop {
            let mut moved = false;
            while let Some(n) = x.pull(now, &mut buf) {
                moved = true;
                y.push(now, &buf[..n]);
            }
            while let Some(n) = y.pull(now, &mut buf) {
                moved = true;
                x.push(now, &buf[..n]);
            }
            if !moved {
                break;
            }
        }
        x.wakers(&mut wakers);
        y.wakers(&mut wakers);
        for w in wakers.drain(..) {
            w.wake();
        }
        let deadline = match (x.deadline(), y.deadline()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let wait = async {
            match deadline {
                Some(d) => sleep_until(d).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            () = wait => {}
            () = x.woken() => {}
            () = y.woken() => {}
        }
    }
}

async fn until(mut cond: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(
            Instant::now() < end,
            "the condition did not hold within 10 s"
        );
        sleep(Duration::from_millis(5)).await;
    }
}

fn case(name: &str, f: impl Future<Output = String> + 'static) {
    let mut exec = Exec::new(64).unwrap();
    let t = Instant::now();
    let r =
        exec.block_on(async move { timeout_at(Instant::now() + Duration::from_secs(20), f).await });
    let took = t.elapsed();
    let s = exec.stats();
    match r {
        Ok(Ok(msg)) => println!(
            "{name:<40} | ok    | {msg} | {took:.1?}, ticks {}, polls {}, os waits {}, timers {}",
            s.ticks, s.polls, s.os_waits, s.timers_fired
        ),
        Ok(Err(_)) => println!("{name:<40} | HANG  | 20 s"),
        Err(e) => println!("{name:<40} | FAIL  | {e:?}"),
    }
}

#[allow(clippy::too_many_lines)]
fn main() {
    println!("wgft-netstack handles on a0-mio-exec");
    println!("{:-<120}", "");

    case("udp between two cores (+3000 B fragmented)", async {
        let a = netstack(A);
        let b = netstack(B);
        let d = spawn(drive(a.clone(), b.clone()));
        let mut ua = UdpSocket::bind(&a, sa(A, 53)).unwrap();
        let mut ub = UdpSocket::bind(&b, sa(B, 5353)).unwrap();
        let mut buf = vec![0u8; 65536];
        ub.send_to(b"hello", sa(A, 53)).await.unwrap();
        let (n, from) = ua.recv_from(&mut buf).await.unwrap();
        assert_eq!((&buf[..n], from), (&b"hello"[..], sa(B, 5353)));
        let big = pattern(3000, 3);
        ua.sender().send_to(&big, from).await.unwrap();
        let (n, from) = ub.recv_from(&mut buf).await.unwrap();
        assert_eq!(from, sa(A, 53));
        assert_eq!(buf[..n], big[..]);
        d.abort();
        "hello and 3000 B arrived".to_owned()
    });

    case("udp senders wait for the budget (Notify)", async {
        const PER_TASK: usize = 2000;
        const TASKS: usize = 3;
        let a = netstack(A);
        let b = netstack(B);
        let mut ua = UdpSocket::bind(&a, sa(A, 53)).unwrap();
        let ub = UdpSocket::bind(&b, sa(B, 5353)).unwrap();
        let mut tasks = Vec::new();
        for t in 0..TASKS {
            let tx = ub.sender();
            tasks.push(spawn(async move {
                for i in 0..PER_TASK {
                    let mut msg = pattern(1200, 0);
                    msg[..8].copy_from_slice(&((t * PER_TASK + i) as u64).to_be_bytes());
                    tx.send_to(&msg, sa(A, 53)).await.unwrap();
                }
            }));
        }
        yield_now().await;
        let waited = tasks.iter().all(|t| !t.is_finished());
        let d = spawn(drive(a.clone(), b.clone()));
        let mut seen = vec![false; TASKS * PER_TASK];
        let mut got = 0;
        let mut buf = vec![0u8; 2048];
        while let Ok(r) = timeout_at(
            Instant::now() + Duration::from_millis(300),
            ua.recv_from(&mut buf),
        )
        .await
        {
            let (n, _) = r.unwrap();
            assert_eq!(n, 1200);
            let k = usize::try_from(u64::from_be_bytes(buf[..8].try_into().unwrap())).unwrap();
            assert!(!seen[k], "datagram {k} arrived twice");
            seen[k] = true;
            got += 1;
        }
        for t in tasks {
            t.await.unwrap();
        }
        let dropped = a.with(|n| n.core().stats().udp_dropped);
        assert_eq!(got + usize::try_from(dropped).unwrap(), TASKS * PER_TASK);
        d.abort();
        format!(
            "senders waited={waited}; received {got} + dropped {dropped} = {}",
            TASKS * PER_TASK
        )
    });

    case("ping between two cores", async {
        let a = netstack(A);
        let b = netstack(B);
        let d = spawn(drive(a.clone(), b.clone()));
        let mut p = Ping::open(&a, B).unwrap();
        let mut msg = vec![8, 0, 0, 0, 0, 0, 0, 1];
        msg.extend_from_slice(b"keepalive");
        p.send(&msg).unwrap();
        let mut buf = [0u8; 64];
        let n = p.recv(&mut buf).await.unwrap();
        assert_eq!(buf[0], 0);
        assert_eq!(&buf[8..n], b"keepalive");
        d.abort();
        "echo reply".to_owned()
    });

    case("tcp echo, AsyncRead/AsyncWrite (tokio io-util)", async {
        let ns = netstack(A);
        let mut l = TcpListener::bind(&ns, sa(A, 80)).unwrap();
        let peer = TcpPeer::connect(sa(B, 40000), sa(A, 80));
        let d = spawn(drive(ns.clone(), peer.clone()));
        let request = pattern(200_000, 1);
        let server = spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut got = Vec::new();
            s.read_to_end(&mut got).await.unwrap();
            got.reverse();
            s.write_all(&got).await.unwrap();
            s.close()
        });
        peer.send(&request);
        peer.finish();
        let closing = server.await.unwrap();
        until(|| peer.state.borrow().fin_received).await;
        let mut want = request.clone();
        want.reverse();
        assert_eq!(peer.state.borrow().received, want);
        until(|| closing.delivered()).await;
        assert!(peer.all_acked());
        ns.with(|n| n.core().check_invariants()).unwrap();
        d.abort();
        "200000 B each way, FIN delivered".to_owned()
    });

    case("abort a task holding a TcpStream -> RST", async {
        let ns = netstack(A);
        let mut l = TcpListener::bind(&ns, sa(A, 80)).unwrap();
        let peers = Peers::default();
        let p1 = peers.connect(sa(B, 40001), sa(A, 80));
        let d = spawn(drive(ns.clone(), peers.clone()));
        let (s, _) = l.accept().await.unwrap();
        let holder = spawn(async move {
            let mut s = s;
            let mut b = [0u8; 16];
            let _ = s.read(&mut b).await;
        });
        yield_now().await;
        holder.abort();
        until(|| p1.state.borrow().rst_received).await;
        let r = holder.await;
        d.abort();
        format!("peer got RST; join -> {r:?}")
    });

    case("panic in a task holding a TcpStream -> RST", async {
        let ns = netstack(A);
        let mut l = TcpListener::bind(&ns, sa(A, 80)).unwrap();
        let peers = Peers::default();
        let p1 = peers.connect(sa(B, 40002), sa(A, 80));
        let d = spawn(drive(ns.clone(), peers.clone()));
        let (s, _) = l.accept().await.unwrap();
        let holder = spawn(async move {
            let _s = s;
            yield_now().await;
            panic!("relay task bug");
        });
        let r = holder.await;
        assert_eq!(r, Err(JoinError::Panicked));
        until(|| p1.state.borrow().rst_received).await;
        // 核は毒されていない (panic は核の借用の外)
        let poisoned = ns.is_poisoned();
        ns.with(|n| n.core().check_invariants()).unwrap();
        d.abort();
        format!("join -> {r:?}; peer got RST; core poisoned={poisoned}")
    });
}
