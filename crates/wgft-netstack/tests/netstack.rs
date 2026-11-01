//! handle の層の試験:代わりの駆動で核を動かし、handle の待ちと知らせ、future を落とした後の一貫、2 つの核を
//! 向かい合わせた UDP と ping、台本の相手との TCP を確かめます。

mod common;

use std::cell::RefCell;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddrV4;
use std::rc::Rc;
use std::task::Poll;
use std::time::Duration;

use common::{A, B, Peers, TcpPeer, drive, netstack, netstack_with, no_drops, pattern};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::{LocalSet, spawn_local};
use tokio::time::{sleep, timeout};
use wgft_netstack::{
    Access, LanHook, LanSocket, LanSockets, LocalNetstack, Ping, TcpListener, UdpSocket,
};
use wgft_wgstack::{BoostPolicy, Hook, NoHook};

const SHORT: Duration = Duration::from_millis(50);

fn sa(ip: std::net::Ipv4Addr, port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(ip, port)
}

fn check(ns: &LocalNetstack<impl Hook>) {
    ns.with(|n| n.core().check_invariants()).unwrap();
}

/// `cond` が真になるまで時計を進めて待ちます。
async fn until(mut cond: impl FnMut() -> bool) {
    for _ in 0..10_000 {
        if cond() {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!("the condition did not hold");
}

/// 試験の本体を自分の local の task として動かします。`run_until` の中で直に poll すると、ほかの task が
/// 起きるたびに本体も poll され、失った知らせが隠れるためです。止めた時計は全ての task が待つと進むので、
/// 知らせを失って止まった試験は、実時間を待たずに時計の上の期限で失敗します。
async fn run(f: impl Future<Output = ()> + 'static) {
    LocalSet::new()
        .run_until(async {
            timeout(Duration::from_secs(600), spawn_local(f))
                .await
                .expect("the test did not finish: a wake-up was lost or a wait never ended")
                .unwrap();
        })
        .await;
}

#[tokio::test(start_paused = true)]
async fn tcp_echo_through_the_handles() {
    run(async {
        let ns = netstack(A);
        let mut l = TcpListener::bind(&ns, sa(A, 80)).unwrap();
        let peer = TcpPeer::connect(sa(B, 40000), sa(A, 80));
        spawn_local(drive(ns.clone(), peer.clone(), no_drops));
        let request = pattern(200_000, 1);
        let server = spawn_local(async move {
            let (mut s, from) = l.accept().await.unwrap();
            assert_eq!(from, sa(B, 40000));
            assert_eq!(s.peer_addr(), Some(sa(B, 40000)));
            assert_eq!(s.local_addr(), Some(sa(A, 80)));
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
        check(&ns);
    })
    .await;
}

/// 記録する LAN 側のソケットです。
#[derive(Clone, Default)]
struct Recorder(Rc<RefCell<Vec<&'static str>>>, bool);

impl LanSocket for Recorder {
    fn boost_granted(&mut self) {
        self.0.borrow_mut().push("granted");
    }

    fn may_return(&mut self) -> bool {
        self.0.borrow_mut().push("asked");
        self.1
    }

    fn boost_returned(&mut self) {
        self.0.borrow_mut().push("returned");
    }
}

#[tokio::test(start_paused = true)]
async fn a_large_write_gets_a_boost_and_the_hook_sees_it() {
    run(async {
        let sockets = LanSockets::<Recorder>::new(common::limits().conns());
        let ns = netstack_with(A, LanHook::new(Rc::clone(&sockets)));
        let mut l = TcpListener::bind(&ns, sa(A, 80)).unwrap();
        let peer = TcpPeer::connect(sa(B, 40000), sa(A, 80));
        spawn_local(drive(ns.clone(), peer.clone(), no_drops));
        let (mut s, _) = l.accept().await.unwrap();
        let lan = Recorder::default();
        let registration = sockets.register(s.id(), lan.clone());
        // 需要で boost を得るので、送信のバッファは floor (256 KiB) を超えて広がります。
        let data = pattern(1 << 20, 7);
        s.write_all(&data).await.unwrap();
        let closing = s.close();
        until(|| peer.state.borrow().fin_received).await;
        assert_eq!(peer.state.borrow().received.len(), data.len());
        assert_eq!(peer.state.borrow().received, data);
        until(|| closing.delivered()).await;
        assert_eq!(lan.0.borrow().first(), Some(&"granted"));
        drop(registration);
        check(&ns);
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn the_hook_reaches_only_the_registered_connection() {
    run(async {
        let sockets = LanSockets::<Recorder>::new(common::limits().conns());
        let ns = netstack_with(A, LanHook::new(Rc::clone(&sockets)));
        let mut l = TcpListener::bind(&ns, sa(A, 80)).unwrap();
        let peers = Peers::default();
        peers.connect(sa(B, 40001), sa(A, 80));
        peers.connect(sa(B, 40002), sa(A, 80));
        spawn_local(drive(ns.clone(), peers.clone(), no_drops));
        let (s1, _) = l.accept().await.unwrap();
        let (s2, _) = l.accept().await.unwrap();
        let held = Recorder(Rc::default(), false);
        let reg = sockets.register(s1.id(), held.clone());
        let mut hook = LanHook::new(Rc::clone(&sockets));
        hook.boost_granted(s1.id());
        assert!(!hook.may_return(s1.id()), "the LAN socket keeps the boost");
        hook.boost_returned(s1.id());
        assert!(hook.may_return(s2.id()), "no LAN socket, no objection");
        assert_eq!(*held.0.borrow(), ["granted", "asked", "returned"]);
        assert!(reg.into_socket().is_some());
        assert!(hook.may_return(s1.id()));
        assert_eq!(held.0.borrow().len(), 3);
        // 閉じた接続の枠を別の接続が使い直しても、古い登録はその接続に届きません。
        // どちらの枠を次の接続が使っても古い組が残るよう、閉じる 2 つの接続の両方に登録します。
        let old = s1.id();
        let stale = sockets.register(old, held.clone());
        let stale2 = sockets.register(s2.id(), held.clone());
        s1.abort();
        drop(s2);
        peers.connect(sa(B, 40003), sa(A, 80));
        let (s3, _) = l.accept().await.unwrap();
        if s3.id().index() == old.index() {
            assert_ne!(s3.id(), old);
        }
        hook.boost_granted(s3.id());
        assert_eq!(held.0.borrow().len(), 3);
        drop(stale);
        drop(stale2);
        check(&ns);
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn udp_between_two_cores() {
    run(async {
        let a = netstack(A);
        let b = netstack(B);
        spawn_local(drive(a.clone(), b.clone(), no_drops));
        let mut ua = UdpSocket::bind(&a, sa(A, 53)).unwrap();
        let mut ub = UdpSocket::bind(&b, sa(B, 5353)).unwrap();
        assert_eq!(ua.local_addr(), sa(A, 53));
        let mut buf = vec![0u8; 65536];
        ub.send_to(b"hello", sa(A, 53)).await.unwrap();
        let (n, from) = ua.recv_from(&mut buf).await.unwrap();
        assert_eq!((&buf[..n], from), (&b"hello"[..], sa(B, 5353)));
        // MTU を超える datagram は断片で運ばれ、相手の核が組み立てます。
        let big = pattern(3000, 3);
        ua.sender().send_to(&big, from).await.unwrap();
        let (n, from) = ub.recv_from(&mut buf).await.unwrap();
        assert_eq!(from, sa(A, 53));
        assert_eq!(buf[..n], big[..]);
        check(&a);
        check(&b);
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn udp_senders_wait_for_the_budget() {
    const PER_TASK: usize = 2000;
    const TASKS: usize = 3;
    run(async {
        let a = netstack(A);
        let b = netstack(B);
        let mut ua = UdpSocket::bind(&a, sa(A, 53)).unwrap();
        let ub = UdpSocket::bind(&b, sa(B, 5353)).unwrap();
        let mut tasks = Vec::new();
        for t in 0..TASKS {
            let tx = ub.sender();
            tasks.push(spawn_local(async move {
                for i in 0..PER_TASK {
                    let mut msg = pattern(1200, 0);
                    msg[..8].copy_from_slice(&((t * PER_TASK + i) as u64).to_be_bytes());
                    tx.send_to(&msg, sa(A, 53)).await.unwrap();
                }
            }));
        }
        // 駆動を後から始めるので、送り手はまず endpoint の送信の予算を使い切って待ちます。
        tokio::task::yield_now().await;
        assert!(tasks.iter().all(|t| !t.is_finished()));
        spawn_local(drive(a.clone(), b.clone(), no_drops));
        // UDP は流れを制御しないので、受け手が遅れた分は受信の予算で捨てられます。届いた数と捨てた数の和が
        // 送った数になり、同じ datagram が 2 度届かないことを確かめます。
        let mut seen = vec![false; TASKS * PER_TASK];
        let mut got = 0;
        let mut buf = vec![0u8; 2048];
        while let Ok(r) = timeout(Duration::from_secs(1), ua.recv_from(&mut buf)).await {
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
        assert!(got > 0);
        check(&a);
        check(&b);
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn ping_between_two_cores() {
    run(async {
        let a = netstack(A);
        let b = netstack(B);
        spawn_local(drive(a.clone(), b.clone(), no_drops));
        let mut p = Ping::open(&a, B).unwrap();
        let mut msg = vec![8, 0, 0, 0, 0, 0, 0, 1];
        msg.extend_from_slice(b"keepalive");
        p.send(&msg).unwrap();
        let mut buf = [0u8; 64];
        let n = p.recv(&mut buf).await.unwrap();
        assert_eq!(buf[0], 0, "an echo reply");
        assert_eq!(&buf[8..n], b"keepalive");
        assert_eq!(
            p.send(&[1, 2, 3]).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        drop(p);
        check(&a);
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn a_dropped_accept_or_read_loses_nothing() {
    run(async {
        let ns = netstack(A);
        let mut l = TcpListener::bind(&ns, sa(A, 80)).unwrap();
        assert!(timeout(SHORT, l.accept()).await.is_err());
        let peer = TcpPeer::connect(sa(B, 40000), sa(A, 80));
        spawn_local(drive(ns.clone(), peer.clone(), no_drops));
        let (mut s, _) = l.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        assert!(timeout(SHORT, s.read(&mut buf)).await.is_err());
        check(&ns);
        peer.send(b"after the dropped read");
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"after the dropped read");
        peer.finish();
        assert_eq!(s.read(&mut buf).await.unwrap(), 0);
        check(&ns);
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn a_dropped_write_writes_nothing() {
    run(async {
        // boost を与えない核にして、送信のバッファを floor の大きさに保ちます。
        let ns = common::netstack_config(A, |c| c.boost = BoostPolicy::Never);
        let mut l = TcpListener::bind(&ns, sa(A, 80)).unwrap();
        let peer = TcpPeer::connect(sa(B, 40000), sa(A, 80));
        spawn_local(drive(ns.clone(), peer.clone(), no_drops));
        let (mut s, _) = l.accept().await.unwrap();
        // 相手が窓を閉じると送信のバッファが満ち、書き込みは待ちます。待つ書き込みを何度も落とします。
        peer.state.borrow_mut().window = 0;
        peer.send(b"x");
        let data = pattern(600_000, 9);
        let mut off = 0;
        let mut dropped = 0;
        while off < data.len() {
            if let Ok(n) = timeout(SHORT, s.write(&data[off..])).await {
                off += n.unwrap();
            } else {
                dropped += 1;
                check(&ns);
                if dropped == 3 {
                    peer.state.borrow_mut().window = 65535;
                    peer.send(b"y");
                }
            }
        }
        assert!(dropped >= 3);
        s.close_write().unwrap();
        until(|| peer.state.borrow().fin_received).await;
        assert_eq!(peer.state.borrow().received, data);
        check(&ns);
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn dropped_udp_futures_lose_and_duplicate_nothing() {
    run(async {
        let a = netstack(A);
        let b = netstack(B);
        let mut ua = UdpSocket::bind(&a, sa(A, 53)).unwrap();
        let ub = UdpSocket::bind(&b, sa(B, 5353)).unwrap();
        let mut buf = [0u8; 64];
        assert!(timeout(SHORT, ua.recv_from(&mut buf)).await.is_err());
        // 駆動の無い間は送った datagram が核に残り、endpoint の送信の予算が尽きると送りは待ちます。
        let mut sent = 0u32;
        while let Ok(r) = timeout(SHORT, ub.send_to(&sent.to_be_bytes(), sa(A, 53))).await {
            r.unwrap();
            sent += 1;
        }
        assert!(sent > 0);
        check(&b);
        spawn_local(drive(a.clone(), b.clone(), no_drops));
        ub.send_to(&sent.to_be_bytes(), sa(A, 53)).await.unwrap();
        for want in 0..=sent {
            let (n, _) = ua.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], &want.to_be_bytes());
        }
        assert!(timeout(SHORT, ua.recv_from(&mut buf)).await.is_err());
        check(&a);
        check(&b);
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn closing_an_endpoint_fails_its_waiting_senders() {
    run(async {
        let b = netstack(B);
        let ub = UdpSocket::bind(&b, sa(B, 5353)).unwrap();
        let tx = ub.sender();
        let waiting = spawn_local(async move {
            loop {
                if let Err(e) = tx.send_to(b"z", sa(A, 53)).await {
                    return e;
                }
            }
        });
        sleep(SHORT).await;
        assert!(!waiting.is_finished(), "the sender waits for the budget");
        drop(ub);
        let e = waiting.await.unwrap();
        assert_eq!(e.kind(), io::ErrorKind::NotConnected);
        check(&b);
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn dropping_handles_resets_and_frees() {
    run(async {
        let ns = netstack(A);
        let mut l = TcpListener::bind(&ns, sa(A, 80)).unwrap();
        let peers = Peers::default();
        let p1 = peers.connect(sa(B, 40001), sa(A, 80));
        spawn_local(drive(ns.clone(), peers.clone(), no_drops));
        let (s, _) = l.accept().await.unwrap();
        drop(s);
        until(|| p1.state.borrow().rst_received).await;
        // accept していない接続は、待ち受けを閉じると RST を受けます。
        let p2 = peers.connect(sa(B, 40002), sa(A, 80));
        until(|| p2.state.borrow().established).await;
        drop(l);
        until(|| p2.state.borrow().rst_received).await;
        let l = TcpListener::bind(&ns, sa(A, 80)).unwrap();
        assert_eq!(l.local_addr(), sa(A, 80));
        let u = UdpSocket::bind(&ns, sa(A, 80)).unwrap();
        drop(u);
        UdpSocket::bind(&ns, sa(A, 80)).unwrap();
        let e = TcpListener::bind(&ns, sa(A, 80)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AddrInUse);
        let e = TcpListener::bind(&ns, sa(B, 81)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AddrNotAvailable);
        let inner = e
            .get_ref()
            .and_then(|e| e.downcast_ref::<wgft_wgstack::Error>());
        assert_eq!(inner, Some(&wgft_wgstack::Error::AddrNotLocal));
        check(&ns);
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn a_panic_inside_the_core_poisons_the_handles() {
    run(async {
        let ns = netstack(A);
        let l = TcpListener::bind(&ns, sa(A, 80)).unwrap();
        let mut u = UdpSocket::bind(&ns, sa(A, 53)).unwrap();
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ns.with(|_| panic!("a bug in the core"));
        }));
        assert!(caught.is_err());
        assert!(ns.is_poisoned());
        let mut buf = [0u8; 8];
        assert!(u.recv_from(&mut buf).await.is_err());
        assert!(TcpListener::bind(&ns, sa(A, 81)).is_err());
        // 落とす handle は壊れたかもしれない核に触りません。待ち受けと endpoint は核の中で開いたままです。
        drop(l);
        drop(u);
        let mut inner = ns.into_inner().unwrap();
        let now = inner.now();
        let core = inner.core_mut();
        assert_eq!(
            core.listen_tcp(now, sa(A, 80)),
            Err(wgft_wgstack::Error::AddrInUse)
        );
        assert_eq!(
            core.bind_udp(now, sa(A, 53)).map(|u| u.port()),
            Err(wgft_wgstack::Error::AddrInUse)
        );
    })
    .await;
}

#[test]
fn the_netstack_closes_with_nothing_held() {
    let ns = netstack(A);
    let l = TcpListener::bind(&ns, sa(A, 80)).unwrap();
    assert!(ns.clone().into_inner().is_err(), "a handle holds it");
    drop(l);
    let ns = ns.into_inner().unwrap();
    assert!(
        ns.waker_bytes()
            <= wgft_netstack::Netstack::<NoHook>::waker_bound(common::limits().conns())
    );
    let closed = ns.close(common::clock());
    assert_eq!(closed.held, wgft_wgstack::Held::default());
}

#[tokio::test(start_paused = true)]
async fn aborting_a_closed_connection_leaves_the_next_user_of_its_slot_alone() {
    run(async {
        let ns = netstack(A);
        let mut l = TcpListener::bind(&ns, sa(A, 80)).unwrap();
        let peers = Peers::default();
        let p1 = peers.connect(sa(B, 40001), sa(A, 80));
        spawn_local(drive(ns.clone(), peers.clone(), no_drops));
        let (s1, _) = l.accept().await.unwrap();
        let closing = s1.close();
        until(|| p1.state.borrow().fin_received).await;
        p1.finish();
        until(|| closing.delivered()).await;
        // 閉じた接続の枠は返り、次の接続が使います。
        let p2 = peers.connect(sa(B, 40002), sa(A, 80));
        let (mut s2, _) = l.accept().await.unwrap();
        let mut buf = [0u8; 64];
        let reader = spawn_local(async move {
            let n = s2.read(&mut buf).await.unwrap();
            buf[..n].to_vec()
        });
        sleep(SHORT).await;
        closing.abort();
        p2.send(b"still woken");
        assert_eq!(reader.await.unwrap(), b"still woken");
        check(&ns);
    })
    .await;
}

/// 時計を進めずに他の task に順を譲ります。駆動が操作の知らせで起きれば、その間に出力を運び終えます。
async fn settle() {
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn operations_wake_the_driver_without_waiting_for_a_timer() {
    run(async {
        let ns = netstack(A);
        let mut l = TcpListener::bind(&ns, sa(A, 80)).unwrap();
        let peers = Peers::default();
        let peer = peers.connect(sa(B, 40000), sa(A, 80));
        spawn_local(drive(ns.clone(), peers.clone(), no_drops));
        let (mut s, _) = l.accept().await.unwrap();
        settle().await;
        let start = tokio::time::Instant::now();
        s.write(b"now").await.unwrap();
        settle().await;
        assert_eq!(peer.state.borrow().received, b"now");
        s.close_write().unwrap();
        settle().await;
        assert!(peer.state.borrow().fin_received);

        let a = netstack(A);
        let b = netstack(B);
        spawn_local(drive(a.clone(), b.clone(), no_drops));
        let ua = UdpSocket::bind(&a, sa(A, 53)).unwrap();
        let mut ub = UdpSocket::bind(&b, sa(B, 53)).unwrap();
        let mut ping = Ping::open(&a, B).unwrap();
        settle().await;
        ua.send_to(b"datagram", sa(B, 53)).await.unwrap();
        settle().await;
        let mut buf = [0u8; 16];
        let got = poll_fn(|cx| Poll::Ready(ub.poll_recv_from(cx, &mut buf))).await;
        assert!(matches!(got, Poll::Ready(Ok((8, _)))));
        ping.send(&[8, 0, 0, 0, 0, 0, 0, 1]).unwrap();
        settle().await;
        let got = poll_fn(|cx| Poll::Ready(ping.poll_recv(cx, &mut buf))).await;
        assert!(matches!(got, Poll::Ready(Ok(8))));
        assert_eq!(tokio::time::Instant::now(), start, "no time passed");
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn a_write_waits_for_room_and_is_woken() {
    run(async {
        // boost を与えない核では送信のバッファが floor のままなので、1 MiB の書き込みは空きを待ちます。
        let ns = common::netstack_config(A, |c| c.boost = BoostPolicy::Never);
        let mut l = TcpListener::bind(&ns, sa(A, 80)).unwrap();
        let peer = TcpPeer::connect(sa(B, 40000), sa(A, 80));
        spawn_local(drive(ns.clone(), peer.clone(), no_drops));
        let (mut s, _) = l.accept().await.unwrap();
        let data = pattern(1 << 20, 8);
        let sent = data.clone();
        let writer = spawn_local(async move {
            s.write_all(&sent).await.unwrap();
            s.close()
        });
        let closing = writer.await.unwrap();
        until(|| closing.delivered()).await;
        assert_eq!(peer.state.borrow().received, data);
        check(&ns);
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn dropping_a_shut_down_stream_delivers_the_tail() {
    run(async {
        let ns = netstack(A);
        let mut l = TcpListener::bind(&ns, sa(A, 80)).unwrap();
        let peers = Peers::default();
        let p1 = peers.connect(sa(B, 40001), sa(A, 80));
        let p2 = peers.connect(sa(B, 40002), sa(A, 80));
        spawn_local(drive(ns.clone(), peers.clone(), no_drops));
        let (mut s1, _) = l.accept().await.unwrap();
        let (mut s2, _) = l.accept().await.unwrap();
        // tokio の書き方の終わり方:書いて shutdown して落とします。書いた分はすべて届きます。
        let data = pattern(1 << 20, 3);
        s1.write_all(&data).await.unwrap();
        s1.shutdown().await.unwrap();
        drop(s1);
        until(|| p1.state.borrow().fin_received).await;
        assert!(!p1.state.borrow().rst_received);
        assert_eq!(p1.state.borrow().received, data);
        // 未読のデータを残して落とすと、Linux と同じく RST で終えます。
        p2.send(b"unread");
        settle().await;
        s2.shutdown().await.unwrap();
        drop(s2);
        until(|| p2.state.borrow().rst_received).await;
        check(&ns);
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn a_read_lets_the_window_update_out_without_a_timer() {
    run(async {
        let ns = common::netstack_config(A, |c| c.boost = BoostPolicy::Never);
        let mut l = TcpListener::bind(&ns, sa(A, 80)).unwrap();
        let peers = Peers::default();
        let peer = peers.connect(sa(B, 40000), sa(A, 80));
        spawn_local(drive(ns.clone(), peers.clone(), no_drops));
        let (mut s, _) = l.accept().await.unwrap();
        settle().await;
        // 受信の窓を何度も満たす量です。窓の更新は読んだ時の知らせでだけ出ます。
        let big = pattern(2 << 20, 4);
        peer.send(&big);
        settle().await;
        let start = tokio::time::Instant::now();
        let mut buf = vec![0u8; 1 << 20];
        let mut got = 0;
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        for _ in 0..200 {
            if let Poll::Ready(Ok(n)) = s.poll_read_bytes(&mut cx, &mut buf) {
                got += n;
            }
            settle().await;
            if got == big.len() {
                break;
            }
        }
        assert_eq!(got, big.len());
        assert_eq!(tokio::time::Instant::now(), start, "no time passed");
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn close_abort_and_listener_drop_wake_the_driver() {
    run(async {
        let ns = netstack(A);
        let mut l = TcpListener::bind(&ns, sa(A, 80)).unwrap();
        let peers = Peers::default();
        let p1 = peers.connect(sa(B, 40001), sa(A, 80));
        let p2 = peers.connect(sa(B, 40002), sa(A, 80));
        spawn_local(drive(ns.clone(), peers.clone(), no_drops));
        let (s1, _) = l.accept().await.unwrap();
        let (s2, _) = l.accept().await.unwrap();
        let p3 = peers.connect(sa(B, 40003), sa(A, 80));
        until(|| p3.state.borrow().established).await;
        settle().await;
        let start = tokio::time::Instant::now();
        let _closing = s1.close();
        settle().await;
        assert!(p1.state.borrow().fin_received, "the FIN of close");
        drop(s2);
        settle().await;
        assert!(p2.state.borrow().rst_received, "the RST of abort");
        drop(l);
        settle().await;
        assert!(
            p3.state.borrow().rst_received,
            "the RST of closing the listener"
        );
        assert_eq!(tokio::time::Instant::now(), start, "no time passed");
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn registering_twice_keeps_the_newer_pairing() {
    run(async {
        let ns = netstack(A);
        let sockets = LanSockets::<Recorder>::new(common::limits().conns());
        let mut l = TcpListener::bind(&ns, sa(A, 80)).unwrap();
        let peer = TcpPeer::connect(sa(B, 40000), sa(A, 80));
        spawn_local(drive(ns.clone(), peer.clone(), no_drops));
        let (s, _) = l.accept().await.unwrap();
        let first = Recorder::default();
        let second = Recorder::default();
        let old = sockets.register(s.id(), first.clone());
        let new = sockets.register(s.id(), second.clone());
        drop(old);
        let mut hook = LanHook::new(Rc::clone(&sockets));
        hook.boost_granted(s.id());
        assert!(first.0.borrow().is_empty());
        assert_eq!(*second.0.borrow(), ["granted"]);
        assert!(new.into_socket().is_some());
    })
    .await;
}

/// 起きた数を数える waker です。`Arc` の数えで、表が持つ waker の数も読みます。
struct Counted(std::sync::atomic::AtomicU32);

impl std::task::Wake for Counted {
    fn wake(self: std::sync::Arc<Self>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[tokio::test(start_paused = true)]
async fn closing_handles_drops_their_wakers() {
    run(async {
        let ns = netstack(A);
        let mut l = TcpListener::bind(&ns, sa(A, 80)).unwrap();
        let peers = Peers::default();
        peers.connect(sa(B, 40001), sa(A, 80));
        peers.connect(sa(B, 40002), sa(A, 80));
        spawn_local(drive(ns.clone(), peers.clone(), no_drops));
        let (mut s1, _) = l.accept().await.unwrap();
        let (mut s2, _) = l.accept().await.unwrap();
        let w = std::sync::Arc::new(Counted(std::sync::atomic::AtomicU32::new(0)));
        let waker = std::task::Waker::from(std::sync::Arc::clone(&w));
        let mut cx = std::task::Context::from_waker(&waker);
        let mut buf = [0u8; 8];
        assert!(s1.poll_read_bytes(&mut cx, &mut buf).is_pending());
        assert!(s2.poll_read_bytes(&mut cx, &mut buf).is_pending());
        assert_eq!(std::sync::Arc::strong_count(&w), 4, "the table holds two");
        drop(s1);
        let _closing = s2.close();
        assert_eq!(std::sync::Arc::strong_count(&w), 2, "closing let them go");
    })
    .await;
}
