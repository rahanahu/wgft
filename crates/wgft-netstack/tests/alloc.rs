//! handle の層が packet ごとにヒープを伸ばさないことの試験。
//!
//! 実行環境を使わず、何もしない waker で handle を手で poll し、packet を手で運びます。同じ往復を繰り返し、
//! 慣らしの後の生きている byte が往復ごとに変わらないことを確かめます。数えはプロセスで 1 つなので、この
//! 試験は自分の試験のバイナリに 1 つだけ置きます。

#[expect(dead_code, reason = "this binary uses only the hand-driven helpers")]
mod common;

use std::net::SocketAddrV4;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use common::{A, B, End, TcpPeer, netstack};
use wgft_alloc_count::{CountingAlloc, live_bytes};
use wgft_netstack::{Access, TcpListener, UdpSocket};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

fn sa(ip: std::net::Ipv4Addr, port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(ip, port)
}

/// 2 つの端の間で、運ぶものが無くなるまで packet を運びます。
fn shuttle(x: &impl End, y: &impl End, buf: &mut [u8], wakers: &mut Vec<Waker>) {
    let now = common::clock();
    loop {
        let mut moved = false;
        while let Some(n) = x.pull(now, buf) {
            moved = true;
            y.push(now, &buf[..n]);
        }
        while let Some(n) = y.pull(now, buf) {
            moved = true;
            x.push(now, &buf[..n]);
        }
        if !moved {
            break;
        }
    }
    x.wakers(wakers);
    y.wakers(wakers);
    wakers.clear();
}

#[test]
fn the_handles_do_not_grow_the_heap_per_packet() {
    let near = netstack(A);
    let far = netstack(B);
    let mut cx = Context::from_waker(Waker::noop());
    let mut buf = vec![0u8; 65536];
    let mut wakers = Vec::with_capacity(64);

    let mut l = TcpListener::bind(&near, sa(A, 80)).unwrap();
    let peer = TcpPeer::connect(sa(B, 40000), sa(A, 80));
    shuttle(&near, &peer, &mut buf, &mut wakers);
    let Poll::Ready(Ok((mut s, _))) = l.poll_accept(&mut cx) else {
        panic!("no connection to accept");
    };
    let mut ua = UdpSocket::bind(&near, sa(A, 53)).unwrap();
    let ub = UdpSocket::bind(&far, sa(B, 5353)).unwrap();
    let msg = common::pattern(1000, 5);
    let mut rbuf = vec![0u8; 4096];

    let mut round = |cx: &mut Context<'_>| {
        // TCP:書いて相手に届け、相手の中身を読みます。
        let Poll::Ready(Ok(n)) = s.poll_write_bytes(cx, &msg) else {
            panic!("the write did not complete");
        };
        assert_eq!(n, msg.len());
        shuttle(&near, &peer, &mut buf, &mut wakers);
        peer.state.borrow_mut().received.clear();
        peer.send(&msg);
        shuttle(&near, &peer, &mut buf, &mut wakers);
        let Poll::Ready(Ok(n)) = s.poll_read_bytes(cx, &mut rbuf) else {
            panic!("the read did not complete");
        };
        assert_eq!(n, msg.len());
        shuttle(&near, &peer, &mut buf, &mut wakers);
        // UDP:b から a に送り、a で受けます。
        let sent = pin!(ub.send_to(&msg, sa(A, 53))).poll(cx);
        assert!(matches!(sent, Poll::Ready(Ok(_))));
        shuttle(&near, &far, &mut buf, &mut wakers);
        let Poll::Ready(Ok((n, _))) = ua.poll_recv_from(cx, &mut rbuf) else {
            panic!("no datagram");
        };
        assert_eq!(n, msg.len());
        // 待ちを 1 つ登録して落とします。
        assert!(ua.poll_recv_from(cx, &mut rbuf).is_pending());
        assert!(s.poll_read_bytes(cx, &mut rbuf).is_pending());
    };

    for _ in 0..200 {
        round(&mut cx);
    }
    let base = live_bytes();
    for i in 0..2000 {
        round(&mut cx);
        assert_eq!(live_bytes(), base, "round {i} changed the live bytes");
    }
    near.with(|n| n.core().check_invariants()).unwrap();
}
