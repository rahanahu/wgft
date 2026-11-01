//! handle の層と核が、packet ごとに何回ヒープを確保するかの試験。
//!
//! 実行環境を使わず、何もしない waker で handle を手で poll し、packet を手で運ぶ。慣らしの後の定常で、
//! 経路ごとに N 回の往復を流し、近い側の核と handle が起こした確保の呼び出しの数を数える。台本の相手と
//! 遠い側の核の確保は数えない (操作の前後でスレッドの数えを読み、近い側の操作の差だけを足す)。
//! 許容は今の測りの値で、新しい確保が増えると試験が落ちる。確保を減らしたら許容を下げる。
//!
//! 1 回の往復は、中継から見た 1 つのメッセージ (TCP は 1 segment、UDP は 1 datagram、ping は 1 echo) と、
//! それに伴い近い側が出す packet (ACK など) の処理を含む。
//!
//! 現在、近い側の核と handle は定常で確保しない。許容 0 は、どの経路でも新しい確保を許さない。

#[expect(dead_code, reason = "this binary uses only the hand-driven helpers")]
mod common;

use std::net::SocketAddrV4;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use common::{A, B, End, TcpPeer, netstack};
use wgft_alloc_count::{CountingAlloc, thread_alloc_calls};
use wgft_netstack::{Access, Ping, TcpListener, TcpStream, UdpSocket};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// 慣らしの往復の数。
const WARMUP: usize = 200;
/// 数える往復の数。
const ROUNDS: usize = 1000;

fn sa(ip: std::net::Ipv4Addr, port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(ip, port)
}

/// 近い側の操作が起こした確保の呼び出しを足し上げる。
#[derive(Default)]
struct Meter {
    calls: usize,
}

impl Meter {
    fn run<R>(&mut self, f: impl FnOnce() -> R) -> R {
        let before = thread_alloc_calls();
        let r = f();
        self.calls += thread_alloc_calls() - before;
        r
    }

    fn reset(&mut self) {
        self.calls = 0;
    }

    /// 往復あたりの許容を超えていないか確かめる。
    fn check(&self, path: &str, allowed_per_round: usize) {
        eprintln!("{path}: {} calls for {ROUNDS} rounds", self.calls);
        assert!(
            self.calls <= allowed_per_round * ROUNDS,
            "{path} allocates {} times for {ROUNDS} rounds; the allowance is {allowed_per_round} per round",
            self.calls
        );
    }
}

/// 近い側 `near` と遠い側 `far` の間で、運ぶものが無くなるまで packet を運ぶ。近い側の核の操作だけを
/// `meter` に数える。
fn shuttle(
    near: &impl End,
    far: &impl End,
    buf: &mut [u8],
    wakers: &mut Vec<Waker>,
    meter: &mut Meter,
) {
    let now = common::clock();
    loop {
        let mut moved = false;
        while let Some(n) = meter.run(|| near.pull(now, buf)) {
            moved = true;
            far.push(now, &buf[..n]);
        }
        while let Some(n) = far.pull(now, buf) {
            moved = true;
            meter.run(|| near.push(now, &buf[..n]));
        }
        if !moved {
            break;
        }
    }
    meter.run(|| near.wakers(wakers));
    far.wakers(wakers);
    wakers.clear();
}

fn tcp() -> (impl End, TcpPeer, TcpStream<impl Access>) {
    let near = netstack(A);
    let mut cx = Context::from_waker(Waker::noop());
    let mut buf = vec![0u8; 65536];
    let mut wakers = Vec::with_capacity(64);
    let mut l = TcpListener::bind(&near, sa(A, 80)).unwrap();
    let peer = TcpPeer::connect(sa(B, 40000), sa(A, 80));
    shuttle(&near, &peer, &mut buf, &mut wakers, &mut Meter::default());
    let Poll::Ready(Ok((s, _))) = l.poll_accept(&mut cx) else {
        panic!("no connection to accept");
    };
    (near, peer, s)
}

/// 数えが生きていることの確認。ここが 0 のままなら、ほかの試験の 0 は何も保証しない。
#[test]
fn the_meter_sees_an_allocation() {
    let mut m = Meter::default();
    let v = m.run(|| vec![1u8; 100]);
    assert_eq!(m.calls, 1, "{v:?}");
}

/// TCP:トンネルから中継へ。台本の相手が 1 segment を送り、中継が読む。
#[test]
fn tcp_from_the_tunnel() {
    let (near, peer, mut s) = tcp();
    let mut cx = Context::from_waker(Waker::noop());
    let mut buf = vec![0u8; 65536];
    let mut wakers = Vec::with_capacity(64);
    let msg = common::pattern(1000, 5);
    let mut rbuf = vec![0u8; 4096];
    let mut m = Meter::default();
    for i in 0..WARMUP + ROUNDS {
        if i == WARMUP {
            m.reset();
        }
        peer.state.borrow_mut().received.clear();
        peer.send(&msg);
        shuttle(&near, &peer, &mut buf, &mut wakers, &mut m);
        let Poll::Ready(Ok(n)) = m.run(|| s.poll_read_bytes(&mut cx, &mut rbuf)) else {
            panic!("the read did not complete");
        };
        assert_eq!(n, msg.len());
        shuttle(&near, &peer, &mut buf, &mut wakers, &mut m);
    }
    m.check("tcp from the tunnel", TCP_FROM_TUNNEL_ALLOWED);
}

/// TCP:中継からトンネルへ。中継が 1 segment を書き、台本の相手が受ける。
#[test]
fn tcp_to_the_tunnel() {
    let (near, peer, mut s) = tcp();
    let mut cx = Context::from_waker(Waker::noop());
    let mut buf = vec![0u8; 65536];
    let mut wakers = Vec::with_capacity(64);
    let msg = common::pattern(1000, 5);
    let mut m = Meter::default();
    for i in 0..WARMUP + ROUNDS {
        if i == WARMUP {
            m.reset();
        }
        peer.state.borrow_mut().received.clear();
        let Poll::Ready(Ok(n)) = m.run(|| s.poll_write_bytes(&mut cx, &msg)) else {
            panic!("the write did not complete");
        };
        assert_eq!(n, msg.len());
        shuttle(&near, &peer, &mut buf, &mut wakers, &mut m);
    }
    m.check("tcp to the tunnel", TCP_TO_TUNNEL_ALLOWED);
}

/// UDP:トンネルから中継へ。遠い側が 1 datagram を送り、中継が受ける。
#[test]
fn udp_from_the_tunnel() {
    let near = netstack(A);
    let far = netstack(B);
    let mut cx = Context::from_waker(Waker::noop());
    let mut buf = vec![0u8; 65536];
    let mut wakers = Vec::with_capacity(64);
    let mut ua = UdpSocket::bind(&near, sa(A, 53)).unwrap();
    let ub = UdpSocket::bind(&far, sa(B, 5353)).unwrap();
    let msg = common::pattern(1000, 5);
    let mut rbuf = vec![0u8; 4096];
    let mut m = Meter::default();
    for i in 0..WARMUP + ROUNDS {
        if i == WARMUP {
            m.reset();
        }
        let sent = pin!(ub.send_to(&msg, sa(A, 53))).poll(&mut cx);
        assert!(matches!(sent, Poll::Ready(Ok(_))));
        shuttle(&near, &far, &mut buf, &mut wakers, &mut m);
        let Poll::Ready(Ok((n, _))) = m.run(|| ua.poll_recv_from(&mut cx, &mut rbuf)) else {
            panic!("no datagram");
        };
        assert_eq!(n, msg.len());
    }
    m.check("udp from the tunnel", UDP_FROM_TUNNEL_ALLOWED);
}

/// UDP:中継からトンネルへ。中継が 1 datagram を送り、遠い側が受ける。
#[test]
fn udp_to_the_tunnel() {
    let near = netstack(A);
    let far = netstack(B);
    let mut cx = Context::from_waker(Waker::noop());
    let mut buf = vec![0u8; 65536];
    let mut wakers = Vec::with_capacity(64);
    let ua = UdpSocket::bind(&near, sa(A, 53)).unwrap();
    let mut ub = UdpSocket::bind(&far, sa(B, 5353)).unwrap();
    let msg = common::pattern(1000, 5);
    let mut rbuf = vec![0u8; 4096];
    let mut m = Meter::default();
    for i in 0..WARMUP + ROUNDS {
        if i == WARMUP {
            m.reset();
        }
        let sent = m.run(|| pin!(ua.send_to(&msg, sa(B, 5353))).poll(&mut cx));
        assert!(matches!(sent, Poll::Ready(Ok(_))));
        shuttle(&near, &far, &mut buf, &mut wakers, &mut m);
        let Poll::Ready(Ok((n, _))) = ub.poll_recv_from(&mut cx, &mut rbuf) else {
            panic!("no datagram");
        };
        assert_eq!(n, msg.len());
    }
    m.check("udp to the tunnel", UDP_TO_TUNNEL_ALLOWED);
}

/// ping:近い側が echo request を送り、遠い側の核が答え、近い側が応答を読む。
#[test]
fn ping_round_trip() {
    let near = netstack(A);
    let far = netstack(B);
    let mut cx = Context::from_waker(Waker::noop());
    let mut buf = vec![0u8; 65536];
    let mut wakers = Vec::with_capacity(64);
    let mut ping = Ping::open(&near, B).unwrap();
    // ICMP echo request: type 8, code 0, checksum, identifier, sequence, payload。識別子は核が書く
    let mut msg = vec![0u8; 8 + 32];
    msg[0] = 8;
    let sum = !0x0800u16;
    msg[2..4].copy_from_slice(&sum.to_be_bytes());
    let mut rbuf = vec![0u8; 4096];
    let mut m = Meter::default();
    for i in 0..WARMUP + ROUNDS {
        if i == WARMUP {
            m.reset();
        }
        let sent = m.run(|| ping.send(&msg));
        sent.expect("send");
        shuttle(&near, &far, &mut buf, &mut wakers, &mut m);
        let Poll::Ready(Ok(_)) = m.run(|| ping.poll_recv(&mut cx, &mut rbuf)) else {
            panic!("no reply");
        };
    }
    m.check("ping", PING_ALLOWED);
}

/// 下の許容は、定常の近い側の核と handle の確保の数。現在は 0 で、どの経路にも許す確保は無い。
const TCP_FROM_TUNNEL_ALLOWED: usize = 0;
const TCP_TO_TUNNEL_ALLOWED: usize = 0;
const UDP_FROM_TUNNEL_ALLOWED: usize = 0;
const UDP_TO_TUNNEL_ALLOWED: usize = 0;
const PING_ALLOWED: usize = 0;
