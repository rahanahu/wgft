//! データプレーンの試験。上の層は packet を積んで送り、受けた packet を記録し、望めば送り返すだけの
//! 代わりの層にする。2 つのデータプレーンをループバックの UDP で向かい合わせ、本物のスレッド、
//! 実行環境、ソケットで動かす。送り出しの規則は、ソケットの代わりに記録する先を置いて確かめる。

use std::collections::VecDeque;
use std::future::poll_fn;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::task::{Poll, Waker};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use wgft_wireguard::{
    Device, DeviceConfig, DropReason, Ipv4Prefix, Limits, PeerConfig, PrivateKey, ProtocolTimers,
    PublicKey, Roaming, Transmit,
};

use super::driver::{Outbox, Sink, pump};
use super::{Carry, Dataplane, Generations, Settings, Upper, UpperInit, clock};

const AGENT_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 2);
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);

/// 世代をまたいで渡る予算の代わり。作った数と閉じた数を数える。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Budget {
    made: u32,
    closed: u32,
}

struct Stub {
    out: VecDeque<Vec<u8>>,
    got: Vec<Vec<u8>>,
    echo: bool,
    pulls: usize,
    budget: Budget,
    /// 受けた数がこの数に届いたら起こす waker。
    watchers: Vec<(usize, Waker)>,
    ready: Vec<Waker>,
    logs: VecDeque<String>,
    /// 真なら次の `poll_log` で panic する。駆動の task が呼ぶ核の中の panic の代わり。
    panic_in_poll_log: bool,
}

impl Stub {
    fn new(budget: Option<Budget>) -> Self {
        Self {
            out: VecDeque::new(),
            got: Vec::new(),
            echo: false,
            pulls: 0,
            budget: budget.unwrap_or(Budget { made: 1, closed: 0 }),
            watchers: Vec::new(),
            ready: Vec::new(),
            logs: VecDeque::new(),
            panic_in_poll_log: false,
        }
    }

    fn from_init(UpperInit { mtu, budget, .. }: UpperInit<Budget>) -> Self {
        assert_eq!(mtu, 1420);
        Self::new(budget)
    }

    fn echoing(init: UpperInit<Budget>) -> Self {
        let mut s = Self::from_init(init);
        s.echo = true;
        s.logs.push_back("stub: echoing".to_owned());
        s
    }

    fn with_packets(n: u32) -> impl FnOnce(UpperInit<Budget>) -> Self + Send + 'static {
        move |init| {
            let mut s = Self::from_init(init);
            s.out.extend((0..n).map(|i| packet(AGENT_IP, SERVER_IP, i)));
            s
        }
    }
}

impl Upper for Stub {
    type Budget = Budget;

    fn handle_packet(&mut self, _now: Instant, packet: &[u8]) {
        self.got.push(packet.to_vec());
        if self.echo {
            let mut reply = packet.to_vec();
            reply[12..20].rotate_left(4);
            self.out.push_back(reply);
        }
        let got = self.got.len();
        let (due, waiting): (Vec<_>, Vec<_>) =
            self.watchers.drain(..).partition(|(n, _)| *n <= got);
        self.watchers = waiting;
        self.ready.extend(due.into_iter().map(|(_, w)| w));
    }

    fn handle_timeout(&mut self, _now: Instant) {}

    fn poll_transmit(&mut self, _now: Instant, buf: &mut [u8]) -> Option<usize> {
        self.pulls += 1;
        let p = self.out.pop_front()?;
        buf[..p.len()].copy_from_slice(&p);
        Some(p.len())
    }

    fn poll_timeout(&self) -> Option<Instant> {
        None
    }

    fn poll_wakers(&mut self, wake: &mut Vec<Waker>) {
        wake.append(&mut self.ready);
    }

    fn poll_log(&mut self) -> Option<String> {
        assert!(!self.panic_in_poll_log, "a panic inside the core");
        self.logs.pop_front()
    }

    fn close(self, _now: Instant) -> Budget {
        Budget {
            closed: self.budget.closed + 1,
            ..self.budget
        }
    }
}

/// 中身に番号を持つ IPv4 の packet。
fn packet(src: Ipv4Addr, dst: Ipv4Addr, seq: u32) -> Vec<u8> {
    let mut p = vec![0u8; 24];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&24u16.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p[20..24].copy_from_slice(&seq.to_be_bytes());
    p
}

fn seq(p: &[u8]) -> u32 {
    u32::from_be_bytes([p[20], p[21], p[22], p[23]])
}

fn keys() -> (PrivateKey, PrivateKey) {
    (
        PrivateKey::generate([0xa1; 32]),
        PrivateKey::generate([0xb2; 32]),
    )
}

fn agent_config(a: &PrivateKey, b: PublicKey, endpoint: SocketAddr) -> DeviceConfig {
    DeviceConfig::agent(
        a.clone(),
        b,
        Some(endpoint),
        SERVER_IP,
        Duration::from_secs(25),
    )
}

fn server_config(b: &PrivateKey, a: PublicKey) -> DeviceConfig {
    DeviceConfig {
        private_key: b.clone(),
        mtu: 1420,
        peers: vec![PeerConfig {
            public_key: a,
            endpoint: None,
            allowed_ips: vec![Ipv4Prefix::host(AGENT_IP)],
            persistent_keepalive: None,
            roaming: Roaming::Any,
        }],
        limits: Limits::default(),
        timers: ProtocolTimers::default(),
    }
}

fn loopback() -> Settings {
    Settings {
        listen: "127.0.0.1:0".parse().unwrap(),
        ..Settings::default()
    }
}

/// `f` が真を返すまで待つ。5 秒で諦める。
async fn wait_for(what: &str, mut f: impl AsyncFnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !f().await {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn got(d: &Dataplane<Stub>) -> Vec<u32> {
    d.call(|l| l.with(|s| s.got.iter().map(|p| seq(p)).collect()))
        .await
        .unwrap()
}

/// server の側と agent の側を立てる。agent の側の上の層は `n` 個の packet を最初から持つ。
async fn pair(n: u32) -> (Dataplane<Stub>, Dataplane<Stub>) {
    let (a_key, b_key) = keys();
    let b = Dataplane::start(
        server_config(&b_key, a_key.public_key()),
        loopback(),
        Carry::first(Duration::ZERO),
        Stub::echoing,
    )
    .await
    .unwrap();
    let a = Dataplane::start(
        agent_config(&a_key, b_key.public_key(), b.local_addr()),
        loopback(),
        Carry::first(Duration::ZERO),
        Stub::with_packets(n),
    )
    .await
    .unwrap();
    (a, b)
}

#[tokio::test]
async fn two_devices_over_loopback_carry_packets_both_ways_in_order() {
    // 128 より多い packet を、セッションの前から上の層に積んでおく。セッションの前に引けば、
    // device の層のハンドシェイクを待つ待ち行列から溢れて古いものから捨てられる
    let (a, b) = pair(300).await;
    let all: Vec<u32> = (0..300).collect();
    wait_for("the server to get every packet", async || {
        got(&b).await == all
    })
    .await;
    wait_for("the agent to get every echo", async || got(&a).await == all).await;
    let sa = a.status().await.unwrap();
    assert_eq!(sa.drops.get(DropReason::StagedOverflow), 0);
    assert_eq!(sa.drops.total(), 0, "{:?}", sa.drops);
    assert!(sa.peer.unwrap().last_handshake.is_some());
    assert_eq!(sa.peer.unwrap().endpoint, Some(b.local_addr()));
    assert_eq!(sa.local, a.local_addr());
    assert_eq!(sa.socket_buffers.port, a.local_addr().port());
    assert_eq!((sa.send_errors, sa.receive_errors), (0, 0));
    assert!(sa.unix_high_water > Duration::ZERO);
    assert_eq!(b.status().await.unwrap().drops.total(), 0);
    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn an_operation_wakes_the_driver_and_readiness_wakes_a_local_task() {
    let (a, b) = pair(1).await;
    wait_for("the first echo", async || got(&a).await.len() == 1).await;
    // 上の層は timer を持たず、device の層の次の timer は秒の先にある。送るのは操作の知らせだけが起こす
    let (tx, rx) = tokio::sync::oneshot::channel();
    a.call(move |l| {
        let waiter = l.clone();
        tokio::task::spawn_local(async move {
            poll_fn(|cx| {
                waiter.with(|s| {
                    if s.got.len() >= 2 {
                        Poll::Ready(())
                    } else {
                        s.watchers.push((2, cx.waker().clone()));
                        Poll::Pending
                    }
                })
            })
            .await;
            let _ = tx.send(());
        });
        // 命令の処理の後は駆動の task が自分で回るので、操作は命令の外の local の task から行う
        let writer = l.clone();
        tokio::task::spawn_local(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            writer.operate(|s| s.out.push_back(packet(AGENT_IP, SERVER_IP, 7)));
        });
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(2), rx)
        .await
        .expect("the echo woke the waiting task")
        .unwrap();
    assert_eq!(got(&b).await, vec![0, 7]);
    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn generations_carry_the_budget_and_the_handshake_high_water() {
    let (a_key, b_key) = keys();
    let wall = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    // 壁時計より先の床は、次の device の印の始まりになる
    let floor = wall + Duration::from_secs(1000);
    let mut g = Generations::<Stub>::new(floor);
    let config = || agent_config(&a_key, b_key.public_key(), "127.0.0.1:9".parse().unwrap());
    g.start(config(), loopback(), Stub::from_init)
        .await
        .unwrap();
    assert!(g.unix_high_water() >= floor + Duration::from_secs(1));
    let first = g.current().unwrap().local_addr();
    g.start(config(), loopback(), Stub::from_init)
        .await
        .unwrap();
    assert_ne!(g.current().unwrap().local_addr(), first, "a new socket");
    assert!(g.unix_high_water() >= floor + Duration::from_secs(2));
    let budget = g
        .current()
        .unwrap()
        .call(|l| l.with(|s| s.budget))
        .await
        .unwrap();
    assert_eq!(budget, Budget { made: 1, closed: 1 });
    g.stop().await;
    assert!(g.has_budget());
    assert!(g.current().is_none());
    // 立てられない設定でも予算は残る
    let mut two = config();
    two.peers.push(two.peers[0].clone());
    assert!(g.start(two, loopback(), Stub::from_init).await.is_err());
    assert!(g.has_budget());
    g.start(config(), loopback(), Stub::from_init)
        .await
        .unwrap();
    let budget = g
        .current()
        .unwrap()
        .call(|l| l.with(|s| s.budget))
        .await
        .unwrap();
    assert_eq!(budget, Budget { made: 1, closed: 2 });
    g.stop().await;
}

#[tokio::test]
async fn a_panic_inside_the_core_ends_the_generation_and_the_next_gets_a_new_budget() {
    let (a_key, b_key) = keys();
    let config = || agent_config(&a_key, b_key.public_key(), "127.0.0.1:9".parse().unwrap());
    let mut g = Generations::<Stub>::new(Duration::ZERO);
    g.start(config(), loopback(), Stub::from_init)
        .await
        .unwrap();
    // 核の外の panic はその task だけを終わらせる
    let d = g.current().unwrap();
    d.call(|_| {
        tokio::task::spawn_local(async { panic!("a relay task outside the core") });
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(d.status().await.is_ok());
    assert!(!d.is_finished());
    // 核を借用している間の panic は世代を終わらせる
    d.call(|l| {
        let l = l.clone();
        tokio::task::spawn_local(async move {
            l.with(|_| panic!("inside the core"));
        });
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(5), g.exited())
        .await
        .expect("the thread ended");
    assert!(g.current().unwrap().status().await.is_err());
    let before = g.unix_high_water();
    g.stop().await;
    assert!(!g.has_budget(), "a poisoned generation gives no budget");
    assert!(g.unix_high_water() >= before);
    g.start(config(), loopback(), Stub::from_init)
        .await
        .unwrap();
    let budget = g
        .current()
        .unwrap()
        .call(|l| l.with(|s| s.budget))
        .await
        .unwrap();
    assert_eq!(budget, Budget { made: 1, closed: 0 });
    g.stop().await;
}

/// 落ちるときに核の操作をする handle の代わり。
struct AbortOnDrop(super::Local<Stub>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0
            .operate(|s| s.out.push_back(packet(AGENT_IP, SERVER_IP, 99)));
    }
}

#[tokio::test]
async fn a_handle_dropped_while_its_task_unwinds_does_not_poison() {
    let (a, b) = pair(0).await;
    a.call(|l| {
        let handle = AbortOnDrop(l.clone());
        tokio::task::spawn_local(async move {
            let _handle = handle;
            panic!("a relay task outside the core");
        });
    })
    .await
    .unwrap();
    // handle の Drop が操作した packet が届くことで、Drop が走ったことを確かめる
    wait_for("the packet from the dropped handle", async || {
        got(&b).await == vec![99]
    })
    .await;
    assert!(!a.call(super::Local::is_poisoned).await.unwrap());
    assert!(a.status().await.is_ok());
    assert!(!a.is_finished());
    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn a_panic_in_the_core_called_by_the_driver_ends_the_generation() {
    let (a_key, b_key) = keys();
    let config = || agent_config(&a_key, b_key.public_key(), "127.0.0.1:9".parse().unwrap());
    let mut g = Generations::<Stub>::new(Duration::ZERO);
    g.start(config(), loopback(), Stub::from_init)
        .await
        .unwrap();
    g.current()
        .unwrap()
        .call(|l| l.with(|s| s.panic_in_poll_log = true))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), g.exited())
        .await
        .expect("the thread ended");
    g.stop().await;
    assert!(
        !g.has_budget(),
        "a generation that panicked gives no budget"
    );
    g.start(config(), loopback(), Stub::from_init)
        .await
        .unwrap();
    let budget = g
        .current()
        .unwrap()
        .call(|l| l.with(|s| s.budget))
        .await
        .unwrap();
    assert_eq!(budget, Budget { made: 1, closed: 0 });
    g.stop().await;
}

#[tokio::test]
async fn a_bad_configuration_returns_the_carry() {
    let (a_key, b_key) = keys();
    let mut config = agent_config(&a_key, b_key.public_key(), "127.0.0.1:9".parse().unwrap());
    config.mtu = 1;
    let carry = Carry {
        unix_high_water: Duration::from_secs(5),
        budget: Some(Budget { made: 3, closed: 3 }),
    };
    let e = Dataplane::start(config, loopback(), carry, Stub::from_init)
        .await
        .unwrap_err();
    assert_eq!(e.error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(e.carry.budget, Some(Budget { made: 3, closed: 3 }));
    assert_eq!(e.carry.unix_high_water, Duration::from_secs(5));
}

#[tokio::test]
async fn set_endpoint_moves_the_peer() {
    let (a, b) = pair(0).await;
    let to: SocketAddr = "127.0.0.1:9".parse().unwrap();
    a.set_endpoint(to).await.unwrap();
    wait_for("the new endpoint", async || {
        a.status().await.unwrap().peer.unwrap().endpoint == Some(to)
    })
    .await;
    a.stop().await;
    b.stop().await;
}

/// 送った datagram を記録する先。`block` の間は `WouldBlock` を、`fail` の間は他の誤りを返す。
#[derive(Default)]
struct Recorder {
    sent: Vec<Transmit>,
    block: bool,
    fail: bool,
}

impl Sink for Recorder {
    fn send(&mut self, transmit: &Transmit) -> io::Result<()> {
        if self.block {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if self.fail {
            return Err(io::ErrorKind::ConnectionRefused.into());
        }
        self.sent.push(transmit.clone());
        Ok(())
    }
}

/// 手で運ぶ 2 つの device と、送り出しの状態。
struct Bench {
    a: Device,
    b: Device,
    b_pub: PublicKey,
    stub: Stub,
    outbox: Outbox,
    sink: Recorder,
}

const A_ADDR: &str = "127.0.0.2:40000";
const B_ADDR: &str = "127.0.0.1:51820";

impl Bench {
    fn new(packets: u32) -> Self {
        let (a_key, b_key) = keys();
        let now = clock::now();
        let a = Device::new(
            agent_config(&a_key, b_key.public_key(), B_ADDR.parse().unwrap()),
            now,
            Duration::ZERO,
        )
        .unwrap();
        let b = Device::new(
            server_config(&b_key, a_key.public_key()),
            now,
            Duration::ZERO,
        )
        .unwrap();
        let mut stub = Stub::new(None);
        stub.out
            .extend((0..packets).map(|i| packet(AGENT_IP, SERVER_IP, i)));
        Self {
            a,
            b,
            b_pub: b_key.public_key(),
            stub,
            outbox: Outbox::new(1420),
            sink: Recorder::default(),
        }
    }

    fn pump(&mut self, cap: usize) -> bool {
        pump(
            &mut self.a,
            &mut self.stub,
            &self.b_pub,
            clock::now(),
            &mut self.outbox,
            &mut self.sink,
            cap,
        )
    }

    /// 記録した datagram を B に渡し、B の答えを A に返す。
    fn deliver(&mut self) {
        let now = clock::now();
        for t in self.sink.sent.drain(..) {
            self.b
                .handle_datagram(now, A_ADDR.parse().unwrap(), &t.payload);
        }
        while let Some(t) = self.b.poll_transmit() {
            self.a
                .handle_datagram(now, B_ADDR.parse().unwrap(), &t.payload);
        }
    }

    fn connect(&mut self) {
        assert!(!self.pump(64));
        self.deliver();
        assert!(self.a.has_session(&self.b_pub, clock::now()));
    }
}

#[test]
fn without_a_session_nothing_is_pulled_and_a_handshake_starts() {
    let mut t = Bench::new(3);
    assert!(!t.pump(64));
    assert_eq!(t.stub.pulls, 0);
    assert_eq!(t.sink.sent.len(), 1);
    assert_eq!(t.sink.sent[0].payload.len(), 148, "an initiation");
    // 進行中のハンドシェイクは始め直さない
    assert!(!t.pump(64));
    assert_eq!((t.stub.pulls, t.sink.sent.len()), (0, 1));
    t.deliver();
    assert!(!t.pump(64));
    assert_eq!(t.stub.out.len(), 0);
    assert_eq!(t.sink.sent.len(), 4);
    assert!(
        t.sink.sent.iter().all(|s| s.payload[0] == 4),
        "data messages"
    );
}

#[test]
fn a_full_socket_stops_the_pulling_and_keeps_the_datagram() {
    let mut t = Bench::new(5);
    t.connect();
    // 確認の keepalive が device の待ち行列に残っている
    t.sink.block = true;
    assert!(!t.pump(64));
    assert_eq!(t.stub.pulls, 0, "the device queue was not empty");
    assert!(t.outbox.pending.is_some());
    t.sink.block = false;
    assert!(!t.pump(64));
    assert_eq!(t.stub.pulls, 6, "five packets and the empty pull");
    // 空の待ち行列で 1 つ引いた後に書けなくなれば、次を引かない
    t.stub.out.extend([
        packet(AGENT_IP, SERVER_IP, 9),
        packet(AGENT_IP, SERVER_IP, 10),
    ]);
    t.sink.block = true;
    assert!(!t.pump(64));
    assert_eq!(t.stub.pulls, 7);
    assert_eq!(t.stub.out.len(), 1);
    assert!(t.outbox.pending.is_some());
    assert_eq!(t.a.held().transmit_packets, 0);
}

#[test]
fn the_cap_ends_a_wake_up_with_more_to_send() {
    let mut t = Bench::new(10);
    t.connect();
    t.sink.sent.clear();
    assert!(t.pump(4));
    assert_eq!(t.stub.out.len(), 6);
    assert!(t.pump(4));
    assert!(!t.pump(4));
    assert!(t.stub.out.is_empty());
}

#[test]
fn send_errors_are_counted_and_skipped() {
    let mut t = Bench::new(2);
    t.connect();
    t.sink.fail = true;
    assert!(!t.pump(64));
    assert!(t.stub.out.is_empty());
    assert!(t.outbox.send_errors >= 2);
    assert!(t.outbox.pending.is_none());
}
