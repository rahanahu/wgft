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

use super::batch::TxBatch;
use super::batch::{RX_SLOT, RxBatch, RxMeta};
use super::driver::{
    Outbox, Sink, Source, Wake, pump, receive_batch, receive_pipelined, send_pipelined,
};
use super::{Carry, Dataplane, Generations, Settings, Upper, UpperError, UpperInit, clock};
use crate::batching::Batching;

const AGENT_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 2);
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);

/// 世代をまたいで渡る予算の代わり。作った数と閉じた数を数える。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Budget {
    made: u32,
    closed: u32,
}

type Made = Result<Stub, UpperError<Budget>>;

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
    /// 同じスレッドの local の task が走った回数。試験の task が増やす。
    task_runs: u32,
    /// 受けた packet ごとの、受けた時の `task_runs`。
    runs_at_packet: Vec<u32>,
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
            task_runs: 0,
            runs_at_packet: Vec::new(),
        }
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "the shape of a factory of the layer above"
    )]
    fn from_init(UpperInit { mtu, budget, .. }: UpperInit<Budget>) -> Made {
        // device の MTU は設定の 1420 を 16 の倍数に切り下げた値
        assert_eq!(mtu, 1408);
        Ok(Self::new(budget))
    }

    fn echoing(init: UpperInit<Budget>) -> Made {
        let mut s = Self::from_init(init)?;
        s.echo = true;
        s.logs.push_back("stub: echoing".to_owned());
        Ok(s)
    }

    fn with_packets(n: u32) -> impl FnOnce(UpperInit<Budget>) -> Made + Send + 'static {
        move |init| {
            let mut s = Self::from_init(init)?;
            s.out.extend((0..n).map(|i| packet(AGENT_IP, SERVER_IP, i)));
            Ok(s)
        }
    }
}

impl Upper for Stub {
    type Budget = Budget;

    fn handle_packet(&mut self, _now: Instant, packet: &[u8]) {
        self.got.push(packet.to_vec());
        self.runs_at_packet.push(self.task_runs);
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
        PrivateKey::generate(&[0xa1; 32]),
        PrivateKey::generate(&[0xb2; 32]),
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
    pair_with(n, loopback(), loopback()).await
}

/// [`pair`] の server の側を `server`、agent の側を `agent` の設定で立てる。
async fn pair_with(
    n: u32,
    server: Settings,
    agent: Settings,
) -> (Dataplane<Stub>, Dataplane<Stub>) {
    let (a_key, b_key) = keys();
    let b = Dataplane::start(
        server_config(&b_key, a_key.public_key()),
        server,
        Carry::first(Duration::ZERO),
        Stub::echoing,
    )
    .await
    .unwrap();
    let a = Dataplane::start(
        agent_config(&a_key, b_key.public_key(), b.local_addr()),
        agent,
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
async fn a_backlog_on_the_socket_lets_local_tasks_run_between_wake_ups() {
    // 起床は時間の予算で終わる。1 つの datagram の復号は 1 µs より長いので、1 回の起床は遅れの予算の
    // 50 µs と、それを超える最後のバッチの分を読む。最後のバッチも、測った時間から予算の半分に収まる大きさで
    // ある
    backlog_runs_stay_under(
        Settings::default().batching,
        Settings::default().batching.slots(),
    )
    .await;
}

/// 1 つずつ送受信する道 (Windows、macOS、`WGFT_AGENT_BATCH_MIB=0`) は、バッチの前と同じく起床を数で区切る。
#[tokio::test]
async fn the_one_slot_path_keeps_the_per_wake_count_cap() {
    backlog_runs_stay_under(Batching::OFF, super::driver::ONE_SLOT_CAP).await;
}

/// server の側を `server` のバッチで立て、ソケットに溜めた datagram の並びのうち、local の task が走らずに
/// 続いた最も長いものが `cap` 以下であることを確かめる。
async fn backlog_runs_stay_under(server: Batching, cap: usize) {
    const BURST: u32 = 400;
    // 送る側は 1 つずつ送る。GSO で送ると、ループバックは 1 つの GSO の packet を server の側に GRO の
    // 1 つの枠として渡し、枠 1 つが最大 64 個の datagram を持つので、並びの長さが枠の数で決まらない
    let (a, b) = pair_with(
        1,
        Settings {
            batching: server,
            ..loopback()
        },
        Settings {
            batching: Batching::OFF,
            ..loopback()
        },
    )
    .await;
    wait_for("the first echo", async || got(&a).await.len() == 1).await;
    // server の側のスレッドに、packet を受けるたびに起こされて走った回数を数える task を置く。中継の
    // accept の task の代わりで、駆動の task が上限で止めた起床の間に順を譲れば、上限ごとに 1 回走る
    b.call(|l| {
        let l = l.clone();
        tokio::task::spawn_local(async move {
            poll_fn(|cx| {
                l.with(|s| {
                    s.task_runs += 1;
                    let next = s.got.len() + 1;
                    s.watchers.push((next, cx.waker().clone()));
                });
                Poll::<()>::Pending
            })
            .await;
        });
    })
    .await
    .unwrap();
    // server の側のスレッドを止めている間に送り、ソケットに上限より多い datagram を溜める
    let (started, start) = tokio::sync::oneshot::channel();
    let stall = b.call(move |_| {
        let _ = started.send(());
        std::thread::sleep(Duration::from_millis(300));
    });
    let send = async {
        start.await.unwrap();
        a.call(|l| {
            l.operate(|s| {
                s.out
                    .extend((1..=BURST).map(|i| packet(AGENT_IP, SERVER_IP, i)));
            });
        })
        .await
        .unwrap();
    };
    let (stalled, ()) = tokio::join!(stall, send);
    stalled.unwrap();
    let mut last = 0;
    wait_for("the server to stop receiving", async || {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let n = got(&b).await.len();
        let done = n == last;
        last = n;
        done
    })
    .await;
    let runs = b
        .call(|l| l.with(|s| s.runs_at_packet[1..].to_vec()))
        .await
        .unwrap();
    assert!(
        runs.len() > 2 * cap,
        "the socket held only {} datagrams of the burst",
        runs.len()
    );
    let longest = runs
        .chunk_by(|x, y| x == y)
        .map(<[u32]>::len)
        .max()
        .unwrap_or(0);
    assert!(
        longest <= cap,
        "{longest} datagrams in a row arrived without the local task running; the cap is {cap}"
    );
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

/// 上の層の作成の失敗は、渡した予算を持つ carry と一緒に start の失敗になり、次の試みに予算が渡る。
#[tokio::test]
async fn a_failing_layer_above_returns_its_budget() {
    let (a_key, b_key) = keys();
    let config = || {
        agent_config(
            &a_key,
            b_key.public_key(),
            SocketAddr::from(([127, 0, 0, 1], 9)),
        )
    };
    let mut g = Generations::<Stub>::new(Duration::ZERO);
    g.start(config(), loopback(), Stub::from_init)
        .await
        .unwrap();
    g.stop().await;
    assert!(g.has_budget());
    let e = g
        .start(config(), loopback(), |init: UpperInit<Budget>| -> Made {
            Err(UpperError {
                error: io::Error::other("no memory"),
                budget: init.budget,
            })
        })
        .await
        .unwrap_err();
    assert_eq!(e.to_string(), "no memory");
    assert!(g.current().is_none());
    assert!(g.has_budget(), "the budget stays for the next attempt");
    g.start(config(), loopback(), Stub::from_init)
        .await
        .unwrap();
    let st = g.current().unwrap().status().await.unwrap();
    assert!(st.peer.is_some());
    g.stop().await;
}

#[tokio::test]
async fn set_endpoint_moves_the_peer() {
    // 相手は答えない UDP のソケットにする。答える相手と組むと、server の側のデータプレーンも
    // 応答だけのセッションを持つ間に自分のハンドシェイクを始め、2 つのハンドシェイクが交差する。
    // 後に済んだ方を確かめる keepalive は、移した後に届くとエンドポイントを送信元へ戻す
    // (`Roaming::NotByInitiation` が受け付ける data と keepalive)。その時機は負荷で変わるので、
    // 何も返さない相手で、命令がピアを移すことだけを確かめる
    let (a_key, b_key) = keys();
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let a = Dataplane::start(
        agent_config(&a_key, b_key.public_key(), silent.local_addr().unwrap()),
        loopback(),
        Carry::first(Duration::ZERO),
        Stub::from_init,
    )
    .await
    .unwrap();
    let to: SocketAddr = "127.0.0.1:9".parse().unwrap();
    a.set_endpoint(to).await.unwrap();
    // 命令は順に処理されるので、次の読み出しは移した後の値を返す
    assert_eq!(a.status().await.unwrap().peer.unwrap().endpoint, Some(to));
    a.stop().await;
}

/// 送った datagram を記録する先。`block` の間は `WouldBlock` を、`fail` の間は他の誤りを返す。`budget` が
/// あれば、その数の datagram を送った後は書けなくなる。`gso` なら message の形も記録する。
#[derive(Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each switch is one way a socket can answer"
)]
struct Recorder {
    sent: Vec<Transmit>,
    /// GSO の message ごとの datagram の数。
    messages: Vec<usize>,
    block: bool,
    fail: bool,
    budget: Option<usize>,
    gso: bool,
    /// GSO の message を `EIO` で拒む。
    refuse_gso: bool,
    /// 次の `send_batch` を `EINTR` で 1 回だけ失敗させる。
    interrupt_once: bool,
    /// 次の `send_batch` を `Ok(0)` で 1 回だけ返す。
    zero_once: bool,
}

impl Sink for Recorder {
    fn send(&mut self, to: SocketAddr, payload: &[u8]) -> io::Result<()> {
        if self.block || self.budget == Some(0) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if self.fail {
            return Err(io::ErrorKind::ConnectionRefused.into());
        }
        if let Some(b) = &mut self.budget {
            *b -= 1;
        }
        self.sent.push(Transmit {
            to,
            payload: payload.to_vec(),
        });
        self.messages.push(1);
        Ok(())
    }

    fn send_batch(&mut self, tx: &mut TxBatch) -> io::Result<usize> {
        if std::mem::take(&mut self.interrupt_once) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if std::mem::take(&mut self.zero_once) {
            return Ok(0);
        }
        let mut sent = 0;
        for k in tx.next..tx.n_msgs {
            let m = tx.msgs[k];
            let count = usize::from(m.count);
            let refused = count > 1 && self.refuse_gso;
            let room = !self.block && self.budget.is_none_or(|b| b >= count);
            if refused || !room || self.fail {
                if sent > 0 {
                    break;
                }
                if refused {
                    // EIO は Linux と macOS で 5
                    return Err(io::Error::from_raw_os_error(5));
                }
                if self.fail {
                    return Err(io::ErrorKind::ConnectionRefused.into());
                }
                return Err(io::ErrorKind::WouldBlock.into());
            }
            for j in 0..count {
                let (to, payload) = tx.datagram(usize::from(m.first) + j);
                assert!(j + 1 == count || payload.len() == m.seg as usize);
                self.sent.push(Transmit {
                    to,
                    payload: payload.to_vec(),
                });
            }
            if let Some(b) = &mut self.budget {
                *b -= count;
            }
            self.messages.push(count);
            sent += 1;
        }
        Ok(sent)
    }

    fn gso(&self) -> bool {
        self.gso
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

std::thread_local! {
    /// [`Bench::new`] のバッチの置き場のレーンの数。2 つ以上なら、暗号の作業者に小さなバッチも渡す。
    static BENCH_LANES: std::cell::Cell<usize> = const { std::cell::Cell::new(1) };
}

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
        let lanes = BENCH_LANES.get();
        let mut outbox = Outbox::new(Batching::default(), a.mtu(), a.max_transmit_len(), lanes);
        if lanes > 1 {
            outbox.crypto = Some(wgft_udp_batch::crypto::Crypto::new(lanes, 0));
        }
        Self {
            a,
            b,
            b_pub: b_key.public_key(),
            stub,
            outbox,
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

    /// 記録した datagram を B に渡し、B の答えを A に返す。B が受けた packet を返す。
    fn deliver(&mut self) -> Vec<Vec<u8>> {
        let now = clock::now();
        let mut plain = vec![0u8; usize::from(u16::MAX)];
        let mut got = Vec::new();
        for t in self.sink.sent.drain(..) {
            if let Some(n) =
                self.b
                    .handle_datagram(now, A_ADDR.parse().unwrap(), &t.payload, &mut plain)
            {
                got.push(plain[..n].to_vec());
            }
        }
        while let Some(t) = self.b.poll_transmit() {
            self.a
                .handle_datagram(now, B_ADDR.parse().unwrap(), &t.payload, &mut plain);
        }
        got
    }

    fn connect(&mut self) {
        assert!(!self.pump(64));
        self.deliver();
        assert!(self.a.has_session(&self.b_pub, clock::now()));
    }

    /// セッションを作り、確認の keepalive を送り、記録を空にする。
    fn connected(&mut self) {
        self.connect();
        assert!(!self.pump(64));
        self.deliver();
        self.sink.messages.clear();
    }
}

/// 番号を持つ TCP の packet。中身の長さで datagram の長さを決める。
fn tcp_packet(seq: u32, len: usize) -> Vec<u8> {
    let mut p = packet(AGENT_IP, SERVER_IP, seq);
    p.resize(len, 0);
    p[2..4].copy_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
    p[9] = 6;
    p
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
fn a_full_socket_stops_the_pulling_and_keeps_the_batch() {
    let mut t = Bench::new(5);
    t.connect();
    // 確認の keepalive が device の待ち行列に残っている
    t.sink.block = true;
    assert!(!t.pump(64));
    assert_eq!(t.stub.pulls, 0, "the device queue was not empty");
    assert!(t.outbox.is_blocked());
    t.sink.block = false;
    assert!(!t.pump(64));
    assert_eq!(t.stub.pulls, 6, "five packets and the empty pull");
    // 空の待ち行列で引いたバッチが書けなければ、バッチを持ったまま次を引かない
    t.stub.out.extend([
        packet(AGENT_IP, SERVER_IP, 9),
        packet(AGENT_IP, SERVER_IP, 10),
    ]);
    t.sink.sent.clear();
    t.sink.block = true;
    assert!(!t.pump(64));
    assert_eq!(t.stub.pulls, 9);
    assert!(t.outbox.is_blocked());
    t.stub.out.push_back(packet(AGENT_IP, SERVER_IP, 11));
    assert!(!t.pump(64));
    assert_eq!(t.stub.pulls, 9, "nothing is pulled while the batch waits");
    assert_eq!(t.a.held().transmit_packets, 0);
    // 書けるようになれば、持っていたバッチを同じ中身と順で送ってから次を引く
    t.sink.block = false;
    assert!(!t.pump(64));
    let got: Vec<u32> = t.deliver().iter().map(|p| seq(p)).collect();
    assert_eq!(got, vec![9, 10, 11]);
}

/// ソケットが書けない間にバッチが残り、device の層が datagram (server が始めたハンドシェイクへの答え) を
/// 持ったとき、答えがバッチの data の message より先に出る。
#[test]
fn datagrams_the_device_queued_go_out_before_a_pending_batch() {
    let mut t = Bench::new(0);
    t.connected();
    t.sink.sent.clear();
    t.stub
        .out
        .extend((0..3).map(|i| packet(AGENT_IP, SERVER_IP, i)));
    t.sink.block = true;
    assert!(!t.pump(64));
    assert!(t.outbox.is_blocked());
    assert_eq!(t.outbox.tx.n_sealed, 3);
    // B が新しいハンドシェイクを始め、その開始を A が受けて答えを device の待ち行列に積む
    let later = clock::now() + Duration::from_secs(10);
    assert!(t.b.start_handshake(later, &keys().0.public_key()));
    let initiation = t.b.poll_transmit().expect("an initiation");
    let mut plain = vec![0u8; usize::from(u16::MAX)];
    t.a.handle_datagram(
        later,
        B_ADDR.parse().unwrap(),
        &initiation.payload,
        &mut plain,
    );
    assert_eq!(
        t.a.held().transmit_packets,
        1,
        "the response waits in the device"
    );
    t.sink.block = false;
    assert!(!t.pump(64));
    // WireGuard の message の種類: 2 が答え、4 が data
    let kinds: Vec<u8> = t.sink.sent.iter().map(|d| d.payload[0]).collect();
    assert_eq!(kinds, vec![2, 4, 4, 4]);
}

#[test]
fn a_batch_cut_by_a_full_socket_resumes_where_it_stopped() {
    let mut t = Bench::new(0);
    t.connected();
    t.sink.sent.clear();
    t.sink.messages.clear();
    t.stub.out.extend((0..10).map(|i| tcp_packet(i, 1408)));
    t.sink.gso = true;
    t.sink.budget = Some(0);
    // 書けないままでは何も送らない
    assert!(!t.pump(64));
    assert!(t.outbox.is_blocked());
    let held: Vec<Vec<u8>> = (0..t.outbox.tx.n_sealed)
        .map(|j| t.outbox.tx.datagram(j).1.to_vec())
        .collect();
    assert_eq!(held.len(), 10);
    // 1 つの GSO の message は 10 個を持ち、4 個の余地では送れない
    t.sink.budget = Some(4);
    assert!(!t.pump(64));
    assert_eq!(t.sink.sent.len(), 0);
    t.sink.budget = None;
    assert!(!t.pump(64));
    assert_eq!(t.sink.messages, vec![10]);
    let sent: Vec<Vec<u8>> = t.sink.sent.iter().map(|s| s.payload.clone()).collect();
    assert_eq!(sent, held, "the batch went out unchanged");
    let got: Vec<u32> = t.deliver().iter().map(|p| seq(p)).collect();
    assert_eq!(got, (0..10).collect::<Vec<_>>());
}

#[test]
fn udp_goes_out_before_the_tcp_of_its_batch_and_runs_share_a_message() {
    let mut t = Bench::new(0);
    t.connected();
    t.sink.sent.clear();
    t.sink.messages.clear();
    t.sink.gso = true;
    t.stub.out.extend([
        tcp_packet(0, 1408),
        tcp_packet(1, 1408),
        packet(AGENT_IP, SERVER_IP, 100),
        tcp_packet(2, 1408),
        tcp_packet(3, 600),
        tcp_packet(4, 1408),
    ]);
    assert!(!t.pump(64));
    // UDP が先で、同じ長さの TCP の並びは短い 1 つで終わる 1 つの message になる
    assert_eq!(t.sink.messages, vec![1, 4, 1]);
    let got: Vec<u32> = t.deliver().iter().map(|p| seq(p)).collect();
    assert_eq!(got, vec![100, 0, 1, 2, 3, 4]);
}

/// GSO の拒否は Unix の errno で判定する。GSO を使うのは Linux だけである
#[cfg(unix)]
#[test]
fn a_refused_gso_send_goes_out_one_by_one() {
    let mut t = Bench::new(0);
    t.connected();
    t.sink.sent.clear();
    t.sink.messages.clear();
    t.sink.gso = true;
    t.sink.refuse_gso = true;
    t.stub.out.extend((0..5).map(|i| tcp_packet(i, 1408)));
    assert!(!t.pump(64));
    assert_eq!(t.sink.messages, vec![1; 5]);
    assert_eq!(t.outbox.send_errors, 0);
    // 以後このソケットでは GSO を使わない
    t.sink.messages.clear();
    t.stub.out.extend((5..8).map(|i| tcp_packet(i, 1408)));
    assert!(!t.pump(64));
    assert_eq!(t.sink.messages, vec![1; 3]);
    let got: Vec<u32> = t.deliver().iter().map(|p| seq(p)).collect();
    assert_eq!(got, (0..8).collect::<Vec<_>>());
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
    assert!(!t.outbox.is_blocked());
}

/// 決まった datagram の列を読ませる受信の元。
struct Feed(VecDeque<(SocketAddr, Vec<u8>)>);

impl Source for Feed {
    fn recv(&mut self, rx: &mut RxBatch, vlen: usize) -> io::Result<usize> {
        if self.0.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let n = vlen.min(rx.slots()).min(self.0.len());
        for i in 0..n {
            let (from, d) = self.0.pop_front().unwrap();
            rx.data_mut()[i * RX_SLOT..i * RX_SLOT + d.len()].copy_from_slice(&d);
            rx.meta[i] = RxMeta {
                from: Some(from),
                len: u32::try_from(d.len()).unwrap(),
                seg: 0,
            };
        }
        Ok(n)
    }
}

/// 交互に並ぶ TCP と UDP の datagram を 1 つの受信のバッチで読み、上の層に渡った順を返す。`lanes` が
/// 2 つ以上なら、暗号の作業者に小さな回も渡す。
async fn receive_mixed(lanes: usize) -> Vec<u32> {
    let mut t = Bench::new(0);
    t.connected();
    // server の側が agent に送る packet。TCP と UDP が交互に並ぶ
    let now = clock::now();
    let mut feed = Feed(VecDeque::new());
    let mut sealed = vec![0u8; t.b.max_transmit_len()];
    for (seq, udp) in [(0, false), (100, true), (1, false), (101, true), (2, false)] {
        let mut p = packet(SERVER_IP, AGENT_IP, seq);
        if !udp {
            p[9] = 6;
        }
        let out = t.b.handle_packet(now, &p, &mut sealed).unwrap();
        feed.0
            .push_back((B_ADDR.parse().unwrap(), sealed[..out.len].to_vec()));
    }
    let local = super::Local(std::rc::Rc::new(super::Shared {
        inner: std::cell::RefCell::new(super::Inner {
            device: t.a,
            upper: Stub::new(None),
        }),
        poisoned: std::cell::Cell::new(false),
        wake: super::Wake::default(),
    }));
    // 密な部分を枠の全体にして、枠 i が data の i × RX_SLOT から始まるようにする
    let mut rx = RxBatch::new(8, false, RX_SLOT, lanes);
    let mut crypto = (lanes > 1).then(|| wgft_udp_batch::crypto::Crypto::new(lanes, 0));
    let (mut errors, mut wakers) = (0, Vec::new());
    let (n, _) = receive_batch(
        &local,
        &mut feed,
        &mut rx,
        crypto.as_mut(),
        now,
        8,
        &mut errors,
        &mut wakers,
    )
    .await
    .unwrap();
    assert_eq!((n, errors), (5, 0));
    local.with(|s| s.got.iter().map(|p| seq(p)).collect())
}

#[tokio::test]
async fn a_receive_batch_hands_udp_first_and_keeps_the_tcp_order() {
    for lanes in [1, 3] {
        assert_eq!(
            receive_mixed(lanes).await,
            vec![100, 101, 0, 1, 2],
            "UDP first, TCP in the order read, {lanes} lanes"
        );
    }
}

#[test]
fn an_interrupted_send_is_retried_and_a_send_of_nothing_keeps_the_batch() {
    let mut t = Bench::new(0);
    t.connected();
    t.sink.sent.clear();
    t.sink.interrupt_once = true;
    t.stub.out.extend((0..3).map(|i| tcp_packet(i, 1408)));
    assert!(!t.pump(64));
    assert_eq!(t.outbox.send_errors, 0);
    let got: Vec<u32> = t.deliver().iter().map(|p| seq(p)).collect();
    assert_eq!(got, vec![0, 1, 2], "EINTR sends the same batch again");
    t.sink.zero_once = true;
    t.stub.out.extend((3..5).map(|i| tcp_packet(i, 1408)));
    assert!(!t.pump(64));
    assert!(t.outbox.is_blocked(), "a send of nothing keeps the batch");
    assert!(!t.pump(64));
    let got: Vec<u32> = t.deliver().iter().map(|p| seq(p)).collect();
    assert_eq!(got, vec![3, 4]);
    assert_eq!(t.outbox.send_errors, 0);
}

/// 作業者と重ねる受信の相を、`datagrams` を読み切るまで流す。上の層に渡った packet の順と device を返す。
/// 遅い build では時間の予算が相を早く区切るので、読ませるものが無くなるまで相を繰り返す。`poison` なら
/// 先に作業者に毒の印を付け、相の誤りを返す。
async fn pipelined_phase(
    datagrams: Vec<Vec<u8>>,
    from: SocketAddr,
    a: Device,
    poison: bool,
) -> io::Result<(Vec<u32>, Device)> {
    let local = super::Local(std::rc::Rc::new(super::Shared {
        inner: std::cell::RefCell::new(super::Inner {
            device: a,
            upper: Stub::new(None),
        }),
        poisoned: std::cell::Cell::new(false),
        wake: super::Wake::default(),
    }));
    let mut feed = Feed(datagrams.into_iter().map(|d| (from, d)).collect());
    // 密な部分を枠の全体にして、枠 i が data の i × RX_SLOT から始まるようにする
    let mut a_store = RxBatch::new(8, false, RX_SLOT, 3);
    let mut b_store = RxBatch::new(8, false, RX_SLOT, 3);
    let mut crypto =
        wgft_udp_batch::crypto::Crypto::new(3, wgft_udp_batch::crypto::PARALLEL_MIN_BYTES);
    assert_eq!(crypto.workers(), 2);
    if poison {
        crypto.poison();
    }
    // 最初のバッチが枠をすべて求めるように、速い費用を記録しておく
    let mut pace = super::batch::Pace::default();
    pace.record(Duration::from_nanos(8), 8);
    let (mut errors, mut wakers) = (0, Vec::new());
    while !feed.0.is_empty() {
        let mut now = clock::now();
        let wake = Wake {
            start: now,
            timed: true,
        };
        receive_pipelined(
            &local,
            &mut feed,
            [&mut a_store, &mut b_store],
            &mut crypto,
            wake,
            &mut now,
            &mut pace,
            &mut errors,
            &mut wakers,
        )
        .await?;
        assert_eq!(crypto.in_flight(), None, "no batch stays with the workers");
    }
    assert_eq!(errors, 0);
    for rx in [&mut a_store, &mut b_store] {
        assert!(
            rx.plain.iter().all(|l| !l.is_empty()),
            "the plaintext lanes came back"
        );
        let _ = rx.data_mut();
    }
    let got = local.with(|s| s.got.iter().map(|p| seq(p)).collect());
    let Ok(shared) = std::rc::Rc::try_unwrap(local.0) else {
        panic!("the data plane is still shared");
    };
    Ok((got, shared.inner.into_inner().device))
}

/// server の側 (B) が agent (A) に送る TCP の packet `seqs` の datagram。
fn sealed_from_b(t: &mut Bench, seqs: std::ops::Range<u32>) -> Vec<Vec<u8>> {
    let now = clock::now();
    let mut out = vec![0u8; t.b.max_transmit_len()];
    seqs.map(|i| {
        let mut p = packet(SERVER_IP, AGENT_IP, i);
        p[9] = 6;
        let o = t.b.handle_packet(now, &p, &mut out).unwrap();
        out[..o.len].to_vec()
    })
    .collect()
}

#[tokio::test]
async fn a_short_read_after_a_pipelined_batch_leaves_nothing_with_the_workers() {
    let mut t = Bench::new(0);
    t.connected();
    let datagrams = sealed_from_b(&mut t, 0..11);
    let (got, device) = pipelined_phase(datagrams, B_ADDR.parse().unwrap(), t.a, false)
        .await
        .unwrap();
    assert_eq!(
        got,
        (0..11).collect::<Vec<_>>(),
        "accepted in arrival order"
    );
    assert_eq!(device.drops().total(), 0);
}

#[tokio::test]
async fn a_datagram_that_is_not_data_waits_for_the_batch_with_the_workers() {
    let mut t = Bench::new(0);
    t.connected();
    let mut datagrams = sealed_from_b(&mut t, 0..8);
    // ハンドシェイクの開始の型の、壊れた datagram。作業者にある前のバッチを受け付けた後に扱う
    let mut junk = vec![0u8; 148];
    junk[0] = 1;
    datagrams.push(junk);
    datagrams.extend(sealed_from_b(&mut t, 8..10));
    let (got, device) = pipelined_phase(datagrams, B_ADDR.parse().unwrap(), t.a, false)
        .await
        .unwrap();
    assert_eq!(got, (0..10).collect::<Vec<_>>());
    assert_eq!(device.drops().total(), 1, "{:?}", device.drops());
}

#[tokio::test]
async fn a_worker_panic_ends_the_pipelined_receive_with_an_error() {
    let mut t = Bench::new(0);
    t.connected();
    let datagrams = sealed_from_b(&mut t, 0..8);
    let Err(e) = pipelined_phase(datagrams, B_ADDR.parse().unwrap(), t.a, true).await else {
        panic!("a poisoned pool ends the phase");
    };
    assert!(
        e.to_string().contains("ended this tunnel generation"),
        "{e}"
    );
}

#[test]
fn the_send_batch_rules_hold_with_the_crypto_workers() {
    BENCH_LANES.set(3);
    without_a_session_nothing_is_pulled_and_a_handshake_starts();
    a_full_socket_stops_the_pulling_and_keeps_the_batch();
    datagrams_the_device_queued_go_out_before_a_pending_batch();
    a_batch_cut_by_a_full_socket_resumes_where_it_stopped();
    udp_goes_out_before_the_tcp_of_its_batch_and_runs_share_a_message();
    #[cfg(unix)]
    a_refused_gso_send_goes_out_one_by_one();
    the_cap_ends_a_wake_up_with_more_to_send();
    send_errors_are_counted_and_skipped();
    an_interrupted_send_is_retried_and_a_send_of_nothing_keeps_the_batch();
    BENCH_LANES.set(1);
}

impl Bench {
    /// 作業者と重ねる送信の相を 1 回流す。最初のバッチが作業者のレーンの枠をすべて引くように、速い費用を
    /// 記録しておく。
    fn pipe(&mut self) -> bool {
        let mut pace = super::batch::Pace::default();
        pace.record(Duration::from_nanos(8), 8);
        let mut now = clock::now();
        let wake = Wake {
            start: now,
            timed: true,
        };
        send_pipelined(
            &mut self.a,
            &mut self.stub,
            &self.b_pub,
            &mut self.outbox,
            &mut self.sink,
            &mut pace,
            wake,
            &mut now,
        )
    }

    fn in_flight(&self) -> Option<usize> {
        self.outbox
            .crypto
            .as_ref()
            .and_then(wgft_udp_batch::crypto::Crypto::seal_in_flight)
    }
}

/// 記録した datagram のうち、データの message の番号を送った順に返す。
fn counters(sent: &[Transmit]) -> Vec<u64> {
    sent.iter()
        .filter(|t| t.payload[0] == 4 && t.payload.len() > 32)
        .map(|t| u64::from_le_bytes(t.payload[8..16].try_into().unwrap()))
        .collect()
}

/// UDP と TCP の packet を混ぜて `n` 個並べる。UDP は 5 つに 1 つ。
fn mixed(n: u32) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| {
            let mut p = tcp_packet(i, 1200);
            if i % 5 == 0 {
                p[9] = 17;
            }
            p
        })
        .collect()
}

#[test]
fn the_pipelined_send_keeps_the_counters_in_send_order_and_leaves_nothing_with_the_workers() {
    BENCH_LANES.set(3);
    let mut t = Bench::new(0);
    BENCH_LANES.set(1);
    assert!(t.outbox.tx2.is_some());
    t.connected();
    t.sink.sent.clear();
    t.stub.out.extend(mixed(100));
    let mut calls = 0;
    while !t.stub.out.is_empty() {
        t.pipe();
        assert_eq!(t.in_flight(), None, "no batch stays with the workers");
        calls += 1;
        assert!(calls < 100);
    }
    let c = counters(&t.sink.sent);
    assert_eq!(c.len(), 100);
    assert!(c.windows(2).all(|w| w[0] + 1 == w[1]), "{c:?}");
    let mut got: Vec<u32> = t.deliver().iter().map(|p| seq(p)).collect();
    assert_eq!(got.len(), 100);
    got.sort_unstable();
    assert_eq!(got, (0..100).collect::<Vec<_>>());
}

#[test]
fn a_full_socket_during_the_pipelined_send_keeps_both_batches_in_order() {
    BENCH_LANES.set(3);
    let mut t = Bench::new(0);
    BENCH_LANES.set(1);
    t.connected();
    t.sink.sent.clear();
    t.stub.out.extend(mixed(60));
    // 最初のバッチの一部だけを受け付け、その後は書けない
    t.sink.budget = Some(3);
    t.pipe();
    assert_eq!(t.in_flight(), None);
    assert!(t.outbox.is_blocked());
    let pulled = t.stub.pulls;
    t.pipe();
    assert_eq!(t.stub.pulls, pulled, "nothing is pulled while batches wait");
    // 書けるようになれば、待っていたバッチを古いものから送り、続きを引く
    t.sink.budget = None;
    while !t.stub.out.is_empty() || t.outbox.is_blocked() {
        t.pipe();
    }
    let c = counters(&t.sink.sent);
    assert_eq!(c.len(), 60);
    assert!(c.windows(2).all(|w| w[0] + 1 == w[1]), "{c:?}");
    assert_eq!(t.deliver().len(), 60);
}

#[test]
fn without_a_session_the_pipelined_send_pulls_nothing_and_starts_a_handshake() {
    BENCH_LANES.set(3);
    let mut t = Bench::new(4);
    BENCH_LANES.set(1);
    t.pipe();
    assert_eq!(t.stub.pulls, 0);
    assert_eq!(t.in_flight(), None);
    assert!(
        t.sink.sent.iter().any(|tr| tr.payload[0] == 1),
        "an initiation went out"
    );
}

#[test]
fn the_final_flush_sends_what_the_pipelined_send_left_waiting() {
    BENCH_LANES.set(3);
    let mut t = Bench::new(0);
    BENCH_LANES.set(1);
    t.connected();
    t.sink.sent.clear();
    t.stub.out.extend(mixed(40));
    t.sink.block = true;
    t.pipe();
    t.sink.block = false;
    // 止めるときの最後の送り出し (Rest::flush) と同じく、pump が待っていたものを送る
    assert!(!t.pump(4096));
    assert!(!t.outbox.is_blocked());
    let c = counters(&t.sink.sent);
    assert!(c.windows(2).all(|w| w[0] + 1 == w[1]), "{c:?}");
    assert_eq!(t.deliver().len() + t.stub.out.len(), 40);
}

#[test]
fn a_single_packet_on_an_idle_tunnel_wakes_no_worker() {
    BENCH_LANES.set(3);
    let mut t = Bench::new(0);
    BENCH_LANES.set(1);
    t.connected();
    t.sink.sent.clear();
    let crypto = |t: &Bench| t.outbox.crypto.as_ref().unwrap().offers();
    // ゲームの応答の向き:1 つの UDP の datagram は、待たずにその相で出る
    let mut p = tcp_packet(7, 120);
    p[9] = 17;
    t.stub.out.push_back(p);
    t.pipe();
    assert_eq!(crypto(&t), 0, "no worker was offered anything");
    assert_eq!(t.in_flight(), None);
    assert_eq!(
        counters(&t.sink.sent).len(),
        1,
        "the datagram went out at once"
    );
    assert_eq!(t.deliver().len(), 1);
    // 枠を満たすバッチは作業者に渡る
    t.stub.out.extend(mixed(60));
    t.pipe();
    assert!(crypto(&t) > 0);
    assert_eq!(t.in_flight(), None);
}

#[test]
fn a_worker_panic_during_the_pipelined_send_ends_the_generation() {
    BENCH_LANES.set(3);
    let mut t = Bench::new(0);
    BENCH_LANES.set(1);
    t.connected();
    t.outbox.crypto.as_ref().unwrap().poison();
    t.stub.out.extend(mixed(60));
    assert!(!t.pipe());
    assert!(
        t.outbox.poisoned,
        "the driver ends the generation on this mark"
    );
}
