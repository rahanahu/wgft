//! UDP の中継が、トンネルへ送る向きの詰まりで止まらず、古い応答を捨てることの試験。
//!
//! セッションの無い間は、データプレーンが核の出力を引かない。核に溜まる応答は、核の送信の予算で止まる。
//! 試験は、agent と server の間に開け閉めできる門を置いて、セッションが無い状態を作る。トンネルの中から
//! 来る datagram は、門を閉じたまま核へ直接入れる。宛先は、受けた datagram をすぐ返すカーネルのソケット
//! である。

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::net::UdpSocket as LanSocket;
use tokio::task::JoinHandle;
use wgft_proto::Proto;
use wgft_wireguard::ProtocolTimers;

use super::testpeer::{AGENT_IP, Peer, SERVER_IP, udp_packet};
use super::tests::{rule, targets};
use super::{Key, Kind, Manager};
use crate::dataplane::clock;
use crate::flowpool::Limits;

const WAIT: Duration = Duration::from_secs(10);

/// agent と server の間の門。閉じている間は、どちらの向きの datagram も捨てる。
struct Gate {
    open: Arc<AtomicBool>,
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for Gate {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn gate(server: SocketAddr) -> Gate {
    let agent_side = LanSocket::bind("127.0.0.1:0").await.unwrap();
    let server_side = LanSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = agent_side.local_addr().unwrap();
    let open = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&open);
    let task = tokio::spawn(async move {
        let mut a = vec![0u8; 65535];
        let mut s = vec![0u8; 65535];
        let mut agent: Option<SocketAddr> = None;
        loop {
            tokio::select! {
                Ok((n, from)) = agent_side.recv_from(&mut a) => {
                    agent = Some(from);
                    if flag.load(Ordering::Relaxed) {
                        let _ = server_side.send_to(&a[..n], server).await;
                    }
                }
                Ok((n, _)) = server_side.recv_from(&mut s) => {
                    if let (true, Some(to)) = (flag.load(Ordering::Relaxed), agent) {
                        let _ = agent_side.send_to(&s[..n], to).await;
                    }
                }
            }
        }
    });
    Gate { open, addr, task }
}

/// 受けた datagram をすぐ返し、受けた数を数える宛先。
async fn echo() -> (SocketAddr, Arc<AtomicUsize>) {
    let s = LanSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, from)) = s.recv_from(&mut buf).await {
            let _ = s.send_to(&buf[..n], from).await;
            seen.fetch_add(1, Ordering::Relaxed);
        }
    });
    (addr, count)
}

/// 核の送信の FIFO にある datagram の数と、予算の尽きで捨てた数と、時間を超えて捨てた数。
async fn held(peer: &Peer) -> (usize, u64, u64) {
    peer.agent()
        .call(|net| {
            net.with(|ns| {
                let c = ns.core();
                let st = c.stats();
                (
                    c.held().udp_tx_datagrams,
                    st.udp_send_evicted,
                    st.udp_send_expired,
                )
            })
        })
        .await
        .unwrap()
}

/// トンネルから来た datagram を核へ直接入れる。門が閉じていても入る。
async fn inject(peer: &Peer, from_port: u16, data: Vec<u8>) {
    peer.agent()
        .call(move |net| {
            let pkt = udp_packet(SERVER_IP, AGENT_IP, from_port, 2456, &data);
            net.with(|ns| ns.handle_packet(clock::now(), &pkt));
        })
        .await
        .unwrap();
}

async fn until(what: &str, mut f: impl AsyncFnMut() -> bool) {
    let end = tokio::time::Instant::now() + WAIT;
    while !f().await {
        assert!(
            tokio::time::Instant::now() < end,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

/// トンネルへ送れない間も、中継は宛先を読み続ける。核の送信の予算は上限を超えず、古い応答が捨てられる。
/// 回復の後に届くのは新しい応答だけで、時間を超えた古い応答は届かない。
#[tokio::test]
async fn a_blocked_tunnel_does_not_stall_the_relay_and_stale_replies_are_dropped() {
    let (mut peer, agent_key) = Peer::server().await;
    let gate = gate(peer.endpoint()).await;
    let timers = ProtocolTimers {
        rekey_timeout: Some(Duration::from_millis(100)),
        ..ProtocolTimers::default()
    };
    peer.start_agent(agent_key, gate.addr, timers).await;
    let (target, echoed) = echo().await;
    let mut m = Manager::new(
        AGENT_IP,
        peer.agent().handle(),
        targets("", vec![]),
        Limits::default(),
        super::DEFAULT_UDP_IDLE,
    );
    let r = [rule("r_u", Proto::Udp, "2456", &target.to_string(), true)];
    assert_eq!(m.apply(&r).await, 1);
    let mut client = peer.udp();
    let port = client.port();

    // 門が閉じている間に、応答をあふれさせる
    let total = 700usize;
    for i in 0..total {
        inject(
            &peer,
            port,
            u32::try_from(i).unwrap().to_be_bytes().to_vec(),
        )
        .await;
        until("the target to see the datagram", async || {
            echoed.load(Ordering::Relaxed) > i
        })
        .await;
    }
    // 宛先の応答はすべて読まれて、核に入るか捨てられた
    until("every reply to be queued or dropped", async || {
        let (queued, evicted, expired) = held(&peer).await;
        queued as u64 + evicted + expired == total as u64
    })
    .await;
    let (queued, evicted, expired) = held(&peer).await;
    let share = 256;
    assert_eq!(queued, share, "the endpoint's share of the send budget");
    assert_eq!(evicted, (total - share) as u64);
    assert_eq!(expired, 0, "nothing is taken while there is no session");
    let sessions = m
        .listener_stats()
        .into_iter()
        .find(|s| {
            s.key
                == Key {
                    kind: Kind::Udp,
                    port: 2456,
                }
        })
        .unwrap()
        .sessions;
    assert_eq!(sessions, 1);

    // 古い応答が時間を超えてから回復する。セッションができて核の出力を引くと、古い応答は捨てられる
    tokio::time::sleep(Duration::from_millis(200)).await;
    gate.open.store(true, Ordering::Relaxed);
    until("the stale replies to be taken", async || {
        held(&peer).await.0 == 0
    })
    .await;
    let (_, evicted, expired) = held(&peer).await;
    assert_eq!((evicted, expired), ((total - share) as u64, share as u64));
    // 新しい応答は届く。古いものは 1 つも届いていない
    inject(&peer, port, u32::MAX.to_be_bytes().to_vec()).await;
    let (_, data) = client.recv(WAIT).await.expect("the fresh reply");
    assert_eq!(data, u32::MAX.to_be_bytes());
    assert!(client.recv(Duration::from_millis(300)).await.is_none());
    m.close().await;
}
