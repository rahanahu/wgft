//! 中継のデータ経路が、packet ごとに何回ヒープを確保するかの試験。
//!
//! 本物のデータプレーンのスレッドと Rust の wgstack の核、試験の相手の server の device を組み、慣らしの
//! 後の定常で、1 つのメッセージを N 回流す。確保の呼び出しは、データプレーンのスレッドの上で
//! `thread_alloc_calls` を読んで数える。トンネルの受信と送信 (UDP のソケット、device、核)、中継の task、
//! LAN 側のソケットはこのスレッドで動く。試験の相手と宛先は別のスレッドの上にあり、数えない。
//! 許容は「agent と試験の相手の間を通った WireGuard の datagram 1 つにつき 2 回」で、窓の間に通った
//! datagram の数は試験の相手が数える。確保は Device の層の次の 4 か所だけで、受けた datagram ごとに
//! 2 回、送る packet ごとに 2 回である。TCP の ACK も datagram として数えるので、ACK の数が起床の時刻で
//! 揺れても割り算は崩れない。中継の層 (relay、wgft-netstack、wgstack、tokio) の許容は 0 である。
//! - crates/wgft-wireguard/src/protocol.rs:242  復号の宛先の `vec!` (受けた datagram ごと)
//! - crates/wgft-wireguard/src/device.rs:387    詰め物を除いた packet の `to_vec` (受けた datagram ごと)
//! - crates/wgft-wireguard/src/device.rs:412    送る packet の `to_vec` (送る packet ごと)
//! - crates/wgft-wireguard/src/protocol.rs:280  暗号文の宛先の `vec!` (送る packet ごと)
//!
//! 確保を減らしたら [`PER_DATAGRAM`] を下げる。
//!
//! 数える窓は読みの 2 回の `call` の間で、その外の確保 (窓の端の `call` 自体) は含まない。窓の間に
//! データプレーンのスレッドで起きる、packet の数に比例しない確保 (タイマーの回り、ログ) を見込んで、
//! [`BACKGROUND`] だけ全体の許容に足す。測りでは 0 だった。250 より十分小さくしておく必要がある。大きい
//! バッファの経路の読みごとに 1 回の確保が加わっても、読みは約 8 segment をまとめるので、2000 メッセージで
//! 250 から 522 しか増えず、大きい値にすると見逃す。

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as LanListener, UdpSocket as LanSocket};
use wgft_alloc_count::thread_alloc_calls;
use wgft_proto::Proto;

use super::Manager;
use super::testpeer::{Outcome, Peer};
use super::tests::{rule, targets};
use crate::flowpool::Limits;

/// 慣らしのメッセージの数。
const WARMUP: usize = 300;
/// 数えるメッセージの数。
const N: usize = 2000;
/// メッセージの大きさ。MTU に収まる 1 packet。
const SIZE: usize = 1000;
/// datagram 1 つあたりの確保の許容。Device の層の 2 回。
const PER_DATAGRAM: usize = 2;
/// packet の数に比例しない、窓の間のデータプレーンのスレッドの確保の見込み。測りは 0。
const BACKGROUND: usize = 64;
const WAIT: Duration = Duration::from_secs(5);

/// データプレーンのスレッドの確保の呼び出しの数と、その時までに agent と試験の相手の間を通った datagram の数。
async fn reading(peer: &Peer) -> (usize, usize) {
    // 窓の前後の読みの間に、データプレーンのスレッドが静まるのを待つ。遅延 ACK の 40 ミリ秒より長い
    tokio::time::sleep(Duration::from_millis(100)).await;
    let calls = peer
        .agent()
        .handle()
        .call(|_| thread_alloc_calls())
        .await
        .unwrap();
    (calls, peer.datagrams())
}

/// 窓の間に通った datagram 1 つあたり、Device の層の 2 回までしか確保しないことを確かめる。
fn check(path: &str, before: (usize, usize), after: (usize, usize)) {
    let calls = after.0 - before.0;
    let datagrams = after.1 - before.1;
    eprintln!("{path}: {calls} calls for {datagrams} datagrams");
    assert!(datagrams >= N, "{path}: only {datagrams} datagrams crossed");
    assert!(
        calls <= PER_DATAGRAM * datagrams + BACKGROUND,
        "{path} allocates {calls} times for {datagrams} datagrams; the allowance is {PER_DATAGRAM} per datagram plus {BACKGROUND}"
    );
}

fn manager(peer: &Peer) -> Manager {
    Manager::new(
        super::testpeer::AGENT_IP,
        peer.agent().handle(),
        targets("", vec![]),
        Limits::default(),
        super::DEFAULT_UDP_IDLE,
    )
}

async fn start() -> Peer {
    let peer = Peer::start().await;
    // ハンドシェイクが済むまで待つ。待ち受けの無いポートへの SYN に RST が返れば、トンネルは通っている
    assert_eq!(peer.connect(1).await.err(), Some(Outcome::Reset));
    peer
}

/// UDP の宛先と、トンネルの側の台本の endpoint、中継のセッションを用意する。
async fn udp_setup(
    peer: &Peer,
) -> (
    Manager,
    LanSocket,
    super::testpeer::UdpClient,
    SocketAddr,
    u16,
) {
    let target = LanSocket::bind("127.0.0.1:0").await.unwrap();
    let port = 2456;
    let mut m = manager(peer);
    let r = [rule(
        "r_u",
        Proto::Udp,
        &port.to_string(),
        &target.local_addr().unwrap().to_string(),
        true,
    )];
    assert_eq!(m.apply(&r).await, 1);
    let client = peer.udp();
    client.send(port, &[1u8; SIZE]);
    let mut buf = vec![0u8; 2048];
    let (_, session) = tokio::time::timeout(WAIT, target.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    (m, target, client, session, port)
}

/// UDP:トンネルから宛先へ。
#[tokio::test]
async fn udp_from_the_tunnel() {
    let peer = start().await;
    let (mut m, target, client, _, port) = udp_setup(&peer).await;
    let msg = vec![7u8; SIZE];
    let mut buf = vec![0u8; 2048];
    for _ in 0..WARMUP {
        client.send(port, &msg);
        tokio::time::timeout(WAIT, target.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
    }
    let before = reading(&peer).await;
    for _ in 0..N {
        client.send(port, &msg);
        tokio::time::timeout(WAIT, target.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
    }
    let after = reading(&peer).await;
    check("udp from the tunnel", before, after);
    m.close().await;
}

/// UDP:宛先からトンネルへ。
#[tokio::test]
async fn udp_to_the_tunnel() {
    let peer = start().await;
    let (mut m, target, mut client, session, _) = udp_setup(&peer).await;
    let msg = vec![7u8; SIZE];
    for _ in 0..WARMUP {
        target.send_to(&msg, session).await.unwrap();
        client.recv(WAIT).await.expect("a reply");
    }
    let before = reading(&peer).await;
    for _ in 0..N {
        target.send_to(&msg, session).await.unwrap();
        client.recv(WAIT).await.expect("a reply");
    }
    let after = reading(&peer).await;
    check("udp to the tunnel", before, after);
    m.close().await;
}

/// TCP の宛先、中継、台本の接続、宛先の側の接続を用意する。
async fn tcp_setup(peer: &Peer) -> (Manager, super::testpeer::Client, tokio::net::TcpStream) {
    let lan = LanListener::bind("127.0.0.1:0").await.unwrap();
    let mut m = manager(peer);
    let rules = [rule(
        "r_t",
        Proto::Tcp,
        "80",
        &lan.local_addr().unwrap().to_string(),
        true,
    )];
    assert_eq!(m.apply(&rules).await, 1);
    // ルールを適用した時の試し接続を先に受けて捨てる
    while let Ok(probe) = tokio::time::timeout(Duration::from_millis(300), lan.accept()).await {
        drop(probe.unwrap());
    }
    let client = peer.connect(80).await.unwrap();
    let (stream, _) = tokio::time::timeout(WAIT, lan.accept())
        .await
        .unwrap()
        .unwrap();
    (m, client, stream)
}

/// TCP:トンネルから宛先へ。1 回に `segments` 個の segment を送り、宛先が読み切る。
async fn tcp_up(path: &str, segments: usize) {
    let peer = start().await;
    let (mut m, mut c, mut s) = tcp_setup(&peer).await;
    let msg = vec![7u8; SIZE * segments];
    let mut buf = vec![0u8; SIZE * segments];
    let rounds = N / segments;
    for _ in 0..WARMUP {
        c.send(&msg);
        tokio::time::timeout(WAIT, s.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
    }
    let before = reading(&peer).await;
    for _ in 0..rounds {
        c.send(&msg);
        tokio::time::timeout(WAIT, s.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
    }
    let after = reading(&peer).await;
    check(path, before, after);
    m.close().await;
}

/// TCP:宛先からトンネルへ。1 回に `segments` 個の segment 分を書き、台本の相手が読み切る。
async fn tcp_down(path: &str, segments: usize) {
    let peer = start().await;
    let (mut m, mut c, mut s) = tcp_setup(&peer).await;
    let msg = vec![7u8; SIZE * segments];
    let rounds = N / segments;
    for _ in 0..WARMUP {
        s.write_all(&msg).await.unwrap();
        c.read_exact(msg.len()).await.unwrap();
    }
    let before = reading(&peer).await;
    for _ in 0..rounds {
        s.write_all(&msg).await.unwrap();
        c.read_exact(msg.len()).await.unwrap();
    }
    let after = reading(&peer).await;
    check(path, before, after);
    m.close().await;
}

#[tokio::test]
async fn tcp_from_the_tunnel() {
    tcp_up("tcp from the tunnel", 1).await;
}

#[tokio::test]
async fn tcp_to_the_tunnel() {
    tcp_down("tcp to the tunnel", 1).await;
}

/// 大きい書き込みで、中継が大きいバッファを借りる経路。
#[tokio::test]
async fn tcp_bulk_from_the_tunnel() {
    tcp_up("tcp bulk from the tunnel", 8).await;
}

#[tokio::test]
async fn tcp_bulk_to_the_tunnel() {
    tcp_down("tcp bulk to the tunnel", 8).await;
}
