//! 中継のデータ経路が、packet ごとに何回ヒープを確保するかの試験。
//!
//! 本物のデータプレーンのスレッドと Rust の wgstack の核、試験の相手の server の device を組み、慣らしの
//! 後の定常で、1 つのメッセージを N 回流す。確保の呼び出しは、データプレーンのスレッドの上で
//! `thread_alloc_calls` を読んで数える。トンネルの受信と送信 (UDP のソケット、device、核)、中継の task、
//! LAN 側のソケットはこのスレッドで動く。試験の相手と宛先は別のスレッドの上にあり、数えない。
//! 許容は今の測りの値で、新しい確保が増えると試験が落ちる。確保を減らしたら許容を下げる。
//!
//! 数える窓は読みの 2 回の `call` の間で、その外の確保 (窓の端の `call` 自体) は含まない。ただし窓の間に
//! データプレーンのスレッドで起きる、packet の数に比例しない確保 (タイマーの回り、ログ) を見込んで、
//! [`BACKGROUND`] だけ全体の許容に足す。

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
/// packet の数に比例しない、窓の間のデータプレーンのスレッドの確保の見込み。
const BACKGROUND: usize = 64;
const WAIT: Duration = Duration::from_secs(5);

// 1000 メッセージあたりの確保の許容。測りの値は、中継の層 (relay、wgft-netstack、wgstack、tokio) が 0 で、
// すべてが Device の層の次の確保である。
// - crates/wgft-wireguard/src/protocol.rs:242  復号の宛先の `vec!` (受けた datagram ごと)
// - crates/wgft-wireguard/src/device.rs:387    詰め物を除いた packet の `to_vec` (受けた datagram ごと)
// - crates/wgft-wireguard/src/device.rs:412    送る packet の `to_vec` (送る packet ごと)
// - crates/wgft-wireguard/src/protocol.rs:280  暗号文の宛先の `vec!` (送る packet ごと)
// 受けた datagram は 2 回、送る packet は 2 回確保する。経路ごとの内訳:
// - UDP の両向き:データの datagram 1 つが 2 回。UDP に ACK は無い
// - TCP の 1 segment ずつ:データの 2 回と、逆向きに流れる ACK の 2 回で 4 回。台本の相手は segment ごとに
//   ACK を返し、agent の核は受けた segment ごとに ACK を返す
// - TCP の 8 segment ずつ (大きいバッファを借りる経路):トンネルから宛先へは、segment ごとの 2 回に、
//   agent の ACK の 2 回が数 segment に 1 回の割合で加わる。ACK の数は時刻に依って 1 割ほど揺れるので、
//   許容は上の揺れを含む最大の 2.5 回にしている。宛先からトンネルへは、segment ごとの 2 回に、台本の
//   相手の ACK を受ける 2 回が 2 segment に 1 回の割合で加わり、3 回
const UDP_UP_ALLOWED: usize = 2000;
const UDP_DOWN_ALLOWED: usize = 2000;
const TCP_UP_ALLOWED: usize = 4000;
const TCP_DOWN_ALLOWED: usize = 4000;
const TCP_BULK_UP_ALLOWED: usize = 2500;
const TCP_BULK_DOWN_ALLOWED: usize = 3000;

async fn dp_calls(peer: &Peer) -> usize {
    // 数える窓の前後の読みの間に、データプレーンのスレッドが静まるのを待つ
    tokio::time::sleep(Duration::from_millis(100)).await;
    peer.agent()
        .handle()
        .call(|_| thread_alloc_calls())
        .await
        .unwrap()
}

fn check(path: &str, calls: usize, allowed_per_1000: usize) {
    eprintln!("{path}: {calls} calls for {N} messages or segments");
    assert!(
        calls <= allowed_per_1000 * N / 1000 + BACKGROUND,
        "{path} allocates {calls} times for {N} messages or segments; the allowance is {allowed_per_1000} per 1000 plus {BACKGROUND}"
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
    let before = dp_calls(&peer).await;
    for _ in 0..N {
        client.send(port, &msg);
        tokio::time::timeout(WAIT, target.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
    }
    let after = dp_calls(&peer).await;
    check("udp from the tunnel", after - before, UDP_UP_ALLOWED);
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
    let before = dp_calls(&peer).await;
    for _ in 0..N {
        target.send_to(&msg, session).await.unwrap();
        client.recv(WAIT).await.expect("a reply");
    }
    let after = dp_calls(&peer).await;
    check("udp to the tunnel", after - before, UDP_DOWN_ALLOWED);
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
async fn tcp_up(path: &str, segments: usize, allowed_per_1000: usize) {
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
    let before = dp_calls(&peer).await;
    for _ in 0..rounds {
        c.send(&msg);
        tokio::time::timeout(WAIT, s.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
    }
    let after = dp_calls(&peer).await;
    check(path, after - before, allowed_per_1000);
    m.close().await;
}

/// TCP:宛先からトンネルへ。1 回に `segments` 個の segment 分を書き、台本の相手が読み切る。
async fn tcp_down(path: &str, segments: usize, allowed_per_1000: usize) {
    let peer = start().await;
    let (mut m, mut c, mut s) = tcp_setup(&peer).await;
    let msg = vec![7u8; SIZE * segments];
    let rounds = N / segments;
    for _ in 0..WARMUP {
        s.write_all(&msg).await.unwrap();
        c.read_exact(msg.len()).await.unwrap();
    }
    let before = dp_calls(&peer).await;
    for _ in 0..rounds {
        s.write_all(&msg).await.unwrap();
        c.read_exact(msg.len()).await.unwrap();
    }
    let after = dp_calls(&peer).await;
    check(path, after - before, allowed_per_1000);
    m.close().await;
}

#[tokio::test]
async fn tcp_from_the_tunnel() {
    tcp_up("tcp from the tunnel", 1, TCP_UP_ALLOWED).await;
}

#[tokio::test]
async fn tcp_to_the_tunnel() {
    tcp_down("tcp to the tunnel", 1, TCP_DOWN_ALLOWED).await;
}

/// 大きい書き込みで、中継が大きいバッファを借りる経路。
#[tokio::test]
async fn tcp_bulk_from_the_tunnel() {
    tcp_up("tcp bulk from the tunnel", 8, TCP_BULK_UP_ALLOWED).await;
}

#[tokio::test]
async fn tcp_bulk_to_the_tunnel() {
    tcp_down("tcp bulk to the tunnel", 8, TCP_BULK_DOWN_ALLOWED).await;
}
