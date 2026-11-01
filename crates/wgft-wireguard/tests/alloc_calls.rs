//! トンネルの受信と送信が、packet ごとに何回ヒープを確保するかの試験。
//!
//! 慣らし (ハンドシェイクと最初の数 packet) の後の定常で、`Device` の送信 (`handle_packet` と
//! `poll_transmit`) と受信 (`handle_datagram` と `poll_packet`) を N 回流し、確保の呼び出しの数を数える。
//! 許容は今の測りの値で、新しい確保が増えると試験が落ちる。確保を減らしたら許容を下げる。数えは窓を開いた
//! スレッドだけを数える。
//!
//! 許容に含まれる確保 (Device の層の内側。復号の相手は `wgft-agent` の駆動が呼ぶ `poll_packet` の戻りで、
//! 呼び手が捨てる):
//! - 送信:`crates/wgft-wireguard/src/device.rs` の `handle_packet` が packet を `to_vec` で写す
//!   (1 packet 1 回)、`crates/wgft-wireguard/src/protocol.rs` の `encapsulate` が暗号文の宛先を `vec!` で
//!   確保する (1 packet 1 回)
//! - 受信:`crates/wgft-wireguard/src/protocol.rs` の `receive` が復号の宛先を `vec!` で確保する
//!   (1 datagram 1 回)、`crates/wgft-wireguard/src/device.rs` の `deliver` が詰め物を除いた packet を
//!   `to_vec` で写す (1 datagram 1 回)

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use wgft_alloc_count::{CountingAlloc, ThreadWindow};
use wgft_wireguard::{
    Device, DeviceConfig, Ipv4Prefix, Limits, PeerConfig, PrivateKey, ProtocolTimers, Roaming,
    Transmit,
};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

const AGENT_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 2);
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);
const KEEPALIVE: Duration = Duration::from_secs(25);

/// 慣らしの後に流す packet の数。
const N: usize = 1000;
/// 1 packet の IP の全長。
const SIZE: usize = 1000;

/// 送信の 1 packet あたりの確保の許容。device.rs の `to_vec` と protocol.rs の暗号文の `vec!`。
const SEND_ALLOWED: usize = 2;
/// 受信の 1 datagram あたりの確保の許容。protocol.rs の復号の宛先の `vec!` と device.rs の `to_vec`。
const RECEIVE_ALLOWED: usize = 2;

fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, total: usize) -> Vec<u8> {
    let mut p = vec![0xa5u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p
}

struct Pair {
    a: Device,
    b: Device,
    a_addr: SocketAddr,
    b_addr: SocketAddr,
    now: Instant,
}

impl Pair {
    /// ハンドシェイクを済ませた agent と server の device を作る。
    fn connected() -> Self {
        let a_key = PrivateKey::generate(&[0xa1; 32]);
        let b_key = PrivateKey::generate(&[0xb2; 32]);
        let a_addr: SocketAddr = "198.51.100.2:40000".parse().unwrap();
        let b_addr: SocketAddr = "203.0.113.1:51820".parse().unwrap();
        let now = Instant::now();
        let a_cfg = DeviceConfig::agent(
            a_key.clone(),
            b_key.public_key(),
            Some(b_addr),
            SERVER_IP,
            KEEPALIVE,
        );
        let b_cfg = DeviceConfig {
            private_key: b_key,
            mtu: 1420,
            peers: vec![PeerConfig {
                public_key: a_key.public_key(),
                endpoint: None,
                allowed_ips: vec![Ipv4Prefix::host(AGENT_IP)],
                persistent_keepalive: None,
                roaming: Roaming::Any,
            }],
            limits: Limits::default(),
            timers: ProtocolTimers::default(),
        };
        let b_pub = b_cfg.private_key.public_key();
        let mut pair = Self {
            a: Device::new(a_cfg, now, Duration::ZERO).unwrap(),
            b: Device::new(b_cfg, now, Duration::ZERO).unwrap(),
            a_addr,
            b_addr,
            now,
        };
        let t = pair.a.poll_timeout().unwrap();
        pair.now = pair.now.max(t);
        pair.a.handle_timeout(pair.now);
        pair.pump();
        assert!(
            pair.a.has_session(&b_pub, pair.now),
            "the handshake completed"
        );
        pair
    }

    /// 両方の device が出した datagram を、出なくなるまで運ぶ。
    fn pump(&mut self) {
        loop {
            let mut moved = false;
            while let Some(tx) = self.a.poll_transmit() {
                moved = true;
                self.b.handle_datagram(self.now, self.a_addr, &tx.payload);
            }
            while let Some(tx) = self.b.poll_transmit() {
                moved = true;
                self.a.handle_datagram(self.now, self.b_addr, &tx.payload);
            }
            while self.a.poll_packet().is_some() || self.b.poll_packet().is_some() {}
            while self.a.poll_event().is_some() || self.b.poll_event().is_some() {}
            if !moved {
                break;
            }
        }
    }
}

#[test]
fn the_tunnel_send_and_receive_allocate_only_what_is_allowed() {
    let mut pair = Pair::connected();
    let packet = ipv4_packet(AGENT_IP, SERVER_IP, SIZE);
    // 慣らし:待ち行列と内部の表が育ち切るまで流す
    for _ in 0..64 {
        pair.a.handle_packet(pair.now, &packet);
        while let Some(tx) = pair.a.poll_transmit() {
            pair.b.handle_datagram(pair.now, pair.a_addr, &tx.payload);
        }
        while pair.b.poll_packet().is_some() {}
        while pair.a.poll_event().is_some() || pair.b.poll_event().is_some() {}
    }

    // 送信:暗号文を先に集めておき、後で受信に流す
    let mut sent: Vec<Transmit> = Vec::with_capacity(N);
    let window = ThreadWindow::open();
    for _ in 0..N {
        pair.a.handle_packet(pair.now, &packet);
        sent.push(pair.a.poll_transmit().expect("a datagram"));
    }
    let send_calls = window.calls();
    eprintln!("send: {send_calls} calls for {N} packets");

    // 受信
    let window = ThreadWindow::open();
    for tx in &sent {
        pair.b.handle_datagram(pair.now, pair.a_addr, &tx.payload);
        let p = pair.b.poll_packet().expect("a packet");
        assert_eq!(p.len(), SIZE);
    }
    let receive_calls = window.calls();
    eprintln!("receive: {receive_calls} calls for {N} datagrams");

    assert!(
        send_calls <= SEND_ALLOWED * N,
        "send allocates {send_calls} times for {N} packets; the allowance is {SEND_ALLOWED} per packet"
    );
    assert!(
        receive_calls <= RECEIVE_ALLOWED * N,
        "receive allocates {receive_calls} times for {N} datagrams; the allowance is {RECEIVE_ALLOWED} per datagram"
    );
}
