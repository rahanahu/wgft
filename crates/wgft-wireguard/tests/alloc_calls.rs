//! トンネルの受信と送信が、packet ごとに何回ヒープを確保するかの試験。
//!
//! 慣らし (ハンドシェイクと最初の数 packet) の後の定常で、`Device` の送信 (`handle_packet`) と受信
//! (`handle_datagram`) を N 回流し、確保の呼び出しの数を数える。許容は packet あたり 0 で、確保が増えると
//! 試験が落ちる。暗号文と平文の宛先は、窓を開く前に確保した buffer で、呼び手の側の置き場に当たる。数えは
//! 窓を開いたスレッドだけを数える。

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use wgft_alloc_count::{CountingAlloc, ThreadWindow};
use wgft_wireguard::{
    DATA_OVERHEAD, Device, DeviceConfig, Ipv4Prefix, Limits, PeerConfig, PrivateKey,
    ProtocolTimers, Roaming,
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

/// 暗号文 1 つの buffer の長さ。詰め物で 16 の倍数に伸びるので、packet の長さに header と tag を足しただけでは足りない。
const SLOT: usize = SIZE.next_multiple_of(16) + DATA_OVERHEAD;

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
    /// 復号の行き先。
    plain: Vec<u8>,
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
            plain: vec![0; usize::from(u16::MAX)],
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
                self.b
                    .handle_datagram(self.now, self.a_addr, &tx.payload, &mut self.plain);
            }
            while let Some(tx) = self.b.poll_transmit() {
                moved = true;
                self.a
                    .handle_datagram(self.now, self.b_addr, &tx.payload, &mut self.plain);
            }
            while self.a.poll_event().is_some() || self.b.poll_event().is_some() {}
            if !moved {
                break;
            }
        }
    }
}

#[test]
fn the_tunnel_send_and_receive_allocate_nothing_per_packet() {
    let mut pair = Pair::connected();
    let packet = ipv4_packet(AGENT_IP, SERVER_IP, SIZE);
    let mut plain = vec![0u8; usize::from(u16::MAX)];
    let mut sealed = vec![0u8; pair.a.max_transmit_len()];
    // 慣らし:内部の表が育ち切るまで流す
    for _ in 0..64 {
        let out = pair
            .a
            .handle_packet(pair.now, &packet, &mut sealed)
            .expect("a datagram");
        let got = pair
            .b
            .handle_datagram(pair.now, pair.a_addr, &sealed[..out.len], &mut plain);
        assert_eq!(got, Some(SIZE));
        while pair.a.poll_event().is_some() || pair.b.poll_event().is_some() {}
    }

    // 送信:暗号文を、先に確保した連続した buffer に集めておき、後で受信に流す
    let mut arena = vec![0u8; N * SLOT];
    let mut lens = vec![0usize; N];
    let window = ThreadWindow::open();
    for (slot, len) in arena.as_chunks_mut::<SLOT>().0.iter_mut().zip(&mut lens) {
        *len = pair
            .a
            .handle_packet(pair.now, &packet, slot)
            .expect("a datagram")
            .len;
    }
    let send_calls = window.calls();
    eprintln!("send: {send_calls} calls for {N} packets");

    // 受信
    let window = ThreadWindow::open();
    for (slot, len) in arena.as_chunks::<SLOT>().0.iter().zip(&lens) {
        let got = pair
            .b
            .handle_datagram(pair.now, pair.a_addr, &slot[..*len], &mut plain);
        assert_eq!(got, Some(SIZE));
    }
    let receive_calls = window.calls();
    eprintln!("receive: {receive_calls} calls for {N} datagrams");

    assert_eq!(
        send_calls, 0,
        "send allocates {send_calls} times for {N} packets; the allowance is 0"
    );
    assert_eq!(
        receive_calls, 0,
        "receive allocates {receive_calls} times for {N} datagrams; the allowance is 0"
    );
}
