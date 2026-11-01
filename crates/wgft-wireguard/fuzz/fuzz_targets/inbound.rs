//! 受信の経路の fuzz。
//!
//! agent の側の Device (A) に、本物の相手 (B) の datagram を壊したり壊さなかったりして渡し、
//! 任意のバイト列の datagram も混ぜ、時計を進める。どの手順でも panic せず、A が持つものが
//! いつも Limits の中にあることを確かめる。A の出力はわざと取り出さずに溜め、上限に当てる。

#![no_main]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use wgft_wireguard::{
    Device, DeviceConfig, Ipv4Prefix, Limits, PeerConfig, PrivateKey, ProtocolTimers, PublicKey,
    Roaming, Zeroizing,
};

const AGENT_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 2);
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);

fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p[20..].copy_from_slice(payload);
    p
}

struct Input<'a>(&'a [u8]);

impl Input<'_> {
    fn byte(&mut self) -> Option<u8> {
        let (b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(*b)
    }

    fn bytes(&mut self, n: usize) -> &[u8] {
        let n = n.min(self.0.len());
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        head
    }
}

/// 固定の鍵と公開鍵。入力に依らず、Device も変えないので、1 回だけ作る (X25519 の計算が高い)
struct Keys {
    a_key: PrivateKey,
    b_key: PrivateKey,
    a_pub: PublicKey,
    b_pub: PublicKey,
}

fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let a_key = PrivateKey::generate(&[0xa1; 32]);
        let b_key = PrivateKey::generate(&[0xb2; 32]);
        Keys {
            a_pub: a_key.public_key(),
            b_pub: b_key.public_key(),
            a_key,
            b_key,
        }
    })
}

fn check(device: &Device) {
    let held = device.held();
    let limits = device.limits();
    assert!(held.transmit_packets <= limits.transmit_packets);
    assert!(held.transmit_bytes <= limits.transmit_bytes);
    assert!(held.deliver_packets <= limits.deliver_packets);
    assert!(held.deliver_bytes <= limits.deliver_bytes);
    assert!(held.events <= limits.events);
    assert!(held.staged_packets_max <= limits.staged_packets);
    assert!(held.staged_bytes_max <= limits.staged_packets * device.mtu());
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let base = Instant::now();
    let unix = Duration::from_hours(500_000);
    let k = keys();
    let a_addr: SocketAddr = "198.51.100.2:40000".parse().unwrap();
    let other: SocketAddr = "192.0.2.66:9999".parse().unwrap();
    let b_addr: SocketAddr = "203.0.113.1:51820".parse().unwrap();

    let mut ca = DeviceConfig::agent(
        k.a_key.clone(),
        k.b_pub,
        Some(b_addr),
        SERVER_IP,
        Duration::from_secs(25),
    );
    // 小さな上限で溢れの経路を通す
    ca.limits = Limits {
        staged_packets: 4,
        transmit_packets: 8,
        transmit_bytes: 4096,
        deliver_packets: 8,
        deliver_bytes: 4096,
        events: 4,
    };
    let cb = DeviceConfig {
        private_key: k.b_key.clone(),
        mtu: 1420,
        peers: vec![PeerConfig {
            public_key: k.a_pub,
            endpoint: None,
            allowed_ips: vec![Ipv4Prefix::host(AGENT_IP)],
            persistent_keepalive: None,
            roaming: Roaming::Any,
        }],
        limits: Limits::default(),
        timers: ProtocolTimers::default(),
    };
    let a_pub = k.a_pub;
    let mut a = Device::with_seed(ca, Zeroizing::new([1; 32]), base, unix).unwrap();
    let mut b = Device::with_seed(cb, Zeroizing::new([2; 32]), base, unix).unwrap();
    let mut t = Duration::ZERO;

    while let Some(op) = input.byte() {
        let now = base + t;
        match op % 10 {
            0 => t += Duration::from_millis(u64::from(input.byte().unwrap_or(0)) * 20),
            1 => t += Duration::from_secs(u64::from(input.byte().unwrap_or(0))),
            2 => {
                // A の送ったものを B へ運ぶ。A の送信のキューはここでだけ空く
                while let Some(tx) = a.poll_transmit() {
                    b.handle_datagram(now, a_addr, &tx.payload);
                }
            }
            3 => {
                // B の次の datagram を、1 バイト壊すか壊さずに、どちらかの送信元から A へ渡す
                let how = input.byte().unwrap_or(0);
                if let Some(mut tx) = b.poll_transmit() {
                    if how & 1 == 1 && !tx.payload.is_empty() {
                        let at = usize::from(how >> 1) % tx.payload.len();
                        tx.payload[at] ^= input.byte().unwrap_or(1) | 1;
                    }
                    let from = if how & 0x80 == 0 { b_addr } else { other };
                    a.handle_datagram(now, from, &tx.payload);
                }
            }
            4 => {
                // 任意のバイト列。先頭の type のバイトは有効な値に寄せる
                let len = usize::from(input.byte().unwrap_or(0)) * 2;
                let mut d = input.bytes(len).to_vec();
                if let Some(first) = d.first_mut() {
                    *first %= 6;
                }
                a.handle_datagram(now, other, &d);
            }
            5 => {
                let len = usize::from(input.byte().unwrap_or(0)) * 8;
                let payload = input.bytes(len).to_vec();
                b.handle_packet(now, &ipv4(SERVER_IP, AGENT_IP, &payload));
            }
            6 => {
                let len = usize::from(input.byte().unwrap_or(0));
                let raw = input.bytes(len).to_vec();
                a.handle_packet(now, &raw);
                a.handle_packet(now, &ipv4(AGENT_IP, SERVER_IP, &raw));
            }
            7 => {
                a.handle_timeout(now);
                b.handle_timeout(now);
            }
            8 => {
                // B の検査を通さない任意の中身を暗号化して A へ渡す。受信の側の中身の検査と
                // AllowedIPs の検査が任意の packet を見る
                let len = usize::from(input.byte().unwrap_or(0)) * 2;
                let raw = input.bytes(len).to_vec();
                if let Some(d) = b.encapsulate_unchecked(now, &a_pub, &raw) {
                    a.handle_datagram(now, b_addr, &d);
                }
            }
            _ => {
                while a.poll_packet().is_some() {}
                while a.poll_event().is_some() {}
            }
        }
        check(&a);
        let _ = a.poll_timeout();
        while b.poll_event().is_some() {}
        while b.poll_packet().is_some() {}
    }
});
