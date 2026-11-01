//! 受信の経路の fuzz。
//!
//! agent の側の Device (A) に、本物の相手 (B) の datagram を壊したり壊さなかったりして渡し、
//! 任意のバイト列の datagram も混ぜ、時計を進める。どの手順でも panic せず、A が持つものが
//! いつも Limits の中にあることを確かめる。device が積む送る datagram は取り出す手順を絞って溜め、上限に当てる。
//! データの datagram は呼び手の buffer に暗号化されるので、手順の側の有限の列 (最大 `WIRE`) に置き、
//! 遅らせて、壊して、別の送信元から渡す。

#![no_main]

use std::collections::VecDeque;
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

/// 手順の側が持つ、まだ渡していないデータの datagram の最大の数。
const WIRE: usize = 8;

fn push_wire(wire: &mut VecDeque<Vec<u8>>, datagram: &[u8]) {
    if wire.len() == WIRE {
        wire.pop_front();
    }
    wire.push_back(datagram.to_vec());
}

fn check(device: &Device) {
    let held = device.held();
    let limits = device.limits();
    assert!(held.transmit_packets <= limits.transmit_packets);
    assert!(held.transmit_bytes <= limits.transmit_bytes);
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
    // 呼び手の buffer。復号の行き先と、暗号文の行き先
    let mut plain = vec![0u8; usize::from(u16::MAX)];
    // 暗号化したまま渡していないデータの datagram。B から A へ向かうものと、A から B へ向かうもの
    let mut b_wire: VecDeque<Vec<u8>> = VecDeque::new();
    let mut a_wire: VecDeque<Vec<u8>> = VecDeque::new();
    let mut sealed = vec![0u8; b.max_transmit_len().max(a.max_transmit_len())];

    while let Some(op) = input.byte() {
        let now = base + t;
        match op % 10 {
            0 => t += Duration::from_millis(u64::from(input.byte().unwrap_or(0)) * 20),
            1 => t += Duration::from_secs(u64::from(input.byte().unwrap_or(0))),
            2 => {
                // A の送ったものを B へ運ぶ。A の送信のキューと、A のデータの列はここでだけ空く
                while let Some(tx) = a.poll_transmit() {
                    b.handle_datagram(now, a_addr, &tx.payload, &mut plain);
                }
                while let Some(d) = a_wire.pop_front() {
                    b.handle_datagram(now, a_addr, &d, &mut plain);
                }
            }
            3 => {
                // B の次の datagram を、1 バイト壊すか壊さずに、どちらかの送信元から A へ渡す
                let how = input.byte().unwrap_or(0);
                // 取り出す先は、device の送信のキューか、データの列。bit 6 で先に見る方を選ぶ
                let queued = if how & 0x40 == 0 {
                    b.poll_transmit()
                        .map(|tx| tx.payload)
                        .or_else(|| b_wire.pop_front())
                } else {
                    b_wire
                        .pop_front()
                        .or_else(|| b.poll_transmit().map(|tx| tx.payload))
                };
                if let Some(mut payload) = queued {
                    if how & 1 == 1 && !payload.is_empty() {
                        let at = usize::from(how >> 1) % payload.len();
                        payload[at] ^= input.byte().unwrap_or(1) | 1;
                    }
                    let from = if how & 0x80 == 0 { b_addr } else { other };
                    a.handle_datagram(now, from, &payload, &mut plain);
                }
            }
            4 => {
                // 任意のバイト列。先頭の type のバイトは有効な値に寄せる
                let len = usize::from(input.byte().unwrap_or(0)) * 2;
                let mut d = input.bytes(len).to_vec();
                if let Some(first) = d.first_mut() {
                    *first %= 6;
                }
                a.handle_datagram(now, other, &d, &mut plain);
            }
            5 => {
                let len = usize::from(input.byte().unwrap_or(0)) * 8;
                let payload = input.bytes(len).to_vec();
                if let Some(o) =
                    b.handle_packet(now, &ipv4(SERVER_IP, AGENT_IP, &payload), &mut sealed)
                {
                    push_wire(&mut b_wire, &sealed[..o.len]);
                }
            }
            6 => {
                let len = usize::from(input.byte().unwrap_or(0));
                let raw = input.bytes(len).to_vec();
                for packet in [raw.clone(), ipv4(AGENT_IP, SERVER_IP, &raw)] {
                    if let Some(o) = a.handle_packet(now, &packet, &mut sealed) {
                        push_wire(&mut a_wire, &sealed[..o.len]);
                    }
                }
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
                    a.handle_datagram(now, b_addr, &d, &mut plain);
                }
            }
            _ => while a.poll_event().is_some() {},
        }
        check(&a);
        let _ = a.poll_timeout();
        while b.poll_event().is_some() {}
    }
});
