//! 暗号の作業者を使う受信と送信が、packet ごとにヒープを確保しないことの試験。
//!
//! 作業者のスレッドの確保も数えるので、プロセスの数え ([`process_alloc_calls`]) を使う。慣らし (仕事の列と
//! 作業者の起動) の後に、作業者に渡る大きさのバッチを何回も暗号化と復号し、確保の呼び出しが 0 であることを
//! 確かめる。

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use wgft_alloc_count::{CountingAlloc, process_alloc_calls};
use wgft_udp_batch::crypto::Crypto;
use wgft_udp_batch::{RX_SLOT, RxBatch, RxMeta, TxBatch};
use wgft_wireguard::{
    DEFAULT_MTU, Device, DeviceConfig, Ipv4Prefix, Limits, PeerConfig, PrivateKey, ProtocolTimers,
    Roaming,
};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

const AGENT_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 2);
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);
/// 1 つの枠の GRO の datagram の数。
const PER_SLOT: usize = 40;
const SLOTS: usize = 4;
const LANES: usize = 3;
const BATCHES: usize = 50;
/// 慣らしのバッチの数。数えない。
const WARM: usize = 2;

fn packet(len: usize, tag: u8) -> Vec<u8> {
    let mut p = vec![tag; len];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
    p[8] = 64;
    p[9] = 6;
    p[12..16].copy_from_slice(&AGENT_IP.octets());
    p[16..20].copy_from_slice(&SERVER_IP.octets());
    p
}

fn connected() -> (Device, Device, SocketAddr, Instant) {
    let a = PrivateKey::generate(&[0xa1; 32]);
    let b = PrivateKey::generate(&[0xb2; 32]);
    let agent_addr: SocketAddr = "198.51.100.2:40000".parse().unwrap();
    let server_addr: SocketAddr = "203.0.113.1:51820".parse().unwrap();
    let now = Instant::now();
    let mut agent = Device::new(
        DeviceConfig::agent(
            a.clone(),
            b.public_key(),
            Some(server_addr),
            SERVER_IP,
            Duration::from_secs(25),
        ),
        now,
        Duration::ZERO,
    )
    .unwrap();
    let mut server = Device::new(
        DeviceConfig {
            private_key: b,
            mtu: DEFAULT_MTU,
            peers: vec![PeerConfig {
                public_key: a.public_key(),
                endpoint: None,
                allowed_ips: vec![Ipv4Prefix::host(AGENT_IP)],
                persistent_keepalive: None,
                roaming: Roaming::Any,
            }],
            limits: Limits::default(),
            timers: ProtocolTimers::default(),
        },
        now,
        Duration::ZERO,
    )
    .unwrap();
    agent.handle_timeout(now);
    let mut buf = vec![0; usize::from(u16::MAX)];
    for _ in 0..4 {
        while let Some(t) = agent.poll_transmit() {
            server.handle_datagram(now, agent_addr, &t.payload, &mut buf);
        }
        while let Some(t) = server.poll_transmit() {
            agent.handle_datagram(now, server_addr, &t.payload, &mut buf);
        }
    }
    (agent, server, agent_addr, now)
}

/// 数えるのはプロセスのすべてのスレッドの確保である。`cargo test` は試験を同じプロセスのスレッドで動かし、
/// libtest の main のスレッドは試験が終わるたびに結果の記録を確保するので、別の試験の窓に混ざる。このため
/// 場面をこの 1 つの試験の中で順に流す。
#[test]
fn the_crypto_workers_allocate_nothing_per_packet() {
    rounds();
    pipelined_opening();
}

/// 回ごとに待つ形の暗号化と復号。
fn rounds() {
    let (mut agent, mut server, from, now) = connected();
    let n = SLOTS * PER_SLOT;
    let mut tx = TxBatch::new(n, false, agent.mtu(), agent.max_transmit_len(), LANES);
    let mut rx = RxBatch::new(SLOTS, false, RX_SLOT, LANES);
    let mut agent_crypto = Crypto::new(LANES, 0);
    let mut server_crypto = Crypto::new(LANES, 0);
    assert_eq!(agent_crypto.workers(), LANES - 1);
    let p = packet(1400, 7);
    {
        let mut slots = tx.packet_slots();
        for i in 0..n {
            slots.slot(i)[..p.len()].copy_from_slice(&p);
            slots.set_len(i, p.len());
        }
    }
    let mut delivered = 0;
    let mut calls = 0;
    for batch in 0..BATCHES {
        let before = process_alloc_calls();
        // agent が暗号化し、server の受信の枠に GRO の形で並べる
        tx.clear();
        agent_crypto.seal(&mut tx, &mut agent, now, n).unwrap();
        assert_eq!(tx.n_sealed, n);
        for s in 0..SLOTS {
            let mut len = 0;
            let seg = tx.datagram(s * PER_SLOT).1.len();
            for k in 0..PER_SLOT {
                let (_, d) = tx.datagram(s * PER_SLOT + k);
                let at = s * RX_SLOT + len;
                rx.data_mut()[at..at + d.len()].copy_from_slice(d);
                len += d.len();
            }
            rx.meta[s] = RxMeta {
                from: Some(from),
                len: u32::try_from(len).unwrap(),
                seg: u32::try_from(seg).unwrap(),
            };
        }
        server_crypto.start_open(&rx, SLOTS);
        while server_crypto.open_round(&mut rx, &mut server, now).unwrap() {
            let (u, o) = server_crypto.each_packet(&rx, false, |_| {});
            delivered += u + o;
        }
        if batch >= WARM {
            calls += process_alloc_calls() - before;
        }
    }
    assert_eq!(delivered, BATCHES * n);
    assert_eq!(server.drops().total(), 0);
    assert_eq!(
        calls,
        0,
        "heap allocations in {} batches of {n} packets",
        BATCHES - WARM
    );
}

/// 受信の重ね。
#[expect(
    clippy::many_single_char_names,
    reason = "the test reads like the data plane it imitates"
)]
fn pipelined_opening() {
    // 作業者の 2 つのレーンに収まるバッチ
    const PIPE_PER_SLOT: usize = 10;
    let (mut agent, mut server, from, now) = connected();
    let n = SLOTS * PIPE_PER_SLOT;
    let mut tx = TxBatch::new(n, false, agent.mtu(), agent.max_transmit_len(), 1);
    let mut stores = [
        RxBatch::new(SLOTS, false, RX_SLOT, LANES),
        RxBatch::new(SLOTS, false, RX_SLOT, LANES),
    ];
    let mut crypto = Crypto::new(LANES, 0);
    let p = packet(1400, 7);
    let mut delivered = 0;
    let mut calls = 0;
    let mut inflight: Option<usize> = None;
    for batch in 0..BATCHES {
        let cur = batch % 2;
        let before = process_alloc_calls();
        tx.clear();
        {
            let mut slots = tx.packet_slots();
            for i in 0..n {
                slots.slot(i)[..p.len()].copy_from_slice(&p);
                slots.set_len(i, p.len());
            }
        }
        for i in 0..n {
            let (packet, sealed) = tx.seal_slot(i);
            let o = agent.handle_packet(now, packet, sealed).unwrap();
            tx.push_sealed(o.to, o.len);
        }
        let rx = &mut stores[cur];
        for s in 0..SLOTS {
            let mut len = 0;
            let seg = tx.datagram(s * PIPE_PER_SLOT).1.len();
            for k in 0..PIPE_PER_SLOT {
                let (_, d) = tx.datagram(s * PIPE_PER_SLOT + k);
                let at = s * RX_SLOT + len;
                rx.data_mut()[at..at + d.len()].copy_from_slice(d);
                len += d.len();
            }
            rx.meta[s] = RxMeta {
                from: Some(from),
                len: u32::try_from(len).unwrap(),
                seg: u32::try_from(seg).unwrap(),
            };
        }
        assert!(crypto.can_pipeline(rx, SLOTS));
        crypto.begin_pipelined(cur, rx, SLOTS, &mut server, now);
        if let Some(prev) = inflight {
            let [a, b] = &mut stores;
            let old = if prev == 0 { a } else { b };
            crypto
                .finish_pipelined(prev, old, &mut server, now)
                .unwrap();
            let (u, o) = crypto.each_pipelined(prev, old, false, |_| {});
            delivered += u + o;
        }
        crypto.offer_pipelined(cur, &mut stores[cur]).unwrap();
        inflight = Some(cur);
        if batch >= WARM {
            calls += process_alloc_calls() - before;
        }
    }
    let prev = inflight.unwrap();
    crypto
        .finish_pipelined(prev, &mut stores[prev], &mut server, now)
        .unwrap();
    let (u, o) = crypto.each_pipelined(prev, &stores[prev], false, |_| {});
    delivered += u + o;
    assert_eq!(delivered, BATCHES * n);
    assert_eq!(server.drops().total(), 0);
    assert_eq!(calls, 0, "heap allocations in pipelined batches");
}
