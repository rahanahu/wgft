//! Hash S の正しさの関門 G0 の決定的な試験 (試作、notes の common-design.md の 6.2 節と independent-exploration.md
//! の 8 節の E2 の「決定的な試験」)。`dataplane::tests` の子の module で、その試験の台 (2 つの device の組) を使う。
//!
//! - 届け方の規則 (6.8.2):TCP、UDP、ICMP、断片の行きと戻りが同じ区画に着く。区画の核を実際に動かし、SYN、
//!   データ、FIN、TIME_WAIT への SYN (RFC 6191 の使い直し)、RST、TCP を引用する ICMP の誤りが、SYN を受けた区画に
//!   着き、その区画だけが答えることを確かめる。dial は agent に無いので試さない
//! - 止まった区画の番号の遅れ (I6):区画 1 が在庫を持ったまま止まり、front かほかの区画が遅れの上限より多く
//!   送った後に区画 1 が送っても、遅れた在庫を捨てて新しい番号で送り、相手の replay の捨てが 0
//! - `sendmmsg` の直前の確かめと `EAGAIN`:暗号化の後に遅れが上限を超えたら暗号化し直し、`EAGAIN` で送れなかった
//!   datagram の在庫を捨てて書けるようになった後に暗号化し直す。相手はすべての packet を 1 回ずつ受ける
//! - WireGuard の timer (I8):相乗りの在庫が使われずに捨てられても、相手が黙った後のハンドシェイクの時機が Inline
//!   と同じ
//!
//! boost の飢えの試験は核の crate (`wgft-wgstack` の `hashs_tests.rs`)、loom の模型は `wgft-hashs-sync` にある。
#![expect(clippy::cast_possible_truncation, reason = "test packets")]

use std::cell::{Cell, RefCell};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use wgft_wgstack::{
    BoostPolicy, BoostPool, Budget, Config, Limits, NoHook, Partition, Stack, Time,
};
use wgft_wireguard::DropReason;

use super::super::batch::{TxBatch, tx_store};
use super::super::hashs::front::Front;
use super::super::hashs::part::{PartSend, PartSent, PartSink, take_lane};
use super::super::hashs::steer::{Route, Steer};
use super::super::hashs::{Hub, LAG_LIMIT, STOCK_MAX_AGE};
use super::super::{Local, Shared, Wake, clock};
use super::{AGENT_IP, B_ADDR, Bench, SERVER_IP, Stub, packet, tcp_packet};
use crate::batching::Batching;

// ---- 届け方の規則 ----

const AGENT: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 2);
const REMOTE: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;

fn checksum(data: &[u8], init: u32) -> u16 {
    let mut sum = init;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(*last) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, frag: u16, body: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    let len = (20 + body.len()) as u16;
    p[2..4].copy_from_slice(&len.to_be_bytes());
    p[6..8].copy_from_slice(&frag.to_be_bytes());
    p[8] = 64;
    p[9] = proto;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let c = checksum(&p, 0);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p.extend_from_slice(body);
    p
}

#[expect(clippy::too_many_arguments, reason = "the fields of a segment")]
fn tcp(
    src: SocketAddrV4,
    dst: SocketAddrV4,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut t = vec![0u8; 20];
    t[0..2].copy_from_slice(&src.port().to_be_bytes());
    t[2..4].copy_from_slice(&dst.port().to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = 5 << 4;
    t[13] = flags;
    t[14..16].copy_from_slice(&65535u16.to_be_bytes());
    t.extend_from_slice(payload);
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src.ip().octets());
    pseudo.extend_from_slice(&dst.ip().octets());
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&(t.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(&t);
    let c = checksum(&pseudo, 0);
    t[16..18].copy_from_slice(&c.to_be_bytes());
    ipv4(*src.ip(), *dst.ip(), 6, 0x4000, &t)
}

fn udp(src: SocketAddrV4, dst: SocketAddrV4, frag: u16) -> Vec<u8> {
    let mut u = vec![0u8; 8];
    u[0..2].copy_from_slice(&src.port().to_be_bytes());
    u[2..4].copy_from_slice(&dst.port().to_be_bytes());
    u[4..6].copy_from_slice(&12u16.to_be_bytes());
    u.extend_from_slice(b"ping");
    ipv4(*src.ip(), *dst.ip(), 17, frag, &u)
}

fn icmp(src: Ipv4Addr, dst: Ipv4Addr, ty: u8, code: u8, quoted: &[u8]) -> Vec<u8> {
    let mut m = vec![ty, code, 0, 0, 0, 0, 0x05, 0x78];
    m.extend_from_slice(&quoted[..quoted.len().min(28)]);
    let c = checksum(&m, 0);
    m[2..4].copy_from_slice(&c.to_be_bytes());
    ipv4(src, dst, 1, 0, &m)
}

#[test]
fn the_no_tcp_on_zero_arm_keeps_tcp_off_partition_0() {
    let steer = Steer::new(4, AGENT).without_tcp_on_zero();
    let mut used = [0usize; 4];
    for i in 0..3000u32 {
        let remote = SocketAddrV4::new(Ipv4Addr::from(0x0a00_0000 + i * 31), 1024 + i as u16);
        let local = SocketAddrV4::new(AGENT, 80);
        let Route::Part(k) = steer.inbound(0, &tcp(remote, local, i, 0, SYN, &[])) else {
            panic!("routed");
        };
        used[k] += 1;
        assert_eq!(steer.outbound(0, &tcp(local, remote, 1, i, ACK, &[])), k);
        assert_eq!(steer.inbound(0, &udp(remote, local, 0)), Route::Part(0));
    }
    assert_eq!(used[0], 0);
    assert!(used[1..].iter().all(|&n| n > 800), "{used:?}");
    // P = 2 では外さない (TCP の区画が 1 つになる)
    let two = Steer::new(2, AGENT).without_tcp_on_zero();
    let zero = (0..200u16).any(|p| {
        two.inbound(
            0,
            &tcp(
                SocketAddrV4::new(REMOTE, 2000 + p),
                SocketAddrV4::new(AGENT, 80),
                0,
                0,
                SYN,
                &[],
            ),
        ) == Route::Part(0)
    });
    assert!(zero);
}

#[test]
fn both_directions_of_every_flow_reach_the_same_partition() {
    let steer = Steer::new(4, AGENT);
    let mut used = [0usize; 4];
    for i in 0..4000u32 {
        let rport = 1024 + (i % 60000) as u16;
        let raddr = Ipv4Addr::from(0x0a00_0000 + i * 7919);
        let lport = [22, 80, 443, 25565][i as usize % 4];
        let remote = SocketAddrV4::new(raddr, rport);
        let local = SocketAddrV4::new(AGENT, lport);
        let Route::Part(k) = steer.inbound(0, &tcp(remote, local, i, 0, SYN, &[])) else {
            panic!("a TCP segment that is not a fragment is routed");
        };
        used[k] += 1;
        for flags in [ACK, ACK | FIN, RST, RST | ACK] {
            assert_eq!(
                steer.inbound(0, &tcp(remote, local, i, 1, flags, b"data")),
                Route::Part(k),
                "every segment of a 4-tuple goes to one partition"
            );
        }
        let reply = tcp(local, remote, 7, i + 1, SYN | ACK, &[]);
        assert_eq!(
            steer.outbound(0, &reply),
            k,
            "the reply belongs to the same partition"
        );
        // TCP を引用する ICMP の誤り (送った segment の引用) は同じ区画
        let err = icmp(raddr, AGENT, 3, 4, &reply);
        assert_eq!(steer.inbound(0, &err), Route::Part(k));
        let ttl = icmp(raddr, AGENT, 11, 0, &reply);
        assert_eq!(steer.inbound(0, &ttl), Route::Part(k));
        // UDP は向きによらず区画 0、UDP の断片も区画 0
        assert_eq!(steer.inbound(0, &udp(remote, local, 0)), Route::Part(0));
        assert_eq!(steer.outbound(0, &udp(local, remote, 0)), 0);
        assert_eq!(
            steer.inbound(0, &udp(remote, local, 0x2000)),
            Route::Part(0)
        );
        // ICMP の echo、UDP を引用する誤りは区画 0
        assert_eq!(
            steer.inbound(0, &icmp(raddr, AGENT, 8, 0, &[0; 8])),
            Route::Part(0)
        );
        assert_eq!(
            steer.inbound(0, &icmp(raddr, AGENT, 0, 0, &[0; 8])),
            Route::Part(0)
        );
        let quoted_udp = udp(local, remote, 0);
        assert_eq!(
            steer.inbound(0, &icmp(raddr, AGENT, 3, 3, &quoted_udp)),
            Route::Part(0)
        );
    }
    assert!(
        used.iter().all(|&n| n > 800),
        "the hash spreads the flows: {used:?}"
    );
    let remote = SocketAddrV4::new(REMOTE, 40000);
    let local = SocketAddrV4::new(AGENT, 80);
    // TCP の断片は捨てて数える (試作)。2 つ目以降の断片も
    let mut frag = tcp(remote, local, 1, 0, ACK, b"x");
    frag[6] = 0x20;
    assert_eq!(steer.inbound(0, &frag), Route::TcpFragment);
    frag[6] = 0x00;
    frag[7] = 0x10;
    assert_eq!(steer.inbound(0, &frag), Route::TcpFragment);
    // 自分のアドレス宛てでない packet、壊れた packet、知らない protocol は区画 0
    let other = tcp(
        remote,
        SocketAddrV4::new(Ipv4Addr::new(10, 200, 0, 9), 80),
        1,
        0,
        SYN,
        &[],
    );
    assert_eq!(steer.inbound(0, &other), Route::Part(0));
    assert_eq!(steer.inbound(0, &[0x45, 0, 0]), Route::Part(0));
    assert_eq!(
        steer.inbound(0, &ipv4(REMOTE, AGENT, 47, 0, b"gre")),
        Route::Part(0)
    );
    // IP の option を持つ TCP も、ポートで同じ区画
    let plain = tcp(remote, local, 1, 0, SYN, &[]);
    let mut opt = plain[..20].to_vec();
    opt[0] = 0x46;
    opt.extend_from_slice(&[1, 1, 1, 1]);
    opt.extend_from_slice(&plain[20..]);
    let len = opt.len() as u16;
    opt[2..4].copy_from_slice(&len.to_be_bytes());
    assert_eq!(steer.inbound(0, &opt), steer.inbound(0, &plain));
    assert_eq!(steer.parts(), 4);
}

/// 区画の核 `parts` 個と振り分け。packet を区画に渡し、どの区画が何を答えたかを集める。
struct Cores {
    steer: Steer,
    cores: Vec<Stack<NoHook>>,
    now: Time,
    _pool: Arc<BoostPool>,
}

impl Cores {
    fn new(parts: usize) -> Self {
        let pool = Arc::new(BoostPool::new(Budget::new().unwrap()).unwrap());
        let limits = Limits {
            max_flows: 64,
            accept_queue: 16,
            syn_rows: 32,
            tw_rows: 64,
            ctl_slots: 32,
            ..Limits::default()
        };
        let cores = (0..parts)
            .map(|k| {
                let config = Config {
                    limits: crate::dataplane::stack::part_limits(limits, k, parts),
                    boost: BoostPolicy::Never,
                    partition: Some(Partition {
                        index: k as u16,
                        count: parts as u16,
                        shared_seed: [5; 64],
                    }),
                    ..Config::new(AGENT, 1420)
                };
                Stack::new(config, pool.view().unwrap(), &[k as u8 + 1; 64], NoHook).unwrap()
            })
            .collect();
        Self {
            steer: Steer::new(parts, AGENT),
            cores,
            now: Time::ZERO,
            _pool: pool,
        }
    }

    /// `p` を振り分けて区画の核に渡し、区画の番号を返す。
    fn deliver(&mut self, p: &[u8]) -> usize {
        let Route::Part(k) = self.steer.inbound(0, p) else {
            panic!("not routed");
        };
        self.cores[k].handle_packet(self.now, p);
        k
    }

    /// 全区画の出力を (区画、packet) で集める。どの出力も、送った区画の流れに属する。
    fn outputs(&mut self) -> Vec<(usize, Vec<u8>)> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 2048];
        for (k, c) in self.cores.iter_mut().enumerate() {
            while let Some(n) = c.poll_transmit(self.now, &mut buf) {
                let p = buf[..n].to_vec();
                assert_eq!(
                    self.steer.outbound(0, &p),
                    k,
                    "a partition answers only its flows"
                );
                out.push((k, p));
            }
            c.check_invariants().unwrap();
        }
        out
    }

    fn advance(&mut self, d: Duration) {
        self.now = self.now + d;
        for c in &mut self.cores {
            c.handle_timeout(self.now);
        }
    }
}

fn seq_of(p: &[u8]) -> u32 {
    u32::from_be_bytes([p[24], p[25], p[26], p[27]])
}

fn flags_of(p: &[u8]) -> u8 {
    p[33]
}

#[test]
fn a_flow_lives_and_ends_inside_its_partition() {
    let parts = 4;
    let mut n = Cores::new(parts);
    let mut ls = Vec::new();
    for c in &mut n.cores {
        ls.push(c.listen_tcp(n.now, SocketAddrV4::new(AGENT, 80)).unwrap());
    }
    let local = SocketAddrV4::new(AGENT, 80);
    // 各区画に当たる相手のポートを 1 つずつ探す
    let mut flows = vec![None; parts];
    for rport in 40000..41000u16 {
        let remote = SocketAddrV4::new(REMOTE, rport);
        if let Route::Part(k) = n.steer.inbound(0, &tcp(remote, local, 0, 0, SYN, &[])) {
            flows[k].get_or_insert(remote);
        }
    }
    for (k, remote) in flows.into_iter().enumerate() {
        let remote = remote.expect("a port for every partition");
        // 握手:SYN、SYN-ACK、最後の ACK。accept は区画 k だけで成功する
        assert_eq!(n.deliver(&tcp(remote, local, 1000, 0, SYN, &[])), k);
        let out = n.outputs();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, k);
        assert_eq!(flags_of(&out[0].1), SYN | ACK);
        let iss = seq_of(&out[0].1);
        n.deliver(&tcp(remote, local, 1001, iss + 1, ACK, &[]));
        assert!(n.outputs().is_empty());
        let mut accepted = None;
        for (j, c) in n.cores.iter_mut().enumerate() {
            match c.accept(n.now, ls[j]) {
                Ok((id, from)) => {
                    assert_eq!(j, k, "only the partition that got the SYN accepts");
                    assert_eq!(from, remote);
                    accepted = Some(id);
                }
                Err(_) => assert_ne!(j, k),
            }
        }
        let id = accepted.unwrap();
        // データ、agent の側からの close、相手の FIN。TIME_WAIT は区画 k に残る
        n.deliver(&tcp(remote, local, 1001, iss + 1, ACK, b"hello"));
        let mut b = [0u8; 16];
        assert_eq!(n.cores[k].read(n.now, id, &mut b).unwrap(), 5);
        n.cores[k].close_conn(n.now, id);
        n.advance(Duration::from_millis(250));
        let out = n.outputs();
        assert!(out.iter().all(|(j, _)| *j == k));
        assert!(
            out.iter().any(|(_, p)| flags_of(p) & FIN != 0),
            "the agent's FIN"
        );
        n.deliver(&tcp(remote, local, 1006, iss + 2, ACK | FIN, &[]));
        let out = n.outputs();
        assert!(out.iter().all(|(j, _)| *j == k));
        assert!(!out.is_empty(), "the ACK of the peer's FIN");
        // TIME_WAIT への新しい SYN (番号は前の接続より先、RFC 6191 の使い直し) は同じ区画が答える
        assert_eq!(n.deliver(&tcp(remote, local, 90_000, 0, SYN, &[])), k);
        let out = n.outputs();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, k);
        assert_eq!(
            flags_of(&out[0].1),
            SYN | ACK,
            "the TIME_WAIT 4-tuple is reused"
        );
        let syn_ack = out[0].1.clone();
        // その SYN-ACK を引用する ICMP の誤り (PMTU) も区画 k に着く
        let err = icmp(REMOTE, AGENT, 3, 4, &syn_ack);
        assert_eq!(n.deliver(&err), k);
        let _ = n.outputs();
        // RST も区画 k に着き、握手の途中の行を消す
        assert_eq!(n.deliver(&tcp(remote, local, 90_001, 0, RST, &[])), k);
        assert!(n.outputs().is_empty());
    }
    // UDP は区画 0 だけが受ける
    assert_eq!(
        n.deliver(&udp(
            SocketAddrV4::new(REMOTE, 5000),
            SocketAddrV4::new(AGENT, 53),
            0
        )),
        0
    );
    let out = n.outputs();
    assert!(
        out.iter().all(|(j, _)| *j == 0),
        "the port-unreachable comes from partition 0"
    );
}

// ---- 番号の在庫と遅れの上限 ----

/// 区画の送り先の記録。`block` の間は `WouldBlock` を返す。
#[derive(Default)]
struct PartRecorder {
    sent: Vec<Vec<u8>>,
    block: bool,
}

impl PartSink for PartRecorder {
    fn send(&mut self, tx: &mut TxBatch) -> io::Result<usize> {
        if self.block {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let n = tx.n_msgs - tx.next;
        for k in tx.next..tx.n_msgs {
            let m = tx.msgs[k];
            for j in usize::from(m.first)..usize::from(m.first) + usize::from(m.count) {
                self.sent.push(tx.datagram(j).1.to_vec());
            }
        }
        Ok(n)
    }
}

/// front と区画の組。Bench の agent の device を front が持つ。
struct Lanes {
    t: Bench,
    front: Front,
    hub: Arc<Hub>,
}

impl Lanes {
    fn new(parts: usize) -> Self {
        let mut t = Bench::new(0);
        t.connected();
        let hub = Arc::new(Hub::new(parts, 1, 64 * 1452, clock::now()));
        let front = Front::new(Arc::clone(&hub), Steer::new(parts, AGENT_IP), t.b_pub);
        Self { t, front, hub }
    }

    fn part(&self, k: usize) -> (PartSend, Local<Stub>) {
        let tx = tx_store(
            Batching::default(),
            self.t.a.mtu(),
            self.t.a.max_transmit_len(),
        );
        let send = PartSend::new(k, Arc::clone(&self.hub), tx, false);
        let local = Local(Rc::new(Shared {
            inner: RefCell::new(Stub::new(None)),
            poisoned: Cell::new(false),
            wake: Wake::default(),
        }));
        (send, local)
    }

    /// 相手 (B) に datagram を渡し、受けた packet の数を返す。
    fn to_server(&mut self, datagrams: &[Vec<u8>]) -> usize {
        let now = clock::now();
        let mut plain = vec![0u8; usize::from(u16::MAX)];
        let mut got = 0;
        for d in datagrams {
            if self
                .t
                .b
                .handle_datagram(now, super::A_ADDR.parse().unwrap(), d, &mut plain)
                .is_some()
            {
                got += 1;
            }
        }
        got
    }

    /// front 自身の送りを `n` 回 (B に届ける)。
    fn front_sends(&mut self, n: usize) {
        let now = clock::now();
        let mut out = vec![0u8; self.t.a.max_transmit_len()];
        let mut sent = Vec::new();
        for i in 0..n {
            let it = self.front.reserve(&mut self.t.a, now).unwrap();
            let p = tcp_packet(i as u32, 100);
            let len = it.seal.seal(&p, &mut out).unwrap();
            sent.push(out[..len].to_vec());
        }
        self.front.publish();
        assert_eq!(self.to_server(&sent), n);
    }

    fn replayed(&self) -> u64 {
        self.t.b.drops().get(DropReason::Replayed)
    }
}

fn stub_out(local: &Local<Stub>, n: u32) {
    local.with(|s| {
        s.out.extend((0..n).map(|i| tcp_packet(1000 + i, 200)));
    });
}

#[test]
fn a_stalled_partition_drops_lagging_stock_and_the_peer_replays_nothing() {
    let mut l = Lanes::new(3);
    let (mut p1, local1) = l.part(1);
    // 区画 1 が在庫を求め、front が応える。区画 1 はそれを受けた後に止まる
    l.hub.links[1].demand.ask(64, &l.hub.front_bell);
    l.front.serve(&mut l.t.a, clock::now());
    take_lane(&local1, &mut p1, clock::now());
    assert_eq!(p1.stock.len(), 64);
    // その間に front が上限より多く送る
    l.front_sends(LAG_LIMIT as usize + 100);
    // 区画 1 が再び送る:遅れた在庫を捨て、求め、補充の後に新しい番号で送る
    stub_out(&local1, 10);
    let mut sink = PartRecorder::default();
    let now = clock::now();
    let (pulled, state) = local1.with(|s| p1.send_batch(s, &mut sink, now, 64));
    assert_eq!((pulled, state), (10, PartSent::Starved));
    assert!(sink.sent.is_empty());
    assert_eq!(
        l.hub
            .counts
            .lag_drops
            .load(std::sync::atomic::Ordering::Relaxed),
        64
    );
    l.front.serve(&mut l.t.a, clock::now());
    take_lane(&local1, &mut p1, clock::now());
    let now = clock::now();
    let (_, state) = local1.with(|s| p1.send_batch(s, &mut sink, now, 64));
    assert_eq!(state, PartSent::Idle);
    assert_eq!(sink.sent.len(), 10);
    let sent = std::mem::take(&mut sink.sent);
    assert_eq!(l.to_server(&sent), 10);
    assert_eq!(l.replayed(), 0, "the peer's replay window dropped nothing");
}

#[test]
fn the_test_detects_a_lagging_counter() {
    // 検出力:遅れの上限を外して古い在庫で送ると、相手の replay の窓が捨てる
    let mut l = Lanes::new(2);
    let now = clock::now();
    let stale = l.front.reserve(&mut l.t.a, now).unwrap();
    l.front_sends(9000);
    let mut out = vec![0u8; l.t.a.max_transmit_len()];
    let len = stale.seal.seal(&tcp_packet(1, 100), &mut out).unwrap();
    assert_eq!(l.to_server(&[out[..len].to_vec()]), 0);
    assert_eq!(l.replayed(), 1);
}

#[test]
fn another_partition_sending_makes_the_stalled_one_drop_its_stock() {
    let mut l = Lanes::new(3);
    let (mut p1, local1) = l.part(1);
    let (mut p2, local2) = l.part(2);
    l.hub.links[1].demand.ask(32, &l.hub.front_bell);
    l.front.serve(&mut l.t.a, clock::now());
    take_lane(&local1, &mut p1, clock::now());
    // 区画 2 が送り続ける (区画 1 は止まっている)
    let mut sink2 = PartRecorder::default();
    let mut total = 0;
    while total < LAG_LIMIT as usize + 200 {
        stub_out(&local2, 64);
        let now = clock::now();
        let (_, state) = local2.with(|s| p2.send_batch(s, &mut sink2, now, 64));
        if state == PartSent::Starved {
            l.front.serve(&mut l.t.a, clock::now());
            take_lane(&local2, &mut p2, clock::now());
            let now = clock::now();
            local2.with(|s| p2.send_batch(s, &mut sink2, now, 64));
        }
        let sent = std::mem::take(&mut sink2.sent);
        total += sent.len();
        assert_eq!(l.to_server(&sent), sent.len());
    }
    stub_out(&local1, 5);
    let mut sink1 = PartRecorder::default();
    let now = clock::now();
    let (_, state) = local1.with(|s| p1.send_batch(s, &mut sink1, now, 64));
    assert_eq!(state, PartSent::Starved, "the stalled stock lags");
    l.front.serve(&mut l.t.a, clock::now());
    take_lane(&local1, &mut p1, clock::now());
    let now = clock::now();
    local1.with(|s| p1.send_batch(s, &mut sink1, now, 64));
    let sent = std::mem::take(&mut sink1.sent);
    assert_eq!(l.to_server(&sent), 5);
    assert_eq!(l.replayed(), 0);
}

#[test]
fn would_block_drops_the_unsent_stock_and_reseals_after() {
    let mut l = Lanes::new(2);
    let (mut p1, local1) = l.part(1);
    l.hub.links[1].demand.ask(16, &l.hub.front_bell);
    l.front.serve(&mut l.t.a, clock::now());
    take_lane(&local1, &mut p1, clock::now());
    stub_out(&local1, 8);
    let mut sink = PartRecorder {
        block: true,
        ..PartRecorder::default()
    };
    let now = clock::now();
    let (_, state) = local1.with(|s| p1.send_batch(s, &mut sink, now, 64));
    assert_eq!(state, PartSent::Blocked);
    assert_eq!(
        l.hub
            .counts
            .eagain_drops
            .load(std::sync::atomic::Ordering::Relaxed),
        8
    );
    assert!(p1.is_blocked());
    // 書けるようになった:残りの在庫 8 で暗号化し直して送る
    sink.block = false;
    p1.write_blocked = false;
    let now = clock::now();
    let (_, state) = local1.with(|s| p1.send_batch(s, &mut sink, now, 64));
    assert_eq!(state, PartSent::Idle);
    let sent = std::mem::take(&mut sink.sent);
    assert_eq!(sent.len(), 8);
    assert_eq!(l.to_server(&sent), 8, "every packet arrives once");
    assert_eq!(l.replayed(), 0);
}

#[test]
fn old_stock_is_dropped_before_sealing() {
    let mut l = Lanes::new(2);
    let (mut p1, local1) = l.part(1);
    l.hub.links[1].demand.ask(4, &l.hub.front_bell);
    l.front.serve(&mut l.t.a, clock::now());
    take_lane(&local1, &mut p1, clock::now());
    stub_out(&local1, 2);
    let mut sink = PartRecorder::default();
    let later = clock::now() + STOCK_MAX_AGE + Duration::from_millis(10);
    let (_, state) = local1.with(|s| p1.send_batch(s, &mut sink, later, 64));
    assert_eq!(state, PartSent::Starved);
    assert_eq!(
        l.hub
            .counts
            .age_drops
            .load(std::sync::atomic::Ordering::Relaxed),
        4
    );
}

#[test]
fn the_check_before_sendmmsg_reseals_lagging_datagrams() {
    let mut l = Lanes::new(2);
    let (mut p1, local1) = l.part(1);
    l.hub.links[1].demand.ask(4, &l.hub.front_bell);
    l.front.serve(&mut l.t.a, clock::now());
    take_lane(&local1, &mut p1, clock::now());
    stub_out(&local1, 4);
    // 暗号化した後、sendmmsg の前に front が上限より多く予約した (区画が CPU を取られた間に当たる)
    let now = clock::now();
    assert!(local1.with(|s| p1.pull_and_seal(s, now, 64)));
    l.front_sends(LAG_LIMIT as usize + 1);
    let mut sink = PartRecorder::default();
    assert_eq!(
        p1.flush_for_test(&mut sink, clock::now()),
        Err(PartSent::Starved)
    );
    assert!(sink.sent.is_empty(), "nothing lagging went out");
    assert_eq!(
        l.hub
            .counts
            .lag_reseals
            .load(std::sync::atomic::Ordering::Relaxed),
        4
    );
    // 補充の後に平文を新しい在庫で暗号化し直して送る
    l.front.serve(&mut l.t.a, clock::now());
    take_lane(&local1, &mut p1, clock::now());
    let now = clock::now();
    local1.with(|s| p1.send_batch(s, &mut sink, now, 64));
    let sent = std::mem::take(&mut sink.sent);
    assert_eq!(sent.len(), 4);
    assert_eq!(l.to_server(&sent), 4);
    assert_eq!(l.replayed(), 0);
}

/// 相手 (B) の TCP の segment を A に届ける。`payload` 0 は中身の無い ACK。復号した packet を返す。
fn from_server(t: &mut Bench, now: Instant, payload: usize) -> Vec<u8> {
    let mut p = packet(SERVER_IP, AGENT_IP, 0);
    p.resize(40 + payload, 0);
    let len = p.len() as u16;
    p[2..4].copy_from_slice(&len.to_be_bytes());
    p[9] = 6;
    p[32] = 5 << 4;
    p[33] = ACK;
    let mut sealed = vec![0u8; t.b.max_transmit_len()];
    let out = t.b.handle_packet(now, &p, &mut sealed).unwrap();
    let mut plain = vec![0u8; 2048];
    let n =
        t.a.handle_datagram(now, B_ADDR.parse().unwrap(), &sealed[..out.len], &mut plain)
            .unwrap();
    plain[..n].to_vec()
}

/// 相手が黙った後に A が最初に出す datagram の時刻 (`t0` からの時間、100 ms 刻み) と長さ。
fn first_emission(t: &mut Bench, t0: Instant) -> (Duration, usize) {
    while t.a.poll_transmit().is_some() {}
    for step in 1..=600u32 {
        let now = t0 + Duration::from_millis(100) * step;
        t.a.handle_timeout(now);
        if let Some(x) = t.a.poll_transmit() {
            return (now - t0, x.payload.len());
        }
    }
    panic!("nothing within 60 s");
}

/// I8:相手の中身の無い ACK を受けて agent が何も送らない時 (送る向きの大きな送りの終わり)、Inline は 10 秒後に
/// passive keepalive を送る。Hash S は中身の無い ACK に相乗りの在庫を付けないので、同じ時機に送る。中身のある
/// segment には在庫を付けるが、核は答えの ACK を送るので、Inline と同じく送ったことになる。
#[test]
fn piggybacked_stock_keeps_the_keepalive_and_handshake_timing_of_inline() {
    let inline = {
        let mut t = Bench::new(0);
        t.connected();
        let t0 = clock::now();
        from_server(&mut t, t0, 0);
        first_emission(&mut t, t0)
    };
    assert_eq!(inline.1, 32, "Inline sends a passive keepalive: {inline:?}");
    let hashs = {
        let mut l = Lanes::new(2);
        let (mut p1, local1) = l.part(1);
        let t0 = clock::now();
        let ack = from_server(&mut l.t, t0, 0);
        l.front.stage(1, &ack, &mut l.t.a, t0);
        l.front.ship_all(&mut l.t.a, t0);
        take_lane(&local1, &mut p1, t0);
        assert_eq!(p1.stock.len(), 0, "no stock rides on a bare ACK");
        first_emission(&mut l.t, t0)
    };
    assert_eq!(hashs.1, 32);
    assert!(
        inline.0.abs_diff(hashs.0) <= Duration::from_millis(100),
        "the keepalive leaves at {:?} with Hash S, {:?} with Inline",
        hashs.0,
        inline.0
    );
    // 中身のある segment:在庫が付き、核の ACK に使う。残りは捨てる。送った時機は Inline の ACK と同じ
    let inline = {
        let mut t = Bench::new(0);
        t.connected();
        let t0 = clock::now();
        from_server(&mut t, t0, 100);
        let mut out = vec![0u8; t.a.max_transmit_len()];
        assert!(
            t.a.handle_packet(t0, &tcp_packet(1, 40), &mut out)
                .is_some()
        );
        first_emission(&mut t, t0)
    };
    let hashs = {
        let mut l = Lanes::new(2);
        let (mut p1, local1) = l.part(1);
        let t0 = clock::now();
        for _ in 0..8 {
            let data = from_server(&mut l.t, t0, 100);
            l.front.stage(1, &data, &mut l.t.a, t0);
        }
        l.front.ship_all(&mut l.t.a, t0);
        take_lane(&local1, &mut p1, t0);
        assert_eq!(p1.stock.len(), 8);
        stub_out(&local1, 1);
        let mut sink = PartRecorder::default();
        local1.with(|s| p1.send_batch(s, &mut sink, t0, 64));
        assert_eq!(sink.sent.len(), 1);
        p1.stock.clear();
        first_emission(&mut l.t, t0)
    };
    // sanstun はハンドシェイクの開始に 0 から 333 ms の揺らぎを足す
    assert_eq!(inline.1, hashs.1);
    assert!(
        inline.0.abs_diff(hashs.0) <= Duration::from_millis(450),
        "the first datagram after silence leaves at {:?} with Hash S, {:?} with Inline",
        hashs.0,
        inline.0
    );
}

#[test]
fn the_timing_test_detects_an_unused_reservation() {
    // 検出力:中身の無い ACK に在庫を付けて使わなければ、passive keepalive が消える (I8 の穴)
    let mut l = Lanes::new(2);
    let t0 = clock::now();
    from_server(&mut l.t, t0, 0);
    let unused = l.front.reserve(&mut l.t.a, t0);
    assert!(unused.is_some());
    let (at, len) = first_emission(&mut l.t, t0);
    assert!(
        len != 32 || at > Duration::from_millis(10_500),
        "an unused reservation suppresses the keepalive: {len} bytes at {at:?}"
    );
}

#[test]
fn the_bound_counts_partitions() {
    let caps = crate::flowpool::Limits::default();
    let one = crate::memory::MemoryBound::for_partitions(caps, Batching::default(), 1);
    assert_eq!(
        one,
        crate::memory::MemoryBound::for_limits(caps, Batching::default())
    );
    let two = crate::memory::MemoryBound::for_partitions(caps, Batching::default(), 2);
    let eight = crate::memory::MemoryBound::for_partitions(caps, Batching::default(), 8);
    assert!(two.total > one.total && eight.total > two.total);
}
