//! 外側の IP の ECN の欄の試験。本物のデータプレーン (socket、batch、device) に、本物の UDP socket の
//! 相手を向かい合わせ、相手が datagram ごとに IP の TOS を付けて送り、データプレーンの送る datagram の
//! TOS を相手が `IP_RECVTOS` で読む。Linux だけ (制御の message の並びが Linux のもの)。
//!
//! 規範は RFC 6040 4.2 の Figure 4 で、全 16 通りの表は `wgft-wireguard` の `tests/rfc6040_decap.rs` に
//! 引用してある。ここでは同じ表を使い、socket から device までの道で次を確かめる。
//!
//! - 外側 CE と内側 Not-ECT の packet は上の層に届かず、数えられる
//! - 外側 CE と内側 ECT の packet は、内側が CE になって届き、header checksum は有効である
//! - 受信の batch (`recvmmsg`、UDP GRO) があっても、datagram ごとの外側の ECN がその datagram だけに効く
//! - 送る datagram の外側は、内側の ECN によらず Not-ECT のまま (compatibility mode)
//!
//! # 継ぎ目 (seam)
//!
//! 外側の ECN を受けて device へ運ぶ修正は、`RxBatch::recv` が datagram ごとの TOS を読むこと
//! (`IP_RECVTOS` を有効にし、制御の message から読む) と、`RxBatch::decrypt_each` の呼び出しがそれを
//! datagram ごとに device へ渡すことを要る。UDP GRO が TOS の違う datagram を 1 つの buffer にまとめる
//! なら、まとめた buffer の TOS 1 つでは足りない。まとめない (TOS ごとに分ける) か、segment ごとに持つ。
//! この試験は公開の入口だけを使い、それらの内部の形には依らない。そのため、外側の ECN の効きを見る試験は、
//! 修正が入るまで `#[ignore]` にしてある。

use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use socket2::{Domain, MaybeUninitSlice, MsgHdrMut, Protocol, SockAddr, Socket, Type};
use wgft_wireguard::Device;

use super::{
    AGENT_IP, Budget, Dataplane, Made, SERVER_IP, Stub, UpperInit, agent_config, keys, loopback,
    server_config, wait_for,
};
use crate::dataplane::Carry;

const NOT_ECT: u8 = 0b00;
const ECT1: u8 = 0b01;
const ECT0: u8 = 0b10;
const CE: u8 = 0b11;
/// Figure 4 の行と列の順。
const CODEPOINTS: [u8; 4] = [NOT_ECT, ECT0, ECT1, CE];
/// 内側と外側に付ける DSCP (EF)。ECN を直しても変わらないことを見る。
const DSCP: u8 = 0b10_1110;

/// RFC 6040 4.2 Figure 4。行が内側、列が外側で、順は Not-ECT、ECT(0)、ECT(1)、CE。`None` は `<drop>`。
const FIGURE_4: [[Option<u8>; 4]; 4] = [
    [Some(NOT_ECT), Some(NOT_ECT), Some(NOT_ECT), None],
    [Some(ECT0), Some(ECT0), Some(ECT1), Some(CE)],
    [Some(ECT1), Some(ECT1), Some(ECT1), Some(CE)],
    [Some(CE), Some(CE), Some(CE), Some(CE)],
];

fn figure_4(inner: u8, outer: u8) -> Option<u8> {
    let row = CODEPOINTS.iter().position(|c| *c == inner).unwrap();
    let col = CODEPOINTS.iter().position(|c| *c == outer).unwrap();
    FIGURE_4[row][col]
}

fn folded_sum(words: impl Iterator<Item = u16>) -> u16 {
    let mut sum: u32 = words.map(u32::from).sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    u16::try_from(sum).unwrap()
}

/// 内側の IPv4 の packet (header 20 バイトと 8 バイトの中身)。中身の先頭 4 バイトが番号。checksum は有効。
fn inner(src: Ipv4Addr, dst: Ipv4Addr, ecn: u8, seq: u32) -> Vec<u8> {
    let mut p = vec![0u8; 28];
    p[0] = 0x45;
    p[1] = (DSCP << 2) | ecn;
    p[2..4].copy_from_slice(&28u16.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p[20..24].copy_from_slice(&seq.to_be_bytes());
    let sum = !folded_sum(
        p[..20]
            .chunks(2)
            .enumerate()
            .filter(|(i, _)| *i != 5)
            .map(|(_, w)| u16::from_be_bytes([w[0], w[1]])),
    );
    p[10..12].copy_from_slice(&sum.to_be_bytes());
    p
}

fn checksum_valid(p: &[u8]) -> bool {
    folded_sum(p[..20].chunks(2).map(|w| u16::from_be_bytes([w[0], w[1]]))) == 0xffff
}

fn seq_of(p: &[u8]) -> u32 {
    u32::from_be_bytes([p[20], p[21], p[22], p[23]])
}

/// 上の層が最初から持つ packet を `packets` にした Stub の工場。
fn with_inner(packets: Vec<Vec<u8>>) -> impl FnOnce(UpperInit<Budget>) -> Made + Send + 'static {
    move |init| {
        let mut s = Stub::from_init(init)?;
        s.out.extend(packets);
        Ok(s)
    }
}

/// 読んだ datagram とその IP の TOS。
struct Read {
    data: Vec<u8>,
    from: SocketAddr,
    tos: u8,
}

/// `IP_RECVTOS` を有効にした socket から、待っている datagram を 1 つ読む。無ければ `None`。
fn recv_with_tos(socket: &Socket) -> Option<Read> {
    let mut data = [MaybeUninit::<u8>::new(0); 2048];
    let mut control = [MaybeUninit::<u8>::new(0); 128];
    let mut from = SockAddr::from(SocketAddr::from(([0, 0, 0, 0], 0)));
    let mut bufs = [MaybeUninitSlice::new(&mut data)];
    let mut msg = MsgHdrMut::new()
        .with_addr(&mut from)
        .with_buffers(&mut bufs)
        .with_control(&mut control);
    let n = match socket.recvmsg(&mut msg, 0) {
        Ok(n) => n,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return None,
        Err(e) => panic!("recvmsg: {e}"),
    };
    let control_len = msg.control_len();
    // SAFETY: `data` と `control` は new(0) で初期化した配列で、核は書き足すだけである
    let byte = |b: &MaybeUninit<u8>| unsafe { b.assume_init() };
    let data: Vec<u8> = data[..n].iter().map(byte).collect();
    let control: Vec<u8> = control[..control_len].iter().map(byte).collect();
    Some(Read {
        data,
        from: from.as_socket().unwrap(),
        tos: tos_of(&control).expect("the TOS control message arrived"),
    })
}

/// 制御の message の並びから、`IP_TOS` の message の 1 byte を取る。
fn tos_of(control: &[u8]) -> Option<u8> {
    let header = size_of::<libc::cmsghdr>();
    let mut off = 0;
    while off + header <= control.len() {
        let len = usize::from_ne_bytes(control[off..off + size_of::<usize>()].try_into().unwrap());
        let word = |at: usize| i32::from_ne_bytes(control[at..at + 4].try_into().unwrap());
        let (level, kind) = (
            word(off + size_of::<usize>()),
            word(off + size_of::<usize>() + 4),
        );
        if len < header {
            return None;
        }
        if level == libc::IPPROTO_IP && kind == libc::IP_TOS {
            return control.get(off + header).copied();
        }
        off += len.next_multiple_of(size_of::<usize>());
    }
    None
}

/// データプレーンの相手の server。本物の UDP socket と、その向こうの device を持つ。
struct Peer {
    socket: Socket,
    device: Device,
    /// 受けた packet。
    got: Vec<Vec<u8>>,
    /// 受けた datagram の TOS の ECN の 2 bit。
    seen_ecn: Vec<u8>,
}

impl Peer {
    fn new(server: &wgft_wireguard::PrivateKey, agent: wgft_wireguard::PublicKey) -> Self {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        socket.set_nonblocking(true).unwrap();
        socket.set_recv_tos_v4(true).unwrap();
        socket
            .bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into())
            .unwrap();
        Self {
            socket,
            device: Device::new(server_config(server, agent), Instant::now(), Duration::ZERO)
                .unwrap(),
            got: Vec::new(),
            seen_ecn: Vec::new(),
        }
    }

    fn addr(&self) -> SocketAddr {
        self.socket.local_addr().unwrap().as_socket().unwrap()
    }

    /// 着いた datagram をすべて device に渡し、device の返事を送る。
    fn service(&mut self) {
        let mut plain = vec![0u8; usize::from(u16::MAX)];
        while let Some(read) = recv_with_tos(&self.socket) {
            self.seen_ecn.push(read.tos & 0b11);
            if let Some(len) =
                self.device
                    .handle_datagram(Instant::now(), read.from, &read.data, &mut plain)
            {
                self.got.push(plain[..len].to_vec());
            }
        }
        self.flush();
    }

    fn flush(&mut self) {
        while let Some(tx) = self.device.poll_transmit() {
            self.socket.set_tos_v4(0).unwrap();
            self.socket.send_to(&tx.payload, &tx.to.into()).unwrap();
        }
        while self.device.poll_event().is_some() {}
    }

    /// `packet` を暗号化し、外側の TOS を `tos` にして agent へ送る。
    fn send(&mut self, packet: &[u8], tos: u8) {
        self.flush();
        let mut out = vec![0u8; self.device.max_transmit_len()];
        let o = self
            .device
            .handle_packet(Instant::now(), packet, &mut out)
            .expect("the session is up");
        self.socket.set_tos_v4(u32::from(tos)).unwrap();
        self.socket.send_to(&out[..o.len], &o.to.into()).unwrap();
    }
}

/// agent の側のデータプレーンと、相手の server を立て、セッションができるまで待つ。
async fn up(agent_packets: Vec<Vec<u8>>) -> (Dataplane<Stub>, Peer) {
    let (a_key, b_key) = keys();
    let mut peer = Peer::new(&b_key, a_key.public_key());
    let a_pub = a_key.public_key();
    let a = Dataplane::start(
        agent_config(&a_key, b_key.public_key(), peer.addr()),
        loopback(),
        Carry::first(Duration::ZERO),
        with_inner(agent_packets),
    )
    .await
    .unwrap();
    // 相手の側は、agent の開始を受けて返事をする。agent の開始が届くまで、相手の socket を読み続ける
    wait_for("the agent to hold a session", async || {
        peer.service();
        peer.device.has_session(&a_pub, Instant::now())
            && a.status()
                .await
                .unwrap()
                .peer
                .is_some_and(|p| p.last_handshake.is_some())
    })
    .await;
    (a, peer)
}

async fn agent_got(a: &Dataplane<Stub>) -> Vec<Vec<u8>> {
    a.call(|l| l.with(|s| s.got.clone())).await.unwrap()
}

// 以下は今も通る。道具の確認と、送信側の compatibility mode の関門。

#[test]
fn the_harness_sets_and_reads_the_tos_of_a_datagram() {
    let (a_key, b_key) = keys();
    let rx = Peer::new(&b_key, a_key.public_key());
    let tx = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
    for tos in [0u8, 0b10, 0b11, (DSCP << 2) | 0b01] {
        tx.set_tos_v4(u32::from(tos)).unwrap();
        tx.send_to(b"x", &rx.addr().into()).unwrap();
        let mut got = None;
        for _ in 0..200 {
            got = recv_with_tos(&rx.socket);
            if got.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(got.expect("the datagram arrived").tos, tos);
    }
}

#[tokio::test]
async fn datagrams_the_data_plane_sends_have_outer_not_ect_whatever_the_inner_ecn() {
    // 内側は Not-ECT、ECT(0)、ECT(1)、CE を混ぜる。送る道は batch と UDP GSO を通る数にする。
    // ハンドシェイクの datagram、データ、keepalive のすべての外側が Not-ECT である
    const N: u32 = 96;
    let packets: Vec<Vec<u8>> = (0..N)
        .map(|i| {
            inner(
                AGENT_IP,
                SERVER_IP,
                CODEPOINTS[usize::try_from(i).unwrap() % 4],
                i,
            )
        })
        .collect();
    let (a, mut peer) = up(packets.clone()).await;
    wait_for("the server to get every packet", async || {
        peer.service();
        peer.got.len() == packets.len()
    })
    .await;
    assert_eq!(peer.got, packets, "the inner packets arrive untouched");
    assert!(
        peer.seen_ecn.len() > 1,
        "the handshake and the data were read: {}",
        peer.seen_ecn.len()
    );
    assert!(
        peer.seen_ecn.iter().all(|e| *e == NOT_ECT),
        "outer ECN of every datagram: {:?}",
        peer.seen_ecn
    );
    a.stop().await;
}

#[tokio::test]
async fn outer_not_ect_delivers_the_inner_packet_unchanged_through_the_socket() {
    let (a, mut peer) = up(Vec::new()).await;
    for (i, ecn) in CODEPOINTS.into_iter().enumerate() {
        peer.send(
            &inner(SERVER_IP, AGENT_IP, ecn, u32::try_from(i).unwrap()),
            NOT_ECT,
        );
    }
    wait_for("the agent to get four packets", async || {
        agent_got(&a).await.len() == 4
    })
    .await;
    for (i, p) in agent_got(&a).await.iter().enumerate() {
        assert_eq!(p[1] & 0b11, CODEPOINTS[i]);
        assert!(checksum_valid(p));
    }
    assert_eq!(a.status().await.unwrap().drops.total(), 0);
    a.stop().await;
}

// 以下は、外側の ECN を device へ運ぶ修正が入るまで通らない。

#[tokio::test]
async fn outer_ce_with_inner_not_ect_is_dropped_and_counted() {
    let (a, mut peer) = up(Vec::new()).await;
    peer.send(&inner(SERVER_IP, AGENT_IP, NOT_ECT, 1), CE);
    // 捨てた packet の後に届く目印で、先の datagram の処理が済んだことを知る
    peer.send(&inner(SERVER_IP, AGENT_IP, NOT_ECT, 2), NOT_ECT);
    wait_for("the marker to arrive", async || {
        agent_got(&a).await.iter().any(|p| seq_of(p) == 2)
    })
    .await;
    let seqs: Vec<u32> = agent_got(&a).await.iter().map(|p| seq_of(p)).collect();
    assert_eq!(seqs, vec![2], "the packet 1 must not be delivered");
    assert_eq!(a.status().await.unwrap().drops.total(), 1);
    a.stop().await;
}

#[tokio::test]
async fn outer_ce_with_inner_ect_arrives_as_inner_ce_with_a_valid_checksum() {
    let (a, mut peer) = up(Vec::new()).await;
    for (i, ecn) in [ECT0, ECT1].into_iter().enumerate() {
        peer.send(
            &inner(SERVER_IP, AGENT_IP, ecn, u32::try_from(i).unwrap()),
            CE,
        );
    }
    wait_for("the agent to get two packets", async || {
        agent_got(&a).await.len() == 2
    })
    .await;
    for p in agent_got(&a).await {
        assert_eq!(p[1] & 0b11, CE);
        assert_eq!(p[1] >> 2, DSCP);
        assert!(checksum_valid(&p));
    }
    assert_eq!(a.status().await.unwrap().drops.total(), 0);
    a.stop().await;
}

#[tokio::test]
async fn a_burst_keeps_each_datagrams_own_outer_ecn() {
    // 同じ大きさの datagram を続けて送り、受信の batch (recvmmsg) と、核が許せば UDP GRO に
    // 同じ大きさの datagram がまとまる状況を作る。外側の ECN は 1 つごとに変え、16 通りの組を 3 周する
    let (a, mut peer) = up(Vec::new()).await;
    let mut want = Vec::new();
    let mut dropped = 0u64;
    let mut seq = 0u32;
    for _ in 0..3 {
        for inner_ecn in CODEPOINTS {
            for outer in CODEPOINTS {
                peer.send(&inner(SERVER_IP, AGENT_IP, inner_ecn, seq), outer);
                match figure_4(inner_ecn, outer) {
                    Some(e) => want.push((seq, e)),
                    None => dropped += 1,
                }
                seq += 1;
            }
        }
    }
    // 最後に、目印を外側 Not-ECT で送る
    peer.send(&inner(SERVER_IP, AGENT_IP, NOT_ECT, seq), NOT_ECT);
    want.push((seq, NOT_ECT));
    wait_for("the marker to arrive", async || {
        agent_got(&a).await.iter().any(|p| seq_of(p) == seq)
    })
    .await;
    let got: Vec<(u32, u8)> = agent_got(&a)
        .await
        .iter()
        .map(|p| (seq_of(p), p[1] & 0b11))
        .collect();
    assert_eq!(got, want, "delivered packets and their inner ECN, in order");
    for p in agent_got(&a).await {
        assert!(checksum_valid(&p), "seq {}", seq_of(&p));
    }
    let status = a.status().await.unwrap();
    assert_eq!(status.drops.total(), dropped);
    assert_eq!(status.receive_truncated, 0);
    a.stop().await;
}
