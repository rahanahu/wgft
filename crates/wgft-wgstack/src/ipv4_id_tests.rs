//! IPv4 の Identification (ID) の試験です。所有者の決定 (2026-11-07) の期待を、RFC 791 と RFC 6864 から書きました。
//!
//! 核が出す packet の ID は次の 2 つの規則に従います。
//!
//! 1. DF を立てた、断片でない packet (atomic な datagram) の ID は 0 です。RFC 6864 4.1 節は atomic な datagram の
//!    ID を意味の無い値とし、送り手が任意の値を入れてよい (MAY) としています。0 にすれば、核の全体の送信量を
//!    packet の ID から読まれません (DNAT のルールの相手は一般のクライアントで、他の接続の送信量を知ってはいけません)。
//! 2. 断片にされうる packet (DF を下ろした packet と、その断片) の ID は、(送信元アドレス、宛先アドレス、protocol) の
//!    組ごとに重ならないよう管理します (RFC 791 の ID の定義:「送り手が、同じ (src, dst, protocol) の間で datagram が
//!    ネットワークに生きている間、一意に選ぶ」。RFC 6864 4.2 節と 4.3 節:非 atomic な datagram の ID はその
//!    間隔の中で重ならない)。1 つの datagram の断片は同じ ID を共有します (RFC 791 の組み立ての規則)。他の組の
//!    送信量が、この組で見える ID の列を変えてはいけません。
//!
//! 核が DF を下ろして出す packet は、UDP の datagram (小さくても) と ICMP の echo reply です。TCP と ICMP の誤り
//! と echo request は DF を立てます。
//!
//! 「重ならない間隔」として試験が仮定する窓は、同じ組の連続する [`WINDOW`] 個の datagram です。ID は 16 bit なので、
//! 窓は空間の半分です。RFC 6864 4.3 節は間隔を datagram の最大の寿命と送る速さの積で決めるとしますが、核は時計と
//! 関係なく送れるので、数で窓を取ります。数の窓の中で重ならなければ、時間の窓の中でも重ならない速さの上限が
//! 立つためです。窓に半分を選ぶのは、組ごとの数え (連番) が 65535 個重ならず、無作為に選ぶ実装 (65536 の空間の
//! 誕生日の問題で、2^15 個の間に重なりがほぼ確実に出る) を落とすためです。
//!
//! 組ごとの状態は、核の既存の上限の中で持ちます (表の大きさに依る)。状態が追い出された組が、すぐに最近の ID を
//! 再び使ってはいけません。試験が仮定する「すぐに」は [`EVICT_WINDOW`] 個の datagram です。時計を進めずに別の組
//! の送信で状態を追い出しても、追い出された組の次の [`EVICT_WINDOW`] 個の ID は、追い出される前の
//! [`EVICT_WINDOW`] 個の ID と重なってはいけません。追い出しが datagram の寿命より前に起きても重ねない
//! 仕組み (鍵つき hash の初期値に頼らず、追い出した状態の下限を覚えるなど) が要ります。
//!

#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "tests collect packets"
)]
#![expect(clippy::cast_possible_truncation, reason = "test data")]

use crate::dnat_peer_tests::{VICTIM, established};
use crate::icmp::ECHO;
use crate::listen_tests::{cookie_then_full_queue, flooded};
use crate::testnet_tests::{
    DUT, PEER, TSeg, TestNet, build_icmp, build_udp, parse_out, small_limits,
};
use crate::wire::{FLAG_RST, FLAG_SYN, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use core::net::{Ipv4Addr, SocketAddrV4};
use std::collections::HashSet;

/// 組の連続する datagram の数で取る、ID が重ならない窓です。
const WINDOW: usize = 1 << 15;
/// 状態の追い出しの後で重ならない窓です。
const EVICT_WINDOW: usize = 300;
/// 状態を追い出すために使う、別の宛先の数です。表の大きさの既存の上限より十分に多い値です。
const FLOOD: u32 = 100_000;

const DF: u16 = 0x4000;
const MF: u16 = 0x2000;
const OFFSET: u16 = 0x1fff;

#[derive(Clone, Copy, Debug)]
struct Hdr {
    id: u16,
    flags: u16,
    proto: u8,
    src: u32,
    dst: u32,
}

impl Hdr {
    fn of(p: &[u8]) -> Self {
        Self {
            id: u16::from_be_bytes([p[4], p[5]]),
            flags: u16::from_be_bytes([p[6], p[7]]),
            proto: p[9],
            src: u32::from_be_bytes([p[12], p[13], p[14], p[15]]),
            dst: u32::from_be_bytes([p[16], p[17], p[18], p[19]]),
        }
    }

    fn df(&self) -> bool {
        self.flags & DF != 0
    }

    fn fragment(&self) -> bool {
        self.flags & (MF | OFFSET) != 0
    }

    fn first_or_whole(&self) -> bool {
        self.flags & OFFSET == 0
    }
}

/// 核が今出す packet をすべて、確かめなしで読み出します。
fn drain_hdrs(n: &mut TestNet) -> Vec<Hdr> {
    let mut buf = vec![0u8; 65536];
    let mut out = Vec::new();
    while let Some(k) = n.s.poll_transmit(n.now, &mut buf) {
        out.push(Hdr::of(&buf[..k]));
    }
    out
}

// 1. DF を立てた、断片でない packet の ID は 0

/// cookie の ACK が満杯の待ち行列に当たって握手の途中の行になり、待ち行列が空かないまま SYN-ACK の再送を使い切って
/// RST|ACK で切られるまでの、核の packet をすべて返します。最後の packet が行の RST|ACK です。
fn handshake_row_reset() -> Vec<Vec<u8>> {
    let (mut n, _l) = flooded();
    let mut p = cookie_then_full_queue(&mut n, 42000);
    n.peer_ack(&mut p, &[]);
    let mut out = Vec::new();
    let mut reset = false;
    for _ in 0..200 {
        n.advance(std::time::Duration::from_secs(1));
        for pkt in n.drain_raw() {
            let o = parse_out(&pkt);
            if o.rport != 42000 {
                continue;
            }
            if o.has(FLAG_RST) {
                reset = true;
            } else {
                n.peer_ack(&mut p, &[]);
            }
            out.push(pkt);
        }
    }
    assert!(
        reset,
        "the row ran out of retransmissions and reset the peer"
    );
    out
}

/// 核が出す、DF を立てた断片でない packet (TCP の SYN-ACK、データ、ACK、FIN、RST、challenge ACK、ICMP の誤り、
/// ICMP の echo request) の ID は 0 です (RFC 6864 4.1 節)。
#[test]
fn df_set_non_fragments_carry_id_zero() {
    let (mut n, _l, v) = established(&[VICTIM]);
    let (c, mut p) = v[0];
    let mut all: Vec<Vec<u8>> = Vec::new();
    // 握手 (SYN-ACK)
    n.inject(&TSeg {
        sport: 41000,
        dport: 80,
        seq: 1000,
        flags: FLAG_SYN,
        wnd: 65535,
        mss: 1380,
        ws: Some(7),
        sack_ok: true,
        ts: Some((5000, 0)),
        ..TSeg::default()
    });
    all.extend(n.drain_raw());
    // 待ち受けの無いポートへの SYN (RST)
    n.inject(&TSeg {
        sport: 41001,
        dport: 9999,
        seq: 1,
        flags: FLAG_SYN,
        wnd: 65535,
        ..TSeg::default()
    });
    all.extend(n.drain_raw());
    // データと ACK
    n.s.write(n.now, c, &[7u8; 3000]).unwrap();
    let raw = n.drain_raw();
    let outs: Vec<_> = raw.iter().map(|q| parse_out(q)).collect();
    p.absorb(&outs);
    all.extend(raw);
    n.peer_ack(&mut p, &[]);
    all.extend(n.drain_raw());
    // 確立した接続への SYN (challenge ACK)
    n.inject(&p.seg(FLAG_SYN, &[]));
    all.extend(n.drain_raw());
    // 閉じる (FIN) と相手の FIN
    n.s.close_conn(n.now, c);
    let raw = n.drain_raw();
    let outs: Vec<_> = raw.iter().map(|q| parse_out(q)).collect();
    p.absorb(&outs);
    all.extend(raw);
    n.peer_fin(&mut p);
    all.extend(n.drain_raw());
    // 待ち受けの無い UDP のポート (ICMP の誤り)
    n.write(&build_udp(SocketAddrV4::new(PEER, 5000), 9999, b"x"));
    all.extend(n.drain_raw());
    // ping (ICMP の echo request)
    let pc = n.s.open_ping(n.now, PEER).unwrap();
    n.s.send_ping(n.now, pc, &[ECHO, 0, 0, 0, 0, 1, 0, 7, b'i', b'd'])
        .unwrap();
    all.extend(n.drain_raw());

    // 握手の途中の行が、SYN-ACK の再送を使い切って送る RST|ACK
    all.extend(handshake_row_reset());

    let hdrs: Vec<Hdr> = all.iter().map(|q| Hdr::of(q)).collect();
    let rows = hdrs
        .iter()
        .filter(|h| h.proto == PROTO_TCP && h.df() && h.dst == PEER.to_bits())
        .count();
    assert!(rows >= 1);
    let atomic: Vec<&Hdr> = hdrs.iter().filter(|h| h.df() && !h.fragment()).collect();
    let tcp = atomic.iter().filter(|h| h.proto == PROTO_TCP).count();
    let icmp = atomic.iter().filter(|h| h.proto == PROTO_ICMP).count();
    assert!(
        tcp >= 6 && icmp >= 2,
        "scenario covers {tcp} TCP and {icmp} ICMP packets"
    );
    for h in &atomic {
        assert_eq!(h.id, 0, "an atomic datagram has a nonzero ID: {h:?}");
    }
}

// 2. 断片にされうる packet の ID は (src, dst, protocol) の組ごとに重ならない

/// 宛先 `dst` に `len` byte の UDP の datagram を送り、組 (DUT, dst, UDP) の ID を返します。断片なら全部の断片が
/// 同じ ID で、DF が下りています。
fn send_udp(n: &mut TestNet, pc: crate::UdpId, dst: Ipv4Addr, len: usize) -> u16 {
    n.s.send_to(n.now, pc, &vec![0x5a; len], SocketAddrV4::new(dst, 5000))
        .unwrap();
    let hs = drain_hdrs(n);
    assert!(!hs.is_empty());
    let first = hs[0];
    for h in &hs {
        assert_eq!(
            (h.proto, h.src, h.dst),
            (PROTO_UDP, DUT.to_bits(), dst.to_bits())
        );
        assert!(!h.df(), "a UDP datagram is sent without DF: {h:?}");
        assert_eq!(h.id, first.id, "the fragments of one datagram share the ID");
    }
    assert!(first.first_or_whole());
    first.id
}

/// 同じ組の連続する [`WINDOW`] 個の datagram の ID は重なりません (RFC 6864 4.3 節)。小さい datagram も断片の
/// datagram も同じ数えです。
#[test]
fn non_atomic_ids_do_not_repeat_within_a_tuple() {
    let mut n = TestNet::new(small_limits());
    let pc = n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
    let mut seen = HashSet::new();
    for i in 0..WINDOW {
        let len = if i % 7 == 0 { 3000 } else { 40 };
        let id = send_udp(&mut n, pc, PEER, len);
        assert!(seen.insert(id), "ID {id} repeats at datagram {i}");
    }
}

/// echo reply (DF を下ろす) も同じ規則です。組は (DUT, 要求の送り手, ICMP) です。
#[test]
fn echo_reply_ids_do_not_repeat_within_a_tuple() {
    let mut n = TestNet::new(small_limits());
    let mut seen = HashSet::new();
    for i in 0..WINDOW {
        let len = if i % 11 == 0 { 3000 } else { 16 };
        let mut msg = vec![0u8; 8 + len];
        msg[0] = ECHO;
        msg[7] = i as u8;
        n.write(&build_icmp(PEER, &msg));
        let hs = drain_hdrs(&mut n);
        assert!(!hs.is_empty(), "reply {i}");
        for h in &hs {
            assert!(!h.df() && h.proto == PROTO_ICMP, "{h:?}");
            assert_eq!(h.id, hs[0].id, "the fragments share the ID");
        }
        assert!(
            seen.insert(hs[0].id),
            "ID {} repeats at reply {i}",
            hs[0].id
        );
    }
}

/// 別の組の送信量が、この組で見える ID の列を変えません (組の間に副チャネルが無い)。同じ種の核 2 つで、組 A への送信
/// を同じ列にし、片方だけ、間に別の宛先 (別の組) への UDP と、A への ICMP の echo reply (別の protocol の組) を
/// 挟みます。A の UDP の ID の列は同じです。
#[test]
fn traffic_on_another_tuple_does_not_change_the_sequence() {
    let a = PEER;
    let b = Ipv4Addr::new(10, 9, 0, 3);
    let run = |interleave: bool| {
        let mut n = TestNet::new(small_limits());
        let pc = n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
        let mut ids = Vec::new();
        for i in 0..40 {
            ids.push(send_udp(&mut n, pc, a, if i % 5 == 0 { 3000 } else { 40 }));
            if interleave {
                for _ in 0..=(i % 4) {
                    send_udp(&mut n, pc, b, 100);
                }
                let mut msg = vec![0u8; 16];
                msg[0] = ECHO;
                n.write(&build_icmp(a, &msg));
                drain_hdrs(&mut n);
            }
        }
        ids
    };
    assert_eq!(
        run(false),
        run(true),
        "the IDs on one tuple depend on traffic on other tuples"
    );
}

/// 追い出した組が、追い出される前の範囲の後ろから戻ります (追い出した状態の下限を覚える仕組みを、公開の面だけで
/// 確かめる試験)。組 X が前の `PRE` 個の ID を使った後、多数の別の宛先を送って X の状態を追い出し、X が次の `POST` 個を
/// 使います。ID の列が組ごとの連番の置換なら、X の後の範囲は前の範囲の終わり以降から始まり、置換は全単射なので、
/// 前の ID と重ならない。窓は次の考えで選びます。
///
/// - 下限:`PRE` 個の範囲が 2^16 の輪の中で後の範囲と重ならないことで、追い出しの前進を 1 だけにする実装と、追い出した
///   状態の使った数を別の組の前進に足す実装(後の範囲が前の範囲の始めの近くから戻る)を落とします。
/// - 無作為な始めの後に連番を続ける実装:2 つの範囲 (どちらも 20000 個) が 2^16 の輪の上で重ならない確率は
///   25536 / 65536 で約 39%、8 つの種で全部通る確率は 5e-4 ほどです。
/// - 上限:`PRE + POST + 前進の余り` が 2^16 を超えると後の範囲が前の範囲の始めに回り込んで重なるので、前進が使った数から
///   大きく離れる実装 (使った数の 2 倍以上など) も落とします。余りは、flood が別の組の使った数を同じ前進の枠に足す分で、
///   flood の数を抑えて小さく保ちます。
const PRE: usize = 20_000;
const POST: usize = 20_000;
const ADVANCE_FLOOD: u32 = 600;

#[test]
fn evicted_tuple_resumes_after_its_previous_range() {
    for seed in 0..8u8 {
        let mut n = TestNet::with_seed(small_limits(), [seed; 64]);
        let pc = n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
        let pre: HashSet<u16> = (0..PRE).map(|_| send_udp(&mut n, pc, PEER, 40)).collect();
        assert_eq!(pre.len(), PRE, "seed {seed}: repeats before the eviction");
        for i in 0..ADVANCE_FLOOD {
            let dst = Ipv4Addr::from_bits(0x0a0b_0000 + i);
            n.s.send_to(n.now, pc, b"x", SocketAddrV4::new(dst, 9))
                .unwrap();
            drain_hdrs(&mut n);
        }
        let mut post = HashSet::new();
        for i in 0..POST {
            let id = send_udp(&mut n, pc, PEER, 40);
            assert!(
                !pre.contains(&id),
                "seed {seed}: ID {id} of the earlier range comes back at datagram {i}"
            );
            assert!(
                post.insert(id),
                "seed {seed}: ID {id} repeats at datagram {i}"
            );
        }
    }
}

/// 追い出し:別の宛先を多数に送って組の状態を追い出しても、追い出された組の次の [`EVICT_WINDOW`] 個の ID は、追い出す
/// 前の [`EVICT_WINDOW`] 個の ID と重なりません。核の保持は上界の中に収まり、不変条件が保たれます。
///
/// この試験の検出力は限られます。追い出した後の始めを、独立に引いた ID で選ぶ実装なら重なりを見つけますが、無作為な始めの
/// 後に連番を続ける実装は、2 つの 300 個の範囲が重なるときだけ (1 つの種で 600 / 65536 で約 0.9%、8 つの種で約 7%)
/// 見つかります。追い出しの前進の仕組みは、下の `evicted_tuple_resumes_after_its_previous_range` が確かめます。
#[test]
fn eviction_of_tuple_state_does_not_reuse_recent_ids() {
    for seed in 0..8u8 {
        let mut n = TestNet::with_seed(small_limits(), [seed; 64]);
        let pc = n.s.bind_udp(n.now, SocketAddrV4::new(DUT, 53)).unwrap();
        let pre: Vec<u16> = (0..EVICT_WINDOW)
            .map(|_| send_udp(&mut n, pc, PEER, 40))
            .collect();
        for i in 0..FLOOD {
            let dst = Ipv4Addr::from_bits(0x0a0a_0000 + i);
            n.s.send_to(n.now, pc, b"x", SocketAddrV4::new(dst, 9))
                .unwrap();
            drain_hdrs(&mut n);
        }
        n.check();
        let h = n.s.held();
        let b = n.s.bound();
        assert!(
            (h.chunk_bytes + h.record_bytes + h.interval_bytes) as u64 <= b.floor_conn + b.boost,
            "seed {seed}: held beyond the bound after {FLOOD} destinations: {h:?}"
        );
        assert_eq!(h.udp_tx_datagrams, 0, "seed {seed}");
        let post: Vec<u16> = (0..EVICT_WINDOW)
            .map(|_| send_udp(&mut n, pc, PEER, 40))
            .collect();
        let before: HashSet<u16> = pre.iter().copied().collect();
        let after: HashSet<u16> = post.iter().copied().collect();
        assert_eq!(
            after.len(),
            post.len(),
            "seed {seed}: repeats after the eviction"
        );
        assert!(
            before.is_disjoint(&after),
            "seed {seed}: IDs reused after the eviction: {:?}",
            before.intersection(&after).collect::<Vec<_>>()
        );
    }
}
