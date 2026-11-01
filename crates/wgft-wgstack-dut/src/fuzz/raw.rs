//! `raw_adversary` の target:状態を持つ生の packet の敵です。Go に元の試験はありません。
//!
//! 入力の byte を選択の列として読み、相手の TCP の番号を追いながら、もっともらしいが壊れた入力を核に与えます。
//! 混ぜるものは次のとおりです。
//!
//! - option の端の値を持つ SYN (MSS の 0 と下限と上限、窓の scale の 14 を超える値、timestamp、SACK の許可)
//! - 乱れた flag、番号、確認番号、窓、timestamp、SACK の block を持つ segment。握手の途中の表が満ちた後は、
//!   SYN-ACK の番号と TSval から作る ACK が SYN cookie の確かめを通り、書き換えた ACK が断られます
//! - ICMP の frag-needed (送った segment を引くものと偽のもの) とほかの種類、echo
//! - UDP の datagram。大きなものは断片に分け、順を混ぜ、重ね、同じ断片を繰り返します
//! - 生の断片
//! - アプリケーションの操作 (accept、読み書き、閉じる、abort、UDP の送受信、待ち受けの閉じ直し、ping の送受信)。
//!   すべての接続に続けて大きく書く操作と、すべての接続から読み切る操作は、多くの接続が同時に boost を求める
//!   状況と、それまで読まなかった接続が読み始める状況を作ります。boost の枠が尽きると、新しく求めた接続のために
//!   需要の無い保有者を floor に戻します。hook の `may_return` の答えも操作で切り替えます。相手は核の echo に
//!   答えます
//! - 時刻の進み。最大で 25 日まで跳びます
//!
//! 各段の後に不変条件と保持の上界を確かめ (`Net::check`)、最後に核を閉じて会計が 0 に戻ることを確かめます。
//! 入力が尽きたら終えるので、短い入力は短い列です。

#![expect(
    clippy::many_single_char_names,
    reason = "the step helpers name the net, the input and the peer by one letter, as the other targets do"
)]

use std::cell::Cell;
use std::collections::BTreeMap;
use std::net::SocketAddrV4;
use std::rc::Rc;
use std::time::Duration;

use wgft_tcpharness::ip::{self, Icmp, Ipv4};
use wgft_tcpharness::packet::{ACK, FIN, Options, RST, SYN, SackBlock, Segment, Timestamps};
use wgft_wgstack::{ConnId, Hook, ListenerId, PingId, UdpId};

use super::net::{DUT, MTU, Net, PEER, small_limits};

/// 1 つの入力で進める段の上限です。
const MAX_STEPS: usize = 2000;
/// 相手のポートの数です。握手の途中の表の待ち受けの分 (small_limits で 8 行) を超え、cookie を使わせます。
const PORTS: u32 = 24;

/// 需要の無い保有者を floor に戻してよいかを、操作で切り替えた値で答える hook です。
#[derive(Debug)]
struct Flip(Rc<Cell<bool>>);

impl Hook for Flip {
    fn may_return(&mut self, _conn: ConnId) -> bool {
        self.0.get()
    }
}

/// `raw_adversary` の核です。
type RawNet = Net<Flip>;

/// 相手がまとめて送る segment の中身の長さです。
const BULK_LEN: u32 = 1368;

/// 選択の列です。尽きたら 0 を返します。
struct Src<'a>(&'a [u8]);

impl Src<'_> {
    fn u8(&mut self) -> u8 {
        let Some((&b, rest)) = self.0.split_first() else {
            return 0;
        };
        self.0 = rest;
        b
    }

    fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.u8(), self.u8(), self.u8(), self.u8()])
    }

    fn below(&mut self, n: u32) -> u32 {
        if n <= 256 {
            u32::from(self.u8()) % n.max(1)
        } else {
            self.u32() % n
        }
    }

    fn pick<T: Copy>(&mut self, v: &[T]) -> T {
        v[self.below(u32::try_from(v.len()).unwrap_or(1)) as usize]
    }

    fn done(&self) -> bool {
        self.0.is_empty()
    }
}

/// 相手の側の 1 つのポートの番号です。
#[derive(Clone, Debug, Default)]
struct Peer {
    snd: u32,
    rcv_lo: u32,
    rcv_hi: u32,
    ts_seen: u32,
    ts_val: u32,
    last_seg: Option<Vec<u8>>,
}

fn delta(r: &mut Src<'_>) -> u32 {
    match r.below(10) {
        0..=4 => 0,
        5 => r.below(3000),
        6 => r.below(3000).wrapping_neg(),
        7 => (1u32 << 31).wrapping_add(r.below(5)).wrapping_sub(2),
        8 => r.below(1 << 22),
        _ => r.u32(),
    }
}

fn ts(r: &mut Src<'_>, p: &mut Peer) -> Option<Timestamps> {
    match r.below(5) {
        0 => None,
        1 => Some(Timestamps {
            val: r.u32(),
            ecr: r.u32(),
        }),
        2 => Some(Timestamps {
            val: p.ts_val.wrapping_sub(r.below(1 << 31)),
            ecr: p.ts_seen,
        }),
        _ => {
            p.ts_val = p.ts_val.wrapping_add(r.below(20));
            Some(Timestamps {
                val: p.ts_val,
                ecr: p.ts_seen.wrapping_sub(r.below(3)),
            })
        }
    }
}

/// `raw_adversary` の target の 1 回分です。
pub fn raw_adversary(data: &[u8]) {
    let mut r = Src(data);
    let may_return = Rc::new(Cell::new(true));
    let mut n = Net::new(RawNet::config(small_limits()), Flip(may_return.clone()));
    let now = n.now();
    let l = n
        .stack()
        .listen_tcp(now, SocketAddrV4::new(DUT, 80))
        .expect("listen on port 80");
    let u: UdpId = n
        .stack()
        .bind_udp(now, SocketAddrV4::new(DUT, 53))
        .expect("bind port 53");
    let mut peers: BTreeMap<u16, Peer> = BTreeMap::new();
    let mut app = App {
        l,
        u,
        conns: Vec::new(),
        pings: Vec::new(),
        may_return,
    };
    let wbuf = vec![0x5au8; 70_000];
    let mut rbuf = vec![0u8; 70_000];
    let mut steps = 0;
    while !r.done() && steps < MAX_STEPS {
        steps += 1;
        let kind = r.below(100);
        let port = 1000 + u16::try_from(r.below(PORTS)).unwrap_or(0);
        match kind {
            0..5 => syn(&mut n, &mut r, &mut peers, port),
            5..8 => connect(&mut n, &mut r, &mut peers, port),
            8..41 => segment(&mut n, &mut r, &mut peers, port),
            41..45 => bulk(&mut n, &mut r, &mut peers, port),
            45..50 => frag_needed(&mut n, &mut r, &peers, port),
            50..54 => {
                let body = r.pick(&[0usize, 8, 56, 1392, 1500]);
                let m = Icmp {
                    typ: r.pick(&[0u8, 8, 8, 3, 11, 12, 13, 17, 255]),
                    code: u8::try_from(r.below(4)).unwrap_or(0),
                    rest: r.u32(),
                    body: vec![0x11; body],
                };
                let id = u16::try_from(r.below(1 << 16)).unwrap_or(0);
                let p = ip::icmp_packet(PEER, DUT, id, &m);
                send_maybe_fragmented(&mut n, &mut r, &p);
            }
            54..64 => {
                let dport = r.pick(&[53u16, 53, 53, 54, 9]);
                let len = r.pick(&[0usize, 1, 200, 1400, 3000, 9000, 65_000]);
                let id = u16::try_from(r.below(1 << 16)).unwrap_or(0);
                let p = ip::udp_packet(
                    SocketAddrV4::new(PEER, port),
                    SocketAddrV4::new(DUT, dport),
                    id,
                    &vec![0x33; len],
                );
                send_maybe_fragmented(&mut n, &mut r, &p);
            }
            64..68 => {
                let len = r.pick(&[1usize, 8, 16, 1400]) + r.below(80) as usize;
                let p = Ipv4 {
                    src: PEER,
                    dst: DUT,
                    proto: r.pick(&[1u8, 6, 17, 99]),
                    id: u16::try_from(r.below(8)).unwrap_or(0),
                    df: r.below(10) == 0,
                    mf: r.below(3) != 0,
                    offset: r.below(8200) as usize * 8,
                    ttl: 64,
                    payload: vec![0x77; len],
                };
                n.write(&p.marshal());
            }
            68..82 => app.step(&mut n, &mut r, port, (&wbuf, &mut rbuf)),
            82..93 => absorb(&mut n, &mut peers),
            _ => {
                let d = if r.below(20) == 0 {
                    r.pick(&[
                        Duration::ZERO,
                        Duration::from_millis(1),
                        Duration::from_secs(1),
                        Duration::from_secs(31),
                        Duration::from_secs(70),
                        Duration::from_secs(3600),
                        Duration::from_hours(25 * 24),
                    ])
                } else {
                    Duration::from_millis(u64::from(r.below(300)))
                };
                n.advance(d);
            }
        }
        n.check();
    }
    while n.stack().poll_log().is_some() {}
    n.drain();
    n.finish();
}

/// 種 `seed` から決まった `len` byte の入力を作ります。stable の試験と cargo-fuzz の種が使います。
pub fn raw_adversary_input(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[7]
        })
        .collect()
}

/// 種 `seed` から決まった入力を作って流します。stable の試験が使います。
pub fn raw_adversary_seed(seed: u64, len: usize) {
    raw_adversary(&raw_adversary_input(seed, len));
}

fn syn(n: &mut RawNet, r: &mut Src<'_>, peers: &mut BTreeMap<u16, Peer>, port: u16) {
    let mss = r.pick(&[
        None,
        Some(0u16),
        Some(536),
        Some(537),
        Some(1380),
        Some(65535),
    ]);
    let ws = r.pick(&[-1i8, 0, 7, 14, 15, -1]);
    let seq = r.u32();
    let ts = (r.below(2) == 0).then(|| Timestamps {
        val: r.u32(),
        ecr: r.u32(),
    });
    let extra = r.pick(&[0u8, 0, 0, 0, 0, 0, 0, 0, ACK, FIN]);
    let window = r.pick(&[0u16, 1, 65535, 4096]);
    let sack_permitted = r.below(3) != 0;
    n.inject(&Segment {
        src: SocketAddrV4::new(PEER, port),
        dst: SocketAddrV4::new(DUT, 80),
        seq,
        flags: SYN | extra,
        window,
        opts: Options {
            mss,
            ws: i64::from(ws),
            sack_permitted,
            ts,
            ..Options::none()
        },
        ..Segment::default()
    });
    let p = peers.entry(port).or_default();
    p.snd = seq.wrapping_add(1);
    if let Some(t) = ts {
        p.ts_val = t.val;
    }
}

/// 正直な相手が接続を開きます。SYN を送り、核の SYN-ACK に正しい ACK を返して握手を終えます。乱れた SYN と
/// segment だけでは、boost の枠の数を超える接続を同時に開くことがほとんど無いためです。
fn connect(n: &mut RawNet, r: &mut Src<'_>, peers: &mut BTreeMap<u16, Peer>, port: u16) {
    let seq = r.u32();
    let ts = r.below(2) == 0;
    n.inject(&Segment {
        src: SocketAddrV4::new(PEER, port),
        dst: SocketAddrV4::new(DUT, 80),
        seq,
        flags: SYN,
        window: 65535,
        opts: Options {
            mss: Some(1380),
            ws: 7,
            sack_permitted: true,
            ts: ts.then_some(Timestamps { val: 1, ecr: 0 }),
            ..Options::none()
        },
        ..Segment::default()
    });
    let p = peers.entry(port).or_default();
    p.snd = seq.wrapping_add(1);
    p.ts_val = 1;
    absorb(n, peers);
    let Some(p) = peers.get_mut(&port) else {
        return;
    };
    p.ts_val = p.ts_val.wrapping_add(1);
    n.inject(&Segment {
        src: SocketAddrV4::new(PEER, port),
        dst: SocketAddrV4::new(DUT, 80),
        seq: p.snd,
        ack: p.rcv_hi,
        flags: ACK,
        window: 65535,
        opts: Options {
            ts: ts.then_some(Timestamps {
                val: p.ts_val,
                ecr: p.ts_seen,
            }),
            ..Options::none()
        },
        ..Segment::default()
    });
}

/// 相手がまとまったデータを順に送ります。1 つの segment を抜かして順序外のデータを作ることもあります。乱れた
/// segment だけでは、受信の需要 (区間の中に 64 KiB) と boost の段の順序外のデータにほとんど届かないためです。
fn bulk(n: &mut RawNet, r: &mut Src<'_>, peers: &mut BTreeMap<u16, Peer>, port: u16) {
    let Some(p) = peers.get_mut(&port) else {
        return;
    };
    let count = r.pick(&[8u32, 48, 64, 200]);
    let skip = r.pick(&[None, None, Some(0u32), Some(1), Some(7)]);
    for k in 0..count {
        let seq = p.snd.wrapping_add(k * BULK_LEN);
        if skip == Some(k) {
            continue;
        }
        p.ts_val = p.ts_val.wrapping_add(1);
        n.inject(&Segment {
            src: SocketAddrV4::new(PEER, port),
            dst: SocketAddrV4::new(DUT, 80),
            seq,
            ack: p.rcv_hi,
            flags: ACK,
            window: 65535,
            opts: Options {
                ts: (p.ts_seen != 0).then_some(Timestamps {
                    val: p.ts_val,
                    ecr: p.ts_seen,
                }),
                ..Options::none()
            },
            payload: vec![0xb5; BULK_LEN as usize],
            ..Segment::default()
        });
    }
    if skip.is_none() {
        p.snd = p.snd.wrapping_add(count * BULK_LEN);
    }
}

fn segment(n: &mut RawNet, r: &mut Src<'_>, peers: &mut BTreeMap<u16, Peer>, port: u16) {
    let Some(p) = peers.get_mut(&port) else {
        return;
    };
    let flags = r.pick(&[
        ACK,
        ACK,
        ACK,
        ACK,
        ACK,
        ACK,
        ACK | FIN,
        RST,
        RST | ACK,
        SYN,
        ACK | 0x08,
        ACK | 0x20,
        0,
        SYN | FIN,
        0xff,
    ]);
    let seq = p.snd.wrapping_add(delta(r));
    let span = p.rcv_hi.wrapping_sub(p.rcv_lo);
    let ack = match r.below(6) {
        0..=2 => p.rcv_hi,
        3 => p.rcv_lo.wrapping_add(r.below(span.saturating_add(1))),
        4 => p.rcv_hi.wrapping_add(delta(r)),
        _ => r.u32(),
    };
    let mut sack = Vec::new();
    for _ in 0..r.below(5) {
        let a = match r.below(4) {
            0 => ack.wrapping_add(r.below(span.saturating_add(1))),
            1 => p.rcv_lo.wrapping_add(r.below(span.saturating_add(1))),
            2 => ack.wrapping_sub(r.below(70_000)),
            _ => r.u32(),
        };
        let b = a.wrapping_add(match r.below(4) {
            0 => r.below(1400) + 1,
            1 => r.below(span.saturating_add(1)),
            2 => 0,
            _ => r.u32(),
        });
        sack.push(SackBlock { left: a, right: b });
    }
    let ts = ts(r, p);
    if ts.is_some() {
        sack.truncate(3);
    }
    let len = r.pick(&[0usize, 0, 1, 100, 1368]) + r.below(13) as usize;
    let window = r.pick(&[0u16, 1, 2, 65535, 65535, 4096]);
    n.inject(&Segment {
        src: SocketAddrV4::new(PEER, port),
        dst: SocketAddrV4::new(DUT, 80),
        seq,
        ack,
        flags,
        window,
        opts: Options {
            ts,
            sack,
            ..Options::none()
        },
        payload: vec![0xa5; len],
        ..Segment::default()
    });
    if seq == p.snd && flags & (RST | SYN) == 0 {
        let fin = u32::from(flags & FIN != 0);
        p.snd = p
            .snd
            .wrapping_add(u32::try_from(len).unwrap_or(0))
            .wrapping_add(fin);
    }
}

fn frag_needed(n: &mut RawNet, r: &mut Src<'_>, peers: &BTreeMap<u16, Peer>, port: u16) {
    let quoted = peers.get(&port).and_then(|p| p.last_seg.clone());
    let orig = match quoted {
        Some(q) if r.below(4) != 0 => q,
        _ => Segment {
            src: SocketAddrV4::new(DUT, 80),
            dst: SocketAddrV4::new(PEER, port),
            seq: r.u32(),
            ..Segment::default()
        }
        .marshal(),
    };
    let mtu = r.pick(&[0u16, 68, 551, 552, 553, 576, 1000, 1280, 1420, 1500, 65535]);
    let mut pkt = wgft_tcpharness::packet::frag_needed(PEER, &orig, mtu);
    if r.below(8) == 0 && pkt.len() >= 24 {
        // 同じ引用でほかの種類と code
        pkt[20] = r.pick(&[3u8, 4, 5, 11, 12]);
        pkt[21] = u8::try_from(r.below(16)).unwrap_or(0);
        pkt[22..24].fill(0);
        let s = !fold(&pkt[20..]);
        pkt[22..24].copy_from_slice(&s.to_be_bytes());
    }
    n.write(&pkt);
}

/// アプリケーションが持つ handle と、hook の答えです。
struct App {
    l: ListenerId,
    u: UdpId,
    conns: Vec<ConnId>,
    pings: Vec<PingId>,
    may_return: Rc<Cell<bool>>,
}

impl App {
    fn step(
        &mut self,
        n: &mut RawNet,
        r: &mut Src<'_>,
        port: u16,
        (wbuf, rbuf): (&[u8], &mut [u8]),
    ) {
        let now = n.now();
        let (l, u) = (self.l, self.u);
        let conns = &mut self.conns;
        let pick_conn = |r: &mut Src<'_>, conns: &[ConnId]| {
            conns[r.below(u32::try_from(conns.len()).unwrap_or(1)) as usize]
        };
        match r.below(16) {
            0 | 1 => {
                while let Ok((c, _)) = n.stack().accept(now, l) {
                    conns.push(c);
                }
            }
            2 | 3 if !conns.is_empty() => {
                let c = pick_conn(r, conns);
                let k = r.pick(&[1usize, 100, 1000, 65536, 70_000]);
                let _ = n.stack().write(now, c, &wbuf[..k]);
            }
            4 | 5 if !conns.is_empty() => {
                let c = pick_conn(r, conns);
                let _ = n.stack().read(now, c, rbuf);
            }
            6 if !conns.is_empty() => {
                let i = r.below(u32::try_from(conns.len()).unwrap_or(1)) as usize;
                let c = conns.swap_remove(i);
                match r.below(4) {
                    0 => n.stack().abort(now, c),
                    1 => n.stack().close_for_delivery(now, c),
                    _ => n.stack().close_conn(now, c),
                }
            }
            7 if !conns.is_empty() => {
                let c = pick_conn(r, conns);
                let _ = n.stack().close_write(now, c);
            }
            8 => {
                while let Ok((_, from)) = n.stack().recv_from(now, u, rbuf) {
                    if r.below(2) == 0 {
                        let k = r.pick(&[1usize, 1400, 9000, 65_000]);
                        let _ = n.stack().send_to(now, u, &wbuf[..k], from);
                    }
                }
            }
            10 => {
                // すべての接続に続けて大きく書きます。多くの接続が同時に送信の需要を持ちます
                let k = r.pick(&[65_536usize, 70_000]);
                for &c in conns.iter() {
                    let _ = n.stack().write(now, c, &wbuf[..k]);
                }
            }
            11 => {
                // すべての接続から読み切ります。読まなかった接続も受信の需要を持ちます
                for &c in conns.iter() {
                    while n.stack().read(now, c, rbuf).is_ok_and(|k| k > 0) {}
                }
            }
            12 => self.may_return.set(!self.may_return.get()),
            13 => {
                // 待ち受けを閉じて開き直します。待ち行列の接続と握手の途中の行を捨てる経路を通ります
                n.stack().close_listener(now, l);
                self.l = n
                    .stack()
                    .listen_tcp(now, SocketAddrV4::new(DUT, 80))
                    .expect("listen again on port 80");
            }
            14 => {
                // ping の endpoint を開くか、開いた endpoint から echo を送ります
                if self.pings.is_empty() || r.below(3) == 0 {
                    if let Ok(p) = n.stack().open_ping(now, PEER) {
                        self.pings.push(p);
                    }
                } else {
                    let p =
                        self.pings[r.below(u32::try_from(self.pings.len()).unwrap_or(1)) as usize];
                    let len = r.pick(&[8usize, 64, 1400]);
                    let mut m = vec![0x66u8; len];
                    m[0] = 8;
                    let _ = n.stack().send_ping(now, p, &m);
                }
            }
            15 if !self.pings.is_empty() => {
                // 返事を読むか、endpoint を閉じます
                let i = r.below(u32::try_from(self.pings.len()).unwrap_or(1)) as usize;
                if r.below(2) == 0 {
                    while n.stack().recv_ping(now, self.pings[i], rbuf).is_ok() {}
                } else {
                    let p = self.pings.swap_remove(i);
                    n.stack().close_ping(now, p);
                }
            }
            _ => {
                let k = r.pick(&[1usize, 1400, 9000, 65_000]);
                let to = SocketAddrV4::new(PEER, port);
                // 待たずに古いものを捨てる送りと、時間の上限を持つ送りも混ぜます
                match r.below(3) {
                    0 => {
                        let _ = n.stack().send_to(now, u, &wbuf[..k], to);
                    }
                    1 => {
                        let _ = n.stack().send_to_latest(now, u, &wbuf[..k], to, 0);
                    }
                    _ => {
                        let age = r.pick(&[1u16, 30, 100]);
                        let _ = n.stack().send_to_latest(now, u, &wbuf[..k], to, age);
                    }
                }
            }
        }
    }
}

/// 核の出力をすべて引き取り、相手の番号を進めます。
fn absorb(n: &mut RawNet, peers: &mut BTreeMap<u16, Peer>) {
    let mut segs = Vec::new();
    let mut others = Vec::new();
    n.drain_into(&mut segs, &mut others);
    for pkt in others {
        // 相手は核の echo に答えます
        if let Ok(ip) = ip::parse_ipv4(&pkt)
            && ip.proto == ip::PROTO_ICMP
            && ip.payload.first() == Some(&8)
            && ip.payload.len() >= 8
        {
            let mut body = ip.payload.clone();
            body[0] = 0;
            body[2..4].fill(0);
            let id = u16::from_be_bytes([body[4], body[5]]);
            let rest = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
            let m = Icmp {
                typ: 0,
                code: 0,
                rest,
                body: body[8..].to_vec(),
            };
            n.write(&ip::icmp_packet(PEER, DUT, id, &m).marshal());
        }
    }
    for s in segs {
        let p = peers.entry(s.dst.port()).or_default();
        let end = s.seq.wrapping_add(s.seq_len());
        if s.flags & SYN != 0 {
            p.rcv_lo = s.seq;
            p.rcv_hi = end;
            p.snd = s.ack;
        } else if end.wrapping_sub(p.rcv_hi).cast_signed() > 0 {
            p.rcv_hi = end;
        }
        if let Some(t) = s.opts.ts {
            p.ts_seen = t.val;
        }
        p.last_seg = Some(s.marshal());
    }
    while n.stack().poll_event().is_some() {}
}

fn fold(b: &[u8]) -> u16 {
    let mut s: u32 = 0;
    for c in b.chunks(2) {
        s += u32::from(c[0]) << 8 | u32::from(c.get(1).copied().unwrap_or(0));
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    u16::try_from(s).unwrap_or(0)
}

/// datagram をそのままか断片に分けて入れます。断片は順を混ぜ、先頭を繰り返し、重なる断片を足すことがあります。
fn send_maybe_fragmented(n: &mut RawNet, r: &mut Src<'_>, p: &Ipv4) {
    let len = p.payload.len();
    if len + 20 <= MTU && r.below(3) != 0 {
        n.write(&p.marshal());
        return;
    }
    let mut cuts = Vec::new();
    let mut at = 0usize;
    loop {
        at += 8 * (1 + r.below(180) as usize);
        if at >= len {
            break;
        }
        cuts.push(at);
    }
    let mut frags = ip::fragments(p, &cuts);
    for i in (1..frags.len()).rev() {
        let j = r.below(u32::try_from(i + 1).unwrap_or(1)) as usize;
        frags.swap(i, j);
    }
    if r.below(5) == 0
        && let Some(d) = frags.first().cloned()
    {
        frags.push(d);
    }
    if r.below(8) == 0 && len > 16 {
        let a = 8 * r.below(u32::try_from(len / 8).unwrap_or(1)) as usize;
        let b = (a + 8 + 8 * r.below(20) as usize).min(len);
        frags.push(ip::frag(p, a, b));
    }
    for f in frags {
        n.write(&f.marshal());
    }
}
