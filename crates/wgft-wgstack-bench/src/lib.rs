//! wgstack の核の segment ごとの経路を測る道具です。配布せず、製品の依存の木にも入りません。
//!
//! [`Rig`] は核と、トンネルの側の相手の接続を `conns` 本持ちます。相手は公開の API だけで核を動かすので、核の
//! 内部の形 (接続の枠の配置) を変えても同じ負荷を流せます。測り方は `docs/design/v2/wgstack-rs.md` の
//! 「接続の枠の配置」にあります。

use core::net::{Ipv4Addr, SocketAddrV4};
use wgft_wgstack::{BoostPolicy, Bound, Budget, Config, ConnId, Held, Limits, NoHook, Stack, Time};

const DUT: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 1);
const PEER: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 2);
const MTU: usize = 1420;
/// 相手が送る segment の中身の大きさです (timestamp を使わない接続の MSS)。
pub const MSS: usize = MTU - 40;

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const PSH: u8 = 0x08;

/// 相手の側の 1 本の接続です。
#[derive(Clone, Copy, Debug)]
struct Peer {
    id: ConnId,
    port: u16,
    /// 相手の次の番号です。
    snd: u32,
    /// 相手が次に受ける番号 (核の番号) です。
    rcv: u32,
}

/// 核と相手の接続の組です。
#[derive(Debug)]
pub struct Rig {
    stack: Stack<NoHook>,
    now: Time,
    peers: Vec<Peer>,
    /// 握手を終えて accept の待ち行列にいる接続の相手の、ポートと次の番号と核の次の番号です。
    queued: Vec<(u16, u32, u32)>,
    listener: wgft_wgstack::ListenerId,
    pkt: Vec<u8>,
    out: Vec<u8>,
    data: Vec<u8>,
}

/// 16 bit の 1 の補数の和を `sum` に足します。
fn ones(mut sum: u32, b: &[u8]) -> u32 {
    let (pairs, rest) = b.as_chunks::<2>();
    for c in pairs {
        sum += u32::from(u16::from_be_bytes(*c));
    }
    if let [x] = rest {
        sum += u32::from(*x) << 8;
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(0)
}

/// 相手のポート `sport` から核への TCP の packet を `b` に組み立てます。
fn build(b: &mut Vec<u8>, sport: u16, seq: u32, ack: u32, flags: u8, opts: &[u8], payload: &[u8]) {
    let thl = 20 + opts.len();
    let total = 20 + thl + payload.len();
    b.clear();
    b.resize(total, 0);
    b[0] = 0x45;
    b[2..4].copy_from_slice(&u16::try_from(total).unwrap_or(0).to_be_bytes());
    b[6] = 0x40;
    b[8] = 64;
    b[9] = 6;
    b[12..16].copy_from_slice(&PEER.octets());
    b[16..20].copy_from_slice(&DUT.octets());
    let ip = fold(ones(0, &b[..20]));
    b[10..12].copy_from_slice(&ip.to_be_bytes());
    let t = &mut b[20..];
    t[0..2].copy_from_slice(&sport.to_be_bytes());
    t[2..4].copy_from_slice(&80u16.to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = u8::try_from(thl / 4).unwrap_or(0) << 4;
    t[13] = flags;
    t[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
    t[20..thl].copy_from_slice(opts);
    t[thl..].copy_from_slice(payload);
    let tcp_len = u32::try_from(thl + payload.len()).unwrap_or(0);
    let pseudo = ones(ones(0, &PEER.octets()), &DUT.octets()) + 6 + tcp_len;
    let cs = fold(ones(pseudo, t));
    t[16..18].copy_from_slice(&cs.to_be_bytes());
}

/// 核が送った packet の宛先のポート、番号、中身の長さです。
fn parse(p: &[u8]) -> (u16, u32, usize) {
    let hl = usize::from(p[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([p[2], p[3]]));
    let t = &p[hl..total];
    let dport = u16::from_be_bytes([t[2], t[3]]);
    let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
    let thl = usize::from(t[12] >> 4) * 4;
    (dport, seq, t.len() - thl)
}

impl Rig {
    /// 待ち受けを開き、相手から `conns` 本の接続を確立して accept します。相手は SACK を示しません。
    pub fn new(conns: usize) -> Self {
        Self::with_sack(conns, false)
    }

    /// `new` と同じで、`sack` が真なら相手が SACK-permitted を示し、SACK を交渉した接続の経路 (RACK の状態の更新と
    /// TLP の期限) を通ります。
    pub fn with_sack(conns: usize, sack: bool) -> Self {
        Self::build(conns, sack, Limits::default(), BoostPolicy::OnDemand)
    }

    /// `with_sack` と同じで、表の大きさ `limits` と boost の与え方 `boost` を選びます。
    pub fn build(conns: usize, sack: bool, limits: Limits, boost: BoostPolicy) -> Self {
        let config = Config {
            limits,
            boost,
            ..Config::new(DUT, MTU)
        };
        let stack =
            Stack::new(config, Budget::new().expect("budget"), &[7; 64], NoHook).expect("stack");
        let mut stack = stack;
        let l = stack
            .listen_tcp(Time::ZERO, SocketAddrV4::new(DUT, 80))
            .expect("listen");
        // 試験の側が確保の数えに混ざらないよう、list は表の枠の数の容量を先に取ります。
        let slots = conns.max(limits.conns());
        let mut r = Self {
            stack,
            now: Time::ZERO,
            peers: Vec::with_capacity(slots),
            queued: Vec::with_capacity(slots),
            listener: l,
            pkt: Vec::with_capacity(MTU + 64),
            out: vec![0; MTU],
            data: vec![0x5a; MSS],
        };
        // MSS 1380 と窓の scale 7 と、NOP NOP SACK-permitted です。
        let opts: &[u8] = if sack {
            &[2, 4, 0x05, 0x64, 1, 3, 3, 7, 1, 1, 4, 2]
        } else {
            &[2, 4, 0x05, 0x64, 1, 3, 3, 7]
        };
        for i in 0..conns {
            let port = 10_000 + u16::try_from(i).expect("port");
            build(&mut r.pkt, port, 1000, 0, SYN, opts, &[]);
            r.stack.handle_packet(r.now, &r.pkt);
            let n = r.stack.poll_transmit(r.now, &mut r.out).expect("SYN-ACK");
            let (_, iss, _) = parse(&r.out[..n]);
            build(&mut r.pkt, port, 1001, iss.wrapping_add(1), ACK, &[], &[]);
            r.stack.handle_packet(r.now, &r.pkt);
            let (id, _) = r.stack.accept(r.now, l).expect("accept");
            r.peers.push(Peer {
                id,
                port,
                snd: 1001,
                rcv: iss.wrapping_add(1),
            });
        }
        while r.stack.poll_transmit(r.now, &mut r.out).is_some() {}
        while r.stack.poll_event().is_some() {}
        r
    }

    /// 時刻を進め、駆動の層と同じく期限の来たタイマーを処理します。
    fn tick(&mut self) {
        self.now = self.now + core::time::Duration::from_micros(10);
        self.stack.handle_timeout(self.now);
    }

    /// 道具だけの費用です。`recv_one` と同じ packet を組み立てて checksum を計算し、核が送った ACK と同じ大きさの
    /// packet を解きますが、核は呼びません。segment ごとの経路の値からこの値を引くと、核の費用の目安になります。
    pub fn rig_only(&mut self, k: usize) {
        let p = self.peers[k];
        build(
            &mut self.pkt,
            p.port,
            p.snd,
            p.rcv,
            ACK | PSH,
            &[],
            &self.data,
        );
        let n = self.pkt.len();
        self.out[..40].copy_from_slice(&self.pkt[..40]);
        self.out[2..4].copy_from_slice(&40u16.to_be_bytes());
        let (port, seq, len) = parse(&self.out[..40]);
        core::hint::black_box((port, seq, len, n));
    }

    /// 相手 `k` から順序どおりの中身の segment を 1 つ届け、核の出力を取り出し、アプリケーションが読みます。
    pub fn recv_one(&mut self, k: usize) {
        self.tick();
        let p = self.peers[k];
        build(
            &mut self.pkt,
            p.port,
            p.snd,
            p.rcv,
            ACK | PSH,
            &[],
            &self.data,
        );
        self.stack.handle_packet(self.now, &self.pkt);
        self.peers[k].snd = p.snd.wrapping_add(u32::try_from(MSS).unwrap_or(0));
        while self.stack.poll_transmit(self.now, &mut self.out).is_some() {}
        let mut buf = [0u8; MSS];
        while self
            .stack
            .read(self.now, p.id, &mut buf)
            .is_ok_and(|n| n > 0)
        {}
        while self.stack.poll_event().is_some() {}
    }

    /// 接続 `k` に 1 segment 分を書き、核が送る segment を取り出し、相手が確認します。
    pub fn send_one(&mut self, k: usize) {
        self.tick();
        let p = self.peers[k];
        let _ = self.stack.write(self.now, p.id, &self.data);
        let mut acked = p.rcv;
        while let Some(n) = self.stack.poll_transmit(self.now, &mut self.out) {
            let (port, seq, len) = parse(&self.out[..n]);
            let end = seq.wrapping_add(u32::try_from(len).unwrap_or(0));
            // 番号は一周するので、差の符号で比べます。
            if port == p.port && end.wrapping_sub(acked).cast_signed() > 0 {
                acked = end;
            }
        }
        self.peers[k].rcv = acked;
        build(&mut self.pkt, p.port, p.snd, acked, ACK, &[], &[]);
        self.stack.handle_packet(self.now, &self.pkt);
        while self.stack.poll_transmit(self.now, &mut self.out).is_some() {}
        while self.stack.poll_event().is_some() {}
    }

    /// 相手のポート `port` から握手を終え、accept せずに `segments` 個の中身の segment を届けます。核は接続を
    /// accept の待ち行列に置いたまま受けます。確立できれば真を返します。
    pub fn connect_unaccepted(&mut self, port: u16, segments: usize) -> bool {
        build(
            &mut self.pkt,
            port,
            1000,
            0,
            SYN,
            &[2, 4, 0x05, 0x64, 1, 3, 3, 7],
            &[],
        );
        self.stack.handle_packet(self.now, &self.pkt);
        let Some(n) = self.stack.poll_transmit(self.now, &mut self.out) else {
            return false;
        };
        let (_, iss, _) = parse(&self.out[..n]);
        let before = self.stack.held().accept_queued;
        build(
            &mut self.pkt,
            port,
            1001,
            iss.wrapping_add(1),
            ACK,
            &[],
            &[],
        );
        self.stack.handle_packet(self.now, &self.pkt);
        if self.stack.held().accept_queued == before {
            return false;
        }
        self.queued.push((port, 1001, iss.wrapping_add(1)));
        let k = self.queued.len() - 1;
        for _ in 0..segments {
            self.deliver(k, true);
        }
        while self.stack.poll_transmit(self.now, &mut self.out).is_some() {}
        while self.stack.poll_event().is_some() {}
        true
    }

    /// 相手が中身の segment を 1 つ送ります。`queued` なら待ち行列の `k` 番目の相手、偽なら `k` 番目の接続です。
    /// 窓の外の分は核が捨てます。
    fn deliver(&mut self, k: usize, queued: bool) {
        let (port, snd, rcv) = if queued {
            self.queued[k]
        } else {
            let p = self.peers[k];
            (p.port, p.snd, p.rcv)
        };
        build(&mut self.pkt, port, snd, rcv, ACK | PSH, &[], &self.data);
        self.stack.handle_packet(self.now, &self.pkt);
        // 相手の次の番号は、核が確認した番号です。窓の外で捨てた分は送り直しません。
        let mut next = snd;
        while let Some(n) = self.stack.poll_transmit(self.now, &mut self.out) {
            let o = &self.out[..n];
            let hl = usize::from(o[0] & 0x0f) * 4;
            let (dport, _, _) = parse(o);
            let ack = u32::from_be_bytes([o[hl + 8], o[hl + 9], o[hl + 10], o[hl + 11]]);
            if dport == port && ack.wrapping_sub(next).cast_signed() > 0 {
                next = ack;
            }
        }
        if queued {
            self.queued[k].1 = next;
        } else {
            self.peers[k].snd = next;
        }
    }

    /// accept の待ち行列の接続をすべて accept し、接続の列に足します。accept した数を返します。
    pub fn accept_queued(&mut self) -> usize {
        let n = self.queued.len();
        for (port, snd, rcv) in self.queued.drain(..) {
            let (id, _) = self.stack.accept(self.now, self.listener).expect("accept");
            self.peers.push(Peer { id, port, snd, rcv });
        }
        while self.stack.poll_event().is_some() {}
        n
    }

    /// 接続 `k` に書けなくなるまで書き、核が送る segment を取り出しますが、相手は確認しません。送信の輪が満ちます。
    pub fn fill_send(&mut self, k: usize) {
        let p = self.peers[k];
        while self
            .stack
            .write(self.now, p.id, &self.data)
            .is_ok_and(|n| n > 0)
        {}
        let mut acked = p.rcv;
        while let Some(n) = self.stack.poll_transmit(self.now, &mut self.out) {
            let (port, seq, len) = parse(&self.out[..n]);
            let end = seq.wrapping_add(u32::try_from(len).unwrap_or(0));
            if port == p.port && end.wrapping_sub(acked).cast_signed() > 0 {
                acked = end;
            }
        }
        self.peers[k].rcv = acked;
        while self.stack.poll_event().is_some() {}
    }

    /// 相手が接続 `k` に `segments` 個の中身の segment を送り、アプリケーションは読みません。受信の輪が満ちます。
    pub fn fill_recv(&mut self, k: usize, segments: usize) {
        for _ in 0..segments {
            self.deliver(k, false);
        }
        while self.stack.poll_event().is_some() {}
    }

    /// 相手が接続 `k` で受けたデータを確認し、核が続けて送る分も確認し続けます。核の送信の輪は空になり、送り
    /// 終えた chunk は置き場に戻ります。
    pub fn ack(&mut self, k: usize) {
        loop {
            let p = self.peers[k];
            build(&mut self.pkt, p.port, p.snd, p.rcv, ACK, &[], &[]);
            self.stack.handle_packet(self.now, &self.pkt);
            let mut acked = p.rcv;
            while let Some(n) = self.stack.poll_transmit(self.now, &mut self.out) {
                let (port, seq, len) = parse(&self.out[..n]);
                let end = seq.wrapping_add(u32::try_from(len).unwrap_or(0));
                if port == p.port && end.wrapping_sub(acked).cast_signed() > 0 {
                    acked = end;
                }
            }
            if acked == p.rcv {
                break;
            }
            self.peers[k].rcv = acked;
        }
        while self.stack.poll_event().is_some() {}
    }

    /// 核の会計です。
    pub fn held(&self) -> Held {
        self.stack.held()
    }

    /// 核の上界です。
    pub fn bound(&self) -> Bound {
        self.stack.bound()
    }

    /// 接続の数です。
    pub fn conns(&self) -> usize {
        self.peers.len()
    }

    /// 核の不変条件を確かめます。
    pub fn check(&self) {
        self.stack.check_invariants().expect("invariants");
    }

    /// 核の不変条件を確かめ、合っていれば真を返します。不変条件の検査の手間を測るのに使います。
    pub fn check_ok(&self) -> bool {
        self.stack.check_invariants().is_ok()
    }
}

/// 既定の表の大きさの核を作って閉じます。核の作成の手間を測るのに使います。
pub fn new_and_close() {
    let config = Config::new(DUT, MTU);
    let stack =
        Stack::new(config, Budget::new().expect("budget"), &[7; 64], NoHook).expect("stack");
    core::hint::black_box(stack.close(Time::ZERO));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rig_moves_data_both_ways() {
        for sack in [false, true] {
            let mut r = Rig::with_sack(4, sack);
            r.rig_only(0);
            for i in 0..200 {
                r.recv_one(i % 4);
                r.send_one(i % 4);
            }
            r.check();
            assert_eq!(r.conns(), 4);
        }
    }

    /// 確認を受けながら送り続け、1 回ごとに 1 segment を送ります。
    #[test]
    fn sending_survives_the_sequence_wrap() {
        let mut r = Rig::new(1);
        for _ in 0..4_000_000 / MSS {
            r.send_one(0);
        }
        let before = r.peers[0].rcv;
        r.send_one(0);
        assert_eq!(
            r.peers[0].rcv.wrapping_sub(before),
            u32::try_from(MSS).unwrap()
        );
        r.check();
    }
}
