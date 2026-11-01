//! wgstack の核の segment ごとの経路を測る道具です。配布せず、製品の依存の木にも入りません。
//!
//! [`Rig`] は核と、トンネルの側の相手の接続を `conns` 本持ちます。相手は公開の API だけで核を動かすので、核の
//! 内部の形 (接続の枠の配置) を変えても同じ負荷を流せます。測り方は `docs/design/v2/wgstack-rs.md` の
//! 「接続の枠の配置」にあります。

use core::net::{Ipv4Addr, SocketAddrV4};
use wgft_wgstack::{Budget, Config, ConnId, NoHook, Stack, Time};

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
    /// 待ち受けを開き、相手から `conns` 本の接続を確立して accept します。
    pub fn new(conns: usize) -> Self {
        let config = Config::new(DUT, MTU);
        let stack =
            Stack::new(config, Budget::new().expect("budget"), &[7; 64], NoHook).expect("stack");
        let mut r = Self {
            stack,
            now: Time::ZERO,
            peers: Vec::with_capacity(conns),
            pkt: Vec::with_capacity(MTU + 64),
            out: vec![0; MTU],
            data: vec![0x5a; MSS],
        };
        let l = r
            .stack
            .listen_tcp(r.now, SocketAddrV4::new(DUT, 80))
            .expect("listen");
        // MSS 1380 と窓の scale 7 です。
        let opts = [2, 4, 0x05, 0x64, 1, 3, 3, 7];
        for i in 0..conns {
            let port = 10_000 + u16::try_from(i).expect("port");
            build(&mut r.pkt, port, 1000, 0, SYN, &opts, &[]);
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

    /// 接続の数です。
    pub fn conns(&self) -> usize {
        self.peers.len()
    }

    /// 核の不変条件を確かめます。
    pub fn check(&self) {
        self.stack.check_invariants().expect("invariants");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rig_moves_data_both_ways() {
        let mut r = Rig::new(4);
        r.rig_only(0);
        for i in 0..200 {
            r.recv_one(i % 4);
            r.send_one(i % 4);
        }
        r.check();
        assert_eq!(r.conns(), 4);
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
