//! The crypto of a batch on the crypto workers ([`crate::pool`]). The rules are in
//! `docs/design/v2/agent-throughput.md` (暗号を並べて行う段).
//!
//! - 受信:持ち主のスレッドが datagram を届いた順に device の層の `begin_datagram` に渡し、復号の仕事を
//!   平文の領域のレーンに順に割り振る。レーンは平文の領域を作業者の数より 1 つ多く分けた部分で、
//!   バッチの byte がしきい値を超えるときは、レーンごとにほぼ同じ byte になるように分ける。復号は
//!   レーンごとに作業者と持ち主が行い、受け付け (`finish_datagram`) は持ち主が届いた順に行う。仕事の数か
//!   平文の領域が尽きたら、その回 (round) をそこで閉じ、残りは次の回にする
//! - 送信:持ち主が送る順 (UDP を先に) に `begin_packet` で番号を取り、その順に仕事をレーンに続けて
//!   割り振る。暗号化はレーンごとに作業者と持ち主が行い、送る順はレーンの順、番号の順のままである
//! - 小さなバッチ:byte がしきい値より小さい回は、作業者を起こさずに持ち主がすべて行う
//! - 持ち物:平文と暗号文のレーンは置き場の buffer で、回の間だけ値でレーンに動き、終わると置き場に
//!   戻る。datagram と packet の領域は作業者が `Arc` で読むだけで、回の後に持ち主だけが持つ。packet ごとの
//!   確保は無い

use std::mem;
use std::sync::Arc;
use std::time::Instant;

use wgft_wireguard::{Device, OpenJob, Opened, Outgoing, SealJob};

use crate::pool::{Poisoned, Pool, Run};
use crate::{MAX_SLOTS, RX_SLOT, RxBatch, TxBatch, is_udp};

/// The most decryption jobs in one lane per round. A round with more datagrams closes there and
/// the rest go to the next round.
pub const LANE_JOBS: usize = 2 * MAX_SLOTS;

/// The bytes of a round below which the owner does all of its crypto without waking a worker. On
/// the host (`wgft-agent-perf`), a hand-off with two workers costs about 4 µs of CPU in all; from
/// about 11 KB a batch already ends sooner on the workers, and from this size it also costs at
/// most about 15% more CPU in all than on the owner alone.
pub const PARALLEL_MIN_BYTES: usize = 32 << 10;

/// The header bytes of a data message that the plaintext does not need room for.
const HEADER: usize = 16;

/// One lane's part of a batch.
#[derive(Debug)]
pub enum Lane {
    Open(OpenLane),
    Seal(SealLane),
}

impl Run for Lane {
    fn run(&mut self) {
        match self {
            Lane::Open(l) => l.run(),
            Lane::Seal(l) => l.run(),
        }
    }
}

#[derive(Debug)]
enum OpenState {
    Pending(OpenJob),
    Opened(Opened),
    Empty,
}

#[derive(Debug)]
struct OpenEntry {
    /// The datagram: `len` bytes at `at` in the datagram area. A datagram that crosses its slot's
    /// two parts is decrypted by the owner from a copy and comes here already opened.
    at: u32,
    len: u32,
    /// Its slot, for its sender.
    slot: u16,
    /// Where its plaintext goes in the lane.
    out: u32,
    /// The packet's length after the round, 0 for none.
    delivered: u32,
    state: OpenState,
}

/// The decryption part of a round.
#[derive(Debug)]
pub struct OpenLane {
    data: Option<Arc<[u8]>>,
    plain: Box<[u8]>,
    fill: usize,
    bytes: usize,
    jobs: Vec<OpenEntry>,
}

impl OpenLane {
    fn run(&mut self) {
        let Some(data) = self.data.take() else {
            return;
        };
        for e in &mut self.jobs {
            e.state = match mem::replace(&mut e.state, OpenState::Empty) {
                OpenState::Pending(job) => {
                    let (at, len, out) = (e.at as usize, e.len as usize, e.out as usize);
                    let room = &mut self.plain[out..out + len - HEADER];
                    OpenState::Opened(job.open(&data[at..at + len], room))
                }
                other => other,
            };
        }
    }

    fn has_pending(&self) -> bool {
        self.jobs
            .iter()
            .any(|e| matches!(e.state, OpenState::Pending(_)))
    }
}

#[derive(Debug)]
enum SealState {
    Pending(SealJob),
    Sealed(Outgoing),
    Empty,
}

#[derive(Debug)]
struct SealEntry {
    /// The packet slot.
    slot: u16,
    state: SealState,
}

/// The encryption part of a send batch. Its `k`-th job seals into its lane's slot `k`.
#[derive(Debug)]
pub struct SealLane {
    packets: Option<Arc<[u8]>>,
    sealed: Box<[u8]>,
    mtu: usize,
    stride: usize,
    jobs: Vec<SealEntry>,
}

impl SealLane {
    fn run(&mut self) {
        let Some(packets) = self.packets.take() else {
            return;
        };
        for (k, e) in self.jobs.iter_mut().enumerate() {
            e.state = match mem::replace(&mut e.state, SealState::Empty) {
                SealState::Pending(job) => {
                    let at = usize::from(e.slot) * self.mtu;
                    let out = &mut self.sealed[k * self.stride..(k + 1) * self.stride];
                    job.seal(&packets[at..at + self.mtu], out)
                        .map_or(SealState::Empty, SealState::Sealed)
                }
                other => other,
            };
        }
    }
}

fn open_lane(l: Option<&Lane>) -> &OpenLane {
    match l {
        Some(Lane::Open(l)) => l,
        _ => unreachable!("open lanes hold open parts between rounds"),
    }
}

fn open_lane_mut(l: &mut Option<Lane>) -> &mut OpenLane {
    match l {
        Some(Lane::Open(l)) => l,
        _ => unreachable!("open lanes hold open parts between rounds"),
    }
}

fn seal_lane_mut(l: &mut Option<Lane>) -> &mut SealLane {
    match l {
        Some(Lane::Seal(l)) => l,
        _ => unreachable!("seal lanes hold seal parts between batches"),
    }
}

/// The crypto workers of one tunnel generation and the lanes they work on. Make it on the data-plane
/// thread; dropping it stops the workers.
#[derive(Debug)]
pub struct Crypto {
    /// `None` when the workers could not start: the owner then runs every lane.
    pool: Option<Pool<Lane>>,
    open: Box<[Option<Lane>]>,
    seal: Box<[Option<Lane>]>,
    min_bytes: usize,
    /// The batch being opened: its filled slots, the next datagram (slot, offset) and the bytes left.
    n: usize,
    slot: usize,
    start: usize,
    left: usize,
}

impl Crypto {
    /// The lanes for stores with `lanes` lanes ([`crate::lanes_for`], at least 2) and `lanes - 1`
    /// workers. A round of fewer than `min_bytes` bytes runs on the owner alone; the data plane
    /// passes [`PARALLEL_MIN_BYTES`].
    #[must_use]
    pub fn new(lanes: usize, min_bytes: usize) -> Self {
        let lanes = lanes.max(1);
        Self {
            pool: Pool::new(lanes - 1).ok(),
            open: (0..lanes)
                .map(|_| {
                    Some(Lane::Open(OpenLane {
                        data: None,
                        plain: Box::default(),
                        fill: 0,
                        bytes: 0,
                        jobs: Vec::with_capacity(LANE_JOBS),
                    }))
                })
                .collect(),
            seal: (0..lanes)
                .map(|_| {
                    Some(Lane::Seal(SealLane {
                        packets: None,
                        sealed: Box::default(),
                        mtu: 0,
                        stride: 0,
                        jobs: Vec::with_capacity(MAX_SLOTS),
                    }))
                })
                .collect(),
            min_bytes,
            n: 0,
            slot: 0,
            start: 0,
            left: 0,
        }
    }

    /// The workers that started.
    #[must_use]
    pub fn workers(&self) -> usize {
        self.pool.as_ref().map_or(0, Pool::workers)
    }

    /// The bytes [`Crypto::new`] holds for `lanes` lanes: the job lists, the lanes and the pool of
    /// `lanes - 1` workers with their stacks. The lanes' buffers belong to the stores.
    #[must_use]
    pub const fn bytes(lanes: usize) -> usize {
        let lanes = if lanes == 0 { 1 } else { lanes };
        lanes * (LANE_JOBS * size_of::<OpenEntry>() + MAX_SLOTS * size_of::<SealEntry>())
            + 2 * lanes * size_of::<Option<Lane>>()
            + crate::pool::bytes::<Lane>(lanes - 1)
    }

    /// Starts opening the first `n` filled slots of `rx`; [`Crypto::open_round`] then opens them.
    pub fn start_open(&mut self, rx: &RxBatch, n: usize) {
        self.n = n;
        self.slot = 0;
        self.start = 0;
        self.left = rx.meta[..n]
            .iter()
            .filter(|m| m.from.is_some())
            .map(|m| (m.len as usize).min(RX_SLOT))
            .sum();
    }

    /// Opens the next round of the batch: begins its datagrams in order, decrypts them on the
    /// workers and here, and finishes them in order. Returns `false` once the batch is done;
    /// otherwise [`Crypto::each_packet`] walks the packets of the round.
    ///
    /// # Errors
    ///
    /// [`Poisoned`] after a worker panicked; the store is then unusable and the generation ends.
    pub fn open_round(
        &mut self,
        rx: &mut RxBatch,
        device: &mut Device,
        now: Instant,
    ) -> Result<bool, Poisoned> {
        let lanes = self.open.len().min(rx.plain.len());
        for l in &mut self.open[..lanes] {
            let l = open_lane_mut(l);
            l.fill = 0;
            l.bytes = 0;
            l.jobs.clear();
        }
        if self.slot >= self.n {
            return Ok(false);
        }
        let parallel = self.pool.is_some() && self.left >= self.min_bytes;
        let target = if parallel {
            self.left.div_ceil(lanes)
        } else {
            usize::MAX
        };
        let mut lane = 0;
        let mut any = false;
        'datagrams: while self.slot < self.n {
            let m = rx.meta[self.slot];
            let len = (m.len as usize).min(RX_SLOT);
            let Some(from) = m.from.filter(|_| self.start < len) else {
                self.slot += 1;
                self.start = 0;
                continue;
            };
            let seg = match m.seg as usize {
                0 => len,
                s => s,
            };
            let (start, stop) = (self.start, (self.start + seg).min(len));
            let size = stop - start;
            let piece = rx.piece(self.slot, start, stop);
            let data = match piece {
                Some(at) => Device::is_data_message(&rx.data[at..at + size]),
                None => Device::is_data_message(rx.gather(self.slot, start, stop)),
            };
            // ハンドシェイクは、それより前に届いたデータを受け付けた後に扱う
            if !data && any {
                break;
            }
            let need = size.saturating_sub(HEADER);
            loop {
                let l = open_lane(self.open[lane].as_ref());
                let full = l.jobs.len() == LANE_JOBS
                    || rx.plain[lane].len() - l.fill < need
                    || (l.bytes >= target && lane + 1 < lanes);
                if !full {
                    break;
                }
                if lane + 1 == lanes {
                    break 'datagrams;
                }
                lane += 1;
            }
            self.start = stop;
            self.left -= size;
            let datagram: &[u8] = match piece {
                Some(at) => &rx.data[at..at + size],
                // 写しは上の確かめで作業の領域にある
                None => &rx.scratch[..size],
            };
            let Some(job) = device.begin_datagram(now, from, datagram) else {
                continue;
            };
            let l = open_lane_mut(&mut self.open[lane]);
            let out = l.fill;
            let state = if piece.is_some() {
                OpenState::Pending(job)
            } else {
                OpenState::Opened(job.open(datagram, &mut rx.plain[lane][out..out + need]))
            };
            l.jobs.push(OpenEntry {
                at: u32::try_from(piece.unwrap_or(0)).unwrap_or(u32::MAX),
                len: u32::try_from(size).unwrap_or(u32::MAX),
                slot: u16::try_from(self.slot).unwrap_or(u16::MAX),
                out: u32::try_from(out).unwrap_or(u32::MAX),
                delivered: 0,
                state,
            });
            l.fill += need;
            l.bytes += need;
            any = true;
        }
        if any {
            self.decrypt(rx, lanes, parallel)?;
            for (j, l) in self.open[..lanes].iter_mut().enumerate() {
                let l = open_lane_mut(l);
                for e in &mut l.jobs {
                    let OpenState::Opened(o) = mem::replace(&mut e.state, OpenState::Empty) else {
                        continue;
                    };
                    let Some(from) = rx.meta[usize::from(e.slot)].from else {
                        continue;
                    };
                    let (out, len) = (e.out as usize, e.len as usize);
                    let plain = &rx.plain[j][out..out + len - HEADER];
                    let got = device.finish_datagram(now, from, len, o, plain);
                    e.delivered = u32::try_from(got.unwrap_or(0)).unwrap_or(0);
                }
            }
        }
        Ok(true)
    }

    /// Decrypts the round's pending jobs: on the workers when `parallel` and more than one lane has
    /// work, else here.
    fn decrypt(&mut self, rx: &mut RxBatch, lanes: usize, parallel: bool) -> Result<(), Poisoned> {
        let mut busy = 0;
        for (j, l) in self.open[..lanes].iter_mut().enumerate() {
            let l = open_lane_mut(l);
            if l.has_pending() {
                busy += 1;
                l.data = Some(Arc::clone(&rx.data));
                l.plain = mem::take(&mut rx.plain[j]);
            }
        }
        let ran = match &self.pool {
            Some(pool) if parallel && busy > 1 => pool.run(&mut self.open[..lanes]),
            _ => {
                for l in &mut self.open[..lanes] {
                    open_lane_mut(l).run();
                }
                Ok(())
            }
        };
        for (j, l) in self.open[..lanes].iter_mut().enumerate() {
            if let Some(Lane::Open(l)) = l
                && !l.plain.is_empty()
            {
                rx.plain[j] = mem::take(&mut l.plain);
            }
        }
        ran
    }

    /// Walks the packets the last round delivered, in the order they arrived, and calls `f` on
    /// those whose being UDP is `udp`. Returns how many it passed to `f` and how many of the other
    /// kind it passed over.
    pub fn each_packet(&self, rx: &RxBatch, udp: bool, mut f: impl FnMut(&[u8])) -> (usize, usize) {
        let (mut taken, mut others) = (0, 0);
        for (j, l) in self.open.iter().enumerate().take(rx.plain.len()) {
            for e in &open_lane(l.as_ref()).jobs {
                if e.delivered == 0 {
                    continue;
                }
                let at = e.out as usize;
                let p = &rx.plain[j][at..at + e.delivered as usize];
                if is_udp(p) == udp {
                    f(p);
                    taken += 1;
                } else {
                    others += 1;
                }
            }
        }
        (taken, others)
    }

    /// Encrypts the first `pulled` packets of `tx`, UDP first and the rest in slot order, into its
    /// sealed lanes and records them to send in that order, which is their counters' order: the
    /// counters are taken here in that order and the lanes hold consecutive runs of it.
    ///
    /// # Errors
    ///
    /// [`Poisoned`] after a worker panicked; the store is then unusable and the generation ends.
    pub fn seal(
        &mut self,
        tx: &mut TxBatch,
        device: &mut Device,
        now: Instant,
        pulled: usize,
    ) -> Result<(), Poisoned> {
        let lanes = self.seal.len().min(tx.sealed.len());
        for l in &mut self.seal[..lanes] {
            let l = seal_lane_mut(l);
            l.jobs.clear();
            l.mtu = tx.mtu;
            l.stride = tx.stride;
        }
        let per_lane = pulled.div_ceil(lanes).clamp(1, tx.per);
        let mut lane = 0;
        let mut bytes = 0;
        for udp in [true, false] {
            for i in 0..pulled {
                if tx.is_udp_slot(i) != udp {
                    continue;
                }
                let Some(job) = device.begin_packet(now, tx.packet(i), tx.stride) else {
                    continue;
                };
                while lane + 1 < lanes && seal_lane_mut(&mut self.seal[lane]).jobs.len() >= per_lane
                {
                    lane += 1;
                }
                bytes += job.len();
                seal_lane_mut(&mut self.seal[lane]).jobs.push(SealEntry {
                    slot: u16::try_from(i).unwrap_or(u16::MAX),
                    state: SealState::Pending(job),
                });
            }
        }
        if bytes == 0 {
            return Ok(());
        }
        let mut busy = 0;
        for (j, l) in self.seal[..lanes].iter_mut().enumerate() {
            let l = seal_lane_mut(l);
            if !l.jobs.is_empty() {
                busy += 1;
                l.packets = Some(Arc::clone(&tx.packets));
                l.sealed = mem::take(&mut tx.sealed[j]);
            }
        }
        let ran = match &self.pool {
            Some(pool) if bytes >= self.min_bytes && busy > 1 => pool.run(&mut self.seal[..lanes]),
            _ => {
                for l in &mut self.seal[..lanes] {
                    seal_lane_mut(l).run();
                }
                Ok(())
            }
        };
        for (j, l) in self.seal[..lanes].iter_mut().enumerate() {
            if let Some(Lane::Seal(l)) = l
                && !l.sealed.is_empty()
            {
                tx.sealed[j] = mem::take(&mut l.sealed);
            }
        }
        ran?;
        for (j, l) in self.seal[..lanes].iter_mut().enumerate() {
            for (k, e) in seal_lane_mut(l).jobs.iter_mut().enumerate() {
                if let SealState::Sealed(o) = mem::replace(&mut e.state, SealState::Empty) {
                    tx.push_sealed_at(o.to, o.len, j * tx.per + k);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RxMeta, TxBatch};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;
    use wgft_wireguard::{
        DEFAULT_MTU, DeviceConfig, Ipv4Prefix, Limits, PeerConfig, PrivateKey, ProtocolTimers,
        Roaming,
    };

    const AGENT_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 2);
    const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);

    struct Pair {
        agent: Device,
        server: Device,
        agent_addr: SocketAddr,
        server_addr: SocketAddr,
        now: Instant,
    }

    /// ハンドシェイクを済ませた agent と server。
    fn connected() -> Pair {
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
        assert!(agent.has_session(&agent.peers().next().unwrap(), now));
        Pair {
            agent,
            server,
            agent_addr,
            server_addr,
            now,
        }
    }

    fn packet(proto: u8, len: usize, tag: u8) -> Vec<u8> {
        let mut p = vec![tag; len];
        p[0] = 0x45;
        p[1] = 0;
        p[2..4].copy_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
        p[8] = 64;
        p[9] = proto;
        p[12..16].copy_from_slice(&AGENT_IP.octets());
        p[16..20].copy_from_slice(&SERVER_IP.octets());
        p
    }

    fn seal_one(d: &mut Device, now: Instant, p: &[u8]) -> Vec<u8> {
        let mut out = vec![0; d.max_transmit_len()];
        let o = d.handle_packet(now, p, &mut out).unwrap();
        out.truncate(o.len);
        out
    }

    /// 枠 `i` に `bytes` を置く。密な部分と溢れの部分に分ける。
    fn put(rx: &mut RxBatch, i: usize, bytes: &[u8], seg: usize, from: SocketAddr) {
        let dense = rx.dense();
        let at = rx.spill_at(i);
        let cut = bytes.len().min(dense);
        let data = rx.data_mut();
        data[i * dense..i * dense + cut].copy_from_slice(&bytes[..cut]);
        data[at..at + bytes.len() - cut].copy_from_slice(&bytes[cut..]);
        rx.meta[i] = RxMeta {
            from: Some(from),
            len: u32::try_from(bytes.len()).unwrap(),
            seg: u32::try_from(seg).unwrap(),
        };
    }

    /// 回ごとに UDP を先に取り出した packet の列。
    fn open_all(
        c: &mut Crypto,
        rx: &mut RxBatch,
        d: &mut Device,
        now: Instant,
        n: usize,
    ) -> (Vec<Vec<u8>>, usize) {
        c.start_open(rx, n);
        let mut got = Vec::new();
        let mut rounds = 0;
        while c.open_round(rx, d, now).unwrap() {
            rounds += 1;
            c.each_packet(rx, true, |p| got.push(p.to_vec()));
            c.each_packet(rx, false, |p| got.push(p.to_vec()));
        }
        (got, rounds)
    }

    #[test]
    fn a_batch_opened_in_lanes_delivers_each_packet_once_in_order() {
        for (lanes, min_bytes) in [(2, 0), (3, 0), (3, usize::MAX)] {
            let mut pair = connected();
            let now = pair.now;
            let from = pair.agent_addr;
            let mut sent: Vec<Vec<u8>> = Vec::new();
            let dg = |pair: &mut Pair, sent: &mut Vec<Vec<u8>>, proto: u8, len: usize| {
                let p = packet(proto, len, u8::try_from(sent.len() % 251).unwrap());
                let d = seal_one(&mut pair.agent, now, &p);
                sent.push(p);
                d
            };
            // 密な部分は 1000 byte。GRO の 608 byte の segment の 2 つ目は 2 つの部分にまたがる
            let mut rx = RxBatch::new(8, false, 1000, lanes);
            let d0 = dg(&mut pair, &mut sent, 6, 900);
            put(&mut rx, 0, &d0, 0, from);
            let gro: Vec<u8> = (0..5)
                .flat_map(|_| dg(&mut pair, &mut sent, 6, 1408))
                .collect();
            put(&mut rx, 1, &gro, 1440, from);
            // 同じバッチの中の重複
            put(&mut rx, 2, &d0, 0, from);
            let mut forged = dg(&mut pair, &mut sent, 6, 500);
            sent.pop();
            forged[30] ^= 1;
            put(&mut rx, 3, &forged, 0, from);
            let gro: Vec<u8> = (0..3)
                .flat_map(|_| dg(&mut pair, &mut sent, 6, 568))
                .collect();
            put(&mut rx, 4, &gro, 608, from);
            let udp = dg(&mut pair, &mut sent, 17, 200);
            put(&mut rx, 5, &udp, 0, from);
            let mut c = Crypto::new(lanes, min_bytes);
            let (got, rounds) = open_all(&mut c, &mut rx, &mut pair.server, now, 6);
            assert_eq!(rounds, 1);
            let want: Vec<Vec<u8>> = sent
                .iter()
                .filter(|p| p[9] == 17)
                .chain(sent.iter().filter(|p| p[9] != 17))
                .cloned()
                .collect();
            assert_eq!(got, want, "lanes {lanes} min {min_bytes}");
            let drops = pair.server.drops();
            assert_eq!(drops.get(wgft_wireguard::DropReason::Replayed), 1);
            assert_eq!(drops.get(wgft_wireguard::DropReason::Unauthenticated), 1);
            assert_eq!(drops.total(), 2);
            // 置き場は元に戻る
            assert!(rx.plain.iter().all(|l| l.len() >= RX_SLOT));
            assert!(Arc::get_mut(&mut rx.data).is_some());
        }
    }

    #[test]
    fn a_batch_with_more_jobs_than_the_lanes_hold_takes_several_rounds() {
        let mut pair = connected();
        let now = pair.now;
        let from = pair.agent_addr;
        let lanes = 3;
        let mut rx = RxBatch::new(8, false, 1440, lanes);
        let mut sent = Vec::new();
        for i in 0..8 {
            let mut gro = Vec::new();
            for k in 0..64 {
                let p = packet(6, 100, u8::try_from((i * 64 + k) % 251).unwrap());
                gro.extend(seal_one(&mut pair.agent, now, &p));
                sent.push(p);
            }
            put(&mut rx, i, &gro, 144, from);
        }
        let mut c = Crypto::new(lanes, 0);
        let (got, rounds) = open_all(&mut c, &mut rx, &mut pair.server, now, 8);
        assert_eq!(got, sent);
        assert!(rounds >= 2, "{rounds}");
        assert_eq!(pair.server.drops().total(), 0);
    }

    #[test]
    fn a_handshake_in_the_batch_waits_for_the_data_before_it() {
        let mut pair = connected();
        let now = pair.now;
        let from = pair.agent_addr;
        let mut rx = RxBatch::new(4, false, 1440, 3);
        let p0 = packet(6, 1000, 1);
        put(&mut rx, 0, &seal_one(&mut pair.agent, now, &p0), 0, from);
        // 壊れた短い datagram は data の message ではないので、そこで回を閉じる
        put(&mut rx, 1, &[1, 0, 0, 0, 9, 9], 0, from);
        let p2 = packet(6, 1000, 2);
        put(&mut rx, 2, &seal_one(&mut pair.agent, now, &p2), 0, from);
        let mut c = Crypto::new(3, 0);
        let (got, rounds) = open_all(&mut c, &mut rx, &mut pair.server, now, 3);
        assert_eq!(got, vec![p0, p2]);
        assert_eq!(rounds, 2);
        assert_eq!(
            pair.server
                .drops()
                .get(wgft_wireguard::DropReason::Malformed),
            1
        );
    }

    #[test]
    fn sealed_lanes_go_out_udp_first_in_counter_order() {
        for (lanes, min_bytes) in [(1, 0), (2, 0), (3, 0), (3, usize::MAX)] {
            let mut pair = connected();
            let now = pair.now;
            let mtu = pair.agent.mtu();
            let stride = pair.agent.max_transmit_len();
            let mut tx = TxBatch::new(16, false, mtu, stride, lanes);
            let packets: Vec<Vec<u8>> = (0..11u8)
                .map(|i| {
                    packet(
                        if i % 4 == 1 { 17 } else { 6 },
                        200 + usize::from(i) * 100,
                        i,
                    )
                })
                .collect();
            {
                let mut slots = tx.packet_slots();
                for (i, p) in packets.iter().enumerate() {
                    slots.slot(i)[..p.len()].copy_from_slice(p);
                    slots.set_len(i, p.len());
                }
            }
            let mut c = Crypto::new(lanes, min_bytes);
            c.seal(&mut tx, &mut pair.agent, now, packets.len())
                .unwrap();
            assert_eq!(tx.n_sealed, packets.len());
            let want: Vec<&Vec<u8>> = packets
                .iter()
                .filter(|p| p[9] == 17)
                .chain(packets.iter().filter(|p| p[9] != 17))
                .collect();
            let mut counters = Vec::new();
            let mut buf = vec![0; usize::from(u16::MAX)];
            for (j, w) in want.iter().enumerate() {
                let (to, d) = tx.datagram(j);
                assert_eq!(to, pair.server_addr);
                counters.push(u64::from_le_bytes(d[8..16].try_into().unwrap()));
                let len = pair
                    .server
                    .handle_datagram(now, pair.agent_addr, d, &mut buf)
                    .unwrap();
                assert_eq!(&buf[..len], w.as_slice(), "lanes {lanes} datagram {j}");
            }
            assert!(
                counters.windows(2).all(|w| w[0] + 1 == w[1]),
                "{counters:?}"
            );
            assert!(Arc::get_mut(&mut tx.packets).is_some());
            assert!(tx.sealed.iter().all(|l| !l.is_empty()));
        }
    }

    #[test]
    fn the_crypto_bytes_cover_its_job_lists() {
        for lanes in 1..=3 {
            let c = Crypto::new(lanes, 0);
            let lists: usize = c
                .open
                .iter()
                .map(|l| open_lane(l.as_ref()).jobs.capacity() * size_of::<OpenEntry>())
                .sum::<usize>()
                + c.seal
                    .iter()
                    .map(|l| match l {
                        Some(Lane::Seal(l)) => l.jobs.capacity() * size_of::<SealEntry>(),
                        _ => 0,
                    })
                    .sum::<usize>();
            assert!(Crypto::bytes(lanes) >= lists);
            assert_eq!(c.workers(), lanes - 1);
        }
    }
}
