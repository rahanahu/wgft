//! 損失、重複、並べ替え、短い不通を混ぜた網で両向きの stream を流す試験 (TCP の正しさの監査で足した試験)。
//!
//! 核と相手の両方の初期の番号を 2^32 の手前に置き、両向きの stream が番号の 1 周をまたぐようにします。相手の
//! timestamp の値も試験の途中で 1 周させます。相手は SACK と D-SACK を返す受け手と、go-back-N で再送する送り手を
//! 持つ単純な TCP で、受信の窓は右端を戻しません。各段の後に核の不変条件を確かめ、相手が受けた byte を元の stream
//! と照らし、決めた時間の内に両向きの stream と FIN が届いて閉じることを確かめます。

#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::struct_excessive_bools,
    reason = "test helpers"
)]
#![expect(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::many_single_char_names,
    reason = "test helpers convert sequence numbers and offsets"
)]

use crate::Error;
use crate::seq;
use crate::stack::ns;
use crate::tcp::conn::{ConnId, State};
use crate::testnet_tests::{Out, TSeg, TestNet, parse_out, small_limits};
use crate::wire::{FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN, SackBlock};
use core::time::Duration;
use std::collections::BTreeMap;

/// 試験の乱数 (splitmix64) です。
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }

    fn chance(&mut self, ppm: u32) -> bool {
        self.below(1_000_000) < u64::from(ppm)
    }
}

/// 網と相手と流す量の設定です。
#[derive(Clone, Debug)]
pub(crate) struct Params {
    pub(crate) seed: u64,
    /// packet ごとの損失と重複の確率 (100 万分の 1)
    pub(crate) loss_ppm: u32,
    pub(crate) dup_ppm: u32,
    /// 片道の遅延の固定の部分と、足す乱数の幅 (ms)。幅が packet の間隔より大きいと並べ替わります
    pub(crate) base_ms: u64,
    pub(crate) jitter_ms: u64,
    /// 両向きのすべての packet を捨てる区間 (ms)
    pub(crate) blackouts: Vec<(u64, u64)>,
    pub(crate) dut_bytes: usize,
    pub(crate) peer_bytes: usize,
    /// 核の初期の番号 (ISS) の目標と相手の初期の番号です
    pub(crate) dut_iss: u32,
    pub(crate) peer_iss: u32,
    /// 相手の timestamp の始めの値です。`None` なら timestamp を使いません
    pub(crate) peer_ts: Option<u32>,
    pub(crate) sack: bool,
    /// 相手の受信のバッファの大きさと、1 ms に読む量と、読まない区間 (ms)
    pub(crate) peer_cap: u64,
    pub(crate) peer_read_per_ms: u64,
    pub(crate) peer_stall: Option<(u64, u64)>,
    /// 核のアプリケーションが読まない区間 (ms)
    pub(crate) dut_stall: Option<(u64, u64)>,
    /// この時間の内に終わらなければ止まったとみなします (ms)
    pub(crate) limit_ms: u64,
    /// 相手が segment の長さを毎回乱数で選びます。再送は前の segment の境と揃わず、一部だけ重なります
    pub(crate) repack: bool,
}

impl Params {
    pub(crate) fn new(seed: u64) -> Self {
        Self {
            seed,
            loss_ppm: 0,
            dup_ppm: 0,
            base_ms: 10,
            jitter_ms: 0,
            blackouts: Vec::new(),
            dut_bytes: 300_000,
            peer_bytes: 300_000,
            dut_iss: 0u32.wrapping_sub(150_000),
            peer_iss: 0u32.wrapping_sub(150_000),
            peer_ts: Some(u32::MAX - 2_000),
            sack: true,
            peer_cap: 256 * 1024,
            peer_read_per_ms: 64 * 1024,
            peer_stall: None,
            dut_stall: None,
            limit_ms: 120_000,
            repack: false,
        }
    }
}

const PEER_MSS: u64 = 1000;
const PEER_CWND: u64 = 40 * PEER_MSS;
const PEER_RTO_MIN: u64 = 300;
const PEER_RTO_MAX: u64 = 3_000;
const SPORT: u16 = 40000;
const DPORT: u16 = 80;
const WSCALE: u8 = 7;

/// 相手の TCP です。番号は stream の offset で持ちます (相手の FIN は offset `stream.len()`)。
struct Peer {
    iss: u32,
    stream: Vec<u8>,
    una: u64,
    nxt: u64,
    max: u64,
    /// 核の窓の右端 (相手の stream の offset)
    dut_right: u64,
    dupacks: u32,
    rto_at: Option<u64>,
    rto: u64,
    // 受け手の側
    dut_base: u32,
    expect: Vec<u8>,
    rcv_off: u64,
    ivs: BTreeMap<u64, u64>,
    recent: Option<(u64, u64)>,
    dsack: Option<(u64, u64)>,
    fin_rcvd: bool,
    read_off: u64,
    cap: u64,
    vis_right: u64,
    ts_base: Option<u32>,
    ts_recent: u32,
    ack_pending: bool,
    sack: bool,
    rst: bool,
    beyond_window: u64,
    /// `Some` なら segment の長さを乱数で選びます
    repack: Option<Rng>,
}

impl Peer {
    fn rcv_seq(&self) -> u32 {
        self.dut_base
            .wrapping_add(self.rcv_off as u32)
            .wrapping_add(u32::from(self.fin_rcvd))
    }

    fn window_field(&mut self) -> u16 {
        let unread = self.rcv_off - self.read_off;
        let free = self.cap.saturating_sub(unread);
        let right = (self.rcv_off + free).max(self.vis_right);
        let w = right - self.rcv_off;
        let field = w.div_ceil(1 << WSCALE).min(65535);
        self.vis_right = self.rcv_off + (field << WSCALE);
        field as u16
    }

    fn blocks(&mut self) -> Vec<SackBlock> {
        let mut v = Vec::new();
        if !self.sack {
            return v;
        }
        let at = |o: u64| self.dut_base.wrapping_add(o as u32);
        if let Some((a, b)) = self.dsack.take() {
            v.push(SackBlock {
                left: at(a),
                right: at(b),
            });
        }
        // 最近に伸びた区間を先頭にし、残りは番号の大きい順です (RFC 2018 4 節)。
        let mut first = None;
        if let Some((a, _)) = self.recent
            && let Some((&l, &r)) = self.ivs.range(..=a).next_back()
            && r > a
        {
            first = Some((l, r));
        }
        if let Some((l, r)) = first {
            v.push(SackBlock {
                left: at(l),
                right: at(r),
            });
        }
        for (&l, &r) in self.ivs.iter().rev() {
            if v.len() >= 3 {
                break;
            }
            if Some((l, r)) == first {
                continue;
            }
            v.push(SackBlock {
                left: at(l),
                right: at(r),
            });
        }
        v.truncate(3);
        v
    }

    fn seg(&mut self, now_ms: u64, off: u64, len: u64, fin: bool) -> TSeg {
        let wnd = self.window_field();
        let sack = self.blocks();
        let payload = if len > 0 {
            self.stream[off as usize..(off + len) as usize].to_vec()
        } else {
            Vec::new()
        };
        self.ack_pending = false;
        TSeg {
            sport: SPORT,
            dport: DPORT,
            seq: self.iss.wrapping_add(1).wrapping_add(off as u32),
            ack: self.rcv_seq(),
            flags: FLAG_ACK | if fin { FLAG_FIN } else { 0 },
            wnd,
            ts: self
                .ts_base
                .map(|b| (b.wrapping_add(now_ms as u32), self.ts_recent)),
            sack,
            payload,
            ..TSeg::default()
        }
    }

    /// 核の segment を受けます。
    fn recv(&mut self, o: &Out, now_ms: u64) -> Result<(), String> {
        if o.has(FLAG_RST) {
            self.rst = true;
            return Ok(());
        }
        if let Some((v, _)) = o.ts
            && seq::le(o.seq, self.rcv_seq())
        {
            self.ts_recent = v;
        }
        // 受け手の側
        let rel = i64::from(o.seq.wrapping_sub(self.dut_base) as i32);
        let len = o.payload.len() as i64;
        if len > 0 {
            for (k, &b) in o.payload.iter().enumerate() {
                let pos = rel + k as i64;
                if pos < 0 {
                    continue;
                }
                let pos = pos as usize;
                if pos >= self.expect.len() {
                    return Err(format!("data beyond the stream at offset {pos}: {o}"));
                }
                if self.expect[pos] != b {
                    return Err(format!("corrupted byte at offset {pos}: {o}"));
                }
            }
            let (a, b) = (rel.max(0) as u64, (rel + len).max(0) as u64);
            if b <= self.rcv_off {
                self.dsack = Some((a, b));
            } else {
                let a = a.max(self.rcv_off);
                let lim = self.vis_right.max(self.rcv_off + 1);
                if b > lim {
                    self.beyond_window += 1;
                }
                let b = b.min(lim.max(a));
                if b > a {
                    self.insert(a, b);
                    self.recent = Some((a, b));
                }
            }
            self.ack_pending = true;
        }
        if len == 0 && !o.has(FLAG_FIN) && !o.has(FLAG_SYN) && o.seq != self.rcv_seq() {
            // 受け入れられない segment (窓の probe の SND.UNA - 1 など) には ACK を返します (RFC 9293 3.10.7.4)。
            self.ack_pending = true;
        }
        if o.has(FLAG_FIN) {
            let fin_off = (rel + len) as u64;
            if fin_off != self.expect.len() as u64 {
                return Err(format!(
                    "FIN at offset {fin_off}, the stream has {} bytes: {o}",
                    self.expect.len()
                ));
            }
            if self.rcv_off == fin_off {
                self.fin_rcvd = true;
            }
            self.ack_pending = true;
        }
        // 送り手の側
        let ack_off = u64::from(o.ack.wrapping_sub(self.iss.wrapping_add(1)));
        if ack_off > self.max {
            return Err(format!(
                "the core acknowledged unsent data: {o} (max {})",
                self.max
            ));
        }
        let right = ack_off + (u64::from(o.wnd) << WSCALE);
        if ack_off > self.una {
            self.una = ack_off;
            self.nxt = self.nxt.max(self.una);
            self.dupacks = 0;
            self.rto = PEER_RTO_MIN;
            self.rto_at = (self.una < self.max).then_some(now_ms + self.rto);
            self.set_right(right);
        } else if ack_off == self.una {
            if len == 0 && !o.has(FLAG_FIN) && self.una < self.max && right == self.dut_right {
                self.dupacks += 1;
                if self.dupacks == 3 {
                    self.nxt = self.una; // 高速の再送 (簡単のため go-back-N)
                }
            }
            self.set_right(right);
        }
        Ok(())
    }

    fn set_right(&mut self, right: u64) {
        self.dut_right = right;
    }

    fn insert(&mut self, mut a: u64, mut b: u64) {
        // 重なる区間と隣の区間をまとめます。
        let keys: Vec<(u64, u64)> = self
            .ivs
            .range(..=b)
            .filter(|&(_, &r)| r >= a)
            .map(|(&l, &r)| (l, r))
            .collect();
        for (l, r) in keys {
            self.ivs.remove(&l);
            a = a.min(l);
            b = b.max(r);
        }
        self.ivs.insert(a, b);
        while let Some((&l, &r)) = self.ivs.iter().next() {
            if l > self.rcv_off {
                break;
            }
            self.ivs.remove(&l);
            self.rcv_off = self.rcv_off.max(r);
        }
    }

    /// 相手が今送る segment を作ります。
    fn output(&mut self, now_ms: u64) -> Vec<TSeg> {
        let mut out = Vec::new();
        let len = self.stream.len() as u64;
        if let Some(at) = self.rto_at
            && now_ms >= at
        {
            self.rto = (self.rto * 2).min(PEER_RTO_MAX);
            if self.una < self.max {
                self.nxt = self.una;
                self.dupacks = 0;
                if self.dut_right <= self.una && self.una < len {
                    // 窓が 0 の間の probe:1 byte を送ります。
                    out.push(self.seg(now_ms, self.una, 1, false));
                }
                self.rto_at = Some(now_ms + self.rto);
            } else if self.una < len + 1 {
                if self.dut_right <= self.una && self.una < len {
                    out.push(self.seg(now_ms, self.una, 1, false));
                    self.max = self.max.max(self.una + 1);
                    self.nxt = self.una + 1;
                }
                self.rto_at = Some(now_ms + self.rto);
            } else {
                self.rto_at = None;
            }
        }
        let limit = self.dut_right.min(self.una + PEER_CWND);
        while self.nxt < len && self.nxt < limit {
            let mss = self
                .repack
                .as_mut()
                .map_or(PEER_MSS, |r| 1 + r.below(PEER_MSS));
            let n = (limit - self.nxt).min(mss).min(len - self.nxt);
            let fin = self.nxt + n == len;
            let s = self.seg(now_ms, self.nxt, n, fin);
            out.push(s);
            self.nxt += n + u64::from(fin);
        }
        if self.nxt == len {
            out.push(self.seg(now_ms, len, 0, true));
            self.nxt = len + 1;
        }
        self.max = self.max.max(self.nxt);
        if self.una < self.max && self.rto_at.is_none() {
            self.rto_at = Some(now_ms + self.rto);
        }
        if self.dut_right <= self.nxt && self.nxt < len && self.rto_at.is_none() {
            self.rto_at = Some(now_ms + self.rto);
        }
        if self.ack_pending {
            out.push(self.seg(
                now_ms,
                self.nxt.min(len + u64::from(self.max > len)),
                0,
                false,
            ));
        }
        out
    }

    fn read(&mut self, n: u64) -> bool {
        let before = self.vis_right.saturating_sub(self.rcv_off);
        self.read_off = self.rcv_off.min(self.read_off + n);
        let free = self.cap.saturating_sub(self.rcv_off - self.read_off);
        // 窓が大きく開くときは窓の更新を送ります。
        before < self.cap / 2 && free >= 2 * before.max(PEER_MSS)
    }
}

/// 網の中の packet です。
enum Pkt {
    ToDut(TSeg),
    ToPeer(Out),
}

/// 試験の結果です。
#[derive(Debug)]
pub(crate) struct Outcome {
    pub(crate) done_ms: u64,
    /// 核が相手の広告した右端の先まで送った segment の数
    pub(crate) beyond_window: u64,
}

fn rand_bytes(rng: &mut Rng, n: usize) -> Vec<u8> {
    (0..n).map(|_| rng.next() as u8).collect()
}

/// 握手を済ませた核と相手を作ります。核の ISS が `p.dut_iss` になる時刻に SYN を送ります。
fn connect(p: &Params, rng: &mut Rng) -> (TestNet, ConnId, Peer) {
    let syn = |n: &mut TestNet, ts: u32| {
        n.inject(&TSeg {
            sport: SPORT,
            dport: DPORT,
            seq: p.peer_iss,
            flags: FLAG_SYN,
            wnd: 65535,
            mss: 1380,
            ws: Some(WSCALE),
            sack_ok: p.sack,
            ts: p.peer_ts.map(|_| (ts, 0)),
            ..TSeg::default()
        });
        let outs = n.drain();
        assert!(outs.len() == 1 && outs[0].flags == FLAG_SYN | FLAG_ACK);
        outs[0].clone()
    };
    // ISS は時刻の 4 µs ごとに 1 進み、4 つ組の鍵つきの hash を足した値です。時刻 0 の ISS から目標の時刻を求めます。
    let mut probe = TestNet::new(small_limits());
    probe.listen(DPORT);
    let h = syn(&mut probe, p.peer_ts.unwrap_or(0)).seq;
    let ticks = u64::from(p.dut_iss.wrapping_sub(h));
    let mut n = TestNet::new(small_limits());
    let l = n.listen(DPORT);
    n.advance(Duration::from_nanos(ticks * 4000));
    let ts0 = p.peer_ts.unwrap_or(0);
    let sa = syn(&mut n, ts0);
    assert_eq!(sa.seq, p.dut_iss, "the ISS did not land on the target");
    let mut peer = Peer {
        iss: p.peer_iss,
        stream: rand_bytes(rng, p.peer_bytes),
        una: 0,
        nxt: 0,
        max: 0,
        dut_right: u64::from(sa.wnd),
        dupacks: 0,
        rto_at: None,
        rto: PEER_RTO_MIN,
        dut_base: sa.seq.wrapping_add(1),
        expect: Vec::new(),
        rcv_off: 0,
        ivs: BTreeMap::new(),
        recent: None,
        dsack: None,
        fin_rcvd: false,
        read_off: 0,
        cap: p.peer_cap,
        vis_right: 0,
        ts_base: p.peer_ts.map(|b| b.wrapping_sub(ms_of(&n) as u32)),
        ts_recent: sa.ts.map_or(0, |(v, _)| v),
        ack_pending: false,
        sack: p.sack,
        rst: false,
        beyond_window: 0,
        repack: p.repack.then_some(Rng(p.seed ^ 0x7e9a)),
    };
    let now_ms = ms_of(&n);
    let ack = peer.seg(now_ms, 0, 0, false);
    n.inject(&ack);
    let c = n.accept(l);
    n.drain();
    (n, c, peer)
}

fn ms_of(n: &TestNet) -> u64 {
    ns(n.now) as u64 / 1_000_000
}

fn in_range(r: Option<(u64, u64)>, t: u64) -> bool {
    r.is_some_and(|(a, b)| t >= a && t < b)
}

/// 両向きの stream を流し、終わった時刻 (握手からの ms) を返します。止まるか壊れたら panic です。
pub(crate) fn run(p: &Params) -> Outcome {
    let mut rng = Rng(p.seed);
    let (mut n, c, mut peer) = connect(p, &mut rng);
    let dut_stream = rand_bytes(&mut rng, p.dut_bytes);
    peer.expect.clone_from(&dut_stream);
    let start = ms_of(&n);
    let mut net: BTreeMap<(u64, u64), Pkt> = BTreeMap::new();
    let mut counter = 0u64;
    let mut written = 0usize;
    let mut shut = false;
    let mut got: Vec<u8> = Vec::new();
    let mut eof = false;
    let mut buf = vec![0u8; 65536];
    let mut send = |net: &mut BTreeMap<(u64, u64), Pkt>, rng: &mut Rng, t: u64, pkt: Pkt| {
        let rel = t - start;
        if p.blackouts.iter().any(|&(a, b)| rel >= a && rel < b) || rng.chance(p.loss_ppm) {
            return;
        }
        let dup = rng.chance(p.dup_ppm);
        let at = t + p.base_ms + rng.below(p.jitter_ms + 1);
        counter += 1;
        if dup {
            let at2 = t + p.base_ms + rng.below(p.jitter_ms + 1);
            let copy = match &pkt {
                Pkt::ToDut(s) => Pkt::ToDut(s.clone()),
                Pkt::ToPeer(o) => Pkt::ToPeer(o.clone()),
            };
            net.insert((at2, counter), copy);
            counter += 1;
        }
        net.insert((at, counter), pkt);
    };
    loop {
        let now = ms_of(&n);
        let rel = now - start;
        assert!(
            rel <= p.limit_ms,
            "{p:?}: stalled at {rel} ms: peer una={} max={} len={} rcv_off={} fin_rcvd={}, core wrote={written} \
             read={} eof={eof}, stats={:?}",
            peer.una,
            peer.max,
            peer.stream.len(),
            peer.rcv_off,
            peer.fin_rcvd,
            got.len(),
            n.s.stats(),
        );
        // 届いた packet
        while let Some((&(at, k), _)) = net.iter().next() {
            if at > now {
                break;
            }
            match net.remove(&(at, k)).expect("present") {
                Pkt::ToDut(s) => n.inject(&s),
                Pkt::ToPeer(o) => {
                    if let Err(e) = peer.recv(&o, now) {
                        panic!("{p:?}: at {rel} ms: {e}");
                    }
                }
            }
        }
        assert!(
            !peer.rst,
            "{p:?}: the core reset the connection at {rel} ms"
        );
        // 核のアプリケーション
        while written < dut_stream.len() {
            match n.s.write(n.now, c, &dut_stream[written..]) {
                Ok(k) => written += k,
                Err(Error::WouldBlock) => break,
                Err(e) => panic!("{p:?}: write at {rel} ms: {e:?}"),
            }
        }
        if written == dut_stream.len() && !shut {
            n.s.close_write(n.now, c).unwrap();
            shut = true;
        }
        if !in_range(p.dut_stall, rel) && !eof {
            loop {
                match n.s.read(n.now, c, &mut buf) {
                    Ok(0) => {
                        eof = true;
                        break;
                    }
                    Ok(k) => {
                        let at = got.len();
                        assert!(
                            peer.stream.get(at..at + k) == Some(&buf[..k]),
                            "{p:?}: the core read corrupted data at offset {at}"
                        );
                        got.extend_from_slice(&buf[..k]);
                    }
                    Err(Error::WouldBlock) => break,
                    Err(e) => panic!("{p:?}: read at {rel} ms: {e:?}"),
                }
            }
        }
        n.check();
        for raw in n.drain_raw() {
            let o = parse_out(&raw);
            send(&mut net, &mut rng, now, Pkt::ToPeer(o));
        }
        // 相手
        if !in_range(p.peer_stall, rel) && peer.read(p.peer_read_per_ms) {
            peer.ack_pending = true;
        }
        for s in peer.output(now) {
            send(&mut net, &mut rng, now, Pkt::ToDut(s));
        }
        let i = n.s.conns.resolve(c);
        let state = i.map(|i| n.s.conns.tcb(i).state);
        let peer_done = peer.fin_rcvd && peer.rcv_off == dut_stream.len() as u64;
        let fin_acked = peer.una == peer.stream.len() as u64 + 1;
        if peer_done
            && fin_acked
            && eof
            && got.len() == peer.stream.len()
            && matches!(state, Some(State::TimeWait | State::Closed))
        {
            n.s.close_conn(n.now, c);
            n.advance(Duration::from_secs(61));
            n.drain();
            assert_eq!(
                n.s.conns.in_use().count(),
                0,
                "{p:?}: the slot was not returned"
            );
            return Outcome {
                done_ms: rel,
                beyond_window: peer.beyond_window,
            };
        }
        n.advance(Duration::from_millis(1));
    }
}

#[test]
fn clean_path_crosses_the_wrap() {
    let o = run(&Params::new(1));
    assert!(o.done_ms < 5_000 && o.beyond_window == 0, "{o:?}");
}

#[test]
fn loss_dup_reorder_across_the_wrap() {
    for seed in 1..=12 {
        let mut p = Params::new(seed);
        p.loss_ppm = 20_000;
        p.dup_ppm = 20_000;
        p.jitter_ms = 8;
        p.sack = seed % 3 != 0;
        if seed % 4 == 0 {
            p.peer_ts = None;
        }
        run(&p);
    }
}

#[test]
fn repacketized_retransmissions_overlap_partially() {
    for seed in 60..=67 {
        let mut p = Params::new(seed);
        p.loss_ppm = 30_000;
        p.dup_ppm = 30_000;
        p.jitter_ms = 6;
        p.repack = true;
        p.sack = seed % 2 == 0;
        run(&p);
    }
}

/// 両向きの FIN がちょうど 2^32 - 1、0、1 の番号に載るように、初期の番号と stream の長さを選びます。
#[test]
fn fins_on_the_wrap_boundary() {
    for (k, extra) in [(0u64, 0u32), (1, 1), (2, 2), (3, 0)] {
        let mut p = Params::new(80 + k);
        let len = 4_000u32;
        p.dut_iss = 0u32.wrapping_sub(len + 2).wrapping_add(extra);
        p.peer_iss = 0u32.wrapping_sub(len + 2).wrapping_add(extra);
        p.dut_bytes = len as usize;
        p.peer_bytes = len as usize;
        if k == 3 {
            p.loss_ppm = 150_000;
            p.jitter_ms = 5;
        }
        run(&p);
    }
}

#[test]
fn outages_and_heavy_loss_recover() {
    for seed in 20..=27 {
        let mut p = Params::new(seed);
        p.loss_ppm = 50_000;
        p.jitter_ms = 4;
        p.blackouts = vec![(300, 2_300), (4_000, 9_000)];
        p.sack = seed % 2 == 0;
        run(&p);
    }
}

#[test]
fn zero_windows_on_both_sides() {
    for seed in 40..=45 {
        let mut p = Params::new(seed);
        p.loss_ppm = 10_000;
        p.jitter_ms = 3;
        p.peer_cap = 64 * 1024;
        p.peer_read_per_ms = 2 * 1024;
        p.peer_stall = Some((200, 3_000));
        p.dut_stall = Some((100, 4_000));
        p.sack = seed % 2 == 0;
        run(&p);
    }
}

/// 種を広く振る探索です。`WGSTACK_NETSIM_SEEDS=開始..終わり` で流します。
#[test]
#[ignore = "a long sweep for manual runs"]
fn sweep() {
    let range = std::env::var("WGSTACK_NETSIM_SEEDS").unwrap_or_else(|_| "1000..1100".into());
    let (a, b) = range.split_once("..").expect("a..b");
    let (a, b): (u64, u64) = (a.parse().unwrap(), b.parse().unwrap());
    for seed in a..b {
        let mut r = Rng(seed ^ 0x5eed);
        let mut p = Params::new(seed);
        p.loss_ppm = [0, 5_000, 20_000, 60_000, 120_000][r.below(5) as usize];
        p.dup_ppm = [0, 10_000, 50_000][r.below(3) as usize];
        p.jitter_ms = [0, 2, 8, 30][r.below(4) as usize];
        p.base_ms = 1 + r.below(60);
        p.sack = r.below(4) != 0;
        p.peer_ts = if r.below(4) == 0 {
            None
        } else {
            Some(r.next() as u32)
        };
        p.dut_iss = 0u32.wrapping_sub(r.below(700_000) as u32);
        p.peer_iss = 0u32.wrapping_sub(r.below(700_000) as u32);
        p.dut_bytes = r.below(700_000) as usize;
        p.peer_bytes = r.below(700_000) as usize;
        p.peer_cap = [16 * 1024, 64 * 1024, 256 * 1024, 4 << 20][r.below(4) as usize];
        p.peer_read_per_ms = [512, 8 * 1024, 1 << 20][r.below(3) as usize];
        if r.below(3) == 0 {
            let a = r.below(5_000);
            p.blackouts.push((a, a + 1 + r.below(20_000)));
        }
        if r.below(3) == 0 {
            let a = r.below(3_000);
            p.peer_stall = Some((a, a + r.below(10_000)));
        }
        if r.below(3) == 0 {
            let a = r.below(3_000);
            p.dut_stall = Some((a, a + r.below(10_000)));
        }
        p.limit_ms = 400_000;
        p.repack = r.below(2) == 0;
        match std::panic::catch_unwind(|| run(&p)) {
            Ok(o) => eprintln!("seed {seed}: {o:?}"),
            Err(_) => eprintln!("seed {seed}: FAILED"),
        }
    }
}
