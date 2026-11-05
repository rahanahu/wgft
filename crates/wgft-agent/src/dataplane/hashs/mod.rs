//! Hash S:hash だけで区画を決める並列のデータプレーン (試作。製品に入れない)。
//!
//! 設計は notes の independent-exploration.md の 6.8 節と common-design.md で、この module はその最小の試作 (E2a)
//! である。
//!
//! - スレッド:区画の数 P = min(使える CPU, 8)。front のスレッドが区画 0 を実行し、区画 1 から P - 1 はそれぞれ
//!   自分のスレッドと tokio の current-thread の実行環境で今の核と中継を動かす。P = 1 は今の Inline の駆動である
//! - front:外側のソケットを読み、復号し、replay の窓を確定し、内側の packet を R0 の鍵 ([`steer`]) で区画に振る。
//!   UDP、ICMP、解釈できない packet は区画 0 で処理する。WireGuard の device とその timer を 1 人で持つ
//! - 番号の在庫:front は区画に渡すデータに相乗りで在庫を付け、区画が求めた時に需要の数だけ補充する。予約の
//!   たびにトンネルの今の予約の番号を公開し、区画は暗号化の前と `sendmmsg` の直前に遅れを確かめる
//! - 区画:受けたバッチを核に渡し、核の出力を在庫で暗号化して、複製したソケットから `sendmmsg` で送る。UDP が
//!   直近 100 ms に働いていれば、1 回の送りの byte を B / (P - 1) までにする
//! - 複数のトンネル (6.8.10):device、ソケット、在庫、公開の番号はトンネルの番号で引く。今は N = 1 である

pub(crate) mod front;
pub(crate) mod part;
pub(crate) mod start;
pub(crate) mod steer;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use std::sync::atomic::{AtomicU64, Ordering};

use wgft_hashs_sync::{Demand, Ending, Notifier, Ring};
use wgft_wireguard::Seal;

/// tokio の `Notify` を起こしの知らせにする。許可を残す。
#[derive(Debug, Default)]
pub(crate) struct TokioNotify(pub(crate) tokio::sync::Notify);

impl Notifier for TokioNotify {
    fn notify_one(&self) {
        self.0.notify_one();
    }
}

/// スレッドの間の起こしの知らせ。
pub(crate) type Bell = wgft_hashs_sync::Bell<TokioNotify>;

/// 区画の数の上限。8 を超える CPU を誰も試していない。
pub(crate) const MAX_PARTS: usize = 8;
/// 遅れの上限 L:相手の replay の窓 8128 の半分 (common-design の I6)。
pub(crate) const LAG_LIMIT: u64 = 4064;
/// 在庫を予約から使うまでの時間の上限 (I8)。区画は普通 µs の単位で使う。
pub(crate) const STOCK_MAX_AGE: Duration = Duration::from_millis(100);
/// データに相乗りで付ける在庫の上限。
pub(crate) const PIGGYBACK_MAX: usize = 8;
/// UDP が働いているとみなす時間。区画 0 が直近にこの時間の内に UDP を送るか受けた。
pub(crate) const UDP_ACTIVE: Duration = Duration::from_millis(100);
/// 区画ごとのバッチの数。front から区画への輪と、戻りの輪の容量。
pub(crate) const LANE_BATCHES: usize = 8;
/// バッチ 1 つの packet の byte。
pub(crate) const BATCH_BYTES: usize = 128 << 10;
/// バッチ 1 つの packet の数。
pub(crate) const BATCH_PACKETS: usize = 128;
/// バッチ 1 つが運ぶ在庫の数。
pub(crate) const BATCH_STOCK: usize = 64;
/// 区画が持つ在庫の上限。超えたら古いものから捨てて数える。
pub(crate) const STOCK_CAP: usize = 256;

/// 起動の時の区画の数 P。Linux でバッチが有効な時だけ 2 以上になる (区画の送りは `sendmmsg` の道だけを持つ)。
/// ラボの build (`lab-observe`) だけは `WGFT_LAB_HASHS_P` で上書きできる。
pub(crate) fn part_count(batched: bool) -> usize {
    if !cfg!(target_os = "linux") || !batched {
        return 1;
    }
    // ラボの build だけ:実行の時の値、無ければ build の時の値 (ラボの VM の中の agent に環境を渡す道が無いので、
    // `WGFT_LAB_HASHS_P=1 lab/lab suite` の build に焼き込む)
    #[cfg(any(test, feature = "lab-observe"))]
    if let Some(p) = std::env::var("WGFT_LAB_HASHS_P")
        .ok()
        .or_else(|| option_env!("WGFT_LAB_HASHS_P").map(str::to_owned))
        .and_then(|v| v.parse::<usize>().ok())
    {
        return p.clamp(1, MAX_PARTS);
    }
    // 試験は値が無ければ今の Inline で流す。Hash S の道は `WGFT_LAB_HASHS_P=2` などで流す
    if cfg!(test) {
        return 1;
    }
    std::thread::available_parallelism()
        .map_or(1, std::num::NonZero::get)
        .clamp(1, MAX_PARTS)
}

/// E2a' の比べの腕 (区画 0 に TCP を置かない) を選ぶか。ラボと試験の build だけが `WGFT_LAB_HASHS_TCP0=0` (実行の時の値か
/// build の時の値) で選べる。製品の build は常に E2a (区画 0 にも TCP を振る)。
pub(crate) fn no_tcp_on_zero() -> bool {
    #[cfg(any(test, feature = "lab-observe"))]
    {
        std::env::var("WGFT_LAB_HASHS_TCP0")
            .ok()
            .or_else(|| option_env!("WGFT_LAB_HASHS_TCP0").map(str::to_owned))
            .is_some_and(|v| v == "0")
    }
    #[cfg(not(any(test, feature = "lab-observe")))]
    {
        false
    }
}

/// 区画 1 つが起動の時に確保する byte のうち、バッチの置き場の外のもの:front との受け渡しのバッチ、在庫の置き場、
/// 暗号化の記録。上界が数える。
pub(crate) fn part_bytes(batching: crate::batching::Batching) -> usize {
    LANE_BATCHES * Batch::bytes()
        + STOCK_CAP * size_of::<Item>()
        + batching.slots() * size_of::<(u64, Instant, usize)>()
}

/// 核が答えを返す TCP の segment か:中身を持つか、SYN か FIN を持つ。中身の無い ACK には核は答えないので、相乗りの
/// 在庫を付けない。付けると使われない予約が passive keepalive を消し、相手が黙った後のハンドシェイクの時機を
/// Inline からずらす (I8)。
pub(crate) fn needs_reply(p: &[u8]) -> bool {
    if p.len() < 20 || p[9] != 6 {
        return false;
    }
    let ihl = usize::from(p[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([p[2], p[3]])).min(p.len());
    let Some(tcp) = p.get(ihl..total) else {
        return false;
    };
    if tcp.len() < 20 {
        return false;
    }
    let doff = usize::from(tcp[12] >> 4) * 4;
    tcp.len() > doff || tcp[13] & 0x03 != 0
}

/// 予約した番号 1 つ。
#[derive(Debug)]
pub(crate) struct Item {
    /// トンネルの番号。
    pub(crate) tunnel: u16,
    pub(crate) seal: Seal,
    /// トンネルの予約の通し番号。front が予約のたびに 1 進める。
    pub(crate) rseq: u64,
    /// 予約の時刻。
    pub(crate) at: Instant,
    /// 送る先 (予約の時の endpoint)。
    pub(crate) to: SocketAddr,
}

/// front から区画へ渡すバッチ。packet を詰め、在庫を添える。起動の時に確保して使い回す。
#[derive(Debug)]
pub(crate) struct Batch {
    data: Box<[u8]>,
    used: usize,
    lens: Vec<u16>,
    /// 答えを生む packet (中身か SYN か FIN を持つ TCP) の数。相乗りの在庫はこの数までにする。
    replies: usize,
    pub(crate) stock: Vec<Item>,
}

impl Batch {
    pub(crate) fn new() -> Self {
        Self {
            data: vec![0; BATCH_BYTES].into_boxed_slice(),
            used: 0,
            lens: Vec::with_capacity(BATCH_PACKETS),
            replies: 0,
            stock: Vec::with_capacity(BATCH_STOCK),
        }
    }

    /// 起動の時に確保する byte。上界が数える。
    pub(crate) fn bytes() -> usize {
        BATCH_BYTES + BATCH_PACKETS * 2 + BATCH_STOCK * size_of::<Item>() + size_of::<Self>()
    }

    /// packet を足す。入らなければ偽。
    pub(crate) fn push(&mut self, p: &[u8]) -> bool {
        if self.lens.len() == self.lens.capacity() || self.used + p.len() > self.data.len() {
            return false;
        }
        let Ok(len) = u16::try_from(p.len()) else {
            return false;
        };
        self.data[self.used..self.used + p.len()].copy_from_slice(p);
        self.used += p.len();
        self.lens.push(len);
        if needs_reply(p) {
            self.replies += 1;
        }
        true
    }

    /// 答えを生む packet の数。
    pub(crate) fn replies(&self) -> usize {
        self.replies
    }

    /// 在庫を足す。入らなければ返す。
    pub(crate) fn push_stock(&mut self, it: Item) -> Result<(), Item> {
        if self.stock.len() == self.stock.capacity() {
            return Err(it);
        }
        self.stock.push(it);
        Ok(())
    }

    pub(crate) fn packets(&self) -> usize {
        self.lens.len()
    }

    pub(crate) fn stock_room(&self) -> usize {
        self.stock.capacity() - self.stock.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.lens.is_empty() && self.stock.is_empty()
    }

    /// 詰めた packet を順に呼ぶ。
    pub(crate) fn each(&self, mut f: impl FnMut(&[u8])) {
        let mut at = 0;
        for &l in &self.lens {
            let l = usize::from(l);
            f(&self.data[at..at + l]);
            at += l;
        }
    }

    /// 空にする。在庫が残っていれば落とす (番号は使わない)。
    pub(crate) fn clear(&mut self) {
        self.used = 0;
        self.lens.clear();
        self.replies = 0;
        self.stock.clear();
    }
}

/// トンネル 1 つの、front と区画が分け合う値。
#[derive(Debug)]
pub(crate) struct TunnelShared {
    /// front の今の予約の通し番号。front は自分の送りと補充の予約の後に公開する (Release)。
    pub(crate) published: AtomicU64,
}

/// front と区画 1 つの間の輪と印。
#[derive(Debug)]
pub(crate) struct Link {
    /// front から区画へ:packet と在庫のバッチ。
    pub(crate) to_part: Ring<Box<Batch>>,
    /// 区画から front へ:空にしたバッチ。
    pub(crate) to_front: Ring<Box<Batch>>,
    /// 区画の起こしの知らせ。
    pub(crate) bell: Bell,
    /// 区画が求める在庫の数。区画が書き、front が 0 に替えて読む。
    pub(crate) demand: Demand,
    /// 区画が送った byte。front が状態の読み出しで device に足す。
    pub(crate) sent_bytes: AtomicU64,
    /// 区画の送信の誤り。
    pub(crate) send_errors: AtomicU64,
}

impl Link {
    fn new() -> Self {
        let link = Self {
            to_part: Ring::new(LANE_BATCHES),
            to_front: Ring::new(LANE_BATCHES),
            bell: Bell::default(),
            demand: Demand::default(),
            sent_bytes: AtomicU64::new(0),
            send_errors: AtomicU64::new(0),
        };
        for _ in 0..LANE_BATCHES {
            let _ = link.to_front.push(Box::new(Batch::new()));
        }
        link
    }
}

/// 試作の診断の数え。ラボの結果の注記と決定的な試験が読む。
#[derive(Debug, Default)]
pub(crate) struct Counts {
    /// 区画への輪のバッチが尽きて捨てた packet。
    pub(crate) lane_drops: AtomicU64,
    /// 捨てた TCP の断片。
    pub(crate) tcp_fragments: AtomicU64,
    /// 遅れの上限を超えて捨てた在庫 (暗号化の前)。
    pub(crate) lag_drops: AtomicU64,
    /// 遅れの上限を超えて捨てた在庫 (`sendmmsg` の直前、暗号化し直した)。
    pub(crate) lag_reseals: AtomicU64,
    /// 時間の上限を超えて捨てた在庫。
    pub(crate) age_drops: AtomicU64,
    /// `EAGAIN` で捨てた在庫。
    pub(crate) eagain_drops: AtomicU64,
    /// 区画の在庫の上限で捨てた在庫。
    pub(crate) overflow_drops: AtomicU64,
    /// 相乗りで渡した在庫。
    pub(crate) piggybacked: AtomicU64,
    /// 求めに応えて補充した在庫。
    pub(crate) refilled: AtomicU64,
    /// 区画が front に在庫を求めた回数。
    pub(crate) requests: AtomicU64,
    /// 区画が送った datagram。
    pub(crate) part_sent: AtomicU64,
    /// UDP が働いている間の上限で短くした区画の送り。
    pub(crate) udp_capped: AtomicU64,
}

impl Counts {
    pub(crate) fn line(&self) -> String {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        format!(
            "hash-s: lane_drops={} tcp_fragments={} lag_drops={} lag_reseals={} age_drops={} eagain_drops={} overflow_drops={} piggybacked={} refilled={} requests={} part_sent={} udp_capped={}",
            g(&self.lane_drops),
            g(&self.tcp_fragments),
            g(&self.lag_drops),
            g(&self.lag_reseals),
            g(&self.age_drops),
            g(&self.eagain_drops),
            g(&self.overflow_drops),
            g(&self.piggybacked),
            g(&self.refilled),
            g(&self.requests),
            g(&self.part_sent),
            g(&self.udp_capped),
        )
    }
}

/// 世代の全スレッドが分け合う値。
#[derive(Debug)]
pub(crate) struct Hub {
    /// トンネルごとの値。今は N = 1。
    pub(crate) tunnels: Box<[TunnelShared]>,
    /// 区画ごとの輪。番号 0 は使わない (区画 0 は front が実行する)。
    pub(crate) links: Box<[Link]>,
    /// front の起こしの知らせ (在庫の求め、枠が欲しい、世代の終わり)。
    pub(crate) front_bell: Bell,
    /// どれかのスレッドが終わった。全員が終わる。
    pub(crate) ending: Ending,
    /// 区画 0 が最後に UDP を送るか受けた時刻 (`epoch` からの ns)。
    pub(crate) last_udp: AtomicU64,
    pub(crate) epoch: Instant,
    /// 1 回の送りの byte の上限 B (Inline の 1 バッチ)。UDP が働いている間、区画は B / (P - 1) までにする。
    pub(crate) batch_cap: usize,
    pub(crate) counts: Counts,
}

impl Hub {
    pub(crate) fn new(parts: usize, tunnels: usize, batch_cap: usize, epoch: Instant) -> Self {
        Self {
            tunnels: (0..tunnels)
                .map(|_| TunnelShared {
                    published: AtomicU64::new(0),
                })
                .collect(),
            links: (0..parts).map(|_| Link::new()).collect(),
            front_bell: Bell::default(),
            ending: Ending::default(),
            last_udp: AtomicU64::new(0),
            epoch,
            batch_cap,
            counts: Counts::default(),
        }
    }

    pub(crate) fn parts(&self) -> usize {
        self.links.len()
    }

    /// 世代を終える。全員を起こす。
    pub(crate) fn end(&self) {
        self.ending.end(
            std::iter::once(&self.front_bell).chain(self.links.iter().skip(1).map(|l| &l.bell)),
        );
    }

    pub(crate) fn is_ending(&self) -> bool {
        self.ending.is_ended()
    }

    /// 区画 0 が UDP を送るか受けた。
    pub(crate) fn note_udp(&self, now: Instant) {
        let ns = u64::try_from(now.saturating_duration_since(self.epoch).as_nanos()).unwrap_or(0);
        self.last_udp.store(ns.max(1), Ordering::Relaxed);
    }

    /// UDP が直近 [`UDP_ACTIVE`] の内に働いたか。
    pub(crate) fn udp_active(&self, now: Instant) -> bool {
        let last = self.last_udp.load(Ordering::Relaxed);
        if last == 0 {
            return false;
        }
        let now = u64::try_from(now.saturating_duration_since(self.epoch).as_nanos()).unwrap_or(0);
        now.saturating_sub(last) < u64::try_from(UDP_ACTIVE.as_nanos()).unwrap_or(u64::MAX)
    }

    /// 区画 1 つの 1 回の送りの byte の上限。UDP が働いていなければ上限なし。
    pub(crate) fn send_cap(&self, now: Instant) -> usize {
        if self.parts() > 1 && self.udp_active(now) {
            self.counts.udp_capped.fetch_add(1, Ordering::Relaxed);
            (self.batch_cap / (self.parts() - 1)).max(1)
        } else {
            usize::MAX
        }
    }

    /// 区画 `except` 以外の全員を起こす (枠が欲しい)。
    pub(crate) fn ring_others(&self, except: usize) {
        if except != 0 {
            self.front_bell.ring();
        }
        for (k, l) in self.links.iter().enumerate().skip(1) {
            if k != except {
                l.bell.ring();
            }
        }
    }

    /// 在庫 `it` が使えるか:遅れが [`LAG_LIMIT`] 以下で、予約から [`STOCK_MAX_AGE`] 以内。
    pub(crate) fn fresh(&self, it: &Item, now: Instant) -> Freshness {
        let published = self.tunnels[usize::from(it.tunnel)]
            .published
            .load(Ordering::Acquire);
        if published.saturating_sub(it.rseq) > LAG_LIMIT {
            Freshness::Lagging
        } else if now.saturating_duration_since(it.at) > STOCK_MAX_AGE {
            Freshness::Old
        } else {
            Freshness::Fresh
        }
    }
}

/// 在庫の新しさ。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Freshness {
    Fresh,
    Lagging,
    Old,
}
