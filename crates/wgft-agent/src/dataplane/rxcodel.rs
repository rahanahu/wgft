//! 受信の取り出しの CoDel。実験の設定 `WGFT_AGENT_EXPERIMENTAL_RX_CODEL` で有効にする。規則の正本は
//! `docs/design/v2/agent-throughput.md` の「受信の取り出しの CoDel (実験)」である。
//!
//! WireGuard の UDP のソケットの受信の待ち行列 (暗号文の FIFO) で datagram が待った時間が、RFC 8289 の
//! 制御の則で目標を超え続けたら、復号した後の中身のある TCP の segment だけを、核に渡す前に落とす。
//! UDP、中身の無い ACK、SYN、FIN、RST、断片、TCP 以外は落とさない。核から見ると経路の損失と同じで、ACK
//! する前に落とすので ACK 済みのデータは捨てない。
//!
//! - 待ちの合図:受信のバッチを読んだ直後に、最後に読んだ datagram のカーネルの受信の時刻を `SIOCGSTAMPNS`
//!   で 1 回だけ読み ([`wgft_udp_batch::sys::receive_stamp`])、壁時計との差を待ちとする。読むのは前の標本から
//!   [`SAMPLE_GAP`] 以上経って、読みがソケットを空にしなかった時だけで、間の batch は前の標本を使う。datagram
//!   ごとの制御の message (`SO_TIMESTAMPNS`) は使わない
//! - 空の印:読みがソケットを空にした (枠より少なく読めたか、読むものが無かった) ら、RFC 8289 の「待ち行列が
//!   空に近い」として目標の下と同じに扱う
//! - 状態機械:RFC 8289 の dequeue の擬似コードを、受信のバッチ 1 つを 1 回の取り出しとして写す。落とすと
//!   決めたら、その batch の中か後の batch の最初の落とせる packet を 1 つ落とす。1 つの batch で落とすのは
//!   高々 1 つで、落とせる packet が来るまで次を決めない
//! - 費用:Linux だけで動く。無効なら状態を作らず、標本も読まない。有効でも、落とすと決めた時だけ packet を
//!   見分ける。状態は固定の数十 byte で、確保も timer も足さない

use std::time::{Duration, Instant};

/// RFC 8289 の interval。最悪の RTT の程度の値で、RFC の既定の値である。
pub(crate) const INTERVAL: Duration = Duration::from_millis(100);

/// 待ちの標本を読む最小の間隔。interval の 100 分の 1 で、目標を超え続けたかの判断に十分な数の標本になる。
pub(crate) const SAMPLE_GAP: Duration = Duration::from_millis(1);

/// 待ちとして受け取る最長の値。これより長いか負の差は壁時計の飛び (NTP の step など) と見て、待ちを 0 とする。
/// 14 MiB の受信のバッファを 200 Mbit/s で流し切る時間 (約 0.6 秒) より長い。
pub(crate) const MAX_SOJOURN: Duration = Duration::from_secs(2);

/// The targets in ms the experimental setting accepts.
pub(crate) const TARGETS_MS: [u8; 3] = [1, 2, 5];

/// The control law of RFC 8289: the time of the next drop after `t` with `count` drops so far.
fn control_law(t: Instant, count: u32) -> Instant {
    t + INTERVAL.div_f64(f64::from(count.max(1)).sqrt())
}

/// RFC 8289 の CoDel の状態。受信のバッチ 1 つを 1 回の取り出しとして扱う。
#[derive(Debug)]
pub(crate) struct Codel {
    target: Duration,
    /// 待ちが目標を超え続けて interval が経つ時刻。目標の下か空になったら消す (RFC の `first_above_time`)。
    first_above: Option<Instant>,
    /// 次に落とす時刻 (RFC の `drop_next`)。最初の落としの前は無い。
    drop_next: Option<Instant>,
    count: u32,
    last_count: u32,
    /// 落とす状態にある (RFC の `dropping`)。
    dropping: bool,
    /// 落とすと決めて、まだ落とせる packet に当たっていない。
    pending: bool,
    /// `pending` が落とす状態に入る最初の落としである。
    entering: bool,
    /// 最後の [`Codel::on_batch`] の時刻。落とす時刻の計算に使う。
    now: Option<Instant>,
    /// 落とした segment の数。
    drops: u64,
}

impl Codel {
    pub(crate) fn new(target: Duration) -> Self {
        Self {
            target,
            first_above: None,
            drop_next: None,
            count: 0,
            last_count: 0,
            dropping: false,
            pending: false,
            entering: false,
            now: None,
            drops: 0,
        }
    }

    /// 受信のバッチ 1 つの取り出し:`now` に読み、そのバッチの待ちが `sojourn`、読みがソケットを空にしたかが
    /// `emptied`。落とすと決めたら [`Codel::pending`] が真になる。
    pub(crate) fn on_batch(&mut self, now: Instant, sojourn: Duration, emptied: bool) {
        self.now = Some(now);
        let ok_to_drop = self.ok_to_drop(now, sojourn, emptied);
        if self.dropping {
            if !ok_to_drop {
                self.dropping = false;
                self.pending = false;
                self.entering = false;
            } else if self.drop_next.is_some_and(|t| now >= t) {
                self.pending = true;
            }
        } else if ok_to_drop {
            self.dropping = true;
            self.pending = true;
            self.entering = true;
        }
    }

    /// RFC の `dodequeue` の判断:待ちが目標を interval の間ずっと超えたか。
    fn ok_to_drop(&mut self, now: Instant, sojourn: Duration, emptied: bool) -> bool {
        if emptied || sojourn < self.target {
            self.first_above = None;
            return false;
        }
        match self.first_above {
            None => {
                self.first_above = Some(now + INTERVAL);
                false
            }
            Some(t) => now >= t,
        }
    }

    /// 落とすと決めて、まだ落としていないか。
    pub(crate) fn pending(&self) -> bool {
        self.pending
    }

    /// 落とすと決めていて `packet` が落とせる packet ([`droppable`]) なら、落としたと数えて `true` を返す。
    pub(crate) fn take(&mut self, packet: &[u8]) -> bool {
        if !self.pending || !droppable(packet) {
            return false;
        }
        let Some(now) = self.now else {
            return false;
        };
        self.pending = false;
        self.drops += 1;
        if self.entering {
            self.entering = false;
            // 前の落とす状態から間が無ければ、その時の数から続ける (RFC 8289 の dequeue)
            let delta = self.count.saturating_sub(self.last_count);
            let recent = self
                .drop_next
                .is_some_and(|t| now < t + INTERVAL.saturating_mul(16));
            self.count = if delta > 1 && recent { delta } else { 1 };
            self.drop_next = Some(control_law(now, self.count));
            self.last_count = self.count;
        } else {
            self.count = self.count.saturating_add(1);
            let base = self.drop_next.unwrap_or(now);
            self.drop_next = Some(control_law(base, self.count));
        }
        true
    }

    /// 落とした segment の数。
    pub(crate) fn drops(&self) -> u64 {
        self.drops
    }

    #[cfg(test)]
    pub(crate) fn dropping(&self) -> bool {
        self.dropping
    }

    #[cfg(test)]
    pub(crate) fn count(&self) -> u32 {
        self.count
    }

    #[cfg(test)]
    pub(crate) fn drop_next(&self) -> Option<Instant> {
        self.drop_next
    }
}

/// Whether CoDel may drop `packet`: an IPv4 TCP segment that carries data, is not a fragment and
/// has none of SYN, FIN and RST. A pure ACK, every other protocol (UDP included) and a packet the
/// check cannot read pass.
pub(crate) fn droppable(packet: &[u8]) -> bool {
    const TCP: u8 = 6;
    const SYN_FIN_RST: u8 = 0x07;
    let Some(&vihl) = packet.first() else {
        return false;
    };
    let ihl = usize::from(vihl & 0x0f) * 4;
    if vihl >> 4 != 4 || ihl < 20 || packet.len() < ihl + 20 || packet[9] != TCP {
        return false;
    }
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    // 断片 (MF か offset のある packet) は落とさない
    let fragment = u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0;
    if fragment || total > packet.len() {
        return false;
    }
    let tcp = &packet[ihl..total.max(ihl)];
    let Some((&off, &flags)) = tcp.get(12).zip(tcp.get(13)) else {
        return false;
    };
    let doff = usize::from(off >> 4) * 4;
    doff >= 20 && tcp.len() > doff && flags & SYN_FIN_RST == 0
}

/// 待ちの標本。前の標本から [`SAMPLE_GAP`] 以上経ち、読みがソケットを空にしなかった時だけ、受信の時刻を
/// 読む。
#[derive(Debug, Default)]
pub(crate) struct Sampler {
    last: Option<Instant>,
    sojourn: Duration,
}

impl Sampler {
    /// `now` に読んだバッチの待ち。`emptied` ならソケットは空で、待ちを 0 とする。標本を読む時は
    /// `stamp` (最後に読んだ datagram の受信の時刻、Unix の起点からの ns) と `wall` (今の壁時計、同じ単位) を
    /// 呼ぶ。受信の時刻が無いか、差が負か [`MAX_SOJOURN`] を超える時は 0 とする。
    pub(crate) fn sojourn(
        &mut self,
        now: Instant,
        emptied: bool,
        stamp: impl FnOnce() -> Option<u64>,
        wall: impl FnOnce() -> u64,
    ) -> Duration {
        if emptied {
            self.sojourn = Duration::ZERO;
            return self.sojourn;
        }
        if self
            .last
            .is_some_and(|t| now.saturating_duration_since(t) < SAMPLE_GAP)
        {
            return self.sojourn;
        }
        self.last = Some(now);
        self.sojourn = stamp()
            .and_then(|s| wall().checked_sub(s))
            .map(Duration::from_nanos)
            .filter(|&d| d <= MAX_SOJOURN)
            .unwrap_or(Duration::ZERO);
        self.sojourn
    }
}

/// The wall clock in ns since the Unix epoch, the clock of the kernel's receive times; 0 before
/// the epoch.
pub(crate) fn wall_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// The receive queue control of one data plane: the sampler and the CoDel state.
#[derive(Debug)]
pub(crate) struct RxCodel {
    pub(crate) codel: Codel,
    sampler: Sampler,
    /// The drops the last log line reported, and when it was written.
    logged: u64,
    logged_at: Option<Instant>,
}

/// The least time between two log lines of the drops.
const LOG_GAP: Duration = Duration::from_secs(10);

impl RxCodel {
    pub(crate) fn new(target: Duration) -> Self {
        Self {
            codel: Codel::new(target),
            sampler: Sampler::default(),
            logged: 0,
            logged_at: None,
        }
    }

    /// One receive batch: `n` datagrams read at `now` from a read of up to `vlen`, with `stamp`
    /// reading the receive time of the last one. A read of fewer than `vlen`, or of none, emptied
    /// the socket.
    pub(crate) fn after_read(
        &mut self,
        now: Instant,
        n: usize,
        vlen: usize,
        stamp: impl FnOnce() -> Option<u64>,
    ) {
        self.after_read_at(now, n, vlen, stamp, wall_ns);
    }

    /// [`RxCodel::after_read`] with `wall` in place of the wall clock.
    fn after_read_at(
        &mut self,
        now: Instant,
        n: usize,
        vlen: usize,
        stamp: impl FnOnce() -> Option<u64>,
        wall: impl FnOnce() -> u64,
    ) {
        let emptied = n < vlen;
        let sojourn = self.sampler.sojourn(now, emptied, stamp, wall);
        self.codel.on_batch(now, sojourn, emptied);
    }

    /// The log line of the drops when they grew since the last line, at most once every
    /// [`LOG_GAP`] unless `last` (the data plane is stopping).
    pub(crate) fn log_line(&mut self, now: Instant, last: bool) -> Option<String> {
        let drops = self.codel.drops();
        if drops == self.logged
            || !last
                && self
                    .logged_at
                    .is_some_and(|t| now.saturating_duration_since(t) < LOG_GAP)
        {
            return None;
        }
        self.logged = drops;
        self.logged_at = Some(now);
        Some(format!(
            "tunnel: the experimental receive queue control dropped {drops} TCP segments so far"
        ))
    }
}

#[cfg(test)]
#[path = "rxcodel_tests.rs"]
mod tests;
