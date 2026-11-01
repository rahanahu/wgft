//! 受信の窓の自動調整 (Go の `rcvwin.go`、wgstack-performance.md の「受信の窓と boost の方針」)。
//!
//! 広告する窓は 2 つの値で決めます。
//!
//! - 窓の上限 (`rcv_clamp`):受け手の往復ごとに読んだ量の測定 (Linux の tcp_rcv_space_adjust) が上げ、測定では
//!   下げません。予約の内側に収めます
//! - 歩みの上限 (`rcv_ssthresh`):届いた segment ごとに有界の量だけ広げます (Linux の tcp_grow_window)
//!
//! 広告する窓は、上限から保持するデータ (未読と順序外) を引いた空きと、歩みの上限の小さい方で、RCV.NXT から
//! 測ります。右端は後ろへ戻しません。
//!
//! 加えて、遅れの目標の窓の上限 (`lat_cap`) で頭打ちにします (agent-throughput.md の「受信の窓の段」)。上限は、
//! 中継が往復の時間あたりに読んだ速さに、往復の時間の最小と目標の待ちの時間の和を掛けた量で、窓に使う時は
//! floor より小さくしません。往復の時間は、新しい TSval を初めて運ぶ segment を送った時刻から、その TSval を TSecr に返す
//! data が届くまでの時間です (RFC 7323 の RTTM を受け手の側で ns の単位で使います)。

use super::ctx::Conn;
use super::{MS, SEC, ts_clock};
use crate::buf::{BOOST_SIZE, RECV_FLOOR};
use crate::wire::Segment;

/// 歩みの上限を広げる順序どおりの segment の中身の最小 (Linux の tcp_event_data_recv の 128) です。
pub(crate) const RCV_GROW_MIN: usize = 128;

/// 遅れの目標の窓が狙う、詰まりの所の待ち行列の時間 (ns) です。
pub(crate) const LAT_TARGET: i64 = MS / 2;
/// 窓が上限の内にあるのに待ちが目標の 2 倍を超えた区間がこの数だけ続いたら、往復の時間の最小を今の標本に
/// 置き直します。
pub(crate) const LAT_STALE_ROUNDS: u8 = 4;
/// 往復の時間の最小を測り直す間隔です。
pub(crate) const LAT_MIN_TTL: i64 = 10 * SEC;
/// 最小を測り直すために右端を止める時間の上限です。
pub(crate) const LAT_DRAIN_MAX: i64 = 200 * MS;

/// 往復の時間の最小 `base` (ns) に対する目標の待ちの時間です。[`LAT_TARGET`] と最小の 16 分の 1 の大きい方です。
/// CoDel (RFC 8289) が目標を往復の時間の数 % (100 ms に 5 ms) にするのと同じく、往復の時間の長い経路では標本の
/// 揺れより広く取ります。
pub(crate) const fn lat_target(base: i64) -> i64 {
    if base / 16 > LAT_TARGET {
        base / 16
    } else {
        LAT_TARGET
    }
}

impl Conn<'_> {
    /// 窓の上限です。floor から予約までの間で、測定が求めた値です。
    pub(crate) fn rcv_clamp(&self) -> u64 {
        self.t.rcv_want.max(RECV_FLOOR).min(self.t.rcv_cap)
    }

    /// 窓の上限から保持するデータを引いた空きです。順序外のデータも空きを減らします。
    pub(crate) fn rcv_free(&self) -> u64 {
        let held = self.b.rcv.unread() + self.b.rcv.ooo_bytes();
        self.rcv_clamp().saturating_sub(held)
    }

    /// 今広告してよい右端 (受信の offset) です。空きと歩みの上限の小さい方を RCV.NXT に足し、窓の欄で表せる量に
    /// 収めます。
    pub(crate) fn rcv_target(&self) -> u64 {
        let nxt = self.b.rcv.nxt_off;
        nxt + self
            .rcv_free()
            .min(self.t.rcv_ssthresh)
            .min(65535u64 << self.t.rcv_wscale)
            .min(self.lat_limit())
    }

    /// 遅れの目標が許す窓 (RCV.NXT から右端までの byte) です。floor より小さくせず、上限が無ければ制限しません。
    /// 最小を測り直すために右端を止めている間は 0 です。
    fn lat_limit(&self) -> u64 {
        match self.t.lat_cap {
            _ if self.t.lat_drain => 0,
            0 => u64::MAX,
            c => c.max(RECV_FLOOR),
        }
    }

    /// segment を送る時に呼びます。timestamp を使う接続で、新しい TSval を初めて運ぶ segment なら、測っていない
    /// 間に限り往復の時間を測り始めます。接続で最初に送る segment の TSval は握手の SYN-ACK と同じことがあるので、
    /// 測り始めません。
    pub(crate) fn rcv_lat_mark(&mut self, now: i64) {
        let t = &mut *self.t;
        if !t.ts_ok {
            return;
        }
        let val = ts_clock(now).wrapping_add(t.ts_offset);
        if val == t.ts_sent {
            return;
        }
        if t.lat_sent == 0 && t.ts_sent != 0 && !t.lat_drain {
            (t.lat_tsval, t.lat_sent) = (val, now);
        }
        t.ts_sent = val;
    }

    /// 順序どおりか順序外の data を受け入れた時に呼びます。測っている TSval を TSecr に返す data なら、往復の
    /// 時間の標本を取ります。TSecr がそれより新しければ、その TSval への応答は来ないので測るのをやめます。
    pub(crate) fn rcv_lat_sample(&mut self, seg: &Segment<'_>, now: i64) {
        let t = &mut *self.t;
        if t.lat_sent == 0 {
            return;
        }
        let Some((_, ecr)) = seg.opt.ts else {
            return;
        };
        #[expect(
            clippy::cast_possible_wrap,
            reason = "the timestamp comparison of RFC 7323 is modulo 2^32"
        )]
        let d = ecr.wrapping_sub(t.lat_tsval) as i32;
        if d == 0 {
            let r = (now - t.lat_sent).max(1);
            t.lat_sent = 0;
            let k = &mut *self.k;
            k.lat_rtt = r;
            if k.lat_min == 0 || r < k.lat_min {
                k.lat_min = r;
            }
            if k.lat_min_at == 0 {
                k.lat_min_at = now;
            }
        } else if d > 0 {
            t.lat_sent = 0;
        }
    }

    /// data を受け入れた時に呼びます。右端を止めている間に、残りの窓が MSS の 2 倍を下回るか止めた時間が
    /// [`LAT_DRAIN_MAX`] を超えたら、右端を進めるのを再開してすぐに ACK を送ります。最小は止め始めた時に捨て、
    /// 止めている間は測りません。この間に届く data は止める前に送られたもので、待ちを含むためです。再開の ACK から
    /// 測る最初の標本が新しい最小になり、それまで遅れの上限は止める前の値のままです。
    pub(crate) fn rcv_lat_drain(&mut self, now: i64) {
        if !self.t.lat_drain {
            return;
        }
        let left = self.t.adv_right.saturating_sub(self.b.rcv.nxt_off);
        if left >= 2 * u64::from(self.rcv_mss()) && now - self.k.lat_drain_at < LAT_DRAIN_MAX {
            return;
        }
        let t = &mut *self.t;
        (t.lat_drain, t.ack_now) = (false, true);
        // 再開の ACK から測ります。止めている間の送り手は窓を使い切って送れず、この ACK の TSval を返す最初の data は
        // 空の待ち行列を通ります。同じ刻みで前に送った ACK の TSval でも、それに応える data は止めている間に
        // 送られていないので、標本は往復の時間より短くなりません。
        t.ts_sent = ts_clock(now).wrapping_add(t.ts_offset).wrapping_sub(1);
        let k = &mut *self.k;
        (k.lat_high, k.lat_min_at) = (0, now);
    }

    /// 届いた `n` byte の segment で歩みの上限を広げます。順序どおりの 128 byte 以上の segment と、SACK を交渉した
    /// 接続の順序外の segment で広げます。広げる量は自分の MSS の 2 倍と中身の 2 倍の大きい方で、上限と空きの小さい
    /// 方を超えません。
    pub(crate) fn rcv_grow(&mut self, n: usize, ooo: bool) {
        if ooo {
            if !self.t.sack_ok {
                return;
            }
        } else if n < RCV_GROW_MIN {
            return;
        }
        let room = self.rcv_clamp().min(self.rcv_free());
        if room <= self.t.rcv_ssthresh {
            return;
        }
        let incr = (2 * u64::from(self.rcv_mss())).max(2 * n as u64);
        self.t.rcv_ssthresh += (room - self.t.rcv_ssthresh).min(incr);
    }

    /// 窓による受け手の RTT の標本を取ります (Linux の tcp_rcv_rtt_measure)。標本は、始めの RCV.NXT にその時の窓を
    /// 足した offset を RCV.NXT が越えるまでの時間で、今の推定より小さいときだけ推定を下げます。
    pub(crate) fn rcv_rtt_window(&mut self, now: i64) {
        let nxt = self.b.rcv.nxt_off;
        let t = &mut *self.t;
        if t.rtt_win_time != 0 {
            if nxt < t.rtt_win_seq {
                return;
            }
            let d = now - t.rtt_win_time;
            if d > 0 && (t.rcv_rtt == 0 || d < t.rcv_rtt) {
                t.rcv_rtt = d;
            }
        }
        let wnd = u64::from(self.rcv_window());
        (self.t.rtt_win_seq, self.t.rtt_win_time) = (nxt + wnd, now);
    }

    /// timestamp による受け手の RTT の標本を取ります (Linux の tcp_rcv_rtt_measure_ts)。
    pub(crate) fn rcv_rtt_stamp(&mut self, seg: &Segment<'_>, n: usize, now: i64) {
        let t = &mut *self.t;
        let Some((_, ecr)) = seg.opt.ts else {
            return;
        };
        if !t.ts_ok
            || ecr == 0
            || ecr == t.rtt_tsecr
            || u32::try_from(n).unwrap_or(u32::MAX) < t.rcv_mss_est
        {
            return;
        }
        t.rtt_tsecr = ecr;
        #[expect(
            clippy::cast_possible_wrap,
            reason = "Go's int32 conversion of the timestamp difference"
        )]
        let d = ts_clock(now).wrapping_add(t.ts_offset).wrapping_sub(ecr) as i32;
        if d < 0 {
            return;
        }
        let r = i64::from(d).max(1) * MS;
        if t.rcv_rtt == 0 || r < t.rcv_rtt {
            t.rcv_rtt = r;
        } else {
            t.rcv_rtt += (r - t.rcv_rtt) / 8;
        }
    }

    /// 読み取りの後に、受け手の RTT の 1 回の間に読んだ量で窓の上限を上げます (Linux の tcp_rcv_space_adjust)。
    pub(crate) fn rcv_space_adjust(&mut self, now: i64) {
        let read_off = self.b.rcv.read_off;
        let mss = u64::from(self.rcv_mss());
        let t = &mut *self.t;
        if t.rs_time == 0 {
            (t.rs_time, t.rs_seq) = (now, read_off);
            t.rs_space = 10 * mss;
            return;
        }
        if t.rcv_rtt == 0 || now - t.rs_time < t.rcv_rtt {
            return;
        }
        let copied = read_off - t.rs_seq;
        let elapsed = now - t.rs_time;
        if copied > t.rs_space {
            // 目標は予約で抑えるので、これより大きな量は目標を変えません。
            let cp = copied.min(BOOST_SIZE);
            let mut win = 2 * cp + 16 * mss;
            win += 2 * (win * (cp - t.rs_space.min(cp)) / t.rs_space);
            t.rcv_want = t.rcv_want.max(win.min(BOOST_SIZE));
            t.rs_space = copied;
        }
        (t.rs_time, t.rs_seq) = (now, read_off);
        self.lat_adjust(copied, elapsed, now);
    }

    /// 受け手の RTT の 1 回の区間ごとに、遅れの目標の窓の上限を決め直します。`copied` は区間の間に中継が読んだ
    /// byte、`elapsed` は区間の長さ (ns、正) です。
    ///
    /// 上限は、読んだ速さ × (往復の時間の最小 + 目標 + 伸びの余地) です。目標は [`lat_target`] です。伸びの余地は、
    /// 最後の標本の待ち (標本から最小を引いた時間) が目標より短いほど大きく、待ちが 0 のとき最小と同じ長さ (窓を
    /// 往復ごとに 2 倍まで広げられる量)、目標以上のとき 0 です。窓に使う時は floor より小さくしません
    /// ([`Conn::rcv_target`])。
    ///
    /// 上限が floor 以上で今の窓が上限の内にあれば、自分の窓が作る待ちは目標までです。それでも待ちが目標の 2 倍を
    /// 超える区間が続けば、待ちは自分の窓ではなく、経路の往復の時間が延びたか、ほかの流れが作ったものです。この時は
    /// 最小を今の標本に置き直し、窓が帯域と往復の時間の積を下回り続けないようにします。上限が floor より小さい間は
    /// floor の窓が待ちを作るので、置き直しません。
    ///
    /// 最小を測り始めてから [`LAT_MIN_TTL`] が過ぎたら、最小を捨てて測り直します。上限が floor 以上なら、右端を
    /// 止めて待ち行列を空にしながら測り直します ([`Conn::rcv_lat_drain`])。待ち行列が初めから空にならない場合 (例えば
    /// 送り手が初めに窓をまとめて送った場合) に、待ちを含む最小が残り続けないためです。
    pub(crate) fn lat_adjust(&mut self, copied: u64, elapsed: i64, now: i64) {
        let window = u64::from(self.rcv_window());
        let (t, k) = (&mut *self.t, &mut *self.k);
        if k.lat_min == 0 || t.lat_drain {
            return;
        }
        if t.lat_cap >= RECV_FLOOR
            && window <= t.lat_cap
            && k.lat_rtt - k.lat_min > 2 * lat_target(k.lat_min)
        {
            k.lat_high += 1;
            if k.lat_high >= LAT_STALE_ROUNDS {
                (k.lat_min, k.lat_high) = (k.lat_rtt, 0);
            }
        } else {
            k.lat_high = 0;
        }
        // 時刻が跳ぶと標本は何日にもなるので、掛け算は 128 bit で行い、溢れる所は飽和させます。
        let base = u128::try_from(k.lat_min).unwrap_or(0);
        let target = u128::try_from(lat_target(k.lat_min)).unwrap_or(1);
        let wait = u128::try_from(k.lat_rtt - k.lat_min).unwrap_or(0);
        let room = base * target.saturating_sub(wait) / target;
        let span = base + target + room;
        let elapsed = u128::try_from(elapsed.max(1)).unwrap_or(1);
        let cap = u128::from(copied).saturating_mul(span) / elapsed;
        t.lat_cap = u64::try_from(cap).unwrap_or(u64::MAX).max(1);
        if now - k.lat_min_at >= LAT_MIN_TTL {
            if t.lat_cap >= RECV_FLOOR {
                (t.lat_drain, t.lat_sent, k.lat_drain_at) = (true, 0, now);
            }
            (k.lat_min, k.lat_high, k.lat_min_at) = (0, 0, now);
        }
    }

    /// 今広告している窓の大きさ (byte) です。
    pub(crate) fn rcv_window(&self) -> u32 {
        let nxt = self.b.rcv.nxt_off;
        if self.t.adv_right <= nxt {
            return 0;
        }
        u32::try_from((self.t.adv_right - nxt).min(1 << 30)).unwrap_or(1 << 30)
    }

    /// 広告する窓の欄を返し、広告した右端を更新します。右端は目標に向けて広げ、後ろへ戻しません。右端を広げるのは、
    /// 広げる量が min(窓の上限の半分, MSS) 以上のときだけです (受け手の SWS の回避、RFC 9293 3.8.6.2.2)。
    pub(crate) fn window_field(&mut self) -> u16 {
        let nxt = self.b.rcv.nxt_off;
        let target = self.rcv_target();
        let step = (self.rcv_clamp() / 2).min(u64::from(self.rcv_mss()));
        let t = &mut *self.t;
        if target > t.adv_right && target - t.adv_right >= step {
            t.adv_right = target;
        }
        if t.adv_right <= nxt {
            return 0;
        }
        u16::try_from(((t.adv_right - nxt) >> t.rcv_wscale).min(65535)).unwrap_or(u16::MAX)
    }

    /// 読み取りで空いた受信のバッファが広告する窓を大きく広げるときに ACK を送ります。Linux の tcp_cleanup_rbuf と
    /// 同じく、今の窓が窓の上限の半分以下で、広げた後の窓が今の窓の 2 倍以上になるときです。
    pub(crate) fn window_update(&mut self) {
        let cur = u64::from(self.rcv_window());
        if 2 * cur > self.rcv_clamp() {
            return;
        }
        let target = self.rcv_target();
        let nxt = self.b.rcv.nxt_off;
        if target <= nxt {
            return;
        }
        let next = target - nxt;
        if next >= 2 * cur && next - cur >= u64::from(self.rcv_mss()) {
            self.t.ack_now = true;
        }
    }
}
