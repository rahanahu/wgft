//! 輻輳の制御 (Go の `cc.go`、`hystart.go`、`cwndval.go`、`lazyegress.go`)。
//!
//! slow start、回復の間の窓 (NewReno の窓の膨らませ方と PRR)、RTO の後の 1 segment は共通の処理が持ち、輻輳の
//! 回避の窓の増やし方と、輻輳の事象での ssthresh の決め方だけが輻輳の制御ごとに違います。輻輳の制御は核の設定で
//! 1 つに決まり (`Config::congestion`)、状態は接続の枠の中に値として埋め込みます。HyStart++ は輻輳の制御の種類に
//! よらず最初の slow start で働きます。

use super::ctx::Conn;
use super::{MS, SEC};
use crate::config::Congestion;
use crate::seq;

/// CUBIC の定数 (RFC 9438 4.6 と 5) です。
const CUBIC_BETA: f64 = 0.7;
const CUBIC_C: f64 = 0.4;
/// Reno と公平な窓の増やし方の係数 3 (1 - β) / (1 + β) です。Go は定数の式を正確に計算してから丸めるので、同じ
/// 値の 9/17 を 1 回の割り算で丸めます。
const CUBIC_ALPHA: f64 = 9.0 / 17.0;
/// Go の `float64(time.Second)` です。
#[expect(clippy::cast_precision_loss, reason = "1e9 is exact in f64")]
const SEC_F: f64 = SEC as f64;

/// RFC 9438 の CUBIC の状態です。窓は segment の数で計算し、byte の窓に 1 byte 未満の端数を持ち越します。
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct Cubic {
    /// 最後の輻輳の事象の直前の窓 (fast convergence で縮めた値) です。
    pub(crate) w_max: f64,
    /// 最後の輻輳の事象の直前の窓です。
    pub(crate) cwnd_prior: f64,
    /// 輻輳の回避の epoch の始まり (ns) です。0 なら次の ACK で始めます。
    pub(crate) epoch: i64,
    /// 窓が `w_max` に戻るまでの時間 (秒) です。
    pub(crate) k: f64,
    /// 3 次の式の原点の窓です。
    pub(crate) origin: f64,
    /// Reno と公平な窓の推定 (RFC 9438 4.3) です。
    pub(crate) w_est: f64,
    /// cwnd に足していない byte の端数です。
    pub(crate) frac: f64,
}

/// Go の組み込みの `min` と同じ値を返します (NaN を伝え、-0 を +0 より小さいとみなします)。
#[expect(clippy::float_cmp, reason = "an exact comparison like Go's min")]
fn go_min(x: f64, y: f64) -> f64 {
    if x.is_nan() || y.is_nan() {
        return f64::NAN;
    }
    if x == y {
        return if x.is_sign_negative() { x } else { y };
    }
    if x < y { x } else { y }
}

/// Go の組み込みの `max` と同じ値を返します。
#[expect(clippy::float_cmp, reason = "an exact comparison like Go's max")]
fn go_max(x: f64, y: f64) -> f64 {
    if x.is_nan() || y.is_nan() {
        return f64::NAN;
    }
    if x == y {
        return if x.is_sign_negative() { y } else { x };
    }
    if x > y { x } else { y }
}

/// Go の `float64(x)` です。値は接続の窓の byte か ns で、2^53 より小さい値は正確に表せます。
#[expect(
    clippy::cast_precision_loss,
    reason = "matches Go's float64 conversion"
)]
fn f(x: i64) -> f64 {
    x as f64
}

/// Go の `uint32(x)` です。呼び手は `x` が 0 以上 2^32 未満であることを保証し、その範囲では Go と同じく 0 の
/// 向きに切り捨てます。
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the value is in range, where Go truncates toward zero as well"
)]
fn u32_from_f64(x: f64) -> u32 {
    x as u32
}

impl Conn<'_> {
    /// 輻輳の回避です。回復の外で cwnd >= ssthresh の間に `acked` byte を確認した ACK で窓を増やします。
    pub(crate) fn cong_avoid(&mut self, acked: u32, now: i64) {
        match self.s.config.congestion {
            Congestion::NewReno => self.reno_cong_avoid(acked),
            Congestion::Cubic => self.cubic_cong_avoid(acked, now),
        }
    }

    /// 輻輳の事象 (回復に入る時、TLP の probe が損失を直した時、最初の RTO) の新しい ssthresh です。`cwnd` は事象の
    /// 直前の輻輳の窓 (W_max と cwnd_prior)、`base` は β 倍する量 (`loss_base`) です。
    pub(crate) fn cc_loss_thresh(&mut self, cwnd: u32, base: u32) -> u32 {
        let mss = self.seg_mss();
        match self.s.config.congestion {
            Congestion::NewReno => (base / 2).max(2 * mss),
            Congestion::Cubic => {
                // RFC 9438 4.6 と 4.7 (fast convergence)。ssthresh は base の β 倍です。
                let m = f(i64::from(mss));
                let w = f(i64::from(cwnd)) / m;
                let k = &mut self.t.cubic;
                k.w_max = if w < k.w_max { w * 1.7 / 2.0 } else { w };
                k.cwnd_prior = w;
                (k.epoch, k.frac) = (0, 0.0);
                u32_from_f64(f(i64::from(base)) * CUBIC_BETA).max(2 * mss)
            }
        }
    }

    /// 送り残しが無いまま `idle` ns の間何も送らなかった後に、時刻 `now` に送り始める時に呼びます。CUBIC は
    /// 送らなかった時間だけ epoch を後ろへずらします (Linux の CA_EVENT_TX_START)。ずらさないと、黙った後の最初の
    /// ACK で 3 次の式が先へ進んだ窓を一度に求めます。epoch は今より先へずらしません。
    pub(crate) fn cc_on_idle(&mut self, idle: i64, now: i64) {
        if self.s.config.congestion == Congestion::Cubic {
            let k = &mut self.t.cubic;
            if k.epoch != 0 && idle > 0 {
                k.epoch = (k.epoch + idle).min(now);
            }
        }
    }

    /// NewReno の輻輳の回避 (RFC 5681) です。
    fn reno_cong_avoid(&mut self, acked: u32) {
        let mss = self.seg_mss();
        let t = &mut *self.t;
        t.ca_acc = t.ca_acc.wrapping_add(acked);
        if t.ca_acc >= t.cwnd {
            t.ca_acc -= t.cwnd;
            t.cwnd = t.cwnd.wrapping_add(mss);
        }
    }

    /// CUBIC の輻輳の回避 (RFC 9438 4.2 から 4.5) です。浮動小数点の演算は Go と同じ順で書き、積和を 1 つの命令に
    /// まとめません。
    fn cubic_cong_avoid(&mut self, acked: u32, now: i64) {
        let mss = f(i64::from(self.seg_mss()));
        let t = &mut *self.t;
        let cwnd = f(i64::from(t.cwnd)) / mss;
        let srtt = t.srtt;
        let k = &mut t.cubic;
        if k.epoch == 0 {
            k.epoch = now;
            k.w_est = cwnd;
            if k.w_max <= cwnd {
                (k.k, k.origin) = (0.0, cwnd);
            } else {
                (k.k, k.origin) = (cbrt((k.w_max - cwnd) / CUBIC_C), k.w_max);
            }
        }
        let el = f(now - k.epoch) / SEC_F;
        let rtt = f(srtt) / SEC_F;
        let (kk, origin) = (k.k, k.origin);
        let w_cubic = |x: f64| {
            let d = x - kk;
            CUBIC_C * d * d * d + origin
        };
        // Reno と公平な窓 (RFC 9438 4.3)。cwnd_prior に届いた後の増え方は Reno と同じにします。
        let alpha = if k.w_est >= k.cwnd_prior {
            1.0
        } else {
            CUBIC_ALPHA
        };
        let acked_seg = f(i64::from(acked)) / mss;
        k.w_est += alpha * acked_seg / cwnd;
        let inc = if w_cubic(el) < k.w_est {
            k.w_est - cwnd // Reno と公平な領域 (RFC 9438 4.3)
        } else {
            // 凹と凸の領域 (RFC 9438 4.4、4.5)。目標は 1 RTT 先の窓で、[cwnd, 1.5 cwnd] に収めます。
            let target = go_min(go_max(w_cubic(el + rtt), cwnd), 1.5 * cwnd);
            (target - cwnd) / cwnd * acked_seg
        };
        if inc <= 0.0 {
            return;
        }
        k.frac += inc * mss;
        let add = k.frac.floor();
        if add >= 1.0 {
            k.frac -= add;
            t.cwnd = u32_from_f64(go_min(f(i64::from(t.cwnd)) + add, f(1 << 30)));
        }
    }
}

/// HyStart++ の値 (RFC 9406)。
const HS_MIN_RTT_THRESH: i64 = 4 * MS;
const HS_MAX_RTT_THRESH: i64 = 16 * MS;
const HS_MIN_RTT_DIVISOR: i64 = 8;
const HS_N_RTT_SAMPLE: i64 = 8;
const HS_CSS_GROWTH_DIV: u32 = 4;
const HS_CSS_ROUNDS: i64 = 5;
const HS_NO_RTT: i64 = i64::MAX;

/// HyStart++ の状態です。接続の枠の中に値として埋め込みます。
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Hystart {
    pub(crate) started: bool,
    css: bool,
    /// 処理中の ACK の前に、ACK のたびに送る送り手なら送り終えていた番号 (`sendable_end`) です。
    pub(crate) snd_nxt_ok: bool,
    pub(crate) snd_nxt: u32,
    /// この往復の終わりの番号 (往復を始めた時の SND.NXT) です。
    pub(crate) window_end: u32,
    last_round_min: i64,
    cur_round_min: i64,
    samples: i64,
    css_baseline: i64,
    css_rounds: i64,
}

impl Conn<'_> {
    /// 輻輳の事象で β 倍する量です。送り残し (RFC 5681 の FlightSize) と送り手の窓の小さい方です。回復の中と RTO の
    /// 後の回復の中では、回復が目指す ssthresh を送り手の窓に使います。
    fn loss_base(&self) -> u32 {
        let t = &*self.t;
        let w = if t.in_recovery || (t.rto_episode && seq::lt(t.snd_una, t.recover)) {
            t.ssthresh
        } else {
            t.cwnd
        };
        t.snd_max.wrapping_sub(t.snd_una).min(w)
    }

    /// 今の状態で起きた輻輳の事象の新しい ssthresh です。
    pub(crate) fn loss_thresh(&mut self) -> u32 {
        let (cwnd, base) = (self.t.cwnd, self.loss_base());
        self.cc_loss_thresh(cwnd, base)
    }

    /// RTO の後の状態を整えます。ssthresh は呼び手が `loss_thresh` で決めます。CUBIC は Linux の bictcp_reset と
    /// 同じく、RTO の後の epoch を 3 次の式の原点から始め直します。
    pub(crate) fn cc_on_rto(&mut self) {
        match self.s.config.congestion {
            Congestion::NewReno => self.t.ca_acc = 0,
            Congestion::Cubic => self.t.cubic = Cubic::default(),
        }
    }

    /// 高速の回復に入り、輻輳の事象として ssthresh を下げ、回復の終わりを SND.MAX にします。窓を下げる前に取り消しの
    /// 印を付けます。TLP の probe が直した損失と同じ窓のデータの損失なら、その縮小が輻輳の事象なので ssthresh を
    /// 下げ直さず、回復は縮小の時の SND.MAX (`tlp_cut_seq`) で終えます。その先のデータの損失は、次の回復で窓を
    /// 下げます。TLP は SACK を交渉した接続だけで使うので、SACK の無い接続では `tlp_cut` は立ちません。
    pub(crate) fn enter_fast_recovery(&mut self) {
        self.init_undo();
        if self.t.tlp_cut && seq::lt(self.t.snd_una, self.t.tlp_cut_seq) {
            self.t.recover = self.t.tlp_cut_seq;
        } else {
            self.t.ssthresh = self.loss_thresh();
            self.t.recover = self.t.snd_max;
        }
        self.t.in_recovery = true;
        self.s.stats.fast_recoveries += 1;
    }

    /// 新しいデータを送った後と、輻輳の窓が新しいデータを止めた時に呼びます (RFC 7661)。`limited` は輻輳の窓が
    /// 止めたか、送った後の輻輳の窓に 1 segment の余地が無いかです。
    pub(crate) fn note_cwnd_use(&mut self, limited: bool) {
        let t = &mut *self.t;
        let flight = t.snd_max.wrapping_sub(t.snd_una);
        if !seq::lt(t.snd_una, t.cwnd_usage_seq)
            || limited
            || (!t.cwnd_limited && flight > t.max_flight)
        {
            t.cwnd_limited = limited;
            t.max_flight = flight;
            t.cwnd_usage_seq = t.snd_max;
        }
    }

    /// 窓を増やしてよいかを返します (Linux の tcp_is_cwnd_limited)。
    pub(crate) fn is_cwnd_limited(&self) -> bool {
        let t = &*self.t;
        if t.cwnd_limited {
            return true;
        }
        if t.cwnd < t.ssthresh {
            return t.cwnd < t.max_flight.wrapping_mul(2);
        }
        false
    }

    /// ACK のたびに送る送り手なら今の SND.NXT になっている番号です (Go の `sendableEnd`)。
    pub(crate) fn sendable_end(&mut self) -> u32 {
        let mut end = self.t.snd_nxt;
        if seq::gt(self.t.snd_max, end) {
            end = self.t.snd_max;
        }
        let pipe = self.pipe();
        if self.t.cwnd <= pipe {
            return end;
        }
        let t = &*self.t;
        let lim = seq::min(self.data_end_seq(), t.snd_una.wrapping_add(t.snd_wnd));
        if seq::gt(lim, end) {
            end = end.wrapping_add((t.cwnd - pipe).min(lim.wrapping_sub(end)));
        }
        end
    }

    /// ACK が送り残しを空にした時に送れる新しいデータがあれば、その時刻を最後に送った時刻にします。
    pub(crate) fn note_drained_with_data(&mut self, now: i64) {
        if self.t.snd_una == self.t.snd_max && self.has_new_data() {
            self.t.last_send_at = now;
        }
    }

    /// 最初の slow start の間だけ真を返します (RFC 9406 4.3)。
    pub(crate) fn hystart_on(&self) -> bool {
        self.t.ssthresh == u32::MAX && !self.t.in_recovery
    }

    /// slow start の ACK で窓を増やします。`acked` は新しく確認された byte、`sample` はこの ACK で測った RTT
    /// (ns、無ければ -1) です。増やす量は RFC 3465 の L = 2 で、CSS の間は 4 分の 1 にします。
    pub(crate) fn slow_start_ack(&mut self, ack: u32, acked: u32, sample: i64) {
        let mut inc = acked.min(2 * self.seg_mss());
        if !self.hystart_on() {
            self.t.cwnd = self.t.cwnd.wrapping_add(inc);
            return;
        }
        let t = &mut *self.t;
        let h = &mut t.hs;
        let mut start = t.snd_nxt;
        if h.snd_nxt_ok && seq::gt(h.snd_nxt, start) {
            start = h.snd_nxt;
        }
        h.snd_nxt_ok = false;
        if !h.started {
            *h = Hystart {
                started: true,
                window_end: start,
                last_round_min: HS_NO_RTT,
                cur_round_min: HS_NO_RTT,
                css_baseline: HS_NO_RTT,
                ..Hystart::default()
            };
        }
        if h.css {
            inc /= HS_CSS_GROWTH_DIV;
        }
        t.cwnd = t.cwnd.wrapping_add(inc);
        if sample >= 0 {
            h.cur_round_min = h.cur_round_min.min(sample);
            h.samples += 1;
        }
        if h.samples >= HS_N_RTT_SAMPLE && h.cur_round_min != HS_NO_RTT {
            if !h.css && h.last_round_min != HS_NO_RTT {
                let thresh = (h.last_round_min / HS_MIN_RTT_DIVISOR)
                    .clamp(HS_MIN_RTT_THRESH, HS_MAX_RTT_THRESH);
                if h.cur_round_min >= h.last_round_min.saturating_add(thresh) {
                    (h.css, h.css_baseline, h.css_rounds) = (true, h.cur_round_min, 0);
                    self.s.stats.hystart_css += 1;
                }
            } else if h.css && h.cur_round_min < h.css_baseline {
                // RTT が戻ったので slow start に戻ります。
                (h.css, h.css_baseline) = (false, HS_NO_RTT);
            }
        }
        // 往復の終わり:window_end を確認した ACK で次の往復を始めます。
        if seq::ge(ack, h.window_end) {
            (h.last_round_min, h.cur_round_min, h.samples, h.window_end) =
                (h.cur_round_min, HS_NO_RTT, 0, start);
            if h.css {
                h.css_rounds += 1;
                if h.css_rounds >= HS_CSS_ROUNDS {
                    t.ssthresh = t.cwnd; // 輻輳の回避に移ります
                    h.css = false;
                    self.s.stats.hystart_exits += 1;
                }
            }
        }
    }
}

// cbrt は Go の `math.Cbrt` (src/math/cbrt.go) を写したもので、Go の値と bit の単位で一致します。Go の
// `math.Cbrt` は amd64 で同じ Go のコードを使います。Go の source の license の通知と、元の C のコードの通知を
// 次に残します。
//
// Copyright 2009 The Go Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google LLC nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// The go code is a modified version of the original C code from
// http://www.netlib.org/fdlibm/s_cbrt.c and came with this notice.
//
// ====================================================
// Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
//
// Developed at SunSoft, a Sun Microsystems, Inc. business.
// Permission to use, copy, modify, and distribute this
// software is freely granted, provided that this notice
// is preserved.
// ====================================================

/// 3 乗根です。Go の `math.Cbrt` と同じ値を返します (wgstack-rs.md の「bit の一致の条件」)。Rust の `f64::cbrt` は
/// OS の数学ライブラリを呼び、最後の桁で値が違いうるので使いません。
#[expect(
    clippy::unreadable_literal,
    clippy::excessive_precision,
    clippy::many_single_char_names,
    reason = "the constants and names are written as in the Go source"
)]
pub(crate) fn cbrt(x: f64) -> f64 {
    const B1: u64 = 715094163; // (682-0.03306235651)*2**20
    const B2: u64 = 696219795; // (664-0.03306235651)*2**20
    const C: f64 = 5.42857142857142815906e-01; // 19/35     = 0x3FE15F15F15F15F1
    const D: f64 = -7.05306122448979611050e-01; // -864/1225 = 0xBFE691DE2532C834
    const E: f64 = 1.41428571428571436819e+00; // 99/70     = 0x3FF6A0EA0EA0EA0F
    const F: f64 = 1.60714285714285720630e+00; // 45/28     = 0x3FF9B6DB6DB6DB6E
    const G: f64 = 3.57142857142857150787e-01; // 5/14      = 0x3FD6DB6DB6DB6DB7
    const SMALLEST_NORMAL: f64 = 2.22507385850720138309e-308; // 2**-1022  = 0x0010000000000000
    if x == 0.0 || x.is_nan() || x.is_infinite() {
        return x;
    }
    let mut x = x;
    let sign = x < 0.0;
    if sign {
        x = -x;
    }
    // rough cbrt to 5 bits
    let mut t = f64::from_bits(x.to_bits() / 3 + (B1 << 32));
    if x < SMALLEST_NORMAL {
        // subnormal number
        t = 18_014_398_509_481_984.0; // 2**54
        t *= x;
        t = f64::from_bits(t.to_bits() / 3 + (B2 << 32));
    }
    // new cbrt to 23 bits
    let mut r = t * t / x;
    let mut s = C + r * t;
    t *= G + F / (s + E + D / s);
    // chop to 22 bits, make larger than cbrt(x)
    t = f64::from_bits((t.to_bits() & (0xF_FFFF_FFFC << 28)) + (1 << 30));
    // one step newton iteration to 53 bits with error less than 0.667ulps
    s = t * t; // t*t is exact
    r = x / s;
    let w = t + t;
    r = (r - t) / (w + r); // r-s is exact
    t = t + t * r;
    // restore the sign bit
    if sign {
        t = -t;
    }
    t
}

#[cfg(test)]
mod tests {
    //! HyStart++ の試験 (Go の `hystart_test.go`)。往復ごとに窓の分の segment を送ったとし、1 segment ごとの ACK に
    //! 往復の番号ごとの RTT を付けて `slow_start_ack` を直接呼びます。

    #![expect(
        clippy::disallowed_types,
        clippy::disallowed_methods,
        reason = "tests collect the windows"
    )]

    use super::*;
    use crate::testnet_tests::{TestNet, small_limits};

    /// ACK ごとに窓いっぱいまで送る ACK の流れで `rounds` 往復を進め、往復ごとの窓 (segment) を返します。
    fn hs_rounds(c: &mut Conn<'_>, rounds: usize, rtt: impl Fn(usize) -> i64) -> Vec<u32> {
        let mss = c.seg_mss();
        let mut w = Vec::new();
        let mut ack = c.t.snd_una;
        c.t.snd_nxt = ack.wrapping_add(c.t.cwnd);
        let mut end = c.t.snd_nxt;
        let mut round = 0;
        while round < rounds && c.t.cwnd < c.t.ssthresh {
            ack = ack.wrapping_add(mss);
            c.slow_start_ack(ack, mss, rtt(round));
            c.t.snd_una = ack;
            c.t.snd_nxt = ack.wrapping_add(c.t.cwnd);
            c.t.snd_max = c.t.snd_nxt;
            if seq::ge(ack, end) {
                w.push(c.t.cwnd / mss);
                end = c.t.snd_nxt;
                round += 1;
            }
        }
        w
    }

    fn hs_net() -> (TestNet, u32) {
        let mut n = TestNet::new(small_limits());
        let (c, _) = n.accepted(true);
        let v = n.s.conn(c.slot);
        v.t.cwnd = 10 * v.seg_mss();
        v.t.hs = Hystart::default();
        (n, c.slot)
    }

    /// `cbrt` は Go の `math.Cbrt` と bit の単位で同じ値を返します。表は `GOAMD64=v1` の Go 1.27 で、決まった種の
    /// 乱数の値 (CUBIC の (W_max - cwnd) / C の範囲と、任意の bit の列) と境目の値の `math.Cbrt` を書き出したものです。
    #[test]
    #[expect(clippy::unreadable_literal, reason = "the table is the Go output")]
    fn cbrt_matches_go() {
        let table: &[(u64, u64)] = &[
            (0x3ff0000000000000, 0x3ff0000000000000),
            (0x4000000000000000, 0x3ff428a2f98d728b),
            (0x4008000000000000, 0x3ff7137449123ef6),
            (0x4020000000000000, 0x4000000000000000),
            (0x403b000000000000, 0x4008000000000000),
            (0x3fe0000000000000, 0x3fe965fea53d6e3c),
            (0x01a56e1fc2f8f359, 0x2b2bff2ee48e0530),
            (0x0000000000001fa0, 0x29d414660c14149b),
            (0x7e37e43c8800759c, 0x54b249ad2594c37d),
            (0xc000000000000000, 0xbff428a2f98d728b),
            (0x4004000000000000, 0x3ff5b7209557b0ee),
            (0x401dffe5c91d14e4, 0x3fff519d00e604f0),
            (0x405edd2f1a9fbe77, 0x4013ead4f488ee35),
            (0x3fe5a58656eef510, 0x3fec173a5abc25c2),
            (0x403787dbc3f0b0cc, 0x4006ecb1f4e862a5),
            (0x40598df4273c97d6, 0x4012b3df03e33f6a),
            (0x40683ac4d5098312, 0x4017263adc1a377f),
            (0x4083f85144b92125, 0x40213a13033e3667),
            (0x407e5d8b27b449b2, 0x401f7211d8f245aa),
            (0x40970e0eaa942897, 0x4026c4def42595a5),
            (0x4089e71111dfb6d3, 0x4022c9834fa08c0b),
            (0x40a85570722cd1aa, 0x402d35449c00e5b4),
            (0x4091d099fbfe301c, 0x4024e4cfe3bbe3c3),
            (0x40a7a0dd154adcb1, 0x402cec4f36a2f7d2),
            (0x40b5ee2ec2424fa1, 0x4031c5e72f8e32c5),
            (0x4092704477e226e8, 0x4025228490b41768),
            (0x40b7fab8f4f56965, 0x40324f681a808a5c),
            (0x40bab41ddf9ee3e7, 0x4032fa95b5f48219),
            (0x40c0ca6a2940e478, 0x40347c4849a77143),
            (0x40c1f8cc05136f1d, 0x4034f47af360b939),
            (0x40c08764239faed4, 0x403460e1d19d624f),
            (0x40ce37a6b321ddd5, 0x4038eaf22a7ff8ae),
            (0x40c2391acbf691dd, 0x40350d5bd7b9629e),
            (0x40c8e90cb0528ec4, 0x40375d38bc50969c),
            (0x40cecfc0d2dc2551, 0x4039147bc7c1c7c9),
            (0x40ca42475b5ed2bf, 0x4037c743946e3bbc),
            (0x40bd4b9cdc24946d, 0x403392f1bfa0e7fd),
            (0x40d56fd774635bf5, 0x403bffee58f11be8),
            (0x40c8ce3e99866c4e, 0x403754d4567c4e19),
            (0x40dc862e6508bf1e, 0x403ecbf49c4f1572),
            (0x40d20d391b8a5bdf, 0x403a70cf28f972bc),
            (0x40a7d62382083d64, 0x402d01fbcf11edd3),
            (0x40db1b5ccc98029f, 0x403e4727faf85688),
            (0x409d8bbd9db8e541, 0x4028bb568f59a182),
            (0x40e3c346288eb7a3, 0x40412ac4d0d34fad),
            (0x40ca1bce665e91b9, 0x4037bba10781763d),
            (0x40c84e6d817a0c78, 0x40372c7befc1cd81),
            (0x40a0253afeb7a5df, 0x402979a29cdcf7c8),
            (0x40ea5e7a26ac2aa0, 0x4042e635f8ead57a),
            (0x40e7bf18558a0a6a, 0x4042402e3388094b),
            (0x40f0559495889d6f, 0x40444c54a7fa7da9),
            (0x40b494ad79f7126a, 0x403166958f991c8d),
            (0x40cf22f29ff55bd4, 0x40392afa40a97b9a),
            (0x57daea1d17ddf421, 0x47e7f9821fc98bc3),
            (0x62f12e08710c8b94, 0x4b9a020926fe92c1),
            (0x32ea9f4a3641bce0, 0x3b97e335e0cda137),
            (0x0daa842c4130b474, 0x2f2e0e7340df79d5),
            (0x21bc0bbd864b1dbf, 0x35de9fa43f4038dc),
            (0x6cb175b16594f26c, 0x4eda260098c1ee17),
            (0x7188fc847a92198d, 0x5077634d4cdebf13),
            (0x0f339eda4f0c8817, 0x2fb12032926b595f),
            (0x644af926a4d4dfa0, 0x4c0e3a65b35ce833),
            (0x52f0b424e7090b87, 0x46447335aa0de0e3),
            (0x54168dd7c554e776, 0x46a69a5a74cfe626),
            (0x6480783902a61251, 0x4c2027b03cbdfe32),
            (0x26ae26aaf9182eb9, 0x3783c343ce42e25b),
            (0x4b4bbaca1ec48691, 0x43b836da9609ade8),
            (0x23810defd0716095, 0x3674979995d646f3),
            (0x16bb859c9deb0e5d, 0x32332bb79ee328bf),
            (0x78db9658647611e5, 0x52e82c3a44e6f879),
            (0x557f76891f2be860, 0x471fd1eb79d99c02),
            (0x781a741cf3983d0f, 0x52a7d644ec2b4dd7),
            (0x781b980cec569b5f, 0x52a82cb9c255133c),
        ];
        for &(x, want) in table {
            let got = cbrt(f64::from_bits(x)).to_bits();
            assert_eq!(
                got,
                want,
                "cbrt({}) = {:#x}, Go {:#x}",
                f64::from_bits(x),
                got,
                want
            );
        }
        assert_eq!(cbrt(-0.0).to_bits(), (-0.0f64).to_bits());
        assert!(cbrt(f64::NAN).is_nan() && cbrt(f64::INFINITY) == f64::INFINITY);
    }

    #[test]
    fn steady_rtt_keeps_slow_start() {
        let (mut n, i) = hs_net();
        let mut c = n.s.conn(i);
        let w = hs_rounds(&mut c, 6, |_| 50 * MS);
        assert!(
            !c.t.hs.css && c.t.ssthresh == u32::MAX && *w.last().unwrap() >= 10 << 5,
            "{w:?}"
        );
    }

    #[test]
    fn enters_css_and_exits_after_five_rounds() {
        let (mut n, i) = hs_net();
        let mut c = n.s.conn(i);
        // 3 往復目から RTT が 50 ms から 60 ms に増えます (閾値は 50 / 8 = 6.25 ms)。
        let w = hs_rounds(&mut c, 20, |r| if r >= 2 { 60 * MS } else { 50 * MS });
        let st = c.s.stats;
        assert!(
            st.hystart_css == 1 && st.hystart_exits == 1 && c.t.ssthresh != u32::MAX,
            "{w:?}"
        );
        // CSS の間は往復ごとに 1.25 倍ほどで、slow start の 2 倍より遅い。
        for k in 3..w.len() {
            assert!(
                f64::from(w[k]) / f64::from(w[k - 1]) <= 1.3,
                "round {k}: {w:?}"
            );
        }
        assert_eq!(c.t.ssthresh, c.t.cwnd);
    }

    #[test]
    fn leaves_css_when_rtt_falls() {
        let (mut n, i) = hs_net();
        let mut c = n.s.conn(i);
        let w = hs_rounds(
            &mut c,
            8,
            |r| if r == 2 || r == 3 { 60 * MS } else { 50 * MS },
        );
        let st = c.s.stats;
        assert!(
            st.hystart_css == 1 && !c.t.hs.css && st.hystart_exits == 0 && c.t.ssthresh == u32::MAX,
            "{w:?}"
        );
    }

    #[test]
    fn only_in_the_first_slow_start() {
        let (mut n, i) = hs_net();
        let mut c = n.s.conn(i);
        c.t.ssthresh = 1000 * c.seg_mss(); // 損失か RTO の後
        hs_rounds(&mut c, 6, |r| (50 + 20 * i64::try_from(r).unwrap()) * MS);
        assert!(c.s.stats.hystart_css == 0 && !c.t.hs.started);
    }
}
