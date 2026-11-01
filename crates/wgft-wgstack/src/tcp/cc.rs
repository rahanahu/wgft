//! 輻輳の制御 (Go の `cc.go`、`hystart.go`、`cwndval.go`、`lazyegress.go`)。
//!
//! slow start、回復の間の窓、RTO の後の 1 segment は共通の処理が持ち、輻輳の回避の窓の増やし方と、輻輳の事象での
//! ssthresh の決め方だけが輻輳の制御ごとに違います。この段は NewReno (RFC 5681 の輻輳の回避と RFC 6582) を持ち、
//! CUBIC は SACK の段 (PR 5) が足します。HyStart++ は輻輳の制御の種類によらず最初の slow start で働くので、
//! NewReno の接続の記録と同じ出力のためにこの段に入れます。

use super::MS;
use super::ctx::Conn;
use crate::seq;

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
    started: bool,
    css: bool,
    /// 処理中の ACK の前に、ACK のたびに送る送り手なら送り終えていた番号 (`sendable_end`) です。
    pub(crate) snd_nxt_ok: bool,
    pub(crate) snd_nxt: u32,
    /// この往復の終わりの番号 (往復を始めた時の SND.NXT) です。
    window_end: u32,
    last_round_min: i64,
    cur_round_min: i64,
    samples: i64,
    css_baseline: i64,
    css_rounds: i64,
}

impl Conn<'_> {
    /// NewReno の輻輳の回避です。回復の外で cwnd >= ssthresh の間に `acked` byte を確認した ACK で窓を増やします。
    pub(crate) fn cong_avoid(&mut self, acked: u32) {
        let mss = self.seg_mss();
        let t = &mut *self.t;
        t.ca_acc = t.ca_acc.wrapping_add(acked);
        if t.ca_acc >= t.cwnd {
            t.ca_acc -= t.cwnd;
            t.cwnd = t.cwnd.wrapping_add(mss);
        }
    }

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

    /// 今の状態で起きた輻輳の事象の新しい ssthresh です (NewReno:max(base/2, 2 MSS))。
    pub(crate) fn loss_thresh(&self) -> u32 {
        (self.loss_base() / 2).max(2 * self.seg_mss())
    }

    /// RTO の後の状態を整えます。ssthresh は呼び手が `loss_thresh` で決めます。
    pub(crate) fn cc_on_rto(&mut self) {
        self.t.ca_acc = 0;
    }

    /// 高速の回復に入り、輻輳の事象として ssthresh を下げ、回復の終わりを SND.MAX にします。窓を下げる前に取り消しの
    /// 印を付けます。TLP の縮小と同じ輻輳の事象を数えない規則は、TLP を足す段 (PR 5) が足します。
    pub(crate) fn enter_fast_recovery(&mut self) {
        self.init_undo();
        self.t.ssthresh = self.loss_thresh();
        self.t.recover = self.t.snd_max;
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
