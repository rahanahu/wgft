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

use super::ctx::Conn;
use super::{MS, ts_clock};
use crate::buf::{BOOST_SIZE, RECV_FLOOR};
use crate::wire::Segment;

/// 歩みの上限を広げる順序どおりの segment の中身の最小 (Linux の tcp_event_data_recv の 128) です。
pub(crate) const RCV_GROW_MIN: usize = 128;

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
        if copied > t.rs_space {
            // 目標は予約で抑えるので、これより大きな量は目標を変えません。
            let cp = copied.min(BOOST_SIZE);
            let mut win = 2 * cp + 16 * mss;
            win += 2 * (win * (cp - t.rs_space.min(cp)) / t.rs_space);
            t.rcv_want = t.rcv_want.max(win.min(BOOST_SIZE));
            t.rs_space = copied;
        }
        (t.rs_time, t.rs_seq) = (now, read_off);
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
