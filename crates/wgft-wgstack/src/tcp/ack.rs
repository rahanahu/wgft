//! 接続の枠の ACK の欄の処理と RTT (Go の `ack.go`、RFC 9293、RFC 5681、RFC 6582、RFC 6298)。

use super::conn::State;
use super::ctx::{Conn, u32_of};
use super::sack::DUP_THRESH;
use super::{MS, RTO_MAX, RTO_MIN, RTX_FAST, RTX_PARTIAL, ts_clock};
use crate::buf::records::REC_RETRANSMITTED;
use crate::seq;
use crate::stack::ns;
use crate::wire::{FLAG_FIN, Segment};

impl Conn<'_> {
    /// RTT の測定値 `r` (ns) で SRTT、RTTVAR、RTO を更新します (RFC 6298 2 節)。
    pub(crate) fn rtt_sample(&mut self, r: i64) {
        if r < 0 {
            return;
        }
        let t = &mut *self.t;
        t.tlp_sampled = true;
        if t.has_rtt {
            let d = (t.srtt - r).abs();
            t.rttvar = (3 * t.rttvar + d) / 4;
            t.srtt = (7 * t.srtt + r) / 8;
        } else {
            (t.srtt, t.rttvar, t.has_rtt) = (r, r / 2, true);
        }
        if !t.has_min_rtt || r < t.min_rtt {
            (t.min_rtt, t.has_min_rtt) = (r, true);
        }
        // 下限は RTO 全体ではなく RTTVAR の項に掛けます (Linux と同じ)。
        t.rto = (t.srtt + (4 * t.rttvar).max(RTO_MIN)).min(RTO_MAX);
    }

    /// 相手が返した自分の TSval (TSecr) から RTT を測ります (RFC 7323 4.1)。自分の今の TSval より先の TSecr は、
    /// 自分が送っていない値なので使いません。測った値を返し、測らなければ -1 を返します。
    pub(crate) fn ts_rtt_sample(&mut self, ts_ecr: u32, now: i64) -> i64 {
        #[expect(
            clippy::cast_possible_wrap,
            reason = "Go's int32 conversion of the timestamp difference"
        )]
        let d = ts_clock(now)
            .wrapping_add(self.t.ts_offset)
            .wrapping_sub(ts_ecr) as i32;
        if d < 0 {
            return -1;
        }
        let r = i64::from(d) * MS;
        self.rtt_sample(r);
        r
    }

    /// ACK の欄を処理します (RFC 9293、RFC 5681、RFC 6582、RFC 6675、RFC 8985)。
    pub(crate) fn process_ack(&mut self, seg: &Segment<'_>, now: i64) {
        let ack = seg.ack;
        if self.hystart_on() {
            // この ACK の前の SND.NXT です (Go の lazyegress.go)。
            self.t.hs.snd_nxt = self.sendable_end();
            self.t.hs.snd_nxt_ok = true;
        }
        self.t.probes_out = 0;
        if self.t.persist {
            self.t.retrans_start = 0; // 相手は probe に応えています
        }
        let wnd_changed = self.update_send_window(seg);
        // RFC 6937 の DeliveredData は SND.UNA の差と SACK 済みの byte の差の和です。累積の確認が先に SACK した
        // byte を覆うと SACK 済みの byte は減るので、差は確認の前の値から取ります。
        let mut delivered: i64 = 0;
        let sacked_before = self.t.sacked;
        self.t.orig_delivered = false;
        let advanced = seq::gt(ack, self.t.snd_una);
        (self.t.prior_una, self.t.prior_cwnd) = (self.t.snd_una, self.t.cwnd);
        if advanced {
            delivered = i64::from(ack.wrapping_sub(self.t.snd_una));
            self.new_ack(seg, ack, now);
        } else if ack == self.t.snd_una
            && seg.payload.is_empty()
            && !seg.has(FLAG_FIN)
            && !wnd_changed
            && self.t.snd_max != self.t.snd_una
        {
            self.dup_ack();
        }
        if matches!(self.t.state, State::Free | State::Closed) {
            return;
        }
        let newly = self.mark_sack(seg, now);
        delivered += i64::from(self.t.sacked) - i64::from(sacked_before);
        if self.t.sack_ok {
            self.rack_detect(now);
            if self.t.frto != 0 && seq::lt(self.t.snd_una, self.t.recover) {
                let dup = newly > 0 || (!advanced && self.t.snd_una != self.t.snd_max);
                self.frto_after_ack(seg, advanced, dup);
            } else if self.t.rto_episode && seq::ge(self.t.snd_una, self.t.recover) {
                self.rto_recovered(seg);
            }
            self.tlp_on_ack(ack, advanced, newly);
            self.sack_after_ack(u32_of(delivered.max(0)));
            if advanced {
                self.schedule_tlp(now);
            } else if self.t.in_recovery {
                self.t.tlp_at = 0;
            }
            self.rearm_retrans();
        } else if self.t.rto_episode && seq::ge(self.t.snd_una, self.t.recover) {
            // SACK を交渉しない接続の RTO の後の回復の終わり。SND.UNA が recover から 2^31 先へ進んだ後に、番号の
            // 比べで回復の中に戻ったとみなさないように、印を消します。
            self.t.rto_episode = false;
        }
        if advanced {
            self.note_drained_with_data(now);
        }
        if self.t.snd_wnd > 0 && self.t.persist {
            self.clear_retrans_timers();
            self.leave_persist(now);
        }
    }

    /// segment が SND.WL1 と SND.WL2 より新しければ相手の窓を更新します (RFC 9293 3.10.7.4)。窓の大きさが
    /// 変わったかを返します。
    fn update_send_window(&mut self, seg: &Segment<'_>) -> bool {
        let t = &mut *self.t;
        if !(seq::lt(t.snd_wl1, seg.seq) || (t.snd_wl1 == seg.seq && seq::le(t.snd_wl2, seg.ack))) {
            return false;
        }
        let w = u32::from(seg.wnd) << t.snd_wscale;
        let changed = w != t.snd_wnd;
        (t.snd_wnd, t.snd_wl1, t.snd_wl2) = (w, seg.seq, seg.ack);
        t.max_snd_wnd = t.max_snd_wnd.max(w);
        changed
    }

    /// 累積の確認を進める ACK を処理します。確認された byte と記録を外し、RTT を測り、輻輳の窓、再送の
    /// タイマー、自分の FIN の確認による状態の順に進めます。
    fn new_ack(&mut self, seg: &Segment<'_>, ack: u32, now: i64) {
        let acked = ack.wrapping_sub(self.t.snd_una);
        let (sample, rtx_acked) = self.retire_acked(ack, now);
        self.t.snd_una = ack;
        if self.t.tlp_cut && seq::ge(ack, self.t.tlp_cut_seq) {
            // 縮小が覆う窓のデータはすべて確認されました。番号が 1 周した後に古い番号と比べません。
            self.t.tlp_cut = false;
        }
        if seq::lt(self.t.snd_nxt, ack) {
            self.t.snd_nxt = ack;
        }
        let ack_rtt = self.rtt_on_ack(seg, sample, rtx_acked, now);
        self.t.backoff = 0;
        self.t.retrans_start = 0;
        self.cwnd_on_ack(seg, ack, acked, ack_rtt, now);
        self.t.dup_acks = 0;
        self.retrans_timer_on_ack(now);
        self.fin_acked_state(now);
        self.signal_write();
    }

    /// SND.UNA から `ack` までに確認された byte を送信の輪から外し、確認された記録を外します。FIN の 1 は byte に
    /// 数えません。最後に外した再送していない記録の RTT の標本 (無ければ -1) と、再送した記録を 1 つでも確認した
    /// かを返します (Karn)。欄の更新は記録を外す前に古い SND.UNA で行うので、SND.UNA を進める前に呼びます。
    fn retire_acked(&mut self, ack: u32, now: i64) -> (i64, bool) {
        let acked = ack.wrapping_sub(self.t.snd_una);
        let data_acked = u64::from(acked).min(self.t.tail_off - self.t.una_off);
        let old = self.t.una_off;
        self.t.una_off += data_acked;
        let (lo, hi) = (self.t.una_off, self.t.tail_off);
        self.b.snd.trim(old, lo, hi, &mut self.s.chunks);
        let mut sample = -1;
        let mut rtx_acked = false;
        while self.b.recs.len() > 0 {
            let r = *self.b.recs.at(0);
            let end = r.seq.wrapping_add(u32::from(r.length));
            if seq::gt(end, ack) {
                if seq::lt(r.seq, ack) {
                    self.trim_head(ack.wrapping_sub(r.seq));
                }
                break;
            }
            if r.flags & REC_RETRANSMITTED == 0 {
                sample = now - ns(r.sent_at);
            } else {
                rtx_acked = true;
            }
            self.drop_head(now);
            self.b.recs.pop();
            self.t.rec_base = self.t.rec_base.wrapping_add(1);
        }
        (sample, rtx_acked)
    }

    /// ACK で RTT を測り、この ACK で測った RTT を返します (HyStart++ が使います。測らなければ -1)。timestamp が
    /// あればその TSecr で、無ければ `retire_acked` の標本で測ります。再送した記録を確認した ACK の標本は使いません。
    fn rtt_on_ack(&mut self, seg: &Segment<'_>, sample: i64, rtx_acked: bool, now: i64) -> i64 {
        if self.t.ts_ok
            && let Some((_, ecr)) = seg.opt.ts
            && ecr != 0
        {
            return self.ts_rtt_sample(ecr, now);
        }
        if sample >= 0 && !rtx_acked {
            self.rtt_sample(sample);
            return sample;
        }
        -1
    }

    /// 累積の確認で輻輳の窓を進めます。回復の中では回復の終わりか部分の確認を処理し、回復の外では slow start か
    /// 輻輳の回避で窓を増やします。SND.UNA を `ack` に進めた後に呼びます。
    fn cwnd_on_ack(&mut self, seg: &Segment<'_>, ack: u32, acked: u32, ack_rtt: i64, now: i64) {
        let mss = self.seg_mss();
        let flight = self.t.snd_max.wrapping_sub(self.t.snd_una);
        if self.t.in_recovery {
            if seq::ge(ack, self.t.recover) {
                // 回復の終わり。SACK では RFC 6937 の cwnd = ssthresh、SACK が無ければ RFC 6582 3.2 の 3 です。
                self.t.in_recovery = false;
                self.rack_recovery_done();
                let t = &mut *self.t;
                t.cwnd = if t.sack_ok {
                    t.ssthresh
                } else {
                    t.ssthresh.min(flight.max(mss) + mss)
                };
                if self.may_undo(seg) {
                    self.undo(); // 回復の再送は不要でした (Linux の tcp_try_undo_recovery)
                }
                self.k.undo_marker = false;
            } else if self.t.sack_ok {
                // SACK による回復の部分の確認。再送は NextSeg が選び、窓は PRR が決めます。
                self.s.stats.partial_acks += 1;
            } else {
                // 部分の確認 (RFC 6582 3.2 の 5):次の穴を再送し、確認された分だけ窓を縮め、1 SMSS 以上を確認したら
                // SMSS を足し戻します。
                let t = &mut *self.t;
                t.fast_rtx = true;
                t.rtx_cause = RTX_PARTIAL;
                self.s.stats.partial_acks += 1;
                t.cwnd -= t.cwnd.min(acked);
                if acked >= mss {
                    t.cwnd += mss;
                }
                t.cwnd = t.cwnd.max(mss);
            }
        } else if !self.is_cwnd_limited() {
            // アプリケーションに制限された間は窓を増やしません (RFC 7661、Linux の tcp_is_cwnd_limited)。
        } else if self.t.cwnd < self.t.ssthresh {
            self.slow_start_ack(ack, acked, ack_rtt);
        } else {
            self.cong_avoid(acked, now);
        }
        self.t.cwnd = self.t.cwnd.min(1 << 30);
    }

    /// 累積の確認の後に再送のタイマーを張り直します (RFC 6298 5.2、5.3)。窓の probe の間は張り直しません。
    fn retrans_timer_on_ack(&mut self, now: i64) {
        if self.t.persist {
            return;
        }
        if self.t.snd_una == self.t.snd_max {
            self.clear_retrans_timers();
        } else {
            let at = now + self.cur_rto();
            self.set_rto(at);
            self.renege_timer(now);
        }
    }

    /// 自分の FIN が確認されたときの状態の遷移を行います。
    fn fin_acked_state(&mut self, now: i64) {
        if !self.fin_acked() {
            return;
        }
        match self.t.state {
            State::FinWait1 => self.t.state = State::FinWait2,
            State::Closing => self.enter_time_wait(now),
            State::LastAck => self.enter_closed(None),
            _ => {}
        }
    }

    /// 重複した ACK を処理します (RFC 5681 3.2、RFC 6582)。
    fn dup_ack(&mut self) {
        self.s.stats.dup_acks_in += 1;
        self.t.dup_acks += 1;
        if self.t.sack_ok {
            return; // 回復に入るかは sack_after_ack が決めます
        }
        let mss = self.seg_mss();
        if self.t.in_recovery {
            self.t.cwnd = self.t.cwnd.wrapping_add(mss);
            return;
        }
        if self.t.dup_acks == DUP_THRESH && seq::gt(self.t.snd_una, self.t.recover) {
            self.enter_fast_recovery();
            let t = &mut *self.t;
            t.cwnd = t.ssthresh.wrapping_add(3 * mss);
            t.fast_rtx = true;
            t.rtx_cause = RTX_FAST;
        }
    }
}
