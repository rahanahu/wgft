//! 接続の枠のタイマーの期限 (Go の `timers.go` と `rack.go` のタイマーの部分)。
//!
//! 再送、窓の probe、遅延 ACK、閉じた後の期限を処理します。再送のタイマーの節は RTO、並べ替え、TLP の期限が
//! 分け合い、最も早い期限を張ります。並べ替えと TLP の期限は SACK の段 (PR 5) が張ります。

use super::conn::{ConnError, State, TMR_CLOSE, TMR_DELACK, TMR_RETRANS};
use super::ctx::Conn;
use super::sack::DUP_THRESH;
use super::{ORPHAN_RETRIES, PROBE_RETRIES, RETRANSMIT_DEADLINE, RTO_MAX, RTX_RTO};

impl Conn<'_> {
    /// 今の後退を含めた RTO です。
    pub(crate) fn cur_rto(&self) -> i64 {
        let mut r = self.t.rto;
        for _ in 0..self.t.backoff {
            r *= 2;
            if r >= RTO_MAX {
                return RTO_MAX;
            }
        }
        r
    }

    /// 再送のタイマーの節を窓の probe に使い始めます。確認を待つものが無いので、前の RTO の起点と後退を持ち越し
    /// ません。持ち越すと、相手が probe に応え続けた長い persist の後の最初の RTO で、再送の打ち切りの時間を過ぎた
    /// と数えます。
    pub(crate) fn enter_persist(&mut self, now: i64) {
        self.clear_retrans_timers();
        self.cancel_tlp();
        self.t.persist = true;
        self.t.retrans_start = 0;
        self.t.backoff = 0;
        let at = now + self.cur_rto();
        self.arm(TMR_RETRANS, at);
    }

    /// 窓の probe を終え、確認を待つデータがあれば RTO を今から張ります。再送のタイマーの節の古い期限を消すかは
    /// 呼び手が決めます。
    pub(crate) fn leave_persist(&mut self, now: i64) {
        self.t.persist = false;
        self.t.backoff = 0;
        if self.t.snd_una != self.t.snd_max {
            let at = now + self.cur_rto();
            self.set_rto(at);
        }
    }

    /// タイマーの節 `kind` の期限を処理します。
    pub(crate) fn on_timer(&mut self, kind: usize, now: i64) {
        match kind {
            TMR_RETRANS => {
                if self.t.persist {
                    self.on_persist(now);
                } else {
                    self.on_retrans_timer(now);
                }
            }
            TMR_DELACK => {
                let t = &mut *self.t;
                if !t.ack_now {
                    t.ack_delayed = true;
                }
                t.ack_now = true;
                t.pingpong = false; // Linux の tcp_delack_timer_handler と同じく対話の印を外します
            }
            TMR_CLOSE => {
                if matches!(self.t.state, State::TimeWait | State::FinWait2) {
                    self.enter_closed(None);
                }
            }
            _ => {}
        }
        self.after_input(now);
    }

    /// 再送のタイマーの期限です (RFC 6298 5.4 から 5.7、RFC 5681 3.1)。
    fn on_rto(&mut self, now: i64) {
        if self.t.snd_una == self.t.snd_max || self.t.state == State::Closed {
            return;
        }
        if self.t.retrans_start == 0 {
            self.t.retrans_start = now - self.cur_rto();
        }
        if now - self.t.retrans_start >= RETRANSMIT_DEADLINE {
            self.s.stats.retransmit_aborts += 1;
            self.send_rst();
            self.abort_with(ConnError::TimedOut);
            return;
        }
        let st = &mut self.s.stats;
        let t = &*self.t;
        st.rtos += 1;
        if t.backoff > 0 {
            st.rtos_backed_off += 1;
        }
        if !t.in_recovery && t.dup_acks > 0 && t.dup_acks < DUP_THRESH {
            st.rtos_short_of_dup_thresh += 1;
        }
        // SACK の取り消しは SACK の段 (PR 5) が足します。
        let mss = self.seg_mss();
        let frto = self.frto_eligible();
        if self.t.backoff == 0 {
            // 最初の RTO が輻輳の事象として ssthresh を下げます。続く RTO は ssthresh を下げ直さず、F-RTO を終えます。
            if !self.t.in_recovery {
                self.init_undo();
            }
            self.t.ssthresh = self.loss_thresh();
        } else {
            self.t.frto = 0;
        }
        self.t.fast_rtx = false; // RTO の規則が SND.UNA から送り直すので、待っている高速の再送で先頭を 2 度送りません
        self.cc_on_rto();
        let t = &mut *self.t;
        t.cwnd = mss;
        t.recover = t.snd_max;
        t.in_recovery = false;
        t.dup_acks = 0;
        t.backoff += 1;
        // 記録は消さずに残し、SACK 済みでない記録を損失にして SND.UNA から順に送り直します (RFC 6675 5.1 節)。
        // F-RTO では先頭の記録だけを損失にして、次の ACK で RTO が不要だったかを決めます (RFC 5682)。
        t.rto_episode = true;
        if frto {
            self.t.frto = 1;
            self.mark_head_lost(RTX_RTO);
        } else {
            self.mark_all_lost(RTX_RTO);
        }
        (self.t.reo_at, self.t.tlp_at) = (0, 0);
        self.cancel_tlp();
        let at = now + self.cur_rto();
        self.set_rto(at);
    }

    /// 窓の probe のタイマーの期限です。相手が probe に応える間は打ち切りません。
    fn on_persist(&mut self, now: i64) {
        if self.t.snd_wnd != 0 || !self.has_unsent() {
            self.leave_persist(now);
            return;
        }
        self.t.probes_out += 1;
        // アプリケーションが閉じた接続は、Linux の tcp_probe_timer と同じく、相手が応えても戻らない後退の回数が
        // orphan の上限以上で、後退を含めた RTO が上限に届いたときに打ち切ります。
        if self.t.probes_out > PROBE_RETRIES
            || (self.t.app_closed && self.t.backoff >= ORPHAN_RETRIES && self.cur_rto() >= RTO_MAX)
        {
            self.s.stats.probe_aborts += 1;
            self.send_rst();
            self.abort_with(ConnError::TimedOut);
            return;
        }
        self.t.probe_pending = true;
        self.t.backoff += 1;
        let at = now + self.cur_rto();
        self.arm(TMR_RETRANS, at);
    }

    /// 送る前の TLP の probe と、確認を待つ probe の印を消します。PTO の期限は消しません。
    pub(crate) fn cancel_tlp(&mut self) {
        let t = &mut *self.t;
        (t.tlp_probe, t.tlp_active, t.tlp_retrans) = (false, false, false);
    }

    /// PTO の期限を決めます。新しいデータを送った後と、累積の確認が進んだ後に呼びます。TLP は SACK を交渉した
    /// 接続だけで使い、SACK の段 (PR 5) が足します。
    pub(crate) fn schedule_tlp(&mut self, _now: i64) {
        self.t.tlp_at = 0;
    }

    /// RTO の期限を `at` にします。0 なら RTO の期限を消します。
    pub(crate) fn set_rto(&mut self, at: i64) {
        self.t.rto_at = at;
        self.rearm_retrans();
    }

    /// RTO、並べ替え、TLP の期限をすべて消します。
    pub(crate) fn clear_retrans_timers(&mut self) {
        let t = &mut *self.t;
        (t.rto_at, t.reo_at, t.tlp_at) = (0, 0, 0);
        self.disarm(TMR_RETRANS);
    }

    /// 再送のタイマーの節に、RTO、並べ替え、TLP の期限のうち最も早いものを張ります。窓の probe の間は窓の probe
    /// が節を使います。
    pub(crate) fn rearm_retrans(&mut self) {
        if self.t.persist {
            return;
        }
        let t = &*self.t;
        let at = [t.rto_at, t.reo_at, t.tlp_at]
            .into_iter()
            .filter(|&d| d != 0)
            .min()
            .unwrap_or(0);
        if at == 0 {
            self.disarm(TMR_RETRANS);
        } else if at != self.t.tdl[TMR_RETRANS] {
            self.arm(TMR_RETRANS, at);
        }
    }

    /// 再送のタイマーの節の期限です。期限の来た種類を 1 つ処理し、残る期限を張り直します。並べ替えと TLP の期限は
    /// SACK の段 (PR 5) が足します。
    fn on_retrans_timer(&mut self, now: i64) {
        if self.t.rto_at != 0 && now >= self.t.rto_at {
            self.t.rto_at = 0;
            self.on_rto(now);
        }
        self.rearm_retrans();
    }
}
