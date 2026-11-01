//! 接続の枠の入力 (Go の `tcpin.go`)。
//!
//! 接続の枠に当たった segment の受け入れの判定 (RFC 9293、RFC 7323 の PAWS、RFC 5961)、中身と FIN の受け入れ、
//! 枠に残る TIME_WAIT の接続の入力です。ACK の欄の処理は `ack` にあります。

use super::conn::{State, TMR_CLOSE, TMR_DELACK};
use super::ctx::{Conn, lo32};
use super::timewait::{Reuse, rfc6191};
use super::{DELACK_TIMEOUT, MS, PAWS_IDLE, RTX_PMTU, TW_TIMEOUT};
use crate::seq;
use crate::stack::shared::LogKind;
use crate::wire::{FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN, Segment};

impl Conn<'_> {
    /// RFC 9293 3.10.7.4 の segment の受け入れの判定です。窓が 0 のときは、番号が RCV.NXT と一致する segment を
    /// ACK と RST のために受け入れ、中身は後で窓の外として捨てます。
    fn acceptable(&self, seg: &Segment<'_>) -> bool {
        let wnd = self.rcv_window();
        let n = seg.seq_len();
        let nxt = self.t.rcv_nxt;
        let inside = |x: u32| seq::ge(x, nxt) && seq::lt(x, nxt.wrapping_add(wnd));
        if wnd == 0 {
            seg.seq == nxt
        } else if n == 0 {
            inside(seg.seq)
        } else {
            inside(seg.seq) || inside(seg.seq.wrapping_add(n - 1))
        }
    }

    /// 受け入れられない segment に ACK を返します。Linux の tcp_oow_rate_limited と同じく、中身のある segment
    /// には制限なく返し、中身の無い segment には接続ごとに 500 ms に 1 回まで返します。
    fn oow_ack(&mut self, seg: &Segment<'_>, now: i64) {
        if seg.payload.is_empty() || seg.has(FLAG_SYN) {
            if self.t.last_oow != 0 && now - self.t.last_oow < 500 * MS {
                return;
            }
            self.t.last_oow = now;
        }
        // RCV.NXT より前にある重複の部分は、範囲を D-SACK で知らせます (RFC 2883、Linux の tcp_dsack_set)。
        let n = u32::try_from(seg.payload.len()).unwrap_or(0);
        if n > 0 && !seg.has(FLAG_SYN) && seq::lt(seg.seq, self.t.rcv_nxt) {
            let end = seq::min(seg.seq.wrapping_add(n), self.t.rcv_nxt);
            self.note_duplicate(seg.seq, end.wrapping_sub(seg.seq));
        }
        self.t.ack_now = true;
    }

    /// RFC 5961 の challenge ACK を、核の全体の速さの制限の内側で送ります。
    pub(crate) fn challenge_ack(&mut self, now: i64) {
        if self.s.challenge_allowed(now) {
            self.t.ack_now = true;
        }
    }

    /// 接続の枠への segment を処理します。真を返したら、呼び手は segment をもう一度表から引きます (TIME_WAIT の
    /// 接続が RFC 6191 の SYN を受けて CLOSED になった)。そのとき `reuse` に前の接続の SND.NXT を書きます。
    pub(crate) fn input(&mut self, seg: &Segment<'_>, now: i64, reuse: &mut Option<u32>) -> bool {
        if self.t.state == State::TimeWait {
            let again = self.time_wait_input(seg, now, reuse);
            self.after_input(now);
            return again;
        }
        let ts_val = seg.opt.ts.map(|(v, _)| v);
        // PAWS (RFC 7323 5.3)。24 日を超えて TS.Recent を更新していなければ、相手の時計が一周しうるので TS.Recent
        // を古いとみなして比べません (RFC 7323 5.5)。
        if self.t.ts_ok
            && !seg.has(FLAG_RST)
            && ts_val.is_some_and(|v| seq::lt(v, self.t.ts_recent))
            && now - self.t.ts_recent_at <= PAWS_IDLE
        {
            self.oow_ack(seg, now);
            self.after_input(now);
            return false;
        }
        if !self.acceptable(seg) {
            if !seg.has(FLAG_RST) {
                if seg.has(FLAG_SYN) {
                    self.challenge_ack(now);
                } else {
                    self.oow_ack(seg, now);
                }
            }
            self.after_input(now);
            return false;
        }
        // RST (RFC 5961 3.2)
        if seg.has(FLAG_RST) {
            if seg.seq == self.t.rcv_nxt {
                self.reset_by_peer();
                return false;
            }
            self.challenge_ack(now);
            self.after_input(now);
            return false;
        }
        // 確立した後の SYN (RFC 5961 4.2)
        if seg.has(FLAG_SYN) {
            self.challenge_ack(now);
            self.after_input(now);
            return false;
        }
        if !seg.has(FLAG_ACK) {
            return false;
        }
        // ACK の受け入れの範囲 (RFC 5961 5.2)
        let t = &*self.t;
        if seq::gt(seg.ack, t.snd_max) || seq::lt(seg.ack, t.snd_una.wrapping_sub(t.max_snd_wnd)) {
            self.challenge_ack(now);
            self.after_input(now);
            return false;
        }
        // TS.Recent の更新 (RFC 7323 4.3)
        if self.t.ts_ok
            && let Some(v) = ts_val
            && seq::le(seg.seq, self.t.last_ack_sent)
        {
            (self.t.ts_recent, self.t.ts_recent_at) = (v, now);
        }
        self.process_ack(seg, now);
        if matches!(self.t.state, State::Free | State::Closed) {
            return false;
        }
        self.input_data(seg, now);
        self.after_input(now);
        false
    }

    /// 枠に残る TIME_WAIT の接続への segment を処理します。
    fn time_wait_input(&mut self, seg: &Segment<'_>, now: i64, reuse: &mut Option<u32>) -> bool {
        if seg.has(FLAG_RST) {
            if seg.seq == self.t.rcv_nxt {
                self.enter_closed(None);
            }
            return false;
        }
        if seg.has(FLAG_SYN) {
            if !seg.has(FLAG_ACK) && rfc6191(seg, self.t.ts_ok, self.t.ts_recent, self.t.rcv_nxt) {
                match self.s.reuse_verdict(seg) {
                    Reuse::NoListener => {
                        self.challenge_ack(now); // Linux と同じく TIME_WAIT の ACK を返します
                        return false;
                    }
                    Reuse::Full => {
                        self.s.refused(LogKind::SynFull, now);
                        return false; // 枠の TIME_WAIT を保ち、相手の SYN の再送を待ちます
                    }
                    Reuse::Ok => {}
                }
                // 接続は CLOSED になり、アプリケーションはそれまでのデータと EOF を読めます。
                *reuse = Some(self.t.snd_max);
                self.enter_closed(None);
                return true;
            }
            self.challenge_ack(now);
            return false;
        }
        let n = u32::try_from(seg.payload.len()).unwrap_or(0);
        if seg.has(FLAG_FIN) && seg.seq.wrapping_add(n).wrapping_add(1) == self.t.rcv_nxt {
            self.t.ack_now = true;
            self.t.tw_enter = now;
            self.arm(TMR_CLOSE, now + TW_TIMEOUT);
            return false;
        }
        if seg.seq_len() > 0 || seg.seq != self.t.rcv_nxt {
            self.oow_ack(seg, now);
        }
        false
    }

    /// segment の中身と FIN を受信のバッファに入れ、ACK の送り方を決めます。
    pub(crate) fn input_data(&mut self, seg: &Segment<'_>, now: i64) {
        let n = seg.payload.len();
        if n == 0 && !seg.has(FLAG_FIN) {
            return;
        }
        match self.t.state {
            State::Established | State::FinWait1 | State::FinWait2 => {}
            _ => {
                // 相手の FIN の後に届いた segment。重複なら ACK を返します。
                if seg.seq_len() > 0 {
                    self.t.ack_now = true;
                }
                return;
            }
        }
        let n32 = u32::try_from(n).unwrap_or(u32::MAX);
        if self.t.app_closed && n > 0 && seq::gt(seg.seq.wrapping_add(n32), self.t.rcv_nxt) {
            // 閉じた後に届いたデータ。Linux と同じく RST で終えます。
            self.send_rst();
            self.release();
            return;
        }
        let base = self.t.irs.wrapping_add(1);
        let nxt = self.b.rcv.nxt_off;
        #[expect(
            clippy::cast_possible_wrap,
            reason = "Go's int32 conversion of the sequence difference"
        )]
        let delta = seg.seq.wrapping_sub(base.wrapping_add(lo32(nxt))) as i32;
        let Ok(off) = u64::try_from(i64::try_from(nxt).unwrap_or(i64::MAX) + i64::from(delta))
        else {
            return;
        };
        let limit = self.t.adv_right.min(self.b.rcv.read_off + self.t.rcv_cap);
        let res = self
            .b
            .rcv
            .insert(off, seg.payload, limit, &mut self.s.chunks);
        if res.no_memory {
            // chunk を確保できなければ、segment を状態を変えずに捨てます。相手は再送します。
            self.s.stats.recv_no_memory += 1;
            return;
        }
        if res.dup_hi > res.dup_lo {
            let dlo = base.wrapping_add(lo32(res.dup_lo));
            self.note_duplicate(dlo, lo32(res.dup_hi - res.dup_lo));
        }
        if res.dropped {
            self.s.refused(LogKind::OooDropped, now);
        }
        if res.trimmed {
            self.s.stats.recv_trimmed += 1;
        }
        if res.accepted > 0 {
            self.signal_read();
            self.rcv_grow(res.accepted, res.ooo);
            self.rcv_rtt_stamp(seg, n, now);
            self.rcv_rtt_window(now);
        }
        if seg.has(FLAG_FIN) && !res.trimmed && !res.dropped {
            let fin_off = off + n as u64;
            if fin_off == self.b.rcv.nxt_off {
                self.fin_recv(now);
            } else if fin_off > self.b.rcv.nxt_off {
                (self.t.ooo_fin, self.t.ooo_fin_off) = (true, fin_off);
            }
        }
        if self.t.ooo_fin && !self.t.fin_rcvd && self.b.rcv.nxt_off == self.t.ooo_fin_off {
            self.fin_recv(now);
        }
        if !self.t.fin_rcvd {
            self.t.rcv_nxt = base.wrapping_add(lo32(self.b.rcv.nxt_off));
        }
        if res.ooo
            || res.dropped
            || res.trimmed
            || res.duplicate
            || res.filled
            || self.b.rcv.intervals_len() > 0
        {
            self.t.ack_now = true;
        } else if res.advanced {
            self.t.rcv_since_ack += i64::try_from(res.accepted).unwrap_or(i64::MAX);
            self.measure_rcv_mss(n);
            self.note_quickack(now);
            // 推定した相手の MSS より多くの byte を確認していなければ ACK を遅らせます (Linux の
            // __tcp_ack_snd_check)。
            let t = &*self.t;
            if t.rcv_since_ack > i64::from(t.rcv_mss_est) || (t.quick_acks > 0 && !t.pingpong) {
                self.t.ack_now = true;
            } else if self.t.tdl[TMR_DELACK] == 0 {
                self.arm(TMR_DELACK, now + DELACK_TIMEOUT);
            }
        }
        if res.accepted > 0 {
            (self.t.last_data_rcvd, self.t.rcvd_data) = (now, true);
        }
    }

    /// 相手の FIN を順序どおりに受けた後の遷移を行います。
    fn fin_recv(&mut self, now: i64) {
        self.t.fin_rcvd = true;
        self.t.ooo_fin = false;
        self.t.rcv_nxt = self
            .t
            .irs
            .wrapping_add(1)
            .wrapping_add(lo32(self.b.rcv.nxt_off))
            .wrapping_add(1);
        self.t.ack_now = true;
        match self.t.state {
            State::Established => self.t.state = State::CloseWait,
            State::FinWait1 => {
                if self.fin_acked() {
                    self.enter_time_wait(now);
                } else {
                    self.t.state = State::Closing;
                }
            }
            State::FinWait2 => self.enter_time_wait(now),
            _ => {}
        }
        self.signal_read();
    }

    pub(crate) fn enter_time_wait(&mut self, now: i64) {
        self.t.state = State::TimeWait;
        self.t.tw_enter = now;
        self.t.persist = false;
        self.clear_retrans_timers();
        // TIME_WAIT の接続は ACK だけを送ります。送り残しの probe と再送の印を残すと、build が何も作らないのに
        // want_output が送るものがあると答え続けます。
        self.cancel_sends();
        self.arm(TMR_CLOSE, now + TW_TIMEOUT);
    }

    /// Fragmentation Needed による PMTU の引き下げです (RFC 1191)。引用された番号が SND.UNA から SND.NXT の範囲に
    /// あるときだけ受け入れます (RFC 5927)。送り残しは小さな segment で送り直します。SND.NXT は再送で戻さないので、
    /// いつも SND.MAX と等しくなります。
    pub(crate) fn pmtu_drop(&mut self, seq: u32, mtu: u32, now: i64) {
        if !seq::ge(seq, self.t.snd_una) || !seq::lt(seq, self.t.snd_nxt) {
            self.s.stats.icmp_dropped += 1;
            return;
        }
        if mtu >= self.t.pmtu {
            return;
        }
        self.t.pmtu = mtu;
        if self.t.snd_max != self.t.snd_una {
            // 記録の境目は保ち、新しい大きさに入らない記録だけを損失にして送り直します (Linux の
            // tcp_simple_retransmit と同じです)。入る記録は届いているかもしれないので、損失の印を付けません。
            // SACK の無い接続は記録の印を使わないので、今までどおり SND.UNA から送り直します。
            self.t.fast_rtx = false;
            if self.t.sack_ok {
                let payload = self.seg_mss();
                self.mark_lost_longer(payload, RTX_PMTU);
                self.advance_loss(); // 小さくなった MSS で DupThresh の byte の規則を数え直します
            } else {
                self.mark_all_lost(RTX_PMTU);
            }
        }
        self.after_input(now);
    }
}
