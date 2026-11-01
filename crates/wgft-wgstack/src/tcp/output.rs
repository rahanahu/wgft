//! 接続の枠の出力 (Go の `tcpout.go`)。
//!
//! 接続は packet を待ち行列に積まず、`poll_transmit` の時に今の状態から segment を 1 つ作ります
//! (wgstack.md の「出力」)。再送は送信の輪から segment を作り直します。

use super::conn::{ConnError, State, TMR_DELACK};
use super::ctx::{Conn, u32_of};
use super::rack::Which;
use super::sack::{Pick, Src};
use super::{DELACK_TIMEOUT, INITIAL_WINDOW_SEGS, IP_TCP_HEADERS, ts_clock};
use crate::buf::records::{REC_IN_T, REC_RETRANSMITTED, REC_RTX, Record};
use crate::seq;
use crate::stack::shared::LogKind;
use crate::stack::time;
use crate::wire::{
    self, FLAG_ACK, FLAG_FIN, FLAG_PSH, IP_HEADER_LEN, MAX_OPTION_LEN, OptWriter, TCP_HEADER_LEN,
    TcpHeader,
};

impl Conn<'_> {
    /// 接続の組から取り出した枠の segment を 1 つ作ります。まだ送るものがあれば list の末尾に入れ直します。
    pub(crate) fn poll(&mut self, b: &mut [u8], now: i64) -> usize {
        if matches!(self.t.state, State::Free | State::Closed) {
            return 0;
        }
        let n = self.build(b, now);
        // 何も作らなかった項目は入れ直しません。入れ直すと poll_transmit が同じ項目を回り続けます。送るものが
        // 後でできれば、入力、タイマー、書き込みが入れ直します。
        if n > 0 && self.want_output() {
            self.s.queue_conn(self.id);
        }
        n
    }

    /// 今送るものがあるかを返します。
    pub(crate) fn want_output(&mut self) -> bool {
        match self.t.state {
            State::Free | State::Closed => return false,
            // TIME_WAIT の接続は ACK だけを送ります (build と同じ)。
            State::TimeWait => return self.t.ack_now,
            _ => {}
        }
        if self.t.fast_rtx || self.t.probe_pending || self.t.ack_now || self.t.tlp_probe {
            return true;
        }
        let o = self.options(0);
        let pc = self.payload_cap(&o, i64::from(self.t.pmtu));
        if let Some(p) = self.pick_rule1()
            && self.resend_allowed(p, pc)
        {
            return true;
        }
        let (n, fin) = self.next_new(pc, false);
        if n > 0 || fin {
            return true;
        }
        self.pick_rule3()
            .is_some_and(|p| self.resend_allowed(p, pc))
    }

    /// segment の option を作ります。SACK の block は SACK の段 (PR 5) が足します。
    pub(crate) fn options(&self, now: i64) -> OptWriter {
        let mut o = OptWriter::default();
        if self.t.ts_ok {
            o.ts(
                ts_clock(now).wrapping_add(self.t.ts_offset),
                self.t.ts_recent,
            );
        }
        o.pad();
        o
    }

    /// option `o` を付けた segment の中身の上限です。`space` は packet の大きさの上限です。
    pub(crate) fn payload_cap(&self, o: &OptWriter, space: i64) -> i64 {
        let h = i64::from(IP_TCP_HEADERS);
        i64::from(self.t.peer_mss)
            .min(i64::from(self.t.pmtu) - h)
            .min(space - h)
            - i64::try_from(o.len()).unwrap_or(0)
    }

    /// 窓と輻輳の窓と送り手の SWS の回避 (RFC 9293 3.8.6.2.1、Nagle を使いません) が許す新しいデータの長さと、FIN
    /// を付けるかを返します。`force` が真なら輻輳の窓を見ません (TLP の probe、RFC 8985 7.3)。
    pub(crate) fn next_new(&mut self, pay_cap: i64, force: bool) -> (u32, bool) {
        if pay_cap <= 0 || self.b.recs.full() {
            return (0, false);
        }
        let end = self.data_end_seq();
        let avail = if seq::lt(self.t.snd_nxt, end) {
            end.wrapping_sub(self.t.snd_nxt)
        } else {
            0
        };
        let fin_pending = self.t.snd_shut && seq::le(self.t.snd_nxt, self.fin_seq());
        let inflight = self.t.snd_nxt.wrapping_sub(self.t.snd_una);
        let pipe = self.pipe();
        let t = &mut *self.t;
        let usable = t.snd_wnd.saturating_sub(inflight);
        let mut room = t.cwnd.saturating_sub(pipe);
        if force || (t.frto == 2 && t.frto_new > 0) {
            room = u32::MAX; // TLP の probe と F-RTO の 2 の段 (RFC 5682 2b)
        }
        if avail == 0 {
            // FIN は番号を 1 つ使うので、Linux と同じく窓に 1 byte の余地があるときだけ送ります。窓が 0 の間は窓の
            // probe を続けます。RFC 9293 の受け入れの判定では、窓が 0 の受け手は長さ 1 の segment を捨てます。
            return (0, fin_pending && usable > 0);
        }
        if t.persist && t.snd_wnd == 0 {
            return (0, false);
        }
        let want = avail.min(u32_of(pay_cap));
        if room < want && pipe > 0 {
            t.cwnd_blocked = true; // 送るデータがあるのに輻輳の窓が止めました
            return (0, false);
        }
        let n = want.min(usable);
        if n == 0 {
            return (0, false);
        }
        if n == want || n >= t.max_snd_wnd / 2 || inflight == 0 {
            // 中身の後ろに FIN を付けるのは、FIN の 1 も窓に入るときだけです。
            return (n, fin_pending && n == avail && n < usable);
        }
        (0, false)
    }

    /// 送るものの優先の順 (高速の再送、窓の probe、再送と新しいデータと FIN、ACK) に segment を 1 つ作ります。
    pub(crate) fn build(&mut self, b: &mut [u8], now: i64) -> usize {
        let space = b.len().min(self.t.pmtu as usize);
        if space < IP_HEADER_LEN + TCP_HEADER_LEN + MAX_OPTION_LEN {
            return 0;
        }
        let space = i64::try_from(space).unwrap_or(i64::MAX);
        if self.t.fast_rtx {
            self.t.fast_rtx = false;
            let n = self.build_rtx(b, space, now);
            if n > 0 || self.ended() {
                return n;
            }
        }
        if self.t.probe_pending {
            self.t.probe_pending = false;
            let s = self.t.snd_una.wrapping_sub(1);
            return self.build_bare(b, s, now);
        }
        if self.t.state != State::TimeWait {
            // 作る処理が会計の不整合で接続を閉じたら、残りの処理を続けません。続けると閉じた接続の欄で次の segment
            // を作り、不整合を重ねて数え、RST を重ねて送ります。TLP の probe は SACK の段 (PR 5) が足します。
            let p = self.pick_rule1();
            let n = self.build_resend(b, space, now, p);
            if n > 0 || self.ended() {
                return n;
            }
            let n = self.build_new(b, space, now, false);
            if n > 0 || self.ended() {
                return n;
            }
            let p = self.pick_rule3();
            let n = self.build_resend(b, space, now, p);
            if n > 0 || self.ended() {
                return n;
            }
        }
        if self.t.ack_now {
            let s = self.t.snd_nxt;
            return self.build_bare(b, s, now);
        }
        0
    }

    /// header と option を書き、送信の輪の offset `off` から `n` byte を中身にして packet を作ります。
    #[expect(
        clippy::too_many_arguments,
        clippy::many_single_char_names,
        reason = "the segment fields and names follow Go's emit"
    )]
    fn emit(
        &mut self,
        b: &mut [u8],
        seq: u32,
        flags: u8,
        o: &mut OptWriter,
        off: u64,
        n: u32,
        now: i64,
    ) -> usize {
        let len = u64::from(n);
        if n > 0 && (off < self.t.una_off || off + len > self.t.tail_off) {
            // 送信の輪の生きている範囲の外を読もうとしました:会計の不整合なので接続を閉じます。
            self.accounting_fault(now);
            return 0;
        }
        let h = TcpHeader {
            tup: self.t.tup,
            seq,
            ack: self.t.rcv_nxt,
            flags: flags | FLAG_ACK,
            wnd: self.window_field(),
        };
        let id = self.s.next_id();
        let n = n as usize;
        let p = wire::write_tcp(b, id, &h, Some(o), n);
        if n > 0 {
            self.b.snd.read(off, &mut b[p..p + n]);
        }
        self.ack_sent();
        wire::finish_tcp(b)
    }

    /// ACK を運ぶ segment を送った後の状態を整えます。
    fn ack_sent(&mut self) {
        let t = &mut *self.t;
        if t.ack_now {
            if t.ack_delayed {
                self.s.stats.acks_delayed += 1;
            } else {
                self.s.stats.acks_immediate += 1;
            }
        }
        if t.quick_acks > 0 && t.ack_now && !t.ack_delayed {
            t.quick_acks -= 1;
        }
        t.ack_delayed = false;
        t.ack_now = false;
        // PR 5 adds: D-SACK の block を載せた印 (dsackPending) を消すこと。
        t.rcv_since_ack = 0;
        self.disarm(TMR_DELACK);
        self.t.last_ack_sent = self.t.rcv_nxt;
    }

    /// 中身の無い ACK を作ります。窓の probe は `seq` に SND.UNA - 1 を渡します (Linux と同じ)。
    fn build_bare(&mut self, b: &mut [u8], seq: u32, now: i64) -> usize {
        let mut o = self.options(now);
        self.emit(b, seq, 0, &mut o, 0, 0, now)
    }

    /// SND.MAX から新しいデータを segment にします (RFC 6675 の NextSeg の規則 2)。
    fn build_new(&mut self, b: &mut [u8], space: i64, now: i64, force: bool) -> usize {
        // 黙った後の輻輳の窓 (RFC 5681 4.1)。送り残しが無い時に黙った時間だけ CUBIC の epoch をずらす規則は
        // CUBIC の段 (PR 5) が足します。NewReno は何もしません。
        if self.t.snd_una == self.t.snd_max && now - self.t.last_send_at > self.cur_rto() {
            let iw = INITIAL_WINDOW_SEGS * self.seg_mss();
            self.t.cwnd = self.t.cwnd.min(iw);
        }
        let mut o = self.options(now);
        self.t.cwnd_blocked = false;
        let pc = self.payload_cap(&o, space);
        let (n, fin) = self.next_new(pc, force);
        if n == 0 && !fin {
            if self.t.cwnd_blocked {
                self.note_cwnd_use(true);
            }
            return 0;
        }
        let seq = self.t.snd_nxt;
        let mut flags = 0;
        if n > 0 && seq.wrapping_add(n) == self.data_end_seq() {
            flags |= FLAG_PSH;
        }
        if fin {
            flags |= FLAG_FIN;
        }
        let off = self.t.una_off + u64::from(seq.wrapping_sub(self.t.snd_una));
        let mut length = n;
        if fin {
            length += 1;
            self.t.fin_sent = true;
        }
        // PR 5 adds: 回復の中の PRR の送った量 (prrOut += length)。
        let t = &mut *self.t;
        if n > 0 && t.rcvd_data && now - t.last_data_rcvd < DELACK_TIMEOUT {
            t.pingpong = true; // 受けた直後に応える対話の流れ (Linux の tcp_event_data_sent)
        }
        if t.frto == 2 && t.frto_new > 0 {
            t.frto_new -= 1;
        }
        self.b.recs.push_back(Record {
            seq,
            length: u16::try_from(length).unwrap_or(u16::MAX),
            sent_at: time(now),
            skip: 1,
            rtx_gen: self.t.rtx_gen,
            ..Record::default()
        });
        let last = self.b.recs.len() - 1;
        self.list_append(Which::T, last, REC_IN_T);
        self.t.snd_nxt = seq.wrapping_add(length);
        self.t.snd_max = seq::max(self.t.snd_max, self.t.snd_nxt);
        // 送った後の輻輳の窓に 1 segment の余地が無ければ、その窓は輻輳の窓に制限されています。
        let limited = self.pipe().wrapping_add(self.seg_mss()) > self.t.cwnd;
        self.note_cwnd_use(limited);
        if self.t.rto_at == 0 && !self.t.persist {
            self.t.rto_at = now + self.cur_rto();
        }
        if !force {
            self.schedule_tlp(now); // 新しいデータの後に PTO を張り直します (RFC 8985 7.2)
        }
        self.rearm_retrans();
        self.t.last_send_at = now;
        self.emit(b, seq, flags, &mut o, off, n, now)
    }

    /// 選んだ記録の再送を窓と輻輳の窓が許すかを返します。`pay_cap` は segment の中身の上限です。
    pub(crate) fn resend_allowed(&mut self, p: Pick, pay_cap: i64) -> bool {
        let i = p.i;
        let off = self.pick_off(p);
        let (mut n, fin) = self.resend_len(i, off, pay_cap);
        if n == 0 && !fin {
            return false;
        }
        if fin {
            n += 1;
        }
        // 窓の外から始まる記録は送りません。先頭の記録は窓の probe を兼ねて送ります (Linux の
        // tcp_retransmit_skb)。窓の probe を張っている間は送りません。
        let seq = self.b.recs.at(i).seq.wrapping_add(off);
        let t = &*self.t;
        if t.persist || (seq != t.snd_una && !seq::lt(seq, t.snd_una.wrapping_add(t.snd_wnd))) {
            return false;
        }
        let pipe = self.pipe();
        let t = &*self.t;
        // F-RTO の RTO の後の先頭の再送は輻輳の窓によらず送ります (RFC 5682 の 1 の段)。
        pipe == 0 || t.cwnd >= pipe.wrapping_add(n) || (t.frto == 1 && i == 0)
    }

    /// 記録 (NextSeg の規則 1 か 3 が選んだ記録) を再送します。記録は SND.UNA から番号の順に選ばれ、SACK 済みの
    /// 記録は飛ばします。新しい segment の大きさを超える記録は複数の segment に分けて送り、記録は分けません。
    #[expect(
        clippy::many_single_char_names,
        reason = "the names follow the Go code"
    )]
    fn build_resend(&mut self, b: &mut [u8], space: i64, now: i64, p: Option<Pick>) -> usize {
        let Some(p) = p else {
            return 0;
        };
        let i = p.i;
        let mut o = self.options(now);
        let pc = self.payload_cap(&o, space);
        if !self.resend_allowed(p, pc) {
            return 0;
        }
        let off = self.pick_off(p);
        let (n, fin) = self.resend_len(i, off, pc);
        if n == 0 && !fin {
            return 0;
        }
        let r = *self.b.recs.at(i);
        let seq = r.seq.wrapping_add(off);
        if !self.send_range_ok(seq, n) {
            self.accounting_fault(now);
            return 0;
        }
        let mut length = n;
        let mut flags = 0;
        if fin {
            flags |= FLAG_FIN;
            length += 1;
        }
        self.adopt_gen(i);
        if !self.rtx_live(i) {
            self.b.recs.at(i).flags |= REC_RTX;
            self.t.rtx_bytes = self.t.rtx_bytes.wrapping_add(u32::from(r.length));
        }
        let rec = self.b.recs.at(i);
        rec.flags |= REC_RETRANSMITTED;
        rec.sent_at = time(now);
        // 再送した記録は送った時刻の順の list の末尾へ移します (RFC 8985)。記録の節は 1 つの list にしか使えないので、
        // 損失の待ち行列から外してから足します。待ち行列の記録を分けて送る間は、送り終えるまで待ち行列に残します。
        let rlen = u32::from(r.length);
        let t = &mut *self.t;
        let to_t = match p.src {
            Src::Pos => {
                t.rxt_off += length;
                t.rxt_mid = t.rxt_off < rlen;
                if !t.rxt_mid {
                    t.rxt_idx += 1;
                    t.rxt_off = 0;
                }
                true
            }
            Src::Queue => {
                t.q_off += length;
                t.q_mid = t.q_off < rlen;
                if !t.q_mid {
                    t.q_off = 0;
                }
                !t.q_mid
            }
        };
        if to_t {
            self.unlink_rec(i);
            self.list_append(Which::T, i, REC_IN_T);
        }
        // PR 5 adds: 回復の中の PRR の送った量 (prrOut += length) と、TLP の probe の再送の原因。
        let cause = self.t.resend_cause;
        self.note_retransmit(now);
        self.s.stats.retrans[usize::from(cause)] += 1;
        if (self.t.rto_at == 0 || i == 0) && !self.t.persist {
            // 先頭の記録を送り直したら RTO を張り直します (Linux の tcp_xmit_retransmit_queue)。
            let at = now + self.cur_rto();
            self.set_rto(at);
        }
        self.t.last_send_at = now;
        let at = self.t.una_off + u64::from(seq.wrapping_sub(self.t.snd_una));
        self.emit(b, seq, flags, &mut o, at, n, now)
    }

    /// SND.UNA からの 1 segment を再送します (SACK を交渉しない接続の高速の再送と NewReno の部分の確認)。
    fn build_rtx(&mut self, b: &mut [u8], space: i64, now: i64) -> usize {
        if self.t.snd_una == self.t.snd_max {
            return 0;
        }
        let mut o = self.options(now);
        let pc = self.payload_cap(&o, space);
        if pc <= 0 {
            return 0;
        }
        // 送ったことのある範囲 (SND.MAX まで) だけを送り直します。記録は SND.MAX まで隙間なく並びます。
        let seq = self.t.snd_una;
        let end = self.data_end_seq();
        let left = if seq::lt(seq, end) {
            seq::min(end, self.t.snd_max).wrapping_sub(seq)
        } else {
            0
        };
        let n = left.min(u32_of(pc));
        let fin = self.t.fin_sent && seq.wrapping_add(n) == end && seq::gt(self.t.snd_max, end);
        let mut flags = 0;
        let mut length = n;
        if fin {
            flags |= FLAG_FIN;
            length += 1;
        }
        // 再送する範囲に掛かる記録をすべて再送の印にします (Karn の規則)。
        let stop = seq.wrapping_add(length);
        for i in 0..self.b.recs.len() {
            let r = self.b.recs.at(i);
            if !seq::lt(r.seq, stop) {
                break;
            }
            r.flags |= REC_RETRANSMITTED;
            r.sent_at = time(now);
            if self.gen_flag(i, REC_IN_T) {
                // 送った時刻の順を保ちます。
                self.list_remove(Which::T, i, REC_IN_T);
                self.list_append(Which::T, i, REC_IN_T);
            }
        }
        self.t.last_send_at = now;
        self.s.stats.retrans[usize::from(self.t.rtx_cause)] += 1;
        self.note_retransmit(now);
        let off = self.t.una_off;
        self.emit(b, seq, flags, &mut o, off, n, now)
    }

    /// 再送する `[seq, seq+n)` が SND.UNA から SND.MAX の内側にあり、送信の輪の生きている範囲に収まるかを返します。
    fn send_range_ok(&self, seq: u32, n: u32) -> bool {
        let t = &*self.t;
        if !seq::ge(seq, t.snd_una) || seq::gt(seq.wrapping_add(n), t.snd_max) {
            return false;
        }
        let off = t.una_off + u64::from(seq.wrapping_sub(t.snd_una));
        off + u64::from(n) <= t.tail_off
    }

    /// 会計の不整合を数えて記録し、RST を送って接続を閉じます (Go の `fault.go`)。
    pub(crate) fn accounting_fault(&mut self, now: i64) {
        self.s.refused(LogKind::AccountingFault, now);
        self.send_rst();
        self.abort_with(ConnError::Accounting);
    }

    /// 接続が CLOSED か空きの枠になったかを返します。
    pub(crate) fn ended(&self) -> bool {
        matches!(self.t.state, State::Closed | State::Free)
    }
}
