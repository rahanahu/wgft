//! RACK-TLP と送信の記録の list (Go の `rack.go`、RFC 8985)。
//!
//! 送り残しの記録は、送った時刻の順の list (`t_list`) と損失の待ち行列 (`lost_q`) のどちらかに入るか、どちらにも
//! 入りません。list の節は記録の `prev` と `next` で、自分の位置からの記録の数の差 (0 は無し) で持つので、輪の
//! 大きさを変えても、先頭の記録を外しても変わりません。list に入っている印と RACK の損失の印は、再送の印と同じく
//! 記録の `rtx_gen` が接続の世代と等しいときだけ有効で、RTO は世代を進めて list を一度に空にします。

use super::conn::RecList;
use super::ctx::Conn;
use super::sack::{DUP_THRESH, idx};
use super::{MS, SEC};
use crate::buf::records::{REC_IN_Q, REC_IN_T, REC_LOST, REC_RETRANSMITTED, REC_RTX, Record};
use crate::seq;
use crate::stack::ns;

/// D-SACK で上げた倍率を保つ回復の数 (RFC 8985 の 16) です。
pub(crate) const RACK_REO_PERSIST: u8 = 16;
/// RFC 8985 7.2 の WCDelAckT です。
const TLP_ONE_SEG_EXTRA: i64 = 200 * MS;
/// RTT を測る前の PTO です。
const TLP_NO_RTT: i64 = SEC;

/// `(t1, e1)` が `(t2, e2)` より後に送られたかを返します (RFC 8985 の RACK_sent_after)。
fn sent_after(t1: i64, e1: u32, t2: i64, e2: u32) -> bool {
    t1 > t2 || (t1 == t2 && seq::gt(e1, e2))
}

/// 記録の list の選び方です。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Which {
    /// 送った時刻の順の list です。
    T,
    /// 損失の待ち行列です。
    Q,
}

/// 記録の位置に、自分からの記録の数の差を足します。
fn offset(i: usize, d: i32) -> usize {
    usize::try_from(i64::try_from(i).unwrap_or(0) + i64::from(d)).unwrap_or(0)
}

/// 記録の通し番号の差を、Go の `int32` の変換と同じく符号つきにします。
#[expect(
    clippy::cast_possible_wrap,
    reason = "matches Go's int32 conversion of a wrapping difference"
)]
fn diff(a: u32, b: u32) -> i32 {
    a.wrapping_sub(b) as i32
}

impl Conn<'_> {
    fn list(&mut self, w: Which) -> &mut RecList {
        match w {
            Which::T => &mut self.t.t_list,
            Which::Q => &mut self.t.lost_q,
        }
    }

    pub(crate) fn rec(&mut self, i: usize) -> &mut Record {
        self.b.recs.at(i)
    }

    pub(crate) fn rec_abs(&self, i: usize) -> u32 {
        self.t
            .rec_base
            .wrapping_add(u32::try_from(i).unwrap_or(u32::MAX))
    }

    pub(crate) fn rec_idx(&self, a: u32) -> usize {
        a.wrapping_sub(self.t.rec_base) as usize
    }

    /// 記録 `i` の世代の印を今の世代に合わせます。古い世代の印はすべて消します。
    pub(crate) fn adopt_gen(&mut self, i: usize) {
        let g = self.t.rtx_gen;
        let r = self.b.recs.at(i);
        if r.rtx_gen != g {
            r.flags &= !(REC_RTX | REC_IN_T | REC_IN_Q | REC_LOST);
            r.rtx_gen = g;
        }
    }

    pub(crate) fn gen_flag(&mut self, i: usize, f: u8) -> bool {
        let g = self.t.rtx_gen;
        let r = self.b.recs.at(i);
        r.flags & f != 0 && r.rtx_gen == g
    }

    /// 記録 `i` を list `w` の末尾に足し、印 `flag` を付けます。
    #[expect(
        clippy::many_single_char_names,
        reason = "the names follow the Go code"
    )]
    pub(crate) fn list_append(&mut self, w: Which, i: usize, flag: u8) {
        self.adopt_gen(i);
        let a = self.rec_abs(i);
        let l = *self.list(w);
        let tail_idx = self.rec_idx(l.tail);
        let r = self.b.recs.at(i);
        r.flags |= flag;
        r.next = 0;
        if l.n == 0 {
            r.prev = 0;
            self.list(w).head = a;
        } else {
            r.prev = diff(l.tail, a);
            self.b.recs.at(tail_idx).next = diff(a, l.tail);
        }
        let l = self.list(w);
        l.tail = a;
        l.n += 1;
    }

    /// 記録 `i` を list `w` から外します。損失の待ち行列の先頭を外すときは、先頭の記録の中で送り終えた位置も
    /// 0 に戻します。
    pub(crate) fn list_remove(&mut self, w: Which, i: usize, flag: u8) {
        let a = self.rec_abs(i);
        if w == Which::Q && self.t.lost_q.head == a {
            (self.t.q_off, self.t.q_mid) = (0, false); // 分けて送っていた先頭の記録が待ち行列を出ました
        }
        let r = *self.b.recs.at(i);
        let pa = a.wrapping_add_signed(r.prev);
        let na = a.wrapping_add_signed(r.next);
        match (r.prev != 0, r.next != 0) {
            (true, true) => {
                self.b.recs.at(offset(i, r.prev)).next = diff(na, pa);
                self.b.recs.at(offset(i, r.next)).prev = diff(pa, na);
            }
            (true, false) => {
                self.b.recs.at(offset(i, r.prev)).next = 0;
                self.list(w).tail = pa;
            }
            (false, true) => {
                self.b.recs.at(offset(i, r.next)).prev = 0;
                self.list(w).head = na;
            }
            (false, false) => {}
        }
        let r = self.b.recs.at(i);
        (r.prev, r.next) = (0, 0);
        r.flags &= !flag;
        self.list(w).n -= 1;
    }

    /// 記録をどちらの list からも外します。
    pub(crate) fn unlink_rec(&mut self, i: usize) {
        if self.gen_flag(i, REC_IN_T) {
            self.list_remove(Which::T, i, REC_IN_T);
        }
        if self.gen_flag(i, REC_IN_Q) {
            self.list_remove(Which::Q, i, REC_IN_Q);
        }
    }

    /// 記録 `i` が RACK の損失の印を持つかを返します。
    pub(crate) fn rack_lost(&mut self, i: usize) -> bool {
        self.gen_flag(i, REC_LOST)
    }

    /// 損失の待ち行列の先頭の、送り直しを待つ記録の位置を返します。
    pub(crate) fn next_queued(&mut self) -> Option<usize> {
        while self.t.lost_q.n > 0 {
            let i = self.rec_idx(self.t.lost_q.head);
            super::sack::step();
            if !self.is_sacked(i) && (!self.rtx_live(i) || self.t.q_mid) {
                return Some(i);
            }
            self.list_remove(Which::Q, i, REC_IN_Q); // 先頭なので、分けて送った位置も戻します
        }
        None
    }

    /// 累積の確認か SACK で新しく届いたと知らせた記録 `i` で RACK の状態を更新します (RFC 8985 6.2 の手順 1 と
    /// 2)。
    pub(crate) fn rack_delivered(&mut self, i: usize, now: i64) {
        let r = *self.b.recs.at(i);
        let end = r.seq.wrapping_add(u32::from(r.length));
        let sent = ns(r.sent_at);
        let t = &mut *self.t;
        if r.flags & REC_RETRANSMITTED != 0 {
            // 元の segment への確認かもしれない再送は使いません。Linux の tcp_rack_advance と同じく最小の RTT
            // だけで見分け、RFC 8985 の TSecr による判定は使いません。穴のある間の SACK の TSecr は受け手の
            // TS.Recent で、穴より前の segment の時刻のままなので、再送への SACK をすべて元の segment への確認と
            // みなしてしまいます。
            if now - sent < t.min_rtt {
                return;
            }
        } else {
            if seq::le(end, t.recover) {
                // RTO の前に送り、再送していないデータ (Linux の FLAG_ORIG_SACK_ACKED)
                t.orig_delivered = true;
            }
            if t.rack_fack_ok && seq::lt(end, t.rack_fack) {
                t.reorder_seen = true;
            }
        }
        if !t.rack_fack_ok || seq::gt(end, t.rack_fack) {
            (t.rack_fack, t.rack_fack_ok) = (end, true);
        }
        if !t.rack_ok || sent_after(sent, end, t.rack_xmit, t.rack_end) {
            (t.rack_xmit, t.rack_end, t.rack_rtt, t.rack_ok) = (sent, end, now - sent, true);
        }
    }

    /// 並べ替えの窓です (RFC 8985 6.2 の手順 4)。D-SACK を受けた往復ごとに倍率を 1 つ上げます。
    pub(crate) fn reo_wnd(&self) -> i64 {
        let t = &*self.t;
        if !t.reorder_seen && (t.in_recovery || i64::from(t.sacked_recs) >= DUP_THRESH) {
            return 0;
        }
        (i64::from(t.reo_wnd_mult.max(1)) * t.min_rtt / 4).min(t.srtt)
    }

    /// D-SACK を受けた ACK で並べ替えの窓の倍率を上げます。1 往復に 1 回だけ上げ、16 回の回復の間保ちます
    /// (RFC 8985 6.2 の手順 4)。
    pub(crate) fn rack_dsack(&mut self) {
        let k = &mut *self.k;
        if k.dsack_round_on && seq::ge(self.t.snd_una, k.dsack_round) {
            k.dsack_round_on = false;
        }
        if k.dsack_round_on {
            return;
        }
        (k.dsack_round, k.dsack_round_on) = (self.t.snd_max, true);
        // 倍率の上限は Linux の reo_wnd_steps と同じ 255 で、欄の型の上限です。倍率と最小の RTT の積が溢れません。
        self.t.reo_wnd_mult = self.t.reo_wnd_mult.max(1).saturating_add(1);
        k.reo_persist = RACK_REO_PERSIST;
        self.s.stats.dsacks_in += 1;
    }

    /// 回復を終えるたびに倍率を保つ残りを減らし、尽きたら倍率を 1 に戻します。
    pub(crate) fn rack_recovery_done(&mut self) {
        if self.k.reo_persist > 0 {
            self.k.reo_persist -= 1;
            if self.k.reo_persist == 0 {
                self.t.reo_wnd_mult = 1;
            }
        }
    }

    /// 送った時刻の順の list の先頭から、RACK の時刻で失われた記録に印を付けて損失の待ち行列へ移します
    /// (RFC 8985 6.2 の手順 5)。まだ期限の来ない最初の記録で止め、その期限を並べ替えの期限にします。印を付けた
    /// 記録があれば真を返します。止まった記録より後の記録は送った時刻が遅いので、期限も遅くなります。
    pub(crate) fn rack_detect(&mut self, now: i64) -> bool {
        self.t.reo_at = 0;
        if !self.t.sack_ok || !self.t.rack_ok {
            return false;
        }
        let mut marked = false;
        let wnd = self.reo_wnd();
        while self.t.t_list.n > 0 {
            let i = self.rec_idx(self.t.t_list.head);
            let r = *self.b.recs.at(i);
            super::sack::step();
            let sent = ns(r.sent_at);
            let t = &mut *self.t;
            let end = r.seq.wrapping_add(u32::from(r.length));
            if !sent_after(t.rack_xmit, t.rack_end, sent, end) {
                break;
            }
            let remain = sent + t.rack_rtt + wnd - now;
            if remain > 0 {
                t.reo_at = now + remain;
                break;
            }
            self.mark_rack_lost(i);
            marked = true;
        }
        marked
    }

    /// 送った時刻の順の list の記録 `i` を失われたとみなし、損失の待ち行列の末尾へ移します。
    pub(crate) fn mark_rack_lost(&mut self, i: usize) {
        self.list_remove(Which::T, i, REC_IN_T);
        let l = u32::from(self.b.recs.at(i).length);
        self.clear_rtx(i);
        if !self.rack_lost(i) {
            self.b.recs.at(i).flags |= REC_LOST;
            if i >= idx(self.t.loss_idx) {
                self.t.rack_lost_beyond = self.t.rack_lost_beyond.wrapping_add(l);
            }
        }
        self.list_append(Which::Q, i, REC_IN_Q);
        self.s.stats.rack_lost += 1;
    }

    /// TLP の probe の期限を張れるかを返します (RFC 8985 7.2)。回復と RTO の後の回復の間、SACK 済みの記録がある
    /// 間、probe の確認を待つ間、窓の probe の間は張りません。SACK 済みの記録があれば、RACK の並べ替えの期限と、
    /// 相手が SACK を取り消した疑いの早めた RTO (`renege_timer`) が損失を扱います。
    pub(crate) fn tlp_eligible(&self) -> bool {
        let t = &*self.t;
        t.sack_ok
            && !t.persist
            && !t.in_recovery
            && !t.tlp_active
            && t.sacked == 0
            && t.snd_una != t.snd_max
            && seq::ge(t.snd_una, t.recover)
    }

    /// PTO の期限を決めます。新しいデータを送った後と、累積の確認が進んだ後に呼びます。RTO の期限より遅くなるなら
    /// RTO の期限に張り、その時刻には RTO ではなく probe を送ります (RFC 8985 7.2)。
    pub(crate) fn schedule_tlp(&mut self, now: i64) {
        self.t.tlp_at = 0;
        if !self.tlp_eligible() {
            return;
        }
        let mss = self.seg_mss();
        let t = &mut *self.t;
        let mut pto = TLP_NO_RTT;
        if t.has_rtt {
            pto = 2 * t.srtt;
            if t.snd_max.wrapping_sub(t.snd_una) <= mss {
                pto = pto.max(t.srtt * 3 / 2 + TLP_ONE_SEG_EXTRA);
            }
        }
        let mut at = now + pto.max(MS);
        if t.rto_at != 0 {
            at = at.min(t.rto_at);
        }
        t.tlp_at = at;
    }

    /// PTO の期限に probe を送れるかを返します。前の probe の後に RTT を測っていなければ (RFC 8985 7.3 の条件 2)
    /// 送りません。
    pub(crate) fn tlp_can_probe(&self) -> bool {
        self.tlp_eligible() && self.t.tlp_sampled
    }

    /// probe の確認を処理します (RFC 8985 7.4、Linux の tcp_process_tlp_ack)。probe が再送で、確認が probe より
    /// 先まで進んだときは、probe が損失を直したとみなして、この ACK の前の窓で輻輳の窓を下げます。この縮小は今の
    /// SND.MAX までに送ったデータの輻輳の事象なので、SND.UNA がそこへ届く前に入る回復は窓を下げ直さず、その番号で
    /// 終わります (`enter_fast_recovery`)。
    pub(crate) fn tlp_on_ack(&mut self, ack: u32, una_advanced: bool, newly_sacked: u32) {
        if !self.t.tlp_active || seq::lt(ack, self.t.tlp_end) {
            return;
        }
        if !self.t.tlp_retrans {
            self.t.tlp_active = false;
        } else if seq::gt(ack, self.t.tlp_end) {
            self.t.tlp_active = false;
            // probe を送った後に回復か RTO が始まっていれば、その応答が probe の前の損失への輻輳の事象なので、
            // 下げ直しません (RFC 8985 7.4.1)。probe を送れたのは SND.UNA >= recover の時なので、recover が probe
            // の終わりに届いているのは、その後に回復か RTO が recover を進めたときです。
            if !self.t.in_recovery && !seq::ge(self.t.recover, self.t.tlp_end) {
                // 窓は損失を見つけた ACK の前の値で決めます。この ACK が probe の後のデータまで確認すると、ACK の
                // 後の送り残しは 0 に近く、窓が下限まで落ちます。TLP は回復の外だけで働くので、送り手の窓は輻輳の
                // 窓です。
                let t = &*self.t;
                let base = t.snd_max.wrapping_sub(t.prior_una).min(t.prior_cwnd);
                let th = self.cc_loss_thresh(t.prior_cwnd, base);
                let t = &mut *self.t;
                t.ssthresh = th;
                t.cwnd = th;
                (t.tlp_cut, t.tlp_cut_seq) = (true, t.snd_max);
                self.s.stats.tlp_recoveries += 1;
            }
        } else if !una_advanced && newly_sacked == 0 {
            self.t.tlp_active = false; // 元の segment と probe の両方が届きました
        }
        if !self.t.tlp_active {
            // 片付いた probe の終わりで後の D-SACK を probe のものとみなしません。
            self.t.tlp_retrans = false;
        }
    }
}
