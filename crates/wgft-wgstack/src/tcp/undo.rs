//! 不要な再送の取り消し (Go の `undo.go`)。
//!
//! 回復に入る時と回復の外の最初の RTO の時に輻輳の窓と ssthresh を覚え、再送が不要だったと分かれば戻します
//! (Linux の tcp_init_undo、tcp_may_undo、tcp_try_undo_recovery、tcp_try_undo_loss)。不要と分かる条件は、すべての
//! 再送が D-SACK で知らされたこと (RFC 3708) か、確認の TSecr が最初の再送の時刻より前であること (RFC 3522 の
//! Eifel) です。

use super::ctx::Conn;
use super::{RTX_RTO, ts_clock};
use crate::buf::records::REC_RETRANSMITTED;
use crate::seq;
use crate::wire::{SackBlock, Segment};

/// SND.UNA より先の D-SACK の block で調べる記録の数の上限です。ACK ごとの手間を定数に保ちます。
const DSACK_UNDO_WALK: usize = 4;

impl Conn<'_> {
    /// 輻輳の窓を下げる前に呼び、今の窓と ssthresh と SND.UNA を覚えます (Linux の tcp_init_undo)。
    /// `undo_retrans` の -1 は、まだ再送していないので数では取り消せないことを表します。
    pub(crate) fn init_undo(&mut self) {
        let k = &mut *self.k;
        (k.undo_marker, k.undo_seq) = (true, self.t.snd_una);
        (k.undo_cwnd, k.undo_ssthresh) = (self.t.cwnd, self.t.ssthresh);
        (k.undo_retrans, k.retrans_ts_ok) = (-1, false);
    }

    /// 再送するたびに呼びます。接続の再送の数と、印の後の最初の再送の時刻 (自分の TSval) と再送の数を数えます。
    pub(crate) fn note_retransmit(&mut self, now: i64) {
        let k = &mut *self.k;
        k.total_retrans = k.total_retrans.wrapping_add(1);
        if !k.undo_marker {
            return;
        }
        if !k.retrans_ts_ok && self.t.ts_ok {
            k.retrans_ts = ts_clock(now).wrapping_add(self.t.ts_offset);
            k.retrans_ts_ok = true;
        }
        k.undo_retrans = k.undo_retrans.max(0) + 1;
    }

    /// 先頭の block が D-SACK の ACK で、重複した segment の数を返します (Linux の tcp_dsack_seen)。範囲が相手の窓の
    /// 最大より広い block と、D-SACK の累計が再送の累計を超えた block は疑わしいので 0 を返します。2 つ目の値は block
    /// が TLP の probe の再送の D-SACK であること (Linux の FLAG_DSACK_TLP) です。
    pub(crate) fn dsack_seen(&mut self, b: SackBlock) -> (u32, bool) {
        let l = b.right.wrapping_sub(b.left);
        if l == 0 || l > self.t.max_snd_wnd {
            return (0, false);
        }
        let mss = self.seg_mss().max(1);
        let mut dup = 1;
        let mut tlp = false;
        if l > mss {
            dup = l.div_ceil(mss);
        } else if self.t.tlp_retrans && b.right == self.t.tlp_end {
            tlp = true;
        }
        let k = &mut *self.k;
        k.dsack_dups = k.dsack_dups.wrapping_add(dup);
        if k.dsack_dups > k.total_retrans {
            return (0, false);
        }
        (dup, tlp)
    }

    /// D-SACK で知らされた、印の後の再送を数から引きます (Linux の tcp_check_dsack と tcp_sacktag_one)。確認済みの
    /// 範囲の block は、印より後に終わり、この ACK の前の SND.UNA までに終わるときだけ `dup` を数えます。SND.UNA より
    /// 先の block は、再送した記録を数えます。TLP の probe の D-SACK は数えません。
    #[expect(
        clippy::many_single_char_names,
        reason = "the names follow the Go code"
    )]
    pub(crate) fn note_undo_dsack(&mut self, b: SackBlock, dup: u32, tlp: bool) {
        if !self.k.undo_marker || self.k.undo_retrans <= 0 || dup == 0 || tlp {
            return;
        }
        let mut n: i32 = 0;
        if seq::le(b.right, self.t.prior_una) {
            if seq::gt(b.right, self.k.undo_seq) {
                n = i32::try_from(dup).unwrap_or(i32::MAX);
            }
        } else if seq::lt(b.left, self.t.snd_una) {
            // 確認済みの範囲と記録の両方にかかる block:確認済みの側の記録は消えたので数えません。
        } else {
            let mut i = self.first_rec_from(b.left);
            let mut k = 0;
            while i < self.b.recs.len() && k < DSACK_UNDO_WALK {
                let r = *self.b.recs.at(i);
                if seq::gt(r.seq.wrapping_add(u32::from(r.length)), b.right) {
                    break;
                }
                if r.flags & REC_RETRANSMITTED != 0 && seq::ge(r.seq, self.k.undo_seq) {
                    n += 1;
                }
                i += 1;
                k += 1;
            }
        }
        self.k.undo_retrans = (self.k.undo_retrans - n).max(0);
    }

    /// 確認が元の segment への確認か (TSecr が最初の再送の時刻より前) を返します。
    fn packet_delayed(&self, seg: &Segment<'_>) -> bool {
        self.k.retrans_ts_ok
            && seg
                .opt
                .ts
                .is_some_and(|(_, ecr)| ecr != 0 && seq::lt(ecr, self.k.retrans_ts))
    }

    /// 再送が不要だったと分かるかを返します (Linux の tcp_may_undo)。
    pub(crate) fn may_undo(&self, seg: &Segment<'_>) -> bool {
        self.k.undo_marker && (self.k.undo_retrans == 0 || self.packet_delayed(seg))
    }

    /// 覚えた輻輳の窓と ssthresh に戻し、並べ替えを見たことにします (Linux の tcp_undo_cwnd_reduction、RFC 4015 の
    /// 応答)。
    pub(crate) fn undo(&mut self) {
        let t = &mut *self.t;
        t.cwnd = t.cwnd.max(self.k.undo_cwnd);
        t.ssthresh = t.ssthresh.max(self.k.undo_ssthresh);
        t.reorder_seen = true;
        self.k.undo_marker = false;
        (t.frto, t.rto_episode) = (0, false);
        self.s.stats.spurious_undos += 1;
    }

    /// RTO の後の回復が終わった ACK で、再送が不要だったと分かれば窓を戻し、F-RTO と取り消しの印を終えます (Linux の
    /// tcp_process_loss の recovered と tcp_try_undo_recovery)。
    pub(crate) fn rto_recovered(&mut self, seg: &Segment<'_>) {
        if self.may_undo(seg) {
            self.undo();
            self.s.stats.spurious_rtos += 1;
        }
        (self.t.rto_episode, self.t.frto) = (false, 0);
        self.k.undo_marker = false;
    }

    /// RTO で F-RTO を使えるかを返します (RFC 5682 の SACK を使う形。回復の外の最初の RTO)。
    pub(crate) fn frto_eligible(&self) -> bool {
        self.t.sack_ok && self.t.backoff == 0 && !self.t.in_recovery && self.b.recs.len() > 1
    }

    /// 先頭の記録だけを損失にします (F-RTO の RTO)。
    pub(crate) fn mark_head_lost(&mut self, cause: u8) {
        if self.b.recs.len() == 0 {
            return;
        }
        self.clear_rtx(0);
        if self.t.loss_idx == 0 {
            let sacked = self.is_sacked(0);
            self.pass_loss(0, sacked);
        }
        self.unlink_rec(0);
        self.reset_rxt();
        self.t.resend_cause = cause;
    }

    /// F-RTO の RTO の後の ACK を処理します (RFC 5682 3.1、Linux の tcp_process_loss)。`advanced` は ACK が SND.UNA を
    /// 進めたか、`dup` は進めない重複の ACK か SACK で新しく届いたデータがあったかです。
    pub(crate) fn frto_after_ack(&mut self, seg: &Segment<'_>, advanced: bool, dup: bool) {
        if self.t.orig_delivered || (advanced && self.packet_delayed(seg)) {
            // 再送していないデータが届いたか、元の segment への確認:RTO は不要でした。
            self.undo();
            self.s.stats.spurious_rtos += 1;
            self.t.recover = self.t.snd_una;
        } else if self.t.frto == 2 {
            // 3 の段:新しいデータを送った後に、届いたのが再送だけなら損失は本物で、今の RTO の規則で送り直します。
            self.t.frto = 0;
            self.mark_all_lost(RTX_RTO);
        } else if advanced {
            // 2 の段:新しいデータを 2 つまで輻輳の窓によらず送ります。送るデータか窓が無ければ今の RTO の規則に
            // 戻ります。
            if self.has_new_data() {
                (self.t.frto, self.t.frto_new) = (2, 2);
            } else {
                self.t.frto = 0;
                self.mark_all_lost(RTX_RTO);
            }
        } else if dup {
            self.t.frto = 0;
            self.mark_all_lost(RTX_RTO);
        }
    }

    /// 未送信のデータがあり、相手の窓に余地があるかを返します。
    pub(crate) fn has_new_data(&self) -> bool {
        let t = &*self.t;
        seq::lt(t.snd_nxt, self.data_end_seq())
            && seq::lt(t.snd_nxt, t.snd_una.wrapping_add(t.snd_wnd))
    }
}
