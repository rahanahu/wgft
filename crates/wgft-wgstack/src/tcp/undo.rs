//! 不要な再送の取り消し (Go の `undo.go`)。
//!
//! 回復に入る時と回復の外の最初の RTO の時に輻輳の窓と ssthresh を覚え、再送が不要だったと分かれば戻します
//! (Linux の tcp_init_undo、tcp_may_undo、tcp_try_undo_recovery)。不要と分かる条件は、すべての再送が D-SACK で
//! 知らされたこと (RFC 3708) か、確認の TSecr が最初の再送の時刻より前であること (RFC 3522 の Eifel) です。
//! D-SACK による数え方と F-RTO の ACK の処理は SACK の段 (PR 5) が足します。

use super::ctx::Conn;
use super::ts_clock;
use crate::seq;
use crate::wire::Segment;

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

    /// 覚えた輻輳の窓と ssthresh に戻します (Linux の tcp_undo_cwnd_reduction、RFC 4015 の応答)。並べ替えを見た
    /// 印は SACK の段 (PR 5) が足します。
    pub(crate) fn undo(&mut self) {
        let t = &mut *self.t;
        t.cwnd = t.cwnd.max(self.k.undo_cwnd);
        t.ssthresh = t.ssthresh.max(self.k.undo_ssthresh);
        self.k.undo_marker = false;
        (t.frto, t.rto_episode) = (0, false);
        self.s.stats.spurious_undos += 1;
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

    /// 未送信のデータがあり、相手の窓に余地があるかを返します。
    pub(crate) fn has_new_data(&self) -> bool {
        let t = &*self.t;
        seq::lt(t.snd_nxt, self.data_end_seq())
            && seq::lt(t.snd_nxt, t.snd_una.wrapping_add(t.snd_wnd))
    }
}
