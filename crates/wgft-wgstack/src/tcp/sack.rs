//! 送信の記録の scoreboard (Go の `scoreboard.go` のうち、SACK の無い接続も使う部分)。
//!
//! 欄の意味は Go と同じです。
//!
//! - `sacked`:SACK 済みの記録の byte の和
//! - `loss_idx`:損失の境目。これより手前の SACK 済みでない記録は失われた (IsLost が真)
//! - `beyond_bytes`、`beyond_cnt`:境目から先 (境目の記録を含む) の SACK 済みの記録の byte の和と数
//! - `rtx_bytes`:今の再送の世代で再送した記録の byte の和
//! - `rxt_idx`、`rxt_off`:次に再送を考える記録と、その記録の中で送り終えた byte (RFC 6675 の HighRxt)
//! - `high_sack`:SACK 済みの記録の最も右の端
//!
//! pipe は SND.MAX - SND.UNA - sacked - (境目より手前の SACK 済みでない byte) + rtx_bytes です。
//! ACK 1 つの手間は、SACK の block の数 x log(記録の数) と、印付けの均した手間と、定数の更新の和を超えません。

use super::conn::{RecList, Tcb};
use super::ctx::{Conn, u32_of};
use super::rack::Which;
use super::{MS, RTX_FAST};
use crate::buf::records::{REC_IN_Q, REC_IN_T, REC_LOST, REC_RTX, REC_SACKED, Record, RecordRing};
use crate::seq;
use crate::wire::Segment;

// scoreboard の手間の数え (Go の `scoreSteps`) です。試験の build だけが数え、Go の試験と同じく ACK 1 つの手間の
// 上界を確かめます。型の大きさを製品と同じに保つため、欄ではなく thread の値に置きます。
#[cfg(test)]
std::thread_local! {
    static STEPS: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

/// scoreboard の手間を 1 つ数えます。製品の build では何もしません。
#[inline]
pub(crate) fn step() {
    #[cfg(test)]
    STEPS.set(STEPS.get() + 1);
}

/// この thread で数えた scoreboard の手間です。
#[cfg(test)]
pub(crate) fn steps() -> u64 {
    STEPS.get()
}

/// RFC 6675 の DupThresh です。
pub(crate) const DUP_THRESH: i64 = 3;

/// SACK の取り消しを疑ってから RTO の処理に移るまでの最短の時間です (Linux の tcp_check_sack_reneging と同じく
/// max(SRTT/2, 10 ms))。
const RENEGE_DELAY_MIN: i64 = 10 * MS;

/// 再送する記録の選び方です。`Queue` は RACK の損失の待ち行列、`Pos` は番号の順の手がかり (損失の境目より
/// 手前と規則 3)、`Tlp` は TLP の probe です。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Src {
    Pos,
    Queue,
    Tlp,
}

/// 再送に選んだ記録です。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Pick {
    pub(crate) i: usize,
    pub(crate) src: Src,
}

/// 記録の番号を `i32` の欄にします。記録の数は輪の容量 (1 万より小さい) 以下です。
pub(crate) fn idx32(i: usize) -> i32 {
    i32::try_from(i).unwrap_or(i32::MAX)
}

/// `i32` の欄の記録の番号です。負の値は 0 にします。
pub(crate) fn idx(i: i32) -> usize {
    usize::try_from(i).unwrap_or(0)
}

/// 失われた byte です。境目より手前の SACK 済みでない byte と、境目から先で RACK が失われたとみなした byte の
/// 和です。
pub(crate) fn lost_bytes(t: &Tcb, recs: &RecordRing) -> u32 {
    let loss = idx(t.loss_idx);
    let front = if loss < recs.len() {
        recs.get(loss).seq
    } else {
        t.snd_max
    };
    front
        .wrapping_sub(t.snd_una)
        .wrapping_sub(t.sacked.wrapping_sub(t.beyond_bytes))
        .wrapping_add(t.rack_lost_beyond)
}

/// RFC 6675 の送り残しの量を、増減で保つ欄から求めます。SACK を交渉しない接続では、回復の外の重複した ACK 2 つ
/// までを受け手が受けた segment とみなします (RFC 3042 の Limited Transmit、Linux の tcp_add_reno_sack)。
pub(crate) fn pipe(t: &Tcb, recs: &RecordRing) -> u32 {
    let mut p = t
        .snd_max
        .wrapping_sub(t.snd_una)
        .wrapping_sub(t.sacked)
        .wrapping_sub(lost_bytes(t, recs))
        .wrapping_add(t.rtx_bytes);
    if !t.sack_ok && !t.in_recovery && t.dup_acks > 0 {
        p -= p.min(reno_sacked(t));
    }
    p
}

/// SACK を交渉しない接続で、回復の外の重複した ACK が受け手に届いたとみなす byte です。
fn reno_sacked(t: &Tcb) -> u32 {
    let k = t.dup_acks.min(DUP_THRESH - 1);
    super::ctx::u32_of(k * i64::from(super::ctx::seg_mss(t)))
}

impl Conn<'_> {
    pub(crate) fn is_sacked(&mut self, i: usize) -> bool {
        let g = self.t.sack_gen;
        let r = self.b.recs.at(i);
        r.flags & REC_SACKED != 0 && r.sack_gen == g
    }

    pub(crate) fn rtx_live(&mut self, i: usize) -> bool {
        self.gen_flag(i, REC_RTX)
    }

    /// 記録 `i` が今の再送の世代で送り残しに入っていれば外します (損失か SACK 済みになった)。
    pub(crate) fn clear_rtx(&mut self, i: usize) {
        if self.rtx_live(i) {
            let r = self.b.recs.at(i);
            r.flags &= !REC_RTX;
            self.t.rtx_bytes = self.t.rtx_bytes.wrapping_sub(u32::from(r.length));
        }
    }

    /// 番号の順の再送の手がかり (RFC 6675 の HighRxt) を SND.UNA の記録の初めに戻します。
    pub(crate) fn reset_rxt(&mut self) {
        (self.t.rxt_idx, self.t.rxt_off, self.t.rxt_mid) = (0, 0, false);
    }

    /// RFC 6675 の送り残しの量です ([`pipe`])。
    pub(crate) fn pipe(&mut self) -> u32 {
        pipe(self.t, &self.b.recs)
    }

    /// 開始の番号が `seq` 以上の最初の記録の位置です。記録は番号の順に隙間なく並びます。
    pub(crate) fn first_rec_from(&mut self, seq: u32) -> usize {
        let una = self.t.snd_una;
        let key = seq.wrapping_sub(una);
        let (mut lo, mut hi) = (0, self.b.recs.len());
        while lo < hi {
            let mid = usize::midpoint(lo, hi);
            step();
            if self.b.recs.at(mid).seq.wrapping_sub(una) < key {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }

    /// SACK 済みの記録 `i` から続く SACK 済みの記録を飛ばし、SACK 済みでない最初の記録の位置 (無ければ記録の
    /// 数) を返します。たどった記録の `skip` を返す位置に書き直します (経路の圧縮)。
    #[expect(
        clippy::many_single_char_names,
        reason = "the names follow the Go code"
    )]
    pub(crate) fn next_unsacked(&mut self, i: usize) -> usize {
        let n = self.b.recs.len();
        let mut j = i;
        while j < n {
            if !self.is_sacked(j) {
                break;
            }
            step();
            j += idx(self.b.recs.at(j).skip).max(1);
        }
        let j = j.min(n);
        let mut k = i;
        while k < j {
            if !self.is_sacked(k) {
                break;
            }
            let r = self.b.recs.at(k);
            let next = k + idx(r.skip).max(1);
            r.skip = idx32(j - k);
            step();
            k = next;
        }
        j
    }

    /// segment の SACK の block で記録に印を付け、損失の境目を進めます。新しく SACK 済みになった byte を返します。
    /// block の 1 つでも範囲の外にあれば、segment の block をすべて捨てます。
    pub(crate) fn mark_sack(&mut self, seg: &Segment<'_>, now: i64) -> u32 {
        let blocks = seg.opt.sack_blocks();
        let Some(&b0) = blocks.first() else {
            return 0;
        };
        let t = &*self.t;
        let low = t.snd_una.wrapping_sub(t.max_snd_wnd);
        if blocks.iter().any(|b| {
            !seq::lt(b.left, b.right) || seq::lt(b.left, low) || seq::gt(b.right, t.snd_max)
        }) {
            return 0;
        }
        if !t.sack_ok {
            return 0;
        }
        // 先頭の block が確認済みの範囲か 2 つ目の block の内側なら D-SACK です (RFC 2883 4 節)。
        if !seq::gt(b0.right, t.snd_una)
            || blocks
                .get(1)
                .is_some_and(|b1| seq::le(b1.left, b0.left) && seq::le(b0.right, b1.right))
        {
            let (dup, tlp) = self.dsack_seen(b0);
            if dup > 0 {
                if !tlp {
                    self.rack_dsack();
                }
                self.note_undo_dsack(b0, dup, tlp);
            }
        }
        if self.b.recs.len() == 0 {
            return 0;
        }
        let before = self.t.sacked;
        for b in blocks {
            let una = self.t.snd_una;
            if !seq::gt(b.right, una) {
                continue; // D-SACK か、確認済みの範囲
            }
            let left = if seq::lt(b.left, una) { una } else { b.left };
            let key = b.right.wrapping_sub(una);
            let mut i = self.first_rec_from(left);
            while i < self.b.recs.len() {
                let r = *self.b.recs.at(i);
                step();
                if r.seq.wrapping_add(u32::from(r.length)).wrapping_sub(una) > key {
                    break;
                }
                if self.is_sacked(i) {
                    i = self.next_unsacked(i);
                    continue;
                }
                self.set_sacked(i, now);
                i += 1;
            }
        }
        self.advance_loss();
        self.t.sacked.wrapping_sub(before)
    }

    /// 位置 `i` の記録に SACK 済みの印を付け、欄を更新します。
    #[expect(
        clippy::many_single_char_names,
        reason = "the names follow the Go code"
    )]
    fn set_sacked(&mut self, i: usize, now: i64) {
        self.rack_delivered(i, now);
        self.unlink_rec(i);
        let l = u32::from(self.b.recs.at(i).length);
        if self.rack_lost(i) {
            if i >= idx(self.t.loss_idx) {
                self.t.rack_lost_beyond = self.t.rack_lost_beyond.wrapping_sub(l);
            }
            self.b.recs.at(i).flags &= !REC_LOST; // SACK の取り消しの後に損失の印が残らないように消します
        }
        let g = self.t.sack_gen;
        let r = self.b.recs.at(i);
        r.flags |= REC_SACKED;
        r.sack_gen = g;
        r.skip = 1;
        let end = r.seq.wrapping_add(l);
        let t = &mut *self.t;
        t.sacked_recs += 1;
        if t.sacked == 0 || seq::gt(end, t.high_sack) {
            t.high_sack = end;
        }
        t.sacked = t.sacked.wrapping_add(l);
        if i >= idx(t.loss_idx) {
            t.beyond_bytes = t.beyond_bytes.wrapping_add(l);
            t.beyond_cnt += 1;
        }
        self.clear_rtx(i);
    }

    /// 境目の記録より先の SACK 済みの量が RFC 6675 の閾値 (DupThresh 個の記録か (DupThresh - 1) x SMSS byte を
    /// 超える量) に届く間、境目を先へ進めます。境目は後ろへ戻りません。
    pub(crate) fn advance_loss(&mut self) {
        if self.t.reorder_seen {
            return; // 並べ替えを見た後は RACK だけで損失を決めます (Linux の tcp_time_to_recover)
        }
        let limit = u32_of((DUP_THRESH - 1) * i64::from(self.seg_mss()));
        while idx(self.t.loss_idx) < self.b.recs.len() {
            let i = idx(self.t.loss_idx);
            let (mut cnt, mut by) = (self.t.beyond_cnt, self.t.beyond_bytes);
            let s = self.is_sacked(i);
            if s {
                cnt -= 1;
                by = by.wrapping_sub(u32::from(self.b.recs.at(i).length));
            }
            if i64::from(cnt) < DUP_THRESH && by <= limit {
                return;
            }
            self.pass_loss(i, s);
        }
    }

    /// 境目を記録 `i` (境目の記録) の先へ進めます。`sacked` は記録が SACK 済みかです。
    pub(crate) fn pass_loss(&mut self, i: usize, sacked: bool) {
        if sacked {
            self.t.beyond_cnt -= 1;
            let l = u32::from(self.b.recs.at(i).length);
            self.t.beyond_bytes = self.t.beyond_bytes.wrapping_sub(l);
        } else {
            if self.rack_lost(i) {
                // 境目の手前の損失として数え直します。
                let l = u32::from(self.b.recs.at(i).length);
                self.t.rack_lost_beyond = self.t.rack_lost_beyond.wrapping_sub(l);
            }
            if self.gen_flag(i, REC_IN_T) && !self.rtx_live(i) {
                // 送り直しを待つので送り残しの list から外します。
                self.list_remove(Which::T, i, REC_IN_T);
            }
        }
        self.t.loss_idx += 1;
        step();
    }

    /// SACK 済みでない記録をすべて損失にし、再送の世代を進め、再送の手がかりを SND.UNA に戻します。RTO で
    /// 呼びます。手間は記録の数によりません (世代が一周した時だけ印を消して回ります)。
    pub(crate) fn mark_all_lost(&mut self, cause: u8) {
        let t = &mut *self.t;
        t.loss_idx = idx32(self.b.recs.len());
        (t.beyond_bytes, t.beyond_cnt) = (0, 0);
        t.rtx_gen = t.rtx_gen.wrapping_add(1);
        if t.rtx_gen == 0 {
            self.b
                .recs
                .clear_flags(REC_RTX | REC_IN_T | REC_IN_Q | REC_LOST);
        }
        let t = &mut *self.t;
        t.t_list = super::conn::RecList::default();
        t.lost_q = super::conn::RecList::default();
        (t.rack_lost_beyond, t.q_off, t.q_mid) = (0, 0, false);
        t.rtx_bytes = 0;
        self.reset_rxt();
        self.t.resend_cause = cause;
    }

    /// 中身が `payload` byte を超える、SACK 済みでも損失の待ち行列にもない記録を損失にします (PMTU の引き下げ)。
    /// 手間は記録の数に比例しますが、PMTU は下がる向きにしか変わらず 552 の下限で止まるので、接続ごとに起きる
    /// 回数は限られます。
    pub(crate) fn mark_lost_longer(&mut self, payload: u32, cause: u8) {
        for i in 0..self.b.recs.len() {
            let length = u32::from(self.b.recs.at(i).length);
            if length <= payload || self.is_sacked(i) || !self.gen_flag(i, REC_IN_T) {
                continue;
            }
            if i == 0 {
                // 先頭を古い大きさで分けて送っていた位置は捨て、新しい大きさで初めから送り直します。
                if self.t.lost_q.n > 0 && self.t.lost_q.head == self.rec_abs(0) {
                    (self.t.q_off, self.t.q_mid) = (0, false);
                }
                self.reset_rxt();
            }
            self.mark_rack_lost(i);
        }
        self.t.resend_cause = cause;
    }

    /// SACK の取り消しで、すべての記録の SACK 済みの印を世代の番号で消します。
    pub(crate) fn clear_sack(&mut self) {
        let t = &mut *self.t;
        t.sack_gen = t.sack_gen.wrapping_add(1);
        if t.sack_gen == 0 {
            self.b.recs.clear_flags(REC_SACKED);
        }
        let t = &mut *self.t;
        (t.sacked, t.beyond_bytes, t.beyond_cnt, t.sacked_recs) = (0, 0, 0, 0);
        self.s.stats.sack_reneging += 1;
    }

    /// 累積の確認で外す先頭の記録の分を欄から引き、位置の欄を 1 つ前へずらします。呼び手はこの後に記録を輪から
    /// 外し、`rec_base` を 1 つ進めます。
    pub(crate) fn drop_head(&mut self, now: i64) {
        let l = u32::from(self.b.recs.at(0).length);
        if !self.is_sacked(0) {
            self.rack_delivered(0, now);
        }
        if self.t.lost_q.n > 0 && self.t.lost_q.head == self.t.rec_base {
            (self.t.q_off, self.t.q_mid) = (0, false);
        }
        self.unlink_rec(0);
        if self.rack_lost(0) && self.t.loss_idx == 0 {
            self.t.rack_lost_beyond = self.t.rack_lost_beyond.wrapping_sub(l);
        }
        if self.is_sacked(0) {
            let t = &mut *self.t;
            t.sacked_recs -= 1;
            t.sacked = t.sacked.wrapping_sub(l);
            if t.loss_idx == 0 {
                t.beyond_bytes = t.beyond_bytes.wrapping_sub(l);
                t.beyond_cnt -= 1;
            }
        }
        if self.rtx_live(0) {
            self.t.rtx_bytes = self.t.rtx_bytes.wrapping_sub(l);
        }
        let t = &mut *self.t;
        if t.loss_idx > 0 {
            t.loss_idx -= 1;
        }
        if t.rxt_idx > 0 {
            t.rxt_idx -= 1;
        } else {
            (t.rxt_off, t.rxt_mid) = (0, false);
        }
    }

    /// 累積の確認が先頭の記録の内側に届いたとき、確認された `d` byte を記録から外します。
    pub(crate) fn trim_head(&mut self, d: u32) {
        if self.is_sacked(0) {
            self.t.sacked = self.t.sacked.wrapping_sub(d);
            if self.t.loss_idx == 0 {
                self.t.beyond_bytes = self.t.beyond_bytes.wrapping_sub(d);
            }
        }
        if self.rtx_live(0) {
            self.t.rtx_bytes = self.t.rtx_bytes.wrapping_sub(d);
        }
        if self.rack_lost(0) && self.t.loss_idx == 0 {
            self.t.rack_lost_beyond = self.t.rack_lost_beyond.wrapping_sub(d);
        }
        if self.t.lost_q.n > 0 && self.t.lost_q.head == self.t.rec_base {
            self.t.q_off -= self.t.q_off.min(d);
        }
        let r = self.b.recs.at(0);
        r.seq = r.seq.wrapping_add(d);
        r.length = r.length.wrapping_sub(u16::try_from(d).unwrap_or(u16::MAX));
        if self.t.rxt_idx == 0 {
            self.t.rxt_off -= self.t.rxt_off.min(d);
        }
    }

    /// NextSeg の規則 1 の記録を、RACK の損失の待ち行列の先頭と、番号の順の手がかりのうち番号の小さい方から
    /// 選びます。Linux と同じく番号の小さい穴から直すので、先頭の穴を先に送り直します。
    pub(crate) fn pick_rule1(&mut self) -> Option<Pick> {
        let q = self.next_queued();
        let p = self.next_resend();
        match (q, p) {
            (Some(q), p) if p.is_none_or(|p| q < p) => Some(Pick {
                i: q,
                src: Src::Queue,
            }),
            (_, Some(p)) => Some(Pick {
                i: p,
                src: Src::Pos,
            }),
            _ => None,
        }
    }

    pub(crate) fn pick_rule3(&mut self) -> Option<Pick> {
        self.next_rule3().map(|i| Pick { i, src: Src::Pos })
    }

    /// 選んだ記録の中で送り終えた byte です。
    pub(crate) fn pick_off(&self, p: Pick) -> u32 {
        match p.src {
            Src::Queue => self.t.q_off,
            Src::Pos => self.t.rxt_off,
            Src::Tlp => 0,
        }
    }

    /// RFC 6675 の NextSeg の規則 1 の記録 (SACK 済みでなく、失われ、今の世代で再送していない記録) の位置です。
    /// 手がかりは前へだけ進むので、手間は均すと記録ごとに定数です。
    pub(crate) fn next_resend(&mut self) -> Option<usize> {
        self.next_resend_up_to(idx(self.t.loss_idx))
    }

    /// NextSeg の規則 3 の記録 (SACK 済みでなく、今の世代で再送しておらず、最も右の SACK 済みの byte より手前に
    /// ある記録) の位置です。回復の中で、規則 1 と 2 で送るものが無いときだけ使います。
    pub(crate) fn next_rule3(&mut self) -> Option<usize> {
        if !self.t.in_recovery || self.t.sacked == 0 {
            return None;
        }
        let n = self.b.recs.len();
        let i = self.next_resend_up_to(n)?;
        seq::lt(self.b.recs.at(i).seq, self.t.high_sack).then_some(i)
    }

    fn next_resend_up_to(&mut self, limit: usize) -> Option<usize> {
        loop {
            let x = idx(self.t.rxt_idx);
            if x >= limit || x >= self.b.recs.len() {
                return None;
            }
            step();
            if self.is_sacked(x) {
                self.t.rxt_idx = idx32(self.next_unsacked(x));
                (self.t.rxt_off, self.t.rxt_mid) = (0, false);
            } else if self.rtx_live(x) && !self.t.rxt_mid {
                self.t.rxt_idx += 1;
            } else {
                return Some(x);
            }
        }
    }

    /// 記録 `i` の中の `off` byte 目から再送する segment の中身の長さと、FIN を付けるかを返します。
    pub(crate) fn resend_len(&mut self, i: usize, off: u32, pay_cap: i64) -> (u32, bool) {
        let r = *self.b.recs.at(i);
        let len = u32::from(r.length);
        if off >= len {
            return (0, false); // 位置が記録の外:送るものはありません
        }
        let start = r.seq.wrapping_add(off);
        let end = r.seq.wrapping_add(len);
        let de = self.data_end_seq();
        let left = if seq::lt(start, de) {
            seq::min(end, de).wrapping_sub(start)
        } else {
            0
        };
        let n = left.min(super::ctx::u32_of(pay_cap.max(0)));
        let fin = self.t.fin_sent && n == left && seq::gt(end, de);
        (n, fin)
    }

    /// SACK による回復に入ります (RFC 6675 5 節、RFC 6937。RecoverFS は RFC 9937)。先頭の記録は損失とみなします。
    /// `delivered` は回復に入る ACK が累積の確認と SACK で新しく届けたと知らせた byte です。
    fn enter_recovery(&mut self, delivered: u32) {
        self.enter_fast_recovery();
        let t = &*self.t;
        let k = &mut *self.k;
        (k.prr_delivered, k.prr_out) = (0, 0);
        // RFC 9937 6.1 の RecoverFS:回復の間に届くかもしれない byte。回復の前に SACK 済みの byte は回復の間に
        // 届いたと数えないので引き、この ACK が届けた byte は足します。
        k.recover_fs = t
            .snd_max
            .wrapping_sub(t.snd_una)
            .wrapping_sub(t.sacked)
            .wrapping_add(delivered);
        self.reset_rxt();
        self.t.resend_cause = RTX_FAST;
        let t = &*self.t;
        if t.loss_idx == 0 && t.rack_lost_beyond == 0 && t.lost_q.n == 0 && self.b.recs.len() > 0 {
            let s = self.is_sacked(0);
            self.pass_loss(0, s);
            self.advance_loss();
        }
    }

    /// 回復の中の ACK ごとに、PRR (RFC 6937 の PRR-SSRB) で輻輳の窓を決めます。`delivered` はこの ACK が累積の
    /// 確認と SACK で新しく届けたと知らせた byte です。
    fn prr_update(&mut self, delivered: u32) {
        let mss = i64::from(self.seg_mss());
        self.k.prr_delivered = self.k.prr_delivered.wrapping_add(delivered);
        let pipe = i64::from(self.pipe());
        let t = &mut *self.t;
        let k = &*self.k;
        let ss = i64::from(t.ssthresh);
        let (pd, po) = (i64::from(k.prr_delivered), i64::from(k.prr_out));
        let mut sndcnt = if pipe > ss {
            let fs = i64::from(k.recover_fs).max(1);
            (pd * ss + fs - 1) / fs - po
        } else {
            let limit = (pd - po).max(i64::from(delivered)) + mss;
            (ss - pipe).min(limit)
        };
        sndcnt = sndcnt.max(0);
        if k.prr_out == 0 && sndcnt < mss {
            sndcnt = mss; // 回復に入った時の最初の再送 (Linux の tcp_cwnd_reduction)
        }
        t.cwnd = u32_of((pipe + sndcnt).min(1 << 30));
    }

    /// SACK を交渉した接続で、ACK の処理の後に回復に入るかを決め、回復の中なら窓を決めます。
    pub(crate) fn sack_after_ack(&mut self, delivered: u32) {
        let t = &*self.t;
        let lost = t.loss_idx > 0 || t.rack_lost_beyond > 0 || t.lost_q.n > 0;
        let dup_entry = t.dup_acks >= DUP_THRESH && !t.reorder_seen;
        if !t.in_recovery
            && t.snd_una != t.snd_max
            && seq::ge(t.snd_una, t.recover)
            && (dup_entry || lost)
        {
            self.enter_recovery(delivered);
        }
        if self.t.in_recovery {
            self.prr_update(delivered);
        }
    }

    /// 累積の確認の後も先頭の記録が SACK 済みのとき (相手が SACK 済みのデータを捨てた疑い)、再送のタイマーを
    /// max(SRTT/2, 10 ms) に早めます。期限までに直す ACK が来なければ、RTO の処理が印を消します。
    pub(crate) fn renege_timer(&mut self, now: i64) {
        if self.t.persist || self.b.recs.len() == 0 || !self.is_sacked(0) {
            return;
        }
        let at = now + (self.t.srtt / 2).max(RENEGE_DELAY_MIN);
        if self.t.rto_at == 0 || at < self.t.rto_at {
            self.set_rto(at);
        }
    }
}

/// 記録 `r` が今の世代の印 `f` を持つかです。
fn gen_flag(t: &Tcb, r: &Record, f: u8) -> bool {
    r.flags & f != 0 && r.rtx_gen == t.rtx_gen
}

/// 使っている接続の送り手の状態を確かめます (`check_invariants`)。Go の敵対的な送り手の試験 (`runAudit`) が
/// 各段の後に確かめることと `checkScoreboard` を写します。SND.UNA ≤ SND.NXT ≤ SND.MAX と輻輳の窓が 0 でない
/// ことを確かめ、[`check_scoreboard`] で scoreboard と pipe を数え直し、分けて送っている記録の中の位置
/// (`q_off`、`rxt_off`) がその記録の長さより小さいことを確かめます。Go の「pipe は送り残しの 2 倍と 1 以下」は
/// 別に確かめません。定義どおりの pipe は 2 つの和を足した値です。1 つは損失の境目から先の SACK 済みでなく
/// 失われてもいない記録の長さの和、もう 1 つは SACK 済みでなく今の世代の再送の印を持つ記録の長さの和で、どちらも
/// 送り残し以下です。数え直した pipe と一致すれば、この上限も満たします。
pub(crate) fn check_sender(t: &Tcb, recs: &RecordRing) -> Result<(), &'static str> {
    if seq::gt(t.snd_una, t.snd_nxt) || seq::gt(t.snd_nxt, t.snd_max) {
        return Err("the send sequence numbers are out of order");
    }
    if t.cwnd == 0 {
        return Err("the congestion window is zero");
    }
    check_scoreboard(t, recs)?;
    if t.q_mid {
        if t.lost_q.n == 0 {
            return Err("a split lost queue retransmission has no lost queue");
        }
        // list の節は check_scoreboard が範囲の内にあることを確かめました。
        let head = recs.get(t.lost_q.head.wrapping_sub(t.rec_base) as usize);
        if t.q_off >= u32::from(head.length) {
            return Err("the split lost queue offset passes its record");
        }
    }
    if t.rxt_mid
        && let Ok(i) = usize::try_from(t.rxt_idx)
        && i < recs.len()
        && t.rxt_off >= u32::from(recs.get(i).length)
    {
        return Err("the split retransmission offset passes its record");
    }
    Ok(())
}

/// 接続の scoreboard の欄を記録から数え直し、増減で保つ値と比べます。記録が SND.UNA から
/// SND.MAX まで隙間なく並ぶこと、SACK 済みの byte と数、境目から先の byte と数、送り残しの再送の byte、境目から先の
/// RACK の損失の byte、位置の欄の範囲、SACK 済みの記録の飛ばし先、2 つの list の節と印と数と順、SACK 済みでない
/// 記録がどこかの list にあるか境目の手前で送り直しを待つことを確かめます。手間は記録の数に比例します。
#[expect(
    clippy::many_single_char_names,
    reason = "the names follow the Go code"
)]
pub(crate) fn check_scoreboard(t: &Tcb, recs: &RecordRing) -> Result<(), &'static str> {
    let n = recs.len();
    if usize::try_from(t.loss_idx).map_or(true, |i| i > n)
        || usize::try_from(t.rxt_idx).map_or(true, |i| i > n)
    {
        return Err("a scoreboard position is out of range");
    }
    let loss = idx(t.loss_idx);
    let sacked = |r: &Record| r.flags & REC_SACKED != 0 && r.sack_gen == t.sack_gen;
    let (mut by, mut beyond_by, mut rtx, mut lost_beyond) = (0u32, 0u32, 0u32, 0u32);
    // RFC 6675 の定義どおりの pipe です。
    let mut def_pipe = 0u64;
    let mut high = None;
    let (mut cnt, mut beyond_cnt) = (0i32, 0i32);
    let mut s = t.snd_una;
    for i in 0..n {
        let r = recs.get(i);
        if r.seq != s {
            return Err("the send records do not cover SND.UNA to SND.MAX");
        }
        let l = u32::from(r.length);
        s = s.wrapping_add(l);
        let in_t = gen_flag(t, r, REC_IN_T);
        let in_q = gen_flag(t, r, REC_IN_Q);
        if gen_flag(t, r, REC_RTX) {
            rtx = rtx.wrapping_add(l);
        }
        if sacked(r) {
            cnt += 1;
            by = by.wrapping_add(l);
            high = Some(s);
            if i >= loss {
                beyond_cnt += 1;
                beyond_by = beyond_by.wrapping_add(l);
            }
            if in_t || in_q {
                return Err("a SACKed record is in a record list");
            }
            continue;
        }
        if gen_flag(t, r, REC_LOST) && i >= loss {
            lost_beyond = lost_beyond.wrapping_add(l);
        }
        if i >= loss && !gen_flag(t, r, REC_LOST) {
            def_pipe += u64::from(l);
        }
        if gen_flag(t, r, REC_RTX) {
            def_pipe += u64::from(l);
        }
        if in_t && in_q {
            return Err("a send record is in both record lists");
        }
        if i < loss && in_t && !gen_flag(t, r, REC_RTX) {
            return Err("a record before the loss frontier waits on the transmit list");
        }
        let waits = i < loss && !gen_flag(t, r, REC_RTX);
        if !in_t && !in_q && !waits {
            return Err("an unSACKed send record is in no list");
        }
    }
    // 飛ばし先は SACK 済みでない次の記録を越えません。後ろからたどり、手間を記録の数に比例させます。
    let mut next_unsacked = n;
    for i in (0..n).rev() {
        let r = recs.get(i);
        if !sacked(r) {
            next_unsacked = i;
            continue;
        }
        let skip = usize::try_from(r.skip).unwrap_or(0);
        if skip == 0 || (next_unsacked < n && i + skip > next_unsacked) {
            return Err("a SACK skip passes an unSACKed record");
        }
    }
    if n > 0 && s != t.snd_max {
        return Err("the send records do not cover SND.UNA to SND.MAX");
    }
    if (by, cnt, beyond_by, beyond_cnt, rtx, lost_beyond)
        != (
            t.sacked,
            t.sacked_recs,
            t.beyond_bytes,
            t.beyond_cnt,
            t.rtx_bytes,
            t.rack_lost_beyond,
        )
    {
        return Err("the SACK scoreboard sums disagree with the send records");
    }
    if t.sacked > 0 && high != Some(t.high_sack) {
        return Err("the highest SACKed byte disagrees with the send records");
    }
    if !t.sack_ok && !t.in_recovery && t.dup_acks > 0 {
        def_pipe -= def_pipe.min(u64::from(reno_sacked(t)));
    }
    if def_pipe != u64::from(pipe(t, recs)) {
        return Err("pipe disagrees with the send records");
    }
    check_list(t, recs, t.t_list, REC_IN_T, true)?;
    check_list(t, recs, t.lost_q, REC_IN_Q, false)
}

/// list `l` を先頭からたどり、節と印と数が合うこと、`time_order` なら送った時刻の順であることを確かめます。
#[expect(
    clippy::many_single_char_names,
    reason = "the names follow the Go code"
)]
fn check_list(
    t: &Tcb,
    recs: &RecordRing,
    l: RecList,
    flag: u8,
    time_order: bool,
) -> Result<(), &'static str> {
    const BROKEN: &str = "a send record list is broken";
    let n = recs.len();
    let len = usize::try_from(l.n).map_err(|_| BROKEN)?;
    let mut a = l.head;
    let mut last = None;
    for k in 0..len {
        let i = a.wrapping_sub(t.rec_base) as usize;
        if i >= n {
            return Err(BROKEN);
        }
        let r = recs.get(i);
        if !gen_flag(t, r, flag) {
            return Err(BROKEN);
        }
        if time_order && last.is_some_and(|x| r.sent_at < x) {
            return Err("the transmit list is out of time order");
        }
        last = Some(r.sent_at);
        if k + 1 == len {
            if a != l.tail || r.next != 0 {
                return Err(BROKEN);
            }
        } else if r.next == 0 {
            return Err(BROKEN);
        }
        a = a.wrapping_add_signed(r.next);
    }
    if (0..n).filter(|&i| gen_flag(t, recs.get(i), flag)).count() != len {
        return Err(BROKEN);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! `check_scoreboard` の検出の 1 つずつに、壊した状態を渡します。

    #![expect(
        clippy::disallowed_methods,
        clippy::cast_possible_truncation,
        reason = "test setup"
    )]

    use super::*;
    use crate::testnet_tests::{TestNet, small_limits};
    use crate::wire::SackBlock;

    /// SACK を交渉し、記録をいくつか送り、最後の記録だけを SACK した接続です。
    fn sacked_net() -> (TestNet, u32) {
        let (mut n, i, s) = sent_net();
        n.inject(&s);
        (n, i)
    }

    /// SACK を交渉して記録をいくつか送った接続と、最後の記録を SACK する相手の segment です。RACK は ACK の
    /// 時刻で先の記録を損失の待ち行列に移すので、SACK の前の記録は送った時刻の順の list にあります。
    fn sent_net() -> (TestNet, u32, crate::testnet_tests::TSeg) {
        let mut n = TestNet::new(small_limits());
        let (c, mut p) = n.accepted_sack(true, true);
        let data = [0u8; 10 * 1000];
        let mut off = 0;
        while off < data.len() {
            off += n.s.write(n.now, c, &data[off..]).unwrap();
        }
        let outs = n.drain();
        assert!(outs.len() >= 6);
        let mut s = p.seg(crate::wire::FLAG_ACK, &[]);
        s.sack = [SackBlock {
            left: outs[outs.len() - 1].seq,
            right: outs[outs.len() - 1]
                .seq
                .wrapping_add(outs[outs.len() - 1].payload.len() as u32),
        }]
        .to_vec();
        (n, c.slot, s)
    }

    fn check(n: &mut TestNet, i: u32) -> Result<(), &'static str> {
        let c = n.s.conn(i);
        check_sender(c.t, &c.b.recs)
    }

    #[test]
    fn each_broken_scoreboard_is_caught() {
        type Break = fn(&mut Conn<'_>);
        let cases: [(Break, &str); 18] = [
            (
                |c| c.t.snd_nxt = c.t.snd_max.wrapping_add(1),
                "the send sequence numbers are out of order",
            ),
            (
                |c| c.t.snd_una = c.t.snd_nxt.wrapping_add(1),
                "the send sequence numbers are out of order",
            ),
            (|c| c.t.cwnd = 0, "the congestion window is zero"),
            // drop_head や clear_rtx が rtx_bytes を減らし忘れた形です。
            (
                |c| c.t.rtx_bytes += 1,
                "the SACK scoreboard sums disagree with the send records",
            ),
            // SACK 済みの記録が再送の印を残すと、和は合っても pipe が定義と合いません。
            (
                |c| {
                    let last = c.b.recs.len() - 1;
                    let g = c.t.rtx_gen;
                    let r = c.b.recs.at(last);
                    (r.flags, r.rtx_gen) = (r.flags | REC_RTX, g);
                    let l = u32::from(r.length);
                    c.t.rtx_bytes += l;
                },
                "pipe disagrees with the send records",
            ),
            (
                |c| (c.t.q_mid, c.t.q_off) = (true, u32::MAX),
                "the split lost queue offset passes its record",
            ),
            (
                |c| (c.t.rxt_mid, c.t.rxt_idx, c.t.rxt_off) = (true, 0, u32::MAX),
                "the split retransmission offset passes its record",
            ),
            (
                |c| c.t.loss_idx = 1000,
                "a scoreboard position is out of range",
            ),
            (
                |c| c.b.recs.at(1).seq ^= 1,
                "the send records do not cover SND.UNA to SND.MAX",
            ),
            (
                |c| c.t.snd_max = c.t.snd_max.wrapping_add(1),
                "the send records do not cover SND.UNA to SND.MAX",
            ),
            (
                |c| c.t.sacked += 1,
                "the SACK scoreboard sums disagree with the send records",
            ),
            (
                |c| {
                    let last = c.b.recs.len() - 1;
                    c.b.recs.at(last).skip = 0;
                },
                "a SACK skip passes an unSACKed record",
            ),
            (
                |c| {
                    let last = c.b.recs.len() - 1;
                    c.b.recs.at(last).flags |= REC_IN_T;
                },
                "a SACKed record is in a record list",
            ),
            (
                |c| c.b.recs.at(0).flags |= REC_IN_Q | REC_IN_T,
                "a send record is in both record lists",
            ),
            (
                |c| c.b.recs.at(0).flags &= !REC_IN_Q,
                "an unSACKed send record is in no list",
            ),
            (|c| c.t.t_list.n += 1, "a send record list is broken"),
            (
                |c| c.t.high_sack = c.t.high_sack.wrapping_sub(1),
                "the highest SACKed byte disagrees with the send records",
            ),
            (
                |c| {
                    c.t.loss_idx = 1;
                    let r = c.b.recs.at(0);
                    r.flags = (r.flags & !REC_IN_Q) | REC_IN_T;
                },
                "a record before the loss frontier waits on the transmit list",
            ),
        ];
        for (brk, want) in cases {
            let (mut n, i) = sacked_net();
            check(&mut n, i).unwrap();
            brk(&mut n.s.conn(i));
            assert_eq!(check(&mut n, i), Err(want));
        }
        // 損失の待ち行列が空のまま、その先頭を分けて送っている印です。
        let (mut n, i, _) = sent_net();
        check(&mut n, i).unwrap();
        n.s.conn(i).t.q_mid = true;
        assert_eq!(
            check(&mut n, i),
            Err("a split lost queue retransmission has no lost queue")
        );
        // 送った時刻の順を崩します。
        let (mut n, i, _) = sent_net();
        let c = n.s.conn(i);
        let head = c.rec_idx(c.t.t_list.head);
        c.b.recs.at(head).sent_at = crate::time::Time::from_nanos(u64::MAX);
        assert_eq!(
            check(&mut n, i),
            Err("the transmit list is out of time order")
        );
    }
}
