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
//! SACK の印付けと SACK による回復 (RFC 6675、PRR) は SACK の段 (PR 5) が足します。

use super::ctx::Conn;
use super::rack::Which;
use crate::buf::records::{REC_IN_Q, REC_IN_T, REC_LOST, REC_RTX, REC_SACKED};
use crate::seq;

/// RFC 6675 の DupThresh です。
pub(crate) const DUP_THRESH: i64 = 3;

/// 再送する記録の選び方です。`Queue` は RACK の損失の待ち行列、`Pos` は番号の順の手がかり (損失の境目より
/// 手前と規則 3) です。TLP の probe は SACK の段が足します。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Src {
    Pos,
    Queue,
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

    /// 失われた byte です。境目より手前の SACK 済みでない byte と、境目から先で RACK が失われたとみなした byte の
    /// 和です。
    pub(crate) fn lost_bytes(&mut self) -> u32 {
        let t = &*self.t;
        let loss = idx(t.loss_idx);
        let front = if loss < self.b.recs.len() {
            self.b.recs.at(loss).seq
        } else {
            t.snd_max
        };
        let t = &*self.t;
        front
            .wrapping_sub(t.snd_una)
            .wrapping_sub(t.sacked.wrapping_sub(t.beyond_bytes))
            .wrapping_add(t.rack_lost_beyond)
    }

    /// RFC 6675 の送り残しの量です。SACK を交渉しない接続では、回復の外の重複した ACK 2 つまでを受け手が受けた
    /// segment とみなします (RFC 3042 の Limited Transmit、Linux の tcp_add_reno_sack)。
    pub(crate) fn pipe(&mut self) -> u32 {
        let lost = self.lost_bytes();
        let t = &*self.t;
        let mut p = t
            .snd_max
            .wrapping_sub(t.snd_una)
            .wrapping_sub(t.sacked)
            .wrapping_sub(lost)
            .wrapping_add(t.rtx_bytes);
        if !t.sack_ok && !t.in_recovery && t.dup_acks > 0 {
            let k = t.dup_acks.min(DUP_THRESH - 1);
            let mss = i64::from(self.seg_mss());
            p -= p.min(super::ctx::u32_of(k * mss));
        }
        p
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
            k = next;
        }
        j
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

    /// 累積の確認で外す先頭の記録の分を欄から引き、位置の欄を 1 つ前へずらします。呼び手はこの後に記録を輪から
    /// 外し、`rec_base` を 1 つ進めます。RACK の状態の更新は SACK の段 (PR 5) が足します。
    pub(crate) fn drop_head(&mut self) {
        let l = u32::from(self.b.recs.at(0).length);
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
}
