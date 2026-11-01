//! 送信の記録の list (Go の `rack.go` の list の部分)。
//!
//! 送り残しの記録は、送った時刻の順の list (`t_list`) と損失の待ち行列 (`lost_q`) のどちらかに入るか、どちらにも
//! 入りません。list の節は記録の `prev` と `next` で、自分の位置からの記録の数の差 (0 は無し) で持つので、輪の
//! 大きさを変えても、先頭の記録を外しても変わりません。list に入っている印と RACK の損失の印は、再送の印と同じく
//! 記録の `rtx_gen` が接続の世代と等しいときだけ有効で、RTO は世代を進めて list を一度に空にします。
//!
//! RACK の損失の判定と TLP は SACK の段 (PR 5) が足します。この段は list の出し入れと、損失の待ち行列の先頭を
//! 選ぶところまでです。

use super::conn::RecList;
use super::ctx::Conn;
use crate::buf::records::{REC_IN_Q, REC_IN_T, REC_LOST, REC_RTX, Record};

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
            if !self.is_sacked(i) && (!self.rtx_live(i) || self.t.q_mid) {
                return Some(i);
            }
            self.list_remove(Which::Q, i, REC_IN_Q); // 先頭なので、分けて送った位置も戻します
        }
        None
    }
}
