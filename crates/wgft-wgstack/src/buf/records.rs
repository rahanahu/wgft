//! 送信の記録の輪 (Go の `records.go` の写し)。
//!
//! 記録は送った segment 1 つの開始の番号、長さ、送った時刻、印を持ちます。記録の境目は送った時のまま変えず、
//! 再送は既存の記録をたどります。`prev` と `next` は RACK の送った時刻の順の list と損失の待ち行列の節で、
//! 自分からの記録の数の差で持ちます。`skip`、`sack_gen`、`rtx_gen` は SACK の scoreboard の欄です。

use crate::fixed_vec::FixedVec;
use crate::time::Time;

/// 送った segment 1 つの記録です。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Record {
    /// 送った時刻です。再送のたびに更新します。
    pub(crate) sent_at: Time,
    /// 開始のシーケンス番号です。
    pub(crate) seq: u32,
    pub(crate) prev: i32,
    pub(crate) next: i32,
    /// SACK 済みの記録から、SACK 済みでないかもしれない次の記録までの数です。
    pub(crate) skip: i32,
    /// 中身の長さです。FIN を含む segment は FIN の 1 を足します。
    pub(crate) length: u16,
    pub(crate) flags: u8,
    pub(crate) sack_gen: u8,
    pub(crate) rtx_gen: u8,
}

/// 1 度でも再送した (Karn の規則)。
pub(crate) const REC_RETRANSMITTED: u8 = 1;
/// SACK 済み。`sack_gen` が接続の世代と等しいときだけ有効です。
pub(crate) const REC_SACKED: u8 = 1 << 1;
/// 再送が送り残しに入っている。`rtx_gen` が接続の世代と等しいときだけ有効です。
pub(crate) const REC_RTX: u8 = 1 << 2;
/// 送った時刻の順の list にある。
pub(crate) const REC_IN_T: u8 = 1 << 3;
/// RACK の損失の待ち行列にある。
pub(crate) const REC_IN_Q: u8 = 1 << 4;
/// RACK が失われたとみなした。
pub(crate) const REC_LOST: u8 = 1 << 5;

/// 送信の記録の固定の容量の輪です。容量は送信のバッファの予約を送り残しの下限で割った数です。
/// 満杯の間は新しい segment を送りません。配列は floor の配列か、`Budget` から借りた boost の配列です。
#[derive(Debug, Default)]
pub(crate) struct RecordRing {
    recs: FixedVec<Record>,
    head: usize,
    n: usize,
}

impl RecordRing {
    /// 長さが容量の配列 `recs` を輪にします。
    pub(crate) fn new(recs: FixedVec<Record>) -> Self {
        Self {
            recs,
            head: 0,
            n: 0,
        }
    }

    pub(crate) fn capacity(&self) -> usize {
        self.recs.len()
    }

    pub(crate) fn len(&self) -> usize {
        self.n
    }

    pub(crate) fn full(&self) -> bool {
        self.n == self.recs.len()
    }

    /// 先頭から `i` 番目の記録です。
    pub(crate) fn at(&mut self, i: usize) -> &mut Record {
        let len = self.recs.len();
        &mut self.recs[(self.head + i) % len]
    }

    /// 末尾に記録を足します。呼び手は満杯でないことを確かめます。
    pub(crate) fn push_back(&mut self, rec: Record) {
        debug_assert!(!self.full());
        let len = self.recs.len();
        self.recs[(self.head + self.n) % len] = rec;
        self.n += 1;
    }

    /// 先頭の記録を外します。
    pub(crate) fn pop(&mut self) {
        debug_assert!(self.n > 0);
        self.head = (self.head + 1) % self.recs.len();
        self.n -= 1;
    }

    /// 配列のすべての記録 (使っていない位置を含む) から印 `mask` を消します。世代の番号が一周した時に使います。
    pub(crate) fn clear_flags(&mut self, mask: u8) {
        for r in self.recs.iter_mut() {
            r.flags &= !mask;
        }
    }

    /// 記録をすべて外します。配列は持ち続けます。
    pub(crate) fn clear(&mut self) {
        self.head = 0;
        self.n = 0;
    }

    /// 記録を配列 `next` に移し、前の配列を返します。呼び手は記録の数が `next` の長さ以下であることを
    /// 保証します。
    pub(crate) fn resize(&mut self, mut next: FixedVec<Record>) -> FixedVec<Record> {
        debug_assert!(self.n <= next.len());
        for i in 0..self.n {
            next[i] = *self.at(i);
        }
        self.head = 0;
        core::mem::replace(&mut self.recs, next)
    }

    /// 配列を取り出し、空の輪にします。
    pub(crate) fn take(&mut self) -> FixedVec<Record> {
        self.clear();
        core::mem::take(&mut self.recs)
    }

    /// 配列が確保した byte 数です。
    pub(crate) fn heap_bytes(&self) -> usize {
        self.recs.heap_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(seq: u32) -> Record {
        Record {
            seq,
            ..Record::default()
        }
    }

    #[test]
    fn ring_wraps_and_moves() {
        let mut r = RecordRing::new(FixedVec::try_filled(3, |_| Record::default()).unwrap());
        for s in 1..=3 {
            r.push_back(rec(s));
        }
        assert!(r.full());
        r.pop();
        r.push_back(rec(4));
        assert_eq!((r.at(0).seq, r.at(2).seq), (2, 4));
        let old = r.resize(FixedVec::try_filled(5, |_| Record::default()).unwrap());
        assert_eq!(old.len(), 3);
        assert_eq!(
            (r.capacity(), r.len(), r.at(0).seq, r.at(2).seq),
            (5, 3, 2, 4)
        );
        r.at(1).flags |= REC_SACKED | REC_RETRANSMITTED;
        assert_eq!(r.at(1).flags, 3);
        let arr = r.take();
        assert_eq!((arr.len(), r.capacity(), r.len()), (5, 0, 0));
        assert_eq!(r.heap_bytes(), 0);
    }
}
