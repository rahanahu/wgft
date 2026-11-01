//! boost の枠の集まり (wgstack-rs.md の「予算の持ち主」、Go の `boost.go` の `boostPool`)。
//!
//! Go の枠の集まりはプロセスで 1 つで、トンネルを作り直しても増えません。Rust では枠の集まりを `Budget` という
//! 値にし、核がそれを所有します。トンネルを作り直すときは、古い核の `close` が返す `Budget` を新しい核に渡します。
//! B 本の枠の分の boost の記録の輪と区間の表は `Budget` の作成の時に確保し、boost を得た接続はその 1 組を借り、
//! floor に戻るか閉じるときに返します。このため boost の取得の時に確保が失敗する場合はありません。
//! 枠を貸す順 (最も小さい空きの枠) と保有者をたどる順 (枠の順) は Go と同じです。

use crate::buf::records::Record;
use crate::buf::recv::Interval;
use crate::buf::{BOOST_INTERVALS, BOOST_RECORDS, BOOST_SLOTS};
use crate::fixed_vec::{AllocError, FixedVec};
use crate::tcp::conn::ConnId;

#[derive(Debug)]
struct Slot {
    holder: Option<ConnId>,
    /// 貸していない間の boost の配列です。貸している間は空です。
    recs: FixedVec<Record>,
    iv: FixedVec<Interval>,
}

/// boost の枠の集まりです。プロセスで 1 つ作り、核から核へ渡します。
#[derive(Debug)]
pub struct Budget {
    slots: FixedVec<Slot>,
}

/// `Budget` を作れなかった理由です。確保に失敗しました。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetError;

impl core::fmt::Display for BudgetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("cannot allocate the boost arrays")
    }
}

impl core::error::Error for BudgetError {}

impl From<AllocError> for BudgetError {
    fn from(_: AllocError) -> Self {
        Self
    }
}

impl Budget {
    /// 枠と boost の配列をすべて確保します。
    pub fn new() -> Result<Self, BudgetError> {
        let mut slots = FixedVec::try_with_capacity(BOOST_SLOTS)?;
        for _ in 0..BOOST_SLOTS {
            let slot = Slot {
                holder: None,
                recs: FixedVec::try_filled(BOOST_RECORDS, |_| Record::default())?,
                iv: FixedVec::try_filled(BOOST_INTERVALS, |_| Interval::default())?,
            };
            if slots.try_push(slot).is_err() {
                return Err(BudgetError);
            }
        }
        Ok(Self { slots })
    }

    /// 枠の管理の配列の byte 数 (boost の配列を除く) です。上界が数えます。
    pub(crate) fn slot_bytes() -> usize {
        BOOST_SLOTS * size_of::<Slot>()
    }

    /// 枠の数 (B) です。
    pub fn slots(&self) -> usize {
        self.slots.len()
    }

    /// 貸している枠の数です。
    pub fn lent(&self) -> usize {
        self.slots.iter().filter(|s| s.holder.is_some()).count()
    }

    /// 枠の管理と、貸していない boost の配列が確保した byte 数です。
    pub(crate) fn heap_bytes(&self) -> usize {
        self.slots.heap_bytes()
            + self
                .slots
                .iter()
                .map(|s| s.recs.heap_bytes() + s.iv.heap_bytes())
                .sum::<usize>()
    }

    /// `c` が持つ枠の番号です。
    pub(crate) fn held_by(&self, c: ConnId) -> Option<usize> {
        self.slots.iter().position(|s| s.holder == Some(c))
    }

    /// 最も小さい空きの枠を `c` に貸し、番号と boost の配列を返します。`c` が既に持つか空きが無ければ `None` です。
    pub(crate) fn acquire(
        &mut self,
        c: ConnId,
    ) -> Option<(usize, FixedVec<Record>, FixedVec<Interval>)> {
        if self.held_by(c).is_some() {
            return None;
        }
        let i = self.slots.iter().position(|s| s.holder.is_none())?;
        let s = &mut self.slots[i];
        s.holder = Some(c);
        Some((i, core::mem::take(&mut s.recs), core::mem::take(&mut s.iv)))
    }

    /// 枠 `i` の保有者を `c` に替えます。枠の取り合いで、floor に戻した保有者の枠を受け取る時に使います。
    /// 配列は前の保有者から返してもらってから貸します。
    pub(crate) fn hand_over(&mut self, i: usize, c: ConnId) {
        self.slots[i].holder = Some(c);
    }

    /// 枠 `i` の保有者です。保有者をたどる順は枠の番号の順です。
    pub(crate) fn holder(&self, i: usize) -> Option<ConnId> {
        self.slots[i].holder
    }

    /// 枠 `i` に配列を返し、枠を空きにします。
    pub(crate) fn release(&mut self, i: usize, recs: FixedVec<Record>, iv: FixedVec<Interval>) {
        let s = &mut self.slots[i];
        s.holder = None;
        s.recs = recs;
        s.iv = iv;
    }

    /// 枠 `i` の配列を借ります (保有者は変えません)。
    pub(crate) fn take_arrays(&mut self, i: usize) -> (FixedVec<Record>, FixedVec<Interval>) {
        let s = &mut self.slots[i];
        (core::mem::take(&mut s.recs), core::mem::take(&mut s.iv))
    }

    /// 枠 `i` に配列を返します (保有者は変えません)。
    pub(crate) fn return_arrays(
        &mut self,
        i: usize,
        recs: FixedVec<Record>,
        iv: FixedVec<Interval>,
    ) {
        let s = &mut self.slots[i];
        s.recs = recs;
        s.iv = iv;
    }

    /// 空きの枠が配列を持ち、保有者が重ならないことを確かめます。
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        for (i, s) in self.slots.iter().enumerate() {
            match s.holder {
                None if s.recs.len() != BOOST_RECORDS || s.iv.len() != BOOST_INTERVALS => {
                    return Err("a free boost slot lost its arrays");
                }
                Some(h) if self.slots[..i].iter().any(|o| o.holder == Some(h)) => {
                    return Err("a connection holds two boost slots");
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(slot: u32) -> ConnId {
        ConnId {
            slot,
            generation: 0,
        }
    }

    #[test]
    fn lends_the_lowest_free_slot_and_takes_the_arrays_back() {
        let mut b = Budget::new().unwrap();
        assert_eq!(b.slots(), BOOST_SLOTS);
        let full = b.heap_bytes();
        let (i, recs, iv) = b.acquire(conn(7)).unwrap();
        assert_eq!(
            (i, recs.len(), iv.len()),
            (0, BOOST_RECORDS, BOOST_INTERVALS)
        );
        assert!(b.acquire(conn(7)).is_none(), "a holder gets one slot");
        assert_eq!(b.held_by(conn(7)), Some(0));
        assert!(b.check().is_ok());
        let (j, r2, i2) = b.acquire(conn(8)).unwrap();
        assert_eq!(j, 1);
        b.release(0, recs, iv);
        assert_eq!(
            b.acquire(conn(9)).map(|x| x.0),
            Some(0),
            "the lowest free slot is lent first"
        );
        assert_eq!((b.lent(), b.holder(1)), (2, Some(conn(8))));
        b.hand_over(1, conn(10));
        b.release(1, r2, i2);
        let (r0, i0) = b.take_arrays(0);
        b.return_arrays(0, r0, i0);
        assert_eq!(b.lent(), 1);
        assert!(b.heap_bytes() <= full);
    }
}
