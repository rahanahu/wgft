//! boost の枠の集まり (wgstack-rs.md の「予算の持ち主」、Go の `boost.go` の `boostPool`)。
//!
//! Go の枠の集まりはプロセスで 1 つで、トンネルを作り直しても増えません。Rust では枠の集まりを `Budget` という
//! 値にし、核がそれを所有します。トンネルを作り直すときは、古い核の `close` が返す `Budget` を新しい核に渡します。
//! B 本の枠の分の boost の記録の輪と区間の表と、送信と受信の輪の chunk の表は `Budget` の作成の時に確保し、
//! boost を得た接続はその 1 組を借り、floor に戻るか閉じるときに返します。このため boost の取得の時に配列の
//! 確保が失敗する場合はありません。
//! 枠を貸す順 (最も小さい空きの枠) と保有者をたどる順 (枠の順) は Go と同じです。

use crate::buf::records::Record;
use crate::buf::recv::Interval;
use crate::buf::ring::{BOOST_RING_SLOTS, ChunkTable, try_chunk_table};
use crate::buf::{BOOST_INTERVALS, BOOST_RECORDS, BOOST_SLOTS};
use crate::fixed_vec::{AllocError, FixedVec};
use crate::tcp::conn::ConnId;

/// boost の枠が貸す配列の 1 組です。
#[derive(Debug, Default)]
pub(crate) struct BoostArrays {
    /// boost の送信の記録の輪です。
    pub(crate) recs: FixedVec<Record>,
    /// boost の順序外の区間の表です。
    pub(crate) iv: FixedVec<Interval>,
    /// boost の段の送信の輪の chunk の表です。
    pub(crate) snd: ChunkTable,
    /// boost の段の受信の輪の chunk の表です。
    pub(crate) rcv: ChunkTable,
}

impl BoostArrays {
    fn try_new() -> Result<Self, AllocError> {
        Ok(Self {
            recs: FixedVec::try_filled(BOOST_RECORDS, |_| Record::default())?,
            iv: FixedVec::try_filled(BOOST_INTERVALS, |_| Interval::default())?,
            snd: try_chunk_table(BOOST_RING_SLOTS)?,
            rcv: try_chunk_table(BOOST_RING_SLOTS)?,
        })
    }

    /// 1 組が確保した byte 数です。
    #[cfg(test)]
    pub(crate) fn heap_bytes(&self) -> usize {
        self.recs.heap_bytes()
            + self.iv.heap_bytes()
            + self.snd.heap_bytes()
            + self.rcv.heap_bytes()
    }

    /// 1 組の長さがすべて boost の大きさかを返します。
    fn is_full(&self) -> bool {
        self.recs.len() == BOOST_RECORDS
            && self.iv.len() == BOOST_INTERVALS
            && self.snd.len() == BOOST_RING_SLOTS
            && self.rcv.len() == BOOST_RING_SLOTS
    }

    /// chunk の表が chunk を持つかを返します。返された表に chunk が残れば、置き場の数と会計から漏れます。
    fn holds_chunks(&self) -> bool {
        self.snd
            .iter()
            .chain(self.rcv.iter())
            .fold(false, |found, c| found | c.is_some())
    }

    /// 1 組がどれも確保していないかを返します。
    fn is_empty(&self) -> bool {
        self.recs.capacity() == 0
            && self.iv.capacity() == 0
            && self.snd.capacity() == 0
            && self.rcv.capacity() == 0
    }
}

#[derive(Debug)]
struct Slot {
    holder: Option<ConnId>,
    /// 貸していない間の boost の配列です。貸している間は空です。
    arrays: BoostArrays,
}

/// boost の枠の集まりです。プロセスで 1 つ作り、核から核へ渡します。
pub struct Budget {
    slots: FixedVec<Slot>,
    /// 前に [`Budget::take_dirty`] を呼んでから、空きの枠に配列を返した枠の印です (枠 `i` が bit `i`)。試験と fuzz の
    /// build だけにあります。書き換えた所だけの確かめが、空きの枠の chunk の表の確かめをこの枠に絞ります。
    #[cfg(any(test, feature = "harness"))]
    dirty: u64,
}

// 空きの枠の印は 1 語に収めます。
const _: () = assert!(BOOST_SLOTS <= 64);

impl core::fmt::Debug for Budget {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Budget")
            .field("slots", &self.slots())
            .field("lent", &self.lent())
            .finish()
    }
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
    /// 試験と fuzz の build だけにある欄 `dirty` の byte です。[`crate::stack::HARNESS_BYTES`] との一致を試験が確かめます。
    #[cfg(test)]
    pub(crate) fn harness_bytes(&self) -> usize {
        size_of_val(&self.dirty)
    }

    /// 枠と boost の配列をすべて確保します。
    pub fn new() -> Result<Self, BudgetError> {
        let mut slots = FixedVec::try_with_capacity(BOOST_SLOTS)?;
        for _ in 0..BOOST_SLOTS {
            let slot = Slot {
                holder: None,
                arrays: BoostArrays::try_new()?,
            };
            if slots.try_push(slot).is_err() {
                return Err(BudgetError);
            }
        }
        Ok(Self {
            slots,
            #[cfg(any(test, feature = "harness"))]
            dirty: 0,
        })
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
    #[cfg(test)]
    pub(crate) fn heap_bytes(&self) -> usize {
        self.slots.heap_bytes()
            + self
                .slots
                .iter()
                .map(|s| s.arrays.heap_bytes())
                .sum::<usize>()
    }

    /// `c` が持つ枠の番号です。
    pub(crate) fn held_by(&self, c: ConnId) -> Option<usize> {
        self.slots.iter().position(|s| s.holder == Some(c))
    }

    /// 最も小さい空きの枠を `c` に貸し、番号と boost の配列を返します。`c` が既に持つか空きが無ければ `None` です。
    pub(crate) fn acquire(&mut self, c: ConnId) -> Option<(usize, BoostArrays)> {
        if self.held_by(c).is_some() {
            return None;
        }
        let i = self.slots.iter().position(|s| s.holder.is_none())?;
        let s = &mut self.slots[i];
        s.holder = Some(c);
        Some((i, core::mem::take(&mut s.arrays)))
    }

    /// 空きの枠 `i` を `c` に貸し、boost の配列を返します。枠の取り合いで、floor に戻した保有者が
    /// [`Budget::release`] で返した枠を受け取る時に使います。枠が空きでなければ `None` です。
    pub(crate) fn hand_over(&mut self, i: usize, c: ConnId) -> Option<BoostArrays> {
        let s = self.slots.get_mut(i)?;
        if s.holder.is_some() || self.slots.iter().any(|o| o.holder == Some(c)) {
            return None;
        }
        let s = &mut self.slots[i];
        s.holder = Some(c);
        Some(core::mem::take(&mut s.arrays))
    }

    /// 枠 `i` の保有者です。保有者をたどる順は枠の番号の順です。
    pub(crate) fn holder(&self, i: usize) -> Option<ConnId> {
        self.slots.get(i).and_then(|s| s.holder)
    }

    /// 枠 `i` に配列を返し、枠を空きにします。
    pub(crate) fn release(&mut self, i: usize, arrays: BoostArrays) {
        #[cfg(any(test, feature = "harness"))]
        {
            self.dirty |= 1 << i;
        }
        let s = &mut self.slots[i];
        s.holder = None;
        s.arrays = arrays;
    }

    /// 空きの枠に配列を返した枠の印を返し、印を外します。試験と fuzz の build だけにあります。
    ///
    /// 枠の配列はこの型の外から見えず、空きの枠の配列を置き換えるのは [`Budget::release`] だけです
    /// ([`Budget::acquire`] と [`Budget::hand_over`] は配列を取り出して枠を貸した枠にします)。このため印の無い
    /// 空きの枠の chunk の表は、印を外した時から変わっていません。
    #[cfg(any(test, feature = "harness"))]
    pub(crate) fn take_dirty(&mut self) -> u64 {
        core::mem::take(&mut self.dirty)
    }

    /// 空きの枠が配列を持ち、貸した枠が配列を持たず、保有者が重ならないことを確かめます。
    #[cfg(test)]
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        self.check_scanning(u64::MAX)
    }

    /// 空きの枠が配列を持ち、貸した枠が配列を持たず、保有者が重ならないことを確かめます。空きの枠の chunk の表が
    /// chunk を持たないことは、`scan` の bit の立った枠だけで確かめます (表をたどる手間が大きいためです)。核の
    /// 全体の確かめはすべての bit を立てて呼びます。
    pub(crate) fn check_scanning(&self, scan: u64) -> Result<(), &'static str> {
        for (i, s) in self.slots.iter().enumerate() {
            match s.holder {
                None if !s.arrays.is_full() => {
                    return Err("a free boost slot lost its arrays");
                }
                None if scan >> i & 1 == 1 && s.arrays.holds_chunks() => {
                    return Err("a free boost slot's chunk table holds a chunk");
                }
                Some(_) if !s.arrays.is_empty() => {
                    return Err("a lent boost slot still holds its arrays");
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
    #![expect(
        clippy::disallowed_macros,
        clippy::many_single_char_names,
        reason = "test names and formatting"
    )]

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
        let (i, a) = b.acquire(conn(7)).unwrap();
        assert_eq!(
            (i, a.recs.len(), a.iv.len(), a.snd.len(), a.rcv.len()),
            (
                0,
                BOOST_RECORDS,
                BOOST_INTERVALS,
                BOOST_RING_SLOTS,
                BOOST_RING_SLOTS
            )
        );
        assert!(b.acquire(conn(7)).is_none(), "a holder gets one slot");
        assert_eq!(b.held_by(conn(7)), Some(0));
        assert!(b.check().is_ok());
        let (j, a2) = b.acquire(conn(8)).unwrap();
        assert_eq!(j, 1);
        b.release(0, a);
        assert_eq!(
            b.acquire(conn(9)).map(|x| x.0),
            Some(0),
            "the lowest free slot is lent first"
        );
        assert_eq!((b.lent(), b.holder(1)), (2, Some(conn(8))));
        b.release(1, a2);
        let a2 = b.hand_over(1, conn(10)).unwrap();
        assert!(
            b.hand_over(1, conn(11)).is_none(),
            "a lent slot is not handed over"
        );
        assert!(b.hand_over(2, conn(10)).is_none(), "a holder gets one slot");
        assert!(b.hand_over(99, conn(12)).is_none());
        assert_eq!(
            (a2.recs.len(), a2.iv.len(), b.holder(1), b.holder(99)),
            (BOOST_RECORDS, BOOST_INTERVALS, Some(conn(10)), None)
        );
        b.check().unwrap();
        b.release(1, a2);
        assert_eq!(b.lent(), 1);
        assert_eq!(format!("{b:?}"), "Budget { slots: 16, lent: 1 }");
        // 貸した印が付いたまま配列を持つ枠と、2 つの枠を持つ接続の検出。
        b.slots[5].holder = Some(conn(20));
        assert_eq!(b.check(), Err("a lent boost slot still holds its arrays"));
        b.slots[5].holder = None;
        let (k, a) = b.acquire(conn(21)).unwrap();
        b.slots[2].holder = Some(conn(21));
        let a2 = core::mem::take(&mut b.slots[2].arrays);
        assert_eq!(b.check(), Err("a connection holds two boost slots"));
        b.release(2, a2);
        b.release(k, a);
        b.check().unwrap();
        // chunk を残したまま返した表の検出。
        let (k, mut a) = b.acquire(conn(22)).unwrap();
        let mut pool = crate::buf::chunk::ChunkPool::new().unwrap();
        a.rcv[3] = Some(pool.get().unwrap());
        b.release(k, a);
        assert_eq!(
            b.check(),
            Err("a free boost slot's chunk table holds a chunk")
        );
        let (k, mut a) = b.acquire(conn(22)).unwrap();
        pool.put(a.rcv[3].take().unwrap());
        b.release(k, a);
        b.check().unwrap();
        assert!(b.heap_bytes() <= full);
    }

    /// 配列を返した枠だけに印が付き、印の無い枠の chunk の表は確かめを省いても同じ答えです。
    #[test]
    fn release_marks_the_slot_whose_tables_changed() {
        let mut b = Budget::new().unwrap();
        b.take_dirty();
        let (k, mut a) = b.acquire(conn(1)).unwrap();
        assert_eq!(b.take_dirty(), 0, "lending a slot does not mark it");
        let mut pool = crate::buf::chunk::ChunkPool::new().unwrap();
        a.snd[7] = Some(pool.get().unwrap());
        b.release(k, a);
        let dirty = b.take_dirty();
        assert_eq!(dirty, 1 << k);
        let bad = Err("a free boost slot's chunk table holds a chunk");
        assert_eq!(b.check_scanning(dirty), bad);
        assert_eq!(b.check(), bad);
        // 印を外した後は、印の無い枠を確かめない形が chunk を見ない (印が付かない書き換えは無いので起きません)。
        let dirty = b.take_dirty();
        assert_eq!(b.check_scanning(dirty), Ok(()));
        let (k, mut a) = b.acquire(conn(1)).unwrap();
        pool.put(a.snd[7].take().unwrap());
        b.release(k, a);
        let dirty = b.take_dirty();
        assert_eq!(b.check_scanning(dirty), Ok(()));
    }
}
