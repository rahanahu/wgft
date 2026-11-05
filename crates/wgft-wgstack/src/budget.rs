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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

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

#[derive(Debug, Default)]
struct Slot {
    holder: Option<ConnId>,
    /// 貸していない間の boost の配列です。貸している間は空です。Hash S の区画の `Budget` では、区画が集まりから
    /// 取った枠 (`owned`) の空きの間だけ配列を控え、それ以外は空です。
    arrays: BoostArrays,
    /// Hash S の区画の `Budget` で、この枠を集まり ([`BoostPool`]) から取っているか。
    owned: bool,
}

/// boost の枠の集まりです。プロセスで 1 つ作り、核から核へ渡します。
///
/// Hash S の区画の核は、[`BoostPool::view`] が作る配列を持たない `Budget` を持ち、枠は hook の
/// [`Hook::boost_pool`](crate::Hook::boost_pool) が返す集まりから取ります (試作)。
pub struct Budget {
    slots: FixedVec<Slot>,
    /// Hash S の区画の `Budget` か。
    shared: bool,
    /// 前に [`Budget::take_raised`] を呼んでから「枠が欲しい」の印を立てたか。
    raised: bool,
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
                owned: false,
            };
            if slots.try_push(slot).is_err() {
                return Err(BudgetError);
            }
        }
        Ok(Self {
            slots,
            shared: false,
            raised: false,
            #[cfg(any(test, feature = "harness"))]
            dirty: 0,
        })
    }

    /// `c` に枠を貸します。1 つの核では [`Budget::acquire`] と同じです。Hash S の区画の `Budget` では、先に自分が
    /// 取ったまま空いた枠を、無ければ集まり `pool` の最も小さい空きの枠を取ります (試作)。
    pub(crate) fn acquire_in(
        &mut self,
        c: ConnId,
        pool: Option<&BoostPool>,
    ) -> Option<(usize, BoostArrays)> {
        if !self.shared {
            return self.acquire(c);
        }
        if self.held_by(c).is_some() {
            return None;
        }
        if let Some(i) = self
            .slots
            .iter()
            .position(|s| s.owned && s.holder.is_none())
        {
            let s = &mut self.slots[i];
            s.holder = Some(c);
            return Some((i, core::mem::take(&mut s.arrays)));
        }
        let pool = pool?;
        let i = pool.take()?;
        let arrays = pool.take_arrays(i);
        let s = &mut self.slots[i];
        s.owned = true;
        s.holder = Some(c);
        Some((i, arrays))
    }

    /// Hash S の区画の `Budget` で、空きを見つけず自分の区画に降ろせる保有者もいない時に、集まりに「枠が欲しい」の
    /// 印を立てます。1 つの核では何もしません。
    pub(crate) fn raise(&mut self, pool: Option<&BoostPool>) {
        if let (true, Some(pool)) = (self.shared, pool) {
            pool.wanted.store(true, Ordering::Release);
            self.raised = true;
        }
    }

    /// 前に呼んでから「枠が欲しい」の印を立てたかを返し、記録を外します。駆動はこれでほかの区画を起こします。
    pub(crate) fn take_raised(&mut self) -> bool {
        core::mem::take(&mut self.raised)
    }

    /// Hash S の区画の `Budget` で、取ったまま空いた枠の配列を集まりに返し、印を外します。1 つの核では何もしません。
    pub(crate) fn sync(&mut self, pool: Option<&BoostPool>) {
        let (true, Some(pool)) = (self.shared, pool) else {
            return;
        };
        for (i, s) in self.slots.iter_mut().enumerate() {
            if s.owned && s.holder.is_none() {
                s.owned = false;
                pool.give(i, core::mem::take(&mut s.arrays));
            }
        }
    }

    /// Hash S の区画の `Budget` か。
    pub(crate) fn is_shared(&self) -> bool {
        self.shared
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
        if s.holder.is_some()
            || (self.shared && !s.owned)
            || self.slots.iter().any(|o| o.holder == Some(c))
        {
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
                // Hash S の区画が取っていない枠の配列は集まりにあります。
                None if self.shared && !s.owned => {
                    if !s.arrays.is_empty() {
                        return Err("a boost slot of the pool holds arrays in a partition");
                    }
                }
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

/// Hash S の区画が分け合う boost の枠の集まりです (試作、independent-exploration.md の 6.8.5 節)。
///
/// 枠を取る区画は印 `taken` の bit を CAS で立て (Acquire)、その枠の配列を取り出します。返す区画は配列を入れて
/// から bit を外します (Release)。bit を持つ区画だけが枠の配列を出し入れするので、枠ごとの錠は取り合いません
/// (錠は安全な所有の受け渡しのためだけで、取るのは枠の出入りの時だけです)。空きを見つけず自分の区画に降ろせる
/// 保有者もいない区画は「枠が欲しい」の印を立て、ほかの区画は [`Stack::release_wanted`](crate::Stack) で自分の
/// 区画の需要の無い保有者を降ろして枠を返します。
pub struct BoostPool {
    taken: AtomicU64,
    wanted: AtomicBool,
    cells: FixedVec<Mutex<BoostArrays>>,
}

impl core::fmt::Debug for BoostPool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BoostPool")
            .field("taken", &self.taken())
            .field("wanted", &self.wanted())
            .finish_non_exhaustive()
    }
}

impl BoostPool {
    /// `budget` の枠をすべて区画で分け合う集まりにします。貸している枠があるか確保に失敗すれば、`budget` を返します。
    pub fn new(budget: Budget) -> Result<Self, Budget> {
        if budget.shared || budget.lent() != 0 {
            return Err(budget);
        }
        let mut cells = match FixedVec::try_with_capacity(budget.slots()) {
            Ok(c) => c,
            Err(_) => return Err(budget),
        };
        let mut budget = budget;
        for s in budget.slots.iter_mut() {
            if cells
                .try_push(Mutex::new(core::mem::take(&mut s.arrays)))
                .is_err()
            {
                // 容量は枠の数なので起きません。
                return Err(budget);
            }
        }
        Ok(Self {
            taken: AtomicU64::new(0),
            wanted: AtomicBool::new(false),
            cells,
        })
    }

    /// 区画の核に渡す、配列を持たない `Budget` です。
    pub fn view(&self) -> Result<Budget, BudgetError> {
        Ok(Budget {
            slots: FixedVec::try_filled(self.cells.len(), |_| Slot::default())?,
            shared: true,
            raised: false,
            #[cfg(any(test, feature = "harness"))]
            dirty: 0,
        })
    }

    /// 閉じた区画の核が返した `Budget` が控えた配列を集まりに返します。
    pub fn put_back(&self, mut budget: Budget) {
        if !budget.shared {
            return;
        }
        for (i, s) in budget.slots.iter_mut().enumerate() {
            if s.owned {
                s.owned = false;
                self.give(i, core::mem::take(&mut s.arrays));
            }
        }
    }

    /// すべての枠が返っていれば、1 つの核の `Budget` に戻します。区画の panic で配列を失った枠があれば `None` です。
    pub fn into_budget(self) -> Option<Budget> {
        if self.taken() != 0 {
            return None;
        }
        let mut slots = FixedVec::try_with_capacity(self.cells.len()).ok()?;
        let mut cells = self.cells;
        while let Some(cell) = cells.pop() {
            let arrays = cell.into_inner().unwrap_or_else(PoisonError::into_inner);
            if !arrays.is_full() {
                return None;
            }
            if slots
                .try_push(Slot {
                    holder: None,
                    arrays,
                    owned: false,
                })
                .is_err()
            {
                return None;
            }
        }
        // 取り出しは後ろからなので、枠の順に戻します。
        slots.reverse();
        Some(Budget {
            slots,
            shared: false,
            raised: false,
            #[cfg(any(test, feature = "harness"))]
            dirty: 0,
        })
    }

    /// どこかの区画が「枠が欲しい」の印を立てているか。
    pub fn wanted(&self) -> bool {
        self.wanted.load(Ordering::Acquire)
    }

    /// 「枠が欲しい」の印を外します。枠を返した区画が呼びます。
    pub(crate) fn clear_wanted(&self) {
        self.wanted.store(false, Ordering::Release);
    }

    /// 区画が取っている枠の数です。
    pub fn taken(&self) -> u32 {
        self.taken.load(Ordering::Acquire).count_ones()
    }

    /// 最も小さい空きの枠の bit を立て、番号を返します。空きが無ければ `None` です。
    fn take(&self) -> Option<usize> {
        let all = if self.cells.len() >= 64 {
            u64::MAX
        } else {
            (1u64 << self.cells.len()) - 1
        };
        let mut t = self.taken.load(Ordering::Relaxed);
        loop {
            let free = !t & all;
            if free == 0 {
                return None;
            }
            let i = free.trailing_zeros();
            match self.taken.compare_exchange_weak(
                t,
                t | 1 << i,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(i as usize),
                Err(now) => t = now,
            }
        }
    }

    /// bit を立てた枠 `i` の配列を取り出します。
    fn take_arrays(&self, i: usize) -> BoostArrays {
        let mut cell = self.cells[i].lock().unwrap_or_else(PoisonError::into_inner);
        core::mem::take(&mut *cell)
    }

    /// 枠 `i` に配列を入れ、bit を外します。
    fn give(&self, i: usize, arrays: BoostArrays) {
        *self.cells[i].lock().unwrap_or_else(PoisonError::into_inner) = arrays;
        self.taken.fetch_and(!(1u64 << i), Ordering::Release);
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
