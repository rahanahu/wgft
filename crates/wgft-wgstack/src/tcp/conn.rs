//! 接続の枠 (Go の `tcb.go` の枠の部分)。
//!
//! 枠は作成の時に N_c 個を確保し、確立の時に使い、枠を返すときに世代を進めます。世代は、枠を返した後も
//! 呼び手が持ち続ける古い handle を見分けます。空きの枠は小さい番号から使い、返した枠を先に使います
//! (Go と同じ順で、枠の番号は出力の順に効くので bit の一致の条件に入ります)。
//! floor の送信の記録の輪と区間の表は、枠を初めて使う時に確保し、枠と共に持ち続けます。
//! TCP の状態の欄は核の段 (PR 4a 以降) が足します。

use crate::buf::chunk::ChunkPool;
use crate::buf::records::{Record, RecordRing};
use crate::buf::recv::{Interval, RecvBuf};
use crate::buf::ring::Ring;
use crate::buf::{
    BOOST_INTERVALS, BOOST_RECORDS, BOOST_SIZE, FLOOR_INTERVALS, FLOOR_RECORDS, RECV_FLOOR,
    SEND_FLOOR,
};
use crate::fixed_vec::{AllocError, FixedVec};
use crate::output::NIL;
use crate::wire::Tuple;

/// 接続の handle です。接続の枠の番号と 64 bit の世代の組で、核への参照を持たない `Copy` の値です。
/// 枠が別の接続に使われた後の handle は、核の操作で古い handle として扱われます。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnId {
    pub(crate) slot: u32,
    pub(crate) generation: u64,
}

impl ConnId {
    /// 接続の枠の番号です。呼び手が接続ごとの表を核の外に持つ時の位置に使えます。
    pub fn index(&self) -> usize {
        self.slot as usize
    }
}

/// 接続の枠です。
#[derive(Debug)]
pub(crate) struct ConnSlot {
    pub(crate) generation: u64,
    pub(crate) in_use: bool,
    /// 4 つ組の hash の表にあります。
    pub(crate) in_index: bool,
    pub(crate) tup: Tuple,
    /// accept の待ち行列の節です。`listener` は待ち受けのポートです。
    pub(crate) queued: bool,
    pub(crate) listener: u16,
    pub(crate) qprev: u32,
    pub(crate) qnext: u32,
    pub(crate) snd: Ring,
    pub(crate) rcv: RecvBuf,
    pub(crate) recs: RecordRing,
    /// 使っていない方の配列の控えです。boost の間の floor の記録の輪と、受信が boost の段に移るまでの boost の
    /// 区間の表 (移った後は floor の区間の表) を置きます。
    pub(crate) spare_recs: FixedVec<Record>,
    pub(crate) spare_iv: FixedVec<Interval>,
    /// 借りている boost の枠の番号です。
    pub(crate) boost: Option<usize>,
}

impl ConnSlot {
    fn new() -> Self {
        Self {
            generation: 0,
            in_use: false,
            in_index: false,
            tup: Tuple::default(),
            queued: false,
            listener: 0,
            qprev: NIL,
            qnext: NIL,
            snd: Ring::new(SEND_FLOOR),
            rcv: RecvBuf::new(RECV_FLOOR, FixedVec::new(), 0),
            recs: RecordRing::default(),
            spare_recs: FixedVec::new(),
            spare_iv: FixedVec::new(),
            boost: None,
        }
    }

    /// 枠が持つ floor の記録の輪と区間の表の byte 数です。使っている配列が boost のものなら、それも数えます。
    pub(crate) fn array_bytes(&self) -> (usize, usize) {
        (
            self.recs.heap_bytes() + self.spare_recs.heap_bytes(),
            self.rcv.intervals_heap_bytes() + self.spare_iv.heap_bytes(),
        )
    }

    /// boost の配列を取り出し、boost の印を外します。受信が boost の段に移っていれば、使っている区間の表が boost
    /// のもので、移っていなければ控えが boost のものです。核を閉じる時に、配列を `Budget` へ返すために使います。
    /// 輪の中身は移さないので、呼び手は続けて枠を返します。
    pub(crate) fn take_boost_arrays(&mut self) -> (FixedVec<Record>, FixedVec<Interval>) {
        self.boost = None;
        let recs = self.recs.take();
        let iv = if self.rcv.intervals_capacity() == BOOST_INTERVALS {
            self.rcv.take_intervals()
        } else {
            core::mem::take(&mut self.spare_iv)
        };
        (recs, iv)
    }

    /// 送受信の輪が持つ chunk の数です。
    pub(crate) fn held_chunks(&self) -> usize {
        self.snd.held_chunks() + self.rcv.r.held_chunks()
    }
}

/// 接続の枠の表と空きの枠の list です。
#[derive(Debug)]
pub(crate) struct ConnSlots {
    slots: FixedVec<ConnSlot>,
    free: FixedVec<u32>,
}

impl ConnSlots {
    pub(crate) fn new(n: usize) -> Result<Self, AllocError> {
        let last = u32::try_from(n).map_err(|_| AllocError)?;
        Ok(Self {
            slots: FixedVec::try_filled(n, |_| ConnSlot::new())?,
            // 小さい番号から使います。
            free: FixedVec::try_filled(n, |i| last - 1 - u32::try_from(i).unwrap_or(0))?,
        })
    }

    pub(crate) fn heap_bytes(&self) -> usize {
        self.slots.heap_bytes() + self.free.heap_bytes()
    }

    pub(crate) fn len(&self) -> usize {
        self.slots.len()
    }

    /// 使っている枠の数です。
    pub(crate) fn in_use(&self) -> usize {
        self.slots.len() - self.free.len()
    }

    pub(crate) fn has_free(&self) -> bool {
        !self.free.is_empty()
    }

    /// 空きの枠を 1 つ取り、使う枠にします。floor の配列をまだ持たない枠では確保します。確保に失敗したら
    /// 枠を空きに戻して誤りを返します。
    pub(crate) fn alloc(&mut self) -> Result<Option<u32>, AllocError> {
        let Some(i) = self.free.pop() else {
            return Ok(None);
        };
        let s = &mut self.slots[i as usize];
        if s.recs.capacity() == 0 && s.spare_recs.capacity() == 0 {
            let (Ok(recs), Ok(iv)) = (
                FixedVec::try_filled(FLOOR_RECORDS, |_| Record::default()),
                FixedVec::try_filled(FLOOR_INTERVALS, |_| Interval::default()),
            ) else {
                let _ = self.free.try_push(i);
                return Err(AllocError);
            };
            s.recs = RecordRing::new(recs);
            if let Err(e) = s.rcv.set_intervals(iv) {
                debug_assert!(e.is_empty(), "an unused slot holds no intervals");
            }
        }
        s.in_use = true;
        Ok(Some(i))
    }

    /// 使っている枠を返します。世代を進め、輪の chunk を置き場に返し、floor の配列は持ち続けます。呼び手は
    /// 先に表と待ち行列と boost の枠から外します。
    pub(crate) fn release(&mut self, i: u32, pool: &mut ChunkPool) {
        let s = &mut self.slots[i as usize];
        if !s.in_use {
            return;
        }
        debug_assert!(!s.in_index && !s.queued && s.boost.is_none());
        s.snd.release(pool);
        s.rcv.r.release(pool);
        s.rcv.clear_intervals();
        s.recs.clear();
        s.snd = Ring::new(SEND_FLOOR);
        s.rcv.r = Ring::new(RECV_FLOOR);
        (s.rcv.read_off, s.rcv.nxt_off) = (0, 0);
        s.generation += 1;
        s.in_use = false;
        s.tup = Tuple::default();
        let pushed = self.free.try_push(i);
        debug_assert!(pushed.is_ok(), "the free list holds every slot");
    }

    /// 枠 `i` です。
    pub(crate) fn slot(&self, i: u32) -> &ConnSlot {
        &self.slots[i as usize]
    }

    pub(crate) fn slot_mut(&mut self, i: u32) -> &mut ConnSlot {
        &mut self.slots[i as usize]
    }

    /// 今の世代の handle です。
    pub(crate) fn id(&self, i: u32) -> ConnId {
        ConnId {
            slot: i,
            generation: self.slots[i as usize].generation,
        }
    }

    /// handle が今使っている枠を指していれば、その番号を返します。
    pub(crate) fn resolve(&self, id: ConnId) -> Option<u32> {
        let s = self.slots.get(id.slot as usize)?;
        (s.in_use && s.generation == id.generation).then_some(id.slot)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (u32, &ConnSlot)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| Some((u32::try_from(i).ok()?, s)))
    }

    /// 枠をすべて返し、floor の配列も解放します。核を閉じる時に呼びます。
    pub(crate) fn free_all(&mut self, pool: &mut ChunkPool) {
        for s in self.slots.iter_mut() {
            s.snd.release(pool);
            s.rcv.r.release(pool);
            s.rcv.take_intervals().free();
            s.recs.take().free();
            s.spare_recs.free();
            s.spare_iv.free();
            s.in_use = false;
            s.in_index = false;
            s.queued = false;
        }
    }

    /// 空きの list と使っている印が一致することを確かめます。
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        let mut seen = FixedVec::try_filled(self.slots.len(), |_| false)
            .map_err(|_| "allocation failed while checking")?;
        for &i in self.free.iter() {
            let s = self
                .slots
                .get(i as usize)
                .ok_or("a free slot number is out of range")?;
            let mark = seen
                .get_mut(i as usize)
                .ok_or("a free slot number is out of range")?;
            if *mark {
                return Err("a slot is twice in the free list");
            }
            *mark = true;
            if s.in_use || s.in_index || s.queued || s.boost.is_some() {
                return Err("a free slot is still in use");
            }
            if s.held_chunks() != 0 {
                return Err("a free slot holds chunks");
            }
        }
        if self.free.len() + self.slots.iter().filter(|s| s.in_use).count() != self.slots.len() {
            return Err("the free slots and the used slots do not add up");
        }
        for (_, s) in self.iter() {
            s.snd.check()?;
            s.rcv.r.check()?;
            s.rcv.check()?;
            check_stage(s)?;
        }
        Ok(())
    }
}

/// 枠の段と配列が合うことを確かめます。boost の無い枠は floor の容量と floor の長さの配列を持ちます。boost の
/// 枠は送信が boost の段で、使っていない floor の記録の輪を控えに持ちます。受信は floor か boost の段で、使って
/// いない方の区間の表を控えに持ちます。使っていない枠は floor の配列を持つか、まだ何も持ちません。
fn check_stage(s: &ConnSlot) -> Result<(), &'static str> {
    let ivs = s.rcv.intervals_capacity();
    if !s.in_use || s.boost.is_none() {
        let arrays = (s.recs.capacity(), ivs);
        let fresh = !s.in_use && arrays == (0, 0);
        if s.snd.cap() != SEND_FLOOR
            || s.rcv.r.cap() != RECV_FLOOR
            || !(fresh || arrays == (FLOOR_RECORDS, FLOOR_INTERVALS))
            || s.spare_recs.capacity() != 0
            || s.spare_iv.capacity() != 0
        {
            return Err("a slot without boost is not at the floor stage");
        }
        return Ok(());
    }
    let recv_ok = match (ivs, s.spare_iv.len()) {
        (FLOOR_INTERVALS, BOOST_INTERVALS) => s.rcv.r.cap() == RECV_FLOOR,
        (BOOST_INTERVALS, FLOOR_INTERVALS) => s.rcv.r.cap() == BOOST_SIZE,
        _ => false,
    };
    if s.snd.cap() != BOOST_SIZE
        || s.recs.capacity() != BOOST_RECORDS
        || s.spare_recs.len() != FLOOR_RECORDS
        || !recv_ok
    {
        return Err("a boosted slot's stage disagrees with its arrays");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_used_lowest_first_and_returned_first() {
        let mut p = ChunkPool::new().unwrap();
        let mut t = ConnSlots::new(4).unwrap();
        assert_eq!(t.alloc().unwrap(), Some(0));
        assert_eq!(t.alloc().unwrap(), Some(1));
        let old = t.id(0);
        t.release(0, &mut p);
        assert_eq!(
            t.resolve(old),
            None,
            "a released slot invalidates its handle"
        );
        assert_eq!(t.alloc().unwrap(), Some(0), "a returned slot is used first");
        assert_eq!(t.id(0).generation, old.generation + 1);
        assert_eq!(t.alloc().unwrap(), Some(2));
        assert_eq!(t.alloc().unwrap(), Some(3));
        assert_eq!(t.alloc().unwrap(), None);
        assert_eq!(t.in_use(), 4);
        t.check().unwrap();
    }

    #[test]
    fn check_catches_broken_free_lists_and_stages() {
        let mut p = ChunkPool::new().unwrap();
        let mut t = ConnSlots::new(3).unwrap();
        t.check().unwrap();
        let i = t.alloc().unwrap().unwrap();
        t.check().unwrap();
        // 同じ枠を 2 度 free list に入れる。
        let _ = t.free.try_push(1);
        assert_eq!(t.check(), Err("a slot is twice in the free list"));
        t.free.pop();
        t.free[0] = 99;
        assert_eq!(t.check(), Err("a free slot number is out of range"));
        t.free[0] = 2;
        t.check().unwrap();
        // 使っている枠が floor でない段を持つ。
        t.slot_mut(i).snd = Ring::new(BOOST_SIZE);
        assert_eq!(
            t.check(),
            Err("a slot without boost is not at the floor stage")
        );
        t.slot_mut(i).boost = Some(0);
        assert_eq!(
            t.check(),
            Err("a boosted slot's stage disagrees with its arrays")
        );
        t.slot_mut(i).boost = None;
        t.slot_mut(i).snd = Ring::new(SEND_FLOOR);
        t.check().unwrap();
        // 数が合わない:使っている印だけを消す。
        t.slot_mut(i).in_use = false;
        assert_eq!(
            t.check(),
            Err("the free slots and the used slots do not add up")
        );
        t.slot_mut(i).in_use = true;
        t.release(i, &mut p);
        t.check().unwrap();
    }

    #[test]
    fn floor_arrays_stay_with_the_slot() {
        let mut p = ChunkPool::new().unwrap();
        let mut t = ConnSlots::new(1).unwrap();
        assert_eq!(
            t.slot(0).array_bytes(),
            (0, 0),
            "arrays are allocated on first use"
        );
        t.alloc().unwrap();
        let bytes = t.slot(0).array_bytes();
        assert_eq!(
            bytes,
            (
                FLOOR_RECORDS * size_of::<Record>(),
                FLOOR_INTERVALS * size_of::<Interval>()
            )
        );
        t.slot_mut(0).snd.write(0, &[1; 100], &mut p).unwrap();
        t.release(0, &mut p);
        assert_eq!(t.slot(0).array_bytes(), bytes);
        assert_eq!((t.slot(0).held_chunks(), p.held()), (0, 0));
        t.free_all(&mut p);
        assert_eq!(t.slot(0).array_bytes(), (0, 0));
        assert!(t.has_free() && t.len() == 1);
        assert!(t.heap_bytes() >= size_of::<ConnSlot>() + 4);
    }
}
