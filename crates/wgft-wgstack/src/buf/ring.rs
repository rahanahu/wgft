//! 予約した容量の byte の輪 (Go の `ring.go` の `ring` の写し)。
//!
//! 位置は接続の始めから数える 64 bit の offset で、offset o の byte は輪の o mod cap に置きます。cap は floor
//! か boost の大きさ (どちらも chunk の倍数の 2 のべき乗) で、chunk は書く時に確保します。生きている範囲
//! [lo, hi) は cap を超えません。生きている範囲に掛からない chunk は返すので、輪が持つ chunk は予約の cap を
//! 超えません。
//!
//! Go と違い、chunk の確保は失敗しえます。書く操作は先に [`Ring::reserve`] で chunk を揃え、失敗したら何も
//! 変えずに誤りを返します。呼び手は予算が尽きたときと同じ動作にします。
//!
//! chunk への pointer の表は、floor の段では輪の中の配列に、floor より大きい段では `Budget` から借りた表に
//! 置きます (wgstack-rs.md の「接続の枠の配置」)。接続の枠のどれもが boost の段の大きさの表を持つと、枠の数に
//! 比例して使わない表を持つためです。

use super::chunk::{CHUNK_SHIFT, CHUNK_SIZE, Chunk, ChunkPool};
use super::{BOOST_SIZE, RECV_FLOOR, SEND_FLOOR};
use crate::fixed_vec::{AllocError, FixedVec};

/// floor の段の輪の chunk の数です。送信と受信の floor は同じ大きさです。
#[expect(clippy::cast_possible_truncation, reason = "256 KiB fits in usize")]
const FLOOR_SLOTS: usize = (SEND_FLOOR as usize) / CHUNK_SIZE;
const _: () = assert!(SEND_FLOOR == RECV_FLOOR);
/// boost の段の輪の chunk の数です。`Budget` が貸す表の長さです。
#[expect(clippy::cast_possible_truncation, reason = "4 MiB fits in usize")]
pub(crate) const BOOST_RING_SLOTS: usize = (BOOST_SIZE as usize) / CHUNK_SIZE;
const MASK: u64 = CHUNK_SIZE as u64 - 1;

/// floor より大きい段の輪の chunk の表です。`Budget` の作成の時に確保し、boost の枠と共に貸し借りします。
pub(crate) type ChunkTable = FixedVec<Option<Chunk>>;

/// 長さ `n` の空の chunk の表を確保します。
pub(crate) fn try_chunk_table(n: usize) -> Result<ChunkTable, AllocError> {
    FixedVec::try_filled(n, |_| None)
}

/// byte の輪です。
#[derive(Debug)]
#[repr(C)]
pub(crate) struct Ring {
    cap: u64,
    /// floor より大きい段の chunk の表です。floor 以下の段では空 (容量 0) で、`small` を使います。
    big: ChunkTable,
    /// floor 以下の段の chunk です。floor より大きい段ではすべて `None` です。
    small: [Option<Chunk>; FLOOR_SLOTS],
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "positions inside a ring of at most 4 MiB"
)]
fn us(x: u64) -> usize {
    x as usize
}

impl Ring {
    /// 容量 `cap` の空の輪です。`cap` は chunk の倍数の 2 のべき乗で、floor 以下です。floor より大きい輪は
    /// [`Ring::with_table`] で作ります。
    pub(crate) fn new(cap: u64) -> Self {
        // 作成と floor に戻す時だけ通るので、製品の build でも確かめます。
        assert!(
            cap.is_power_of_two() && cap >= CHUNK_SIZE as u64 && cap <= SEND_FLOOR,
            "a ring above the floor takes its table from the Budget"
        );
        Self {
            cap,
            big: FixedVec::new(),
            small: [const { None }; FLOOR_SLOTS],
        }
    }

    /// 試験だけが使う、容量 `cap` の空の輪です。floor より大きい輪の表は `Budget` から借りずにここで確保します。
    #[cfg(test)]
    pub(crate) fn owning(cap: u64) -> Self {
        if cap <= SEND_FLOOR {
            Self::new(cap)
        } else {
            Self::with_table(
                cap,
                try_chunk_table(us(cap >> CHUNK_SHIFT)).expect("a test ring's table"),
            )
        }
    }

    /// 容量 `cap` の空の輪を、chunk の表 `table` で作ります。`cap` は floor より大きく、`table` は空で、長さは
    /// `cap` の chunk の数以上です。
    pub(crate) fn with_table(cap: u64, table: ChunkTable) -> Self {
        debug_assert!(cap.is_power_of_two() && cap > SEND_FLOOR && cap <= BOOST_SIZE);
        debug_assert!(table.len() >= us(cap >> CHUNK_SHIFT) && table.iter().all(Option::is_none));
        Self {
            cap,
            big: table,
            small: [const { None }; FLOOR_SLOTS],
        }
    }

    /// chunk の表を取り出し、輪を容量 floor の空の輪にします。floor 以下の輪は空の表を返します。呼び手は先に
    /// chunk を返します。
    pub(crate) fn take_table(&mut self) -> ChunkTable {
        debug_assert!(self.held_chunks() == 0, "take_table with chunks");
        let t = core::mem::take(&mut self.big);
        self.cap = SEND_FLOOR;
        t
    }

    /// 段の chunk の表です。
    #[inline]
    fn table(&self) -> &[Option<Chunk>] {
        if self.big.is_empty() {
            &self.small
        } else {
            &self.big
        }
    }

    #[inline]
    fn table_mut(&mut self) -> &mut [Option<Chunk>] {
        if self.big.is_empty() {
            &mut self.small
        } else {
            &mut self.big
        }
    }

    pub(crate) fn cap(&self) -> u64 {
        self.cap
    }

    fn slots(&self) -> u64 {
        self.cap >> CHUNK_SHIFT
    }

    fn index(&self, off: u64) -> usize {
        us((off & (self.cap - 1)) >> CHUNK_SHIFT)
    }

    /// `[off, off + len)` を書くのに要る chunk を揃えます。確保に失敗したら、この呼び出しで確保した chunk を
    /// 返して誤りを返します。
    pub(crate) fn reserve(
        &mut self,
        off: u64,
        len: usize,
        pool: &mut ChunkPool,
    ) -> Result<(), AllocError> {
        if len == 0 {
            return Ok(());
        }
        let mut added = [0u64; BOOST_RING_SLOTS / 64];
        let first = off >> CHUNK_SHIFT;
        let last = (off + len as u64 - 1) >> CHUNK_SHIFT;
        let n = (last - first + 1).min(self.slots());
        for a in first..first + n {
            let i = self.index(a << CHUNK_SHIFT);
            let chunks = self.table_mut();
            if chunks[i].is_none() {
                match pool.get() {
                    Ok(c) => {
                        chunks[i] = Some(c);
                        added[i / 64] |= 1 << (i % 64);
                    }
                    Err(e) => {
                        for (j, slot) in chunks.iter_mut().enumerate() {
                            if added[j / 64] >> (j % 64) & 1 == 1
                                && let Some(c) = slot.take()
                            {
                                pool.put(c);
                            }
                        }
                        return Err(e);
                    }
                }
            }
        }
        Ok(())
    }

    /// `data` を offset `off` から書きます。必要な chunk はここで確保します。
    pub(crate) fn write(
        &mut self,
        off: u64,
        data: &[u8],
        pool: &mut ChunkPool,
    ) -> Result<(), AllocError> {
        self.reserve(off, data.len(), pool)?;
        self.write_reserved(off, data);
        Ok(())
    }

    /// [`Ring::reserve`] で揃えた範囲に `data` を書きます。
    pub(crate) fn write_reserved(&mut self, mut off: u64, mut data: &[u8]) {
        while !data.is_empty() {
            let i = self.index(off);
            let p = us(off & MASK);
            let n = data.len().min(CHUNK_SIZE - p);
            if let Some(c) = &mut self.table_mut()[i] {
                c[p..p + n].copy_from_slice(&data[..n]);
            } else {
                debug_assert!(false, "write_reserved without reserve");
            }
            data = &data[n..];
            off += n as u64;
        }
    }

    /// offset `off` からの byte を `dst` に写します。範囲は書いた byte の内側です。書いていない位置
    /// (順序外の穴) は読まない呼び手の約束ですが、守りとして 0 を返します。
    pub(crate) fn read(&self, mut off: u64, mut dst: &mut [u8]) {
        while !dst.is_empty() {
            let i = self.index(off);
            let p = us(off & MASK);
            let n = dst.len().min(CHUNK_SIZE - p);
            match &self.table()[i] {
                Some(c) => dst[..n].copy_from_slice(&c[p..p + n]),
                None => dst[..n].fill(0),
            }
            dst = &mut dst[n..];
            off += n as u64;
        }
    }

    /// 生きている範囲 [lo, hi) が輪の位置 i の chunk に掛かるかを返します。
    fn live(&self, i: u64, lo: u64, hi: u64) -> bool {
        if hi <= lo {
            return false;
        }
        let n = self.slots();
        let (a0, a1) = (lo >> CHUNK_SHIFT, (hi - 1) >> CHUNK_SHIFT);
        if a1 - a0 + 1 >= n {
            return true;
        }
        (i + n - a0 % n) % n <= a1 - a0
    }

    /// 生きている範囲が [old_lo, hi) から [lo, hi) に縮んだ後、どこにも掛からなくなった chunk を返します。
    pub(crate) fn trim(&mut self, old_lo: u64, lo: u64, hi: u64, pool: &mut ChunkPool) {
        if lo <= old_lo {
            return;
        }
        let n = self.slots();
        let (mut first, mut last) = (old_lo >> CHUNK_SHIFT, (lo - 1) >> CHUNK_SHIFT);
        if last - first + 1 >= n {
            (first, last) = (0, n - 1);
        }
        for a in first..=last {
            let i = a % n;
            if !self.live(i, lo, hi)
                && let Some(c) = self.table_mut()[us(i)].take()
            {
                pool.put(c);
            }
        }
    }

    /// 生きている範囲 [lo, hi) に掛からない chunk をすべて返します。
    pub(crate) fn retain(&mut self, lo: u64, hi: u64, pool: &mut ChunkPool) {
        for i in 0..self.slots() {
            if !self.live(i, lo, hi)
                && let Some(c) = self.table_mut()[us(i)].take()
            {
                pool.put(c);
            }
        }
    }

    /// すべての chunk を返します。
    pub(crate) fn release(&mut self, pool: &mut ChunkPool) {
        for slot in self.small.iter_mut().chain(self.big.iter_mut()) {
            if let Some(c) = slot.take() {
                pool.put(c);
            }
        }
    }

    /// 持っている chunk の数です。容量の内の位置だけを数えます。容量の外に chunk が無いことは、不変条件の検査の中で
    /// [`Ring::check`] が確かめます。
    pub(crate) fn held_chunks(&self) -> usize {
        self.table()[..us(self.slots())]
            .iter()
            .filter(|c| c.is_some())
            .count()
    }

    /// 生きている範囲 [lo, hi) に掛からない位置に chunk を持つかを返します。送信の輪は確認した分の chunk を返す
    /// ので持ちません。段を変える間の保持の上界 (`bound::STAGE_CHANGE_FITS`) はこれを前提にし、不変条件の検査が
    /// 確かめます。
    pub(crate) fn holds_outside(&self, lo: u64, hi: u64) -> bool {
        let chunks = self.table();
        (0..self.slots()).any(|i| chunks[us(i)].is_some() && !self.live(i, lo, hi))
    }

    /// 容量の外の位置に chunk が無いことを確かめます。途中で止まらない畳み込みにして、位置の比べを vector の
    /// 命令にします。`any` は位置ごとに分岐するので、容量の外の位置の多い floor の輪で遅くなります。
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        let unused: &[Option<Chunk>] = if self.big.is_empty() {
            &[]
        } else {
            &self.small
        };
        if self.table()[us(self.slots())..]
            .iter()
            .chain(unused)
            .fold(false, |found, c| found | c.is_some())
        {
            return Err("a ring holds a chunk outside its capacity");
        }
        if self.big.is_empty() != (self.cap <= SEND_FLOOR) {
            return Err("a ring's chunk table does not match its stage");
        }
        Ok(())
    }

    /// cap を `new_cap` に変え、`written` が渡す範囲 (書いた byte の区間) の中身を新しい位置へ移します。
    /// 呼び手は生きている範囲が `new_cap` 以下であることを保証します。移す間は、新旧の chunk を合わせて生きて
    /// いる範囲の 2 倍まで持ちます。確保に失敗したら新しい chunk を返し、輪を変えずに誤りを返します。
    #[cfg(test)]
    pub(crate) fn resize(
        &mut self,
        new_cap: u64,
        pool: &mut ChunkPool,
        written: impl Fn(&mut dyn FnMut(u64, u64) -> Result<(), AllocError>) -> Result<(), AllocError>,
    ) -> Result<(), AllocError> {
        if new_cap == self.cap {
            return Ok(());
        }
        let next = self
            .copy_into(Ring::owning(new_cap), pool, written)
            .map_err(|_| AllocError)?;
        self.release(pool);
        *self = next;
        Ok(())
    }

    /// 中身を `[lo, hi)` ごと空の輪 `next` に移し、この輪の chunk を返してこの輪を `next` にします。試験が段を
    /// 変えた接続を作るのに使います。
    #[cfg(test)]
    pub(crate) fn move_to(&mut self, next: Ring, lo: u64, hi: u64, pool: &mut ChunkPool) {
        let next = self
            .copy_into(next, pool, |f| f(lo, hi))
            .expect("a test ring's chunks");
        self.release(pool);
        *self = next;
    }

    /// 空の輪 `next` に `written` が渡す範囲の中身を写して返します。この輪は変えません。呼び手は新しい輪を使う
    /// ときにこの輪の chunk を返します。2 つの輪を移す処理が、両方の確保が済んでから輪を替えるために使います。
    /// 確保に失敗したら `next` の chunk を返し、`next` の chunk の表を誤りとして返します。呼び手はその表を
    /// 取り戻せます。
    pub(crate) fn copy_into(
        &self,
        mut next: Ring,
        pool: &mut ChunkPool,
        written: impl Fn(&mut dyn FnMut(u64, u64) -> Result<(), AllocError>) -> Result<(), AllocError>,
    ) -> Result<Ring, ChunkTable> {
        let copied = written(&mut |lo, hi| {
            let mut buf = [0u8; 1024];
            let mut off = lo;
            while off < hi {
                let n = us((hi - off).min(buf.len() as u64));
                self.read(off, &mut buf[..n]);
                next.write(off, &buf[..n], pool)?;
                off += n as u64;
            }
            Ok(())
        });
        if copied.is_err() {
            next.release(pool);
            return Err(next.take_table());
        }
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::disallowed_macros,
        clippy::disallowed_types,
        clippy::disallowed_methods,
        reason = "test data"
    )]
    #![expect(
        clippy::cast_possible_truncation,
        clippy::large_stack_arrays,
        reason = "test data"
    )]

    use super::super::{BOOST_SIZE, SEND_FLOOR};
    use super::*;

    #[test]
    fn check_finds_a_chunk_outside_the_capacity() {
        let mut p = ChunkPool::new().unwrap();
        // floor より小さい輪は、floor の配列の後ろの位置を使いません。
        let mut r = Ring::new(4 * CHUNK_SIZE as u64);
        let inside = us(r.slots());
        r.small[inside - 1] = Some(p.get().unwrap());
        assert_eq!(r.check(), Ok(()));
        // 容量のすぐ外と最後の位置のどちらも見つけます。
        for at in [inside, FLOOR_SLOTS - 1] {
            r.small[at] = Some(p.get().unwrap());
            assert_eq!(r.check(), Err("a ring holds a chunk outside its capacity"));
            p.put(r.small[at].take().unwrap());
        }
        r.release(&mut p);
        // boost の段の輪は floor の配列を使いません。
        let mut r = Ring::with_table(BOOST_SIZE, try_chunk_table(BOOST_RING_SLOTS).unwrap());
        r.big[BOOST_RING_SLOTS - 1] = Some(p.get().unwrap());
        assert_eq!(r.check(), Ok(()));
        r.small[0] = Some(p.get().unwrap());
        assert_eq!(r.check(), Err("a ring holds a chunk outside its capacity"));
        r.release(&mut p);
        assert_eq!(r.take_table().len(), BOOST_RING_SLOTS);
        assert_eq!(r.check(), Ok(()));
        assert_eq!(p.held(), 0);
    }

    #[test]
    fn resize_and_trim() {
        let mut p = ChunkPool::new().unwrap();
        let mut r = Ring::new(SEND_FLOOR);
        let data: Vec<u8> = (0..SEND_FLOOR).map(|i| (i * 7) as u8).collect();
        let base = 100u64;
        r.write(base, &data, &mut p).unwrap();
        assert_eq!(r.held_chunks(), (SEND_FLOOR as usize) / CHUNK_SIZE);
        let c = CHUNK_SIZE as u64;
        r.trim(base, base + c * 3, base + SEND_FLOOR, &mut p);
        assert_eq!(r.held_chunks(), (SEND_FLOOR as usize) / CHUNK_SIZE - 2);
        let (lo, hi) = (base + c * 3, base + SEND_FLOOR);
        r.resize(BOOST_SIZE, &mut p, |f| f(lo, hi)).unwrap();
        let mut got = vec![0u8; (SEND_FLOOR - c * 3) as usize];
        r.read(lo, &mut got);
        assert_eq!(got, data[(c * 3) as usize..]);
        r.check().unwrap();
        r.release(&mut p);
        assert_eq!(p.held(), 0);
    }

    #[test]
    fn retain_keeps_only_live_chunks() {
        let mut p = ChunkPool::new().unwrap();
        let mut r = Ring::new(SEND_FLOOR);
        r.write(0, &[1u8; 3 * CHUNK_SIZE], &mut p).unwrap();
        r.retain(CHUNK_SIZE as u64 + 5, CHUNK_SIZE as u64 + 6, &mut p);
        assert_eq!(r.held_chunks(), 1);
        let mut b = [9u8; 4];
        r.read(0, &mut b);
        assert_eq!(b, [0; 4], "a released position reads as zeros");
        r.read(CHUNK_SIZE as u64 + 5, &mut b[..1]);
        assert_eq!(b[0], 1);
        r.release(&mut p);
    }

    #[test]
    fn wraps_at_the_capacity() {
        let mut p = ChunkPool::new().unwrap();
        let mut r = Ring::new(SEND_FLOOR);
        let off = SEND_FLOOR * 3 - 2;
        r.write(off, b"abcd", &mut p).unwrap();
        assert_eq!(r.held_chunks(), 2);
        let mut b = [0u8; 4];
        r.read(off, &mut b);
        assert_eq!(&b, b"abcd");
        r.trim(off, off + 4, off + 4, &mut p);
        assert_eq!(r.held_chunks(), 0);
        assert_eq!(r.cap(), SEND_FLOOR);
    }
}
