//! 予約した容量の byte の輪 (Go の `ring.go` の `ring` の写し)。
//!
//! 位置は接続の始めから数える 64 bit の offset で、offset o の byte は輪の o mod cap に置きます。cap は floor
//! か boost の大きさ (どちらも chunk の倍数の 2 のべき乗) で、chunk は書く時に確保します。生きている範囲
//! [lo, hi) は cap を超えません。生きている範囲に掛からない chunk は返すので、輪が持つ chunk は予約の cap を
//! 超えません。
//!
//! Go と違い、chunk の確保は失敗しえます。書く操作は先に [`Ring::reserve`] で chunk を揃え、失敗したら何も
//! 変えずに誤りを返します。呼び手は予算が尽きたときと同じ動作にします。

use super::BOOST_SIZE;
use super::chunk::{CHUNK_SHIFT, CHUNK_SIZE, Chunk, ChunkPool};
use crate::fixed_vec::AllocError;

#[expect(clippy::cast_possible_truncation, reason = "4 MiB fits in usize")]
const SLOTS: usize = (BOOST_SIZE as usize) / CHUNK_SIZE;
const MASK: u64 = CHUNK_SIZE as u64 - 1;

/// byte の輪です。
#[derive(Debug)]
#[repr(C)]
pub(crate) struct Ring {
    cap: u64,
    chunks: [Option<Chunk>; SLOTS],
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "positions inside a ring of at most 4 MiB"
)]
fn us(x: u64) -> usize {
    x as usize
}

impl Ring {
    /// 容量 `cap` の空の輪です。`cap` は chunk の倍数の 2 のべき乗で、boost の大きさ以下です。
    pub(crate) fn new(cap: u64) -> Self {
        debug_assert!(cap.is_power_of_two() && cap >= CHUNK_SIZE as u64 && cap <= BOOST_SIZE);
        Self {
            cap,
            chunks: [const { None }; SLOTS],
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
        let mut added = [0u64; SLOTS / 64];
        let first = off >> CHUNK_SHIFT;
        let last = (off + len as u64 - 1) >> CHUNK_SHIFT;
        let n = (last - first + 1).min(self.slots());
        for a in first..first + n {
            let i = self.index(a << CHUNK_SHIFT);
            if self.chunks[i].is_none() {
                match pool.get() {
                    Ok(c) => {
                        self.chunks[i] = Some(c);
                        added[i / 64] |= 1 << (i % 64);
                    }
                    Err(e) => {
                        for (j, slot) in self.chunks.iter_mut().enumerate() {
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
            if let Some(c) = &mut self.chunks[i] {
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
            match &self.chunks[i] {
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
                && let Some(c) = self.chunks[us(i)].take()
            {
                pool.put(c);
            }
        }
    }

    /// 生きている範囲 [lo, hi) に掛からない chunk をすべて返します。
    pub(crate) fn retain(&mut self, lo: u64, hi: u64, pool: &mut ChunkPool) {
        for i in 0..self.slots() {
            if !self.live(i, lo, hi)
                && let Some(c) = self.chunks[us(i)].take()
            {
                pool.put(c);
            }
        }
    }

    /// すべての chunk を返します。
    pub(crate) fn release(&mut self, pool: &mut ChunkPool) {
        for slot in &mut self.chunks {
            if let Some(c) = slot.take() {
                pool.put(c);
            }
        }
    }

    /// 持っている chunk の数です。容量の内の位置だけを数えます。容量の外に chunk が無いことは、不変条件の検査の中で
    /// [`Ring::check`] が確かめます。
    pub(crate) fn held_chunks(&self) -> usize {
        self.chunks[..us(self.slots())]
            .iter()
            .filter(|c| c.is_some())
            .count()
    }

    /// 容量の外の位置に chunk が無いことを確かめます。
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        if self.chunks[us(self.slots())..].iter().any(Option::is_some) {
            return Err("a ring holds a chunk outside its capacity");
        }
        Ok(())
    }

    /// cap を `new_cap` に変え、`written` が渡す範囲 (書いた byte の区間) の中身を新しい位置へ移します。
    /// 呼び手は生きている範囲が `new_cap` 以下であることを保証します。移す間は、新旧の chunk を合わせて生きて
    /// いる範囲の 2 倍まで持ちます。確保に失敗したら新しい chunk を返し、輪を変えずに誤りを返します。
    pub(crate) fn resize(
        &mut self,
        new_cap: u64,
        pool: &mut ChunkPool,
        written: impl Fn(&mut dyn FnMut(u64, u64) -> Result<(), AllocError>) -> Result<(), AllocError>,
    ) -> Result<(), AllocError> {
        if new_cap == self.cap {
            return Ok(());
        }
        let next = self.resized(new_cap, pool, written)?;
        self.release(pool);
        *self = next;
        Ok(())
    }

    /// 容量 `new_cap` の新しい輪を作り、`written` が渡す範囲の中身を写して返します。この輪は変えません。呼び手は
    /// 新しい輪を使うときにこの輪の chunk を返します。2 つの輪を移す処理が、両方の確保が済んでから輪を替えるために
    /// 使います。確保に失敗したら新しい輪の chunk を返して誤りを返します。
    pub(crate) fn resized(
        &self,
        new_cap: u64,
        pool: &mut ChunkPool,
        written: impl Fn(&mut dyn FnMut(u64, u64) -> Result<(), AllocError>) -> Result<(), AllocError>,
    ) -> Result<Ring, AllocError> {
        let mut next = Ring::new(new_cap);
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
        if let Err(e) = copied {
            next.release(pool);
            return Err(e);
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
