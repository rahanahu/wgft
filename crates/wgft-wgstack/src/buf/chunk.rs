//! chunk の置き場 (Go の `ring.go` の `chunkPool` の写し)。
//!
//! 予約の内側で確保した chunk を返すと、上限の数まで次の確保に使い回します。上限を超えて返った chunk は
//! 解放します。置き場の chunk はどの予約にも数えず、上限の分を上界の M_fix に数えます。
//! 置き場に返す chunk は 0 で埋めます。`--cfg wgstack_sentinel` の build は目印の byte で埋め、試験は目印が
//! 出力と読み取りに現れないことを確かめます (wgstack-rs.md の「故障の注入と目印の build」)。

use crate::fixed_vec::{AllocError, FixedVec, try_boxed_bytes};

pub(crate) const CHUNK_SHIFT: u32 = 14;
/// バッファの中身を持つ chunk の大きさです。
pub(crate) const CHUNK_SIZE: usize = 1 << CHUNK_SHIFT;
/// 置き場に残す chunk の上限です。
pub(crate) const POOL_KEEP: usize = 64;
/// 置き場に返す chunk を埋める byte です。目印の build だけが 0 でない値を使います。
#[cfg(not(wgstack_sentinel))]
pub(crate) const FILL: u8 = 0;
#[cfg(wgstack_sentinel)]
pub(crate) const FILL: u8 = 0xa5;

/// バッファの中身の 16 KiB です。
pub(crate) type Chunk = Box<[u8; CHUNK_SIZE]>;

/// chunk の置き場です。
#[derive(Debug)]
pub(crate) struct ChunkPool {
    free: FixedVec<Chunk>,
    /// 輪が今持つ chunk の数です。
    held: usize,
}

impl ChunkPool {
    pub(crate) fn new() -> Result<Self, AllocError> {
        Ok(Self {
            free: FixedVec::try_with_capacity(POOL_KEEP)?,
            held: 0,
        })
    }

    /// 置き場の管理の配列の byte 数です。置き場の chunk は含みません。
    pub(crate) fn heap_bytes(&self) -> usize {
        self.free.heap_bytes()
    }

    /// chunk を 1 つ取ります。置き場が空なら確保します。
    pub(crate) fn get(&mut self) -> Result<Chunk, AllocError> {
        let c = match self.free.pop() {
            Some(c) => c,
            None => try_boxed_bytes::<CHUNK_SIZE>()?,
        };
        self.held += 1;
        Ok(c)
    }

    /// chunk を返します。次に使う接続に前の中身を残さないよう、埋めてから置き場に置きます。
    pub(crate) fn put(&mut self, mut c: Chunk) {
        c.fill(FILL);
        self.held -= 1;
        // 置き場が満杯なら c はここで解放されます。
        let _ = self.free.try_push(c);
    }

    /// 輪が今持つ chunk の数です。
    pub(crate) fn held(&self) -> usize {
        self.held
    }

    /// 置き場にある chunk の数です。
    pub(crate) fn kept(&self) -> usize {
        self.free.len()
    }

    /// 置き場の chunk をすべて解放します。
    pub(crate) fn drain(&mut self) {
        self.free.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reuses_up_to_the_limit_and_fills() {
        let mut p = ChunkPool::new().unwrap();
        let mut c = p.get().unwrap();
        c[100] = 7;
        p.put(c);
        assert_eq!((p.held(), p.kept()), (0, 1));
        let c = p.get().unwrap();
        assert!(
            c.iter().all(|&b| b == FILL),
            "a reused chunk keeps no old bytes"
        );
        p.put(c);
        let mut held = FixedVec::try_with_capacity(POOL_KEEP + 3).unwrap();
        for _ in 0..POOL_KEEP + 3 {
            held.try_push(p.get().unwrap()).unwrap();
        }
        assert_eq!(p.held(), POOL_KEEP + 3);
        while let Some(c) = held.pop() {
            p.put(c);
        }
        assert_eq!((p.held(), p.kept()), (0, POOL_KEEP));
        p.drain();
        assert_eq!(p.kept(), 0);
        assert_eq!(p.heap_bytes(), POOL_KEEP * size_of::<Chunk>());
    }
}
