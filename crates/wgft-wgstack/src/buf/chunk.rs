//! chunk の置き場 (Go の `ring.go` の `chunkPool` の写し)。
//!
//! 予約の内側で確保した chunk を返すと、上限の数まで次の確保に使い回します。上限を超えて返った chunk は
//! 解放します。置き場の chunk はどの予約にも数えず、上限の分を上界の M_fix に数えます。
//! 置き場に返す chunk は 0 で埋めます。`--cfg wgstack_sentinel` の build は目印の byte で埋め、試験は目印が
//! 出力と読み取りに現れないことを確かめます (wgstack-rs.md の「故障の注入と目印の build」)。

use crate::fixed_vec::{AllocError, BoxedBytes, FixedVec, try_boxed_bytes};

pub(crate) const CHUNK_SHIFT: u32 = 14;
/// バッファの中身を持つ chunk の大きさです。
pub(crate) const CHUNK_SIZE: usize = 1 << CHUNK_SHIFT;
/// 置き場に残す chunk の上限の、wgft の agent の値です ([`crate::Limits::pool_chunks`])。
pub(crate) const POOL_KEEP: usize = 64;
/// 置き場に返す chunk を埋める byte です。目印の build だけが 0 でない値を使います。
#[cfg(not(wgstack_sentinel))]
pub(crate) const FILL: u8 = 0;
#[cfg(wgstack_sentinel)]
pub(crate) const FILL: u8 = 0xa5;

/// 8 byte ずつ書く埋めは、chunk の大きさが 8 の倍数でないと端を黙って残します。埋めは守りの性質なので build で止めます。
const _: () = assert!(CHUNK_SIZE.is_multiple_of(8));

/// chunk を [`FILL`] で埋めます。
///
/// 製品の Linux の build は zigbuild の musl で、その `memset` は zig の compiler_rt の実装です。1 byte の
/// store を並べた loop で遅いため、musl では値を `black_box` で隠した 8 byte ずつの書き込みにします。
/// LLVM はこれを `memset` の呼び出しに畳まず、SSE2 の 16 byte の store の loop にします。glibc の `memset` は
/// 速く、同じ書き方が勝てないので、musl 以外は `fill` のままにします。測った倍率は PR に残します。
/// chunk の先頭の整列は確保器の返す値で、`Box<[u8; N]>` の型は 1 byte 整列しか約束しません。musl の
/// 確保器は 16 byte 整列を返すため 8 byte の store は整列しますが、整列は正しさの条件ではありません。
/// 16 KiB の埋めに対して呼び出しの費用は無視できます。`inline(never)` にするのは、`scripts/check-musl-fill.sh` が
/// この関数の機械語に `memset` の呼び出しが無いことを確かめるためです (inline されると `put` の中に埋もれます)。
#[inline(never)]
pub(crate) fn fill_chunk(c: &mut [u8; CHUNK_SIZE]) {
    #[cfg(target_env = "musl")]
    fill_wide(c, FILL);
    #[cfg(not(target_env = "musl"))]
    c.fill(FILL);
}

/// 8 byte ずつの書き込みで埋めます。`unsafe` を使わず、`black_box` で値を隠して `memset` への畳み込みを
/// 避けます。musl 以外では試験だけが使います。
#[cfg(any(test, target_env = "musl"))]
#[inline]
fn fill_wide(c: &mut [u8; CHUNK_SIZE], v: u8) {
    let w = core::hint::black_box(u64::from_ne_bytes([v; 8])).to_ne_bytes();
    for x in c.as_chunks_mut::<8>().0 {
        *x = w;
    }
}

/// バッファの中身の 16 KiB です。
pub(crate) type Chunk = BoxedBytes<CHUNK_SIZE>;

/// chunk の置き場です。
#[derive(Debug)]
pub(crate) struct ChunkPool {
    free: FixedVec<Chunk>,
    /// 輪が今持つ chunk の数です。
    held: usize,
}

// 試験だけが使う確保の失敗の注入です。`Some(n)` なら、この thread の n 回の取得の後の取得を失敗させます。
// 置き場の型の大きさを試験の build で変えないよう、型の外に置きます (上界の表は型の大きさで決まります)。
#[cfg(test)]
std::thread_local! {
    static FAIL_AFTER: core::cell::Cell<Option<usize>> = const { core::cell::Cell::new(None) };
}

// 試験だけが使う、輪が持つ chunk の数の最大です。確保の失敗の注入と同じく型の外に置きます。
#[cfg(test)]
std::thread_local! {
    static PEAK_HELD: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// 試験だけが使う、輪が持つ chunk の数の最大を `held` に戻します。
#[cfg(test)]
pub(crate) fn reset_held_peak(held: usize) {
    PEAK_HELD.set(held);
}

/// 試験だけが使う、[`reset_held_peak`] の後に輪が持った chunk の数の最大です。
#[cfg(test)]
pub(crate) fn held_peak() -> usize {
    PEAK_HELD.get()
}

/// 試験だけが使う、chunk の確保の失敗の注入を設定します。
#[cfg(test)]
pub(crate) fn fail_chunks_after(n: Option<usize>) {
    FAIL_AFTER.set(n);
}

impl ChunkPool {
    /// wgft の agent の数 ([`POOL_KEEP`]) まで残す置き場を作ります。試験が使います。
    #[cfg(test)]
    pub(crate) fn new() -> Result<Self, AllocError> {
        Self::with_keep(POOL_KEEP)
    }

    /// 返った chunk を `keep` 個まで残す置き場を作ります。
    pub(crate) fn with_keep(keep: usize) -> Result<Self, AllocError> {
        Ok(Self {
            free: FixedVec::try_with_capacity(keep)?,
            held: 0,
        })
    }

    /// 置き場の管理の配列の byte 数です。置き場の chunk は含みません。
    #[cfg(test)]
    pub(crate) fn heap_bytes(&self) -> usize {
        self.free.heap_bytes()
    }

    /// chunk を 1 つ取ります。置き場が空なら確保します。
    pub(crate) fn get(&mut self) -> Result<Chunk, AllocError> {
        #[cfg(test)]
        if let Some(n) = FAIL_AFTER.get() {
            if n == 0 {
                return Err(AllocError);
            }
            FAIL_AFTER.set(Some(n - 1));
        }
        let c = match self.free.pop() {
            Some(c) => c,
            None => try_boxed_bytes::<CHUNK_SIZE>()?,
        };
        self.held += 1;
        #[cfg(test)]
        PEAK_HELD.set(PEAK_HELD.get().max(self.held));
        Ok(c)
    }

    /// chunk を返します。次に使う接続に前の中身を残さないよう、埋めてから置き場に置きます。
    pub(crate) fn put(&mut self, mut c: Chunk) {
        fill_chunk(&mut c);
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
    fn fill_chunk_overwrites_full_and_partial_chunks() {
        let mut c = try_boxed_bytes::<CHUNK_SIZE>().unwrap();
        // 全体が 0 以外の chunk と、先頭だけ・末尾だけ・途中だけ書かれた chunk のどれも FILL になる。
        c.fill(0x5c);
        fill_chunk(&mut c);
        assert!(c.iter().all(|&b| b == FILL));
        for (lo, hi) in [
            (0, 1),
            (CHUNK_SIZE - 1, CHUNK_SIZE),
            (3, 1499),
            (4093, 9001),
        ] {
            c[lo..hi].fill(0xff);
            fill_chunk(&mut c);
            assert!(c.iter().all(|&b| b == FILL), "range {lo}..{hi}");
        }
    }

    #[test]
    fn wide_fill_writes_every_byte_for_zero_and_the_sentinel() {
        for v in [0u8, 0xa5, 0xff] {
            let mut c = try_boxed_bytes::<CHUNK_SIZE>().unwrap();
            c.fill(!v);
            fill_wide(&mut c, v);
            assert!(c.iter().all(|&b| b == v), "value {v:#x}");
        }
    }

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
