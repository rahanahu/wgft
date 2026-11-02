//! chunk の置き場 (Go の `ring.go` の `chunkPool` の写し)。
//!
//! 予約の内側で確保した chunk を返すと、上限の数まで次の確保に使い回します。上限を超えて返った chunk は
//! 解放します。置き場の chunk はどの予約にも数えず、上限の分を上界の M_fix に数えます。
//! 製品の build は、置き場に返す chunk を埋めません。輪は書いた範囲だけを読むので、前の持ち主の byte は
//! 読み取りにも送る segment にも届きません。試験と道具の build は、取る chunk を目印の byte で埋め、書いて
//! いない byte を読むと目印が出るようにします (wgstack-rs.md の「置き場の chunk と古い byte」)。

use crate::fixed_vec::{AllocError, BoxedBytes, FixedVec, try_boxed_bytes};

pub(crate) const CHUNK_SHIFT: u32 = 14;
/// バッファの中身を持つ chunk の大きさです。
pub(crate) const CHUNK_SIZE: usize = 1 << CHUNK_SHIFT;
/// 置き場に残す chunk の上限です。
pub(crate) const POOL_KEEP: usize = 64;
/// 試験と道具の build で、取る chunk を埋める目印の byte です。試験の道具の packet の中身の値と違う値にします。
#[cfg(any(test, fuzzing, feature = "harness"))]
pub(crate) const SENTINEL: u8 = 0xc9;

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
    pub(crate) fn new() -> Result<Self, AllocError> {
        Ok(Self {
            free: FixedVec::try_with_capacity(POOL_KEEP)?,
            held: 0,
        })
    }

    /// 置き場の管理の配列の byte 数です。置き場の chunk は含みません。
    #[cfg(test)]
    pub(crate) fn heap_bytes(&self) -> usize {
        self.free.heap_bytes()
    }

    /// chunk を 1 つ取ります。置き場が空なら確保します。置き場の chunk は前の持ち主の byte を持ったままです。
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
        // 書いていない byte を読む経路があれば、試験と道具の build では目印が出ます。新しく確保した chunk も
        // 埋めるので、0 の byte に頼る読み取りも見つかります。
        #[cfg(any(test, fuzzing, feature = "harness"))]
        let c = {
            let mut c = c;
            c.fill(SENTINEL);
            c
        };
        self.held += 1;
        #[cfg(test)]
        PEAK_HELD.set(PEAK_HELD.get().max(self.held));
        Ok(c)
    }

    /// chunk を返します。中身は埋めずに置き場に置きます。
    pub(crate) fn put(&mut self, c: Chunk) {
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
        assert!(
            c.iter().all(|&b| b == SENTINEL),
            "a new chunk holds the sentinel in a test build"
        );
        c[100] = 7;
        p.put(c);
        assert_eq!((p.held(), p.kept()), (0, 1));
        let c = p.get().unwrap();
        assert!(
            c.iter().all(|&b| b == SENTINEL),
            "a reused chunk holds the sentinel in a test build"
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
