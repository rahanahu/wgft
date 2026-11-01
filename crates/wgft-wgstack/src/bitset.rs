//! 番号ごとに 1 bit の印の集合 (wgstack-rs.md の「不変条件の検査の手間」)。
//!
//! list の節の印、ポートの表の開いている印、検査の間の空きの list の重なりの印に使います。印の数え上げと印の
//! 付いた番号のたどりは、番号 64 個で 1 語を読みます。

use crate::fixed_vec::{AllocError, FixedVec};

/// 番号ごとに 1 bit の印の集合です。
#[derive(Debug)]
pub(crate) struct BitSet {
    words: FixedVec<u64>,
}

impl BitSet {
    /// `n` 個の印を外した状態で確保します。
    pub(crate) fn new(n: usize) -> Result<Self, AllocError> {
        Ok(Self {
            words: FixedVec::try_filled(n.div_ceil(64), |_| 0)?,
        })
    }

    /// 印 `n` 個の配列の byte です。上界の式が使います。
    pub(crate) const fn bytes_for(n: usize) -> usize {
        n.div_ceil(64) * size_of::<u64>()
    }

    #[cfg(test)]
    pub(crate) fn heap_bytes(&self) -> usize {
        self.words.heap_bytes()
    }

    #[inline]
    pub(crate) fn get(&self, i: u32) -> bool {
        self.words[(i >> 6) as usize] >> (i & 63) & 1 != 0
    }

    #[inline]
    pub(crate) fn set(&mut self, i: u32) {
        self.words[(i >> 6) as usize] |= 1 << (i & 63);
    }

    #[inline]
    pub(crate) fn unset(&mut self, i: u32) {
        self.words[(i >> 6) as usize] &= !(1 << (i & 63));
    }

    /// すべての印を外します。試験と fuzz の build だけが使います。
    #[cfg(any(test, feature = "harness"))]
    pub(crate) fn clear(&mut self) {
        for w in self.words.iter_mut() {
            *w = 0;
        }
    }

    /// 印の付いた数です。
    pub(crate) fn count(&self) -> usize {
        let ones = |ws: &[u64]| ws.iter().map(|w| w.count_ones() as usize).sum::<usize>();
        let (blocks, rest) = self.words.as_chunks::<BLOCK>();
        blocks
            .iter()
            .filter(|b| any_set(b))
            .map(|b| ones(b))
            .sum::<usize>()
            + ones(rest)
    }

    /// 印の付いた番号を小さい順に渡します。
    pub(crate) fn for_each(&self, mut f: impl FnMut(u32)) {
        let mut base = 0u32;
        let (blocks, rest) = self.words.as_chunks::<BLOCK>();
        for b in blocks {
            if any_set(b) {
                walk(b, base, &mut f);
            }
            base = base.wrapping_add(BLOCK_BITS);
        }
        walk(rest, base, &mut f);
    }
}

/// 印の無い語を飛ばす塊の語の数です。
///
/// ポートの表のような大きくて印の少ない集合では、ほとんどの語が 0 です。塊の語の OR は分岐の無い vector の
/// 命令になるので、塊ごとに 1 回だけ分岐して印の無い塊を飛ばします。x86-64 の既定の命令の集合は popcount の命令を
/// 持たず、1 語の数え上げが 10 命令ほどになるので、数え上げも印のある塊だけにします。
const BLOCK: usize = 8;
#[expect(clippy::cast_possible_truncation, reason = "512 bits")]
const BLOCK_BITS: u32 = (BLOCK * 64) as u32;

fn any_set(b: &[u64; BLOCK]) -> bool {
    b.iter().fold(0, |a, &w| a | w) != 0
}

/// 語の列 `ws` の印を、最初の語の番号を `base` として小さい順に渡します。
fn walk(ws: &[u64], mut base: u32, f: &mut impl FnMut(u32)) {
    for &w in ws {
        let mut w = w;
        while w != 0 {
            f(base | w.trailing_zeros());
            w &= w - 1;
        }
        base = base.wrapping_add(64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_set_marks_counts_and_walks_in_order() {
        let mut b = BitSet::new(130).unwrap();
        assert_eq!(b.heap_bytes(), BitSet::bytes_for(130));
        for i in [129, 0, 64, 63] {
            b.set(i);
        }
        b.set(64);
        b.unset(0);
        assert!(b.get(129) && b.get(63) && !b.get(0) && !b.get(1));
        assert_eq!(b.count(), 3);
        let mut seen = [0u32; 3];
        let mut n = 0;
        b.for_each(|i| {
            seen[n] = i;
            n += 1;
        });
        assert_eq!(seen, [63, 64, 129]);
    }

    #[test]
    fn bit_set_counts_and_walks_across_blocks_and_the_rest() {
        // 塊 2 つと端の語 3 つです。印の無い塊、印のある塊、端の語のどれも数えてたどります。
        let n = 2 * 64 * BLOCK + 3 * 64;
        let mut b = BitSet::new(n).unwrap();
        assert_eq!(b.count(), 0);
        let marks = [700u32, 1023, 1024, u32::try_from(n - 1).unwrap()];
        for i in marks {
            b.set(i);
        }
        assert_eq!(b.count(), marks.len());
        let mut seen = [0u32; 4];
        let mut k = 0;
        b.for_each(|i| {
            seen[k] = i;
            k += 1;
        });
        assert_eq!((k, seen), (marks.len(), marks));
    }
}
