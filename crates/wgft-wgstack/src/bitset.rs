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

    /// 印の付いた数です。
    pub(crate) fn count(&self) -> usize {
        self.words.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// 印の付いた番号を小さい順に渡します。
    pub(crate) fn for_each(&self, mut f: impl FnMut(u32)) {
        let mut base = 0u32;
        for &w in self.words.iter() {
            let mut w = w;
            while w != 0 {
                f(base | w.trailing_zeros());
                w &= w - 1;
            }
            base = base.wrapping_add(64);
        }
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
}
