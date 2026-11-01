//! 容量を作成の時に決め、後から伸ばさない配列 (wgstack-rs.md の「確保の規則」)。
//!
//! 核の可変長の保持はこの型だけで持ちます。
//! 中身は `try_reserve_exact` で取った `Vec` で、`into_boxed_slice` には変えません。
//! `try_reserve_exact` は要求より大きな容量を返すことがあり、`into_boxed_slice` はそのとき縮めるために
//! 再確保するためです。上界と会計は [`FixedVec::capacity`] の実際の値で数えます。
//!
//! clippy の禁止の一覧 (`clippy.toml`) の例外は、この module だけです。

#![expect(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    reason = "FixedVec is the one place that holds a Vec and allocates"
)]

use core::fmt;
use core::mem::size_of;
use core::ops::{Deref, DerefMut};

/// 確保の失敗です。呼び手は予算が尽きたときと同じ動作にします。
/// Rust の標準の確保は失敗するとプロセスを止めるので、核は失敗を返す確保だけを使います。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AllocError;

/// 容量が足りないことを表します。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Full;

/// 作成の時に容量を決める配列です。容量を超える追加は誤りを返し、再確保しません。
pub(crate) struct FixedVec<T> {
    v: Vec<T>,
}

impl<T> FixedVec<T> {
    /// 容量 0 の配列を返します。確保しません。
    pub(crate) const fn new() -> Self {
        Self { v: Vec::new() }
    }

    /// 少なくとも `n` 個を持てる配列を確保します。
    pub(crate) fn try_with_capacity(n: usize) -> Result<Self, AllocError> {
        let mut v = Vec::new();
        v.try_reserve_exact(n).map_err(|_| AllocError)?;
        Ok(Self { v })
    }

    /// 長さと容量が `n` の配列を、`f(i)` の値で埋めて確保します。
    pub(crate) fn try_filled(n: usize, mut f: impl FnMut(usize) -> T) -> Result<Self, AllocError> {
        let mut s = Self::try_with_capacity(n)?;
        for i in 0..n {
            s.v.push(f(i));
        }
        Ok(s)
    }

    /// `x` を末尾に足します。容量が尽きていれば `x` を返します。
    pub(crate) fn try_push(&mut self, x: T) -> Result<(), T> {
        if self.v.len() == self.v.capacity() {
            return Err(x);
        }
        self.v.push(x);
        Ok(())
    }

    /// 末尾の要素を外して返します。
    pub(crate) fn pop(&mut self) -> Option<T> {
        self.v.pop()
    }

    /// 長さを `len` 以下にします。容量は変えません。
    pub(crate) fn truncate(&mut self, len: usize) {
        self.v.truncate(len);
    }

    /// すべての要素を外します。容量は変えません。
    pub(crate) fn clear(&mut self) {
        self.v.clear();
    }

    /// 持てる要素の数です。確保の時に要求した数以上です。
    pub(crate) fn capacity(&self) -> usize {
        self.v.capacity()
    }

    /// 確保した領域の byte 数 (容量と要素の大きさの積) です。上界と会計はこの値で数えます。
    pub(crate) fn heap_bytes(&self) -> usize {
        self.v.capacity() * size_of::<T>()
    }

    /// 確保した領域を解放し、容量 0 の配列に戻します。
    pub(crate) fn free(&mut self) {
        self.v = Vec::new();
    }
}

impl<T: Copy> FixedVec<T> {
    /// `src` の写しを、容量が `src.len()` 以上の新しい配列に確保します。
    pub(crate) fn try_from_slice(src: &[T]) -> Result<Self, AllocError> {
        let mut s = Self::try_with_capacity(src.len())?;
        s.v.extend_from_slice(src);
        Ok(s)
    }

    /// `src` を末尾に写します。容量が足りなければ何も足さずに誤りを返します。
    pub(crate) fn try_extend_from_slice(&mut self, src: &[T]) -> Result<(), Full> {
        if self.v.capacity() - self.v.len() < src.len() {
            return Err(Full);
        }
        self.v.extend_from_slice(src);
        Ok(())
    }
}

impl<T> Default for FixedVec<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Deref for FixedVec<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.v
    }
}

impl<T> DerefMut for FixedVec<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.v
    }
}

impl<T: fmt::Debug> fmt::Debug for FixedVec<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.v.iter()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_stops_at_the_capacity() {
        let mut v = FixedVec::try_with_capacity(3).unwrap();
        let cap = v.capacity();
        assert!(cap >= 3);
        for i in 0..cap {
            v.try_push(i).unwrap();
        }
        assert_eq!(v.try_push(99), Err(99));
        assert_eq!(v.capacity(), cap, "a refused push must not reallocate");
        assert_eq!(v.len(), cap);
        assert_eq!(v.pop(), Some(cap - 1));
        v.try_push(7).unwrap();
        assert_eq!(v[cap - 1], 7);
    }

    #[test]
    fn extend_is_all_or_nothing() {
        let mut v = FixedVec::try_with_capacity(4).unwrap();
        let cap = v.capacity();
        v.try_extend_from_slice(&[1u8, 2]).unwrap();
        let too_long = [0u8; 64];
        assert_eq!(v.try_extend_from_slice(&too_long[..cap - 1]), Err(Full));
        assert_eq!(&v[..], &[1, 2]);
        assert_eq!(v.capacity(), cap);
        v.truncate(1);
        assert_eq!(&v[..], &[1]);
        v.clear();
        assert!(v.is_empty());
    }

    #[test]
    fn filled_and_copied() {
        let v = FixedVec::try_filled(5, |i| i * 2).unwrap();
        assert_eq!(&v[..], &[0, 2, 4, 6, 8]);
        let w = FixedVec::try_from_slice(&v[1..3]).unwrap();
        assert_eq!(&w[..], &[2, 4]);
        assert_eq!(w.heap_bytes(), w.capacity() * size_of::<usize>());
    }

    #[test]
    fn huge_requests_fail_instead_of_aborting() {
        assert_eq!(
            FixedVec::<u64>::try_with_capacity(usize::MAX).err(),
            Some(AllocError)
        );
        assert_eq!(
            FixedVec::<u8>::try_with_capacity(isize::MAX as usize + 1).err(),
            Some(AllocError)
        );
    }

    #[test]
    fn free_returns_to_zero_capacity() {
        let mut v = FixedVec::try_from_slice(&[1u8; 100]).unwrap();
        v.free();
        assert_eq!(v.capacity(), 0);
        assert_eq!(v.heap_bytes(), 0);
        assert!(FixedVec::<u8>::default().is_empty());
    }
}
