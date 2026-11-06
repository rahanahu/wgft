//! Hash S の試作のスレッドの間の受け渡しの部品 (製品に入れない試作)。
//!
//! - [`Ring`] は、容量の決まった 1 対 1 の輪。front から区画への packet のバッチと、その戻りに使う
//! - [`Bell`] は、眠りの印つきの起こしの知らせ。待つ側が眠る時だけ知らせる側が起こす
//! - [`Demand`] は、区画が front に在庫を求める数と、その印
//! - [`Ending`] は、世代の終わりの印と、全員を起こすこと
//!
//! どれも unsafe を使わない。輪の枠は錠で包むが、書き手は読み手が読み終えた枠だけを、読み手は書き手が書き終えた
//! 枠だけを触るので、錠は取り合わない (順は `head` と `tail` の Acquire と Release が決める)。錠は所有の安全な
//! 受け渡しのためだけにあり、取るのはバッチ 1 つごとに 1 回である。
//!
//! loom の模型 (notes の common-design.md の L2、L6、L7) は、この crate の型そのものを `--cfg loom` の試験の
//! build で loom の同期の型に替えて確かめる (`cargo test -p wgft-hashs-sync --lib` を `RUSTFLAGS="--cfg loom"` で)。
//! 待つ仕組みは [`Notifier`] で外から渡す。製品は tokio の `Notify`、模型は loom の `Notify` を使う。

#![forbid(unsafe_code)]

#[cfg(all(loom, test))]
use loom::sync::Mutex;
#[cfg(all(loom, test))]
pub use loom::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

#[cfg(not(all(loom, test)))]
use std::sync::Mutex;
#[cfg(not(all(loom, test)))]
pub use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use std::sync::PoisonError;

#[cfg(all(loom, test))]
mod loom_tests;

/// 容量 `cap` の 1 対 1 の輪。書き手と読み手はそれぞれ 1 つのスレッドだけである。
pub struct Ring<T> {
    slots: Box<[Mutex<Option<T>>]>,
    /// 読み手が次に読む位置。読み手だけが書く。
    head: AtomicUsize,
    /// 書き手が次に書く位置。書き手だけが書く。
    tail: AtomicUsize,
}

impl<T> std::fmt::Debug for Ring<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ring")
            .field("cap", &self.slots.len())
            .finish_non_exhaustive()
    }
}

impl<T> Ring<T> {
    /// 容量 `cap` (1 以上) の空の輪。
    pub fn new(cap: usize) -> Self {
        Self {
            slots: (0..cap.max(1)).map(|_| Mutex::new(None)).collect(),
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    /// 書き手:`v` を足す。満ちていれば `v` を返す。
    pub fn push(&self, v: T) -> Result<(), T> {
        let t = self.tail.load(Ordering::Relaxed);
        let h = self.head.load(Ordering::Acquire);
        if t.wrapping_sub(h) >= self.slots.len() {
            return Err(v);
        }
        *self.slots[t % self.slots.len()]
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(v);
        self.tail.store(t.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// 読み手:最も古い項を取る。空なら `None`。
    pub fn pop(&self) -> Option<T> {
        let h = self.head.load(Ordering::Relaxed);
        let t = self.tail.load(Ordering::Acquire);
        if h == t {
            return None;
        }
        let v = self.slots[h % self.slots.len()]
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.head.store(h.wrapping_add(1), Ordering::Release);
        v
    }

    /// 読み手:項が残っているか。
    pub fn has_items(&self) -> bool {
        self.head.load(Ordering::Relaxed) != self.tail.load(Ordering::Acquire)
    }
}

/// 待つ task を起こす仕組み。許可を残す (待つ前の知らせで次の待ちがすぐ解ける) ものに限る。
pub trait Notifier {
    /// 待つ task を 1 つ起こす。待つ task がいなければ許可を残す。
    fn notify_one(&self);
}

/// 眠りの印つきの起こしの知らせ (event count)。待つのは 1 つの task だけである。
///
/// 1 つの語に、知らせの回数 (2 ずつ進める) と眠りの印 (bit 0) を置く。待つ側は起床の始めに
/// [`Bell::prepare`] で回数を読み、仕事を読み切った後に [`Bell::sleep`] でその回数のまま印を立てられた時だけ
/// [`Bell::notifier`] で待つ。立てられなければ、その間に知らせがあったので仕事を読み直す。知らせる側は仕事を
/// 公開した後に [`Bell::ring`] で回数を進め、印が立っていた時だけ起こす。印と回数が同じ語の読み書き (RMW) なので、
/// 知らせは待つ側の印の前か後のどちらかに並び、仕事が残ったまま待ち続けることは無い (L2)。起こしの知らせは許可を
/// 残すので、印を立ててから待つまでの間の知らせも失わない。
///
/// 最初の版は印と仕事を別の語の SeqCst の読み書きで組んだ (Dekker の形)。loom は SeqCst の読み書きを AcqRel と
/// して扱うのでその形を確かめられず、fence を足しても模型 L2 が眠り続けを報告したので、1 つの語の形にした
/// (2026-11-06)。
#[derive(Debug, Default)]
pub struct Bell<N> {
    state: AtomicU64,
    notify: N,
}

/// 眠りの印。
const SLEEPING: u64 = 1;

impl<N: Notifier> Bell<N> {
    /// 知らせる側:仕事を公開した後に呼ぶ。待つ側が眠る途中か眠っていれば起こす。
    pub fn ring(&self) {
        if self.state.fetch_add(2, Ordering::AcqRel) & SLEEPING != 0 {
            self.notify.notify_one();
        }
    }

    /// 待つ側:起床の始め (仕事を読む前) に知らせの回数を読む。
    pub fn prepare(&self) -> u64 {
        self.state.load(Ordering::Acquire) & !SLEEPING
    }

    /// 待つ側:仕事を読み切った後に、[`Bell::prepare`] の回数 `seen` のまま印を立てる。立てたら真で、待ってよい。
    /// 偽ならその間に知らせがあったので、仕事を読み直す。
    pub fn sleep(&self, seen: u64) -> bool {
        self.state
            .compare_exchange(seen, seen | SLEEPING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// 待つ側:起きた後に印を外す。
    pub fn awake(&self) {
        self.state.fetch_and(!SLEEPING, Ordering::AcqRel);
    }

    /// 待つ側が待つ仕組み。
    pub fn notifier(&self) -> &N {
        &self.notify
    }
}

/// 区画が front に求める在庫の数。区画が足し、front が 0 に替えて読む。
#[derive(Debug, Default)]
pub struct Demand {
    n: AtomicU32,
}

impl Demand {
    /// 区画:`n` 個を求め、front を起こす。前の求めが残っていれば大きい方にする。
    pub fn ask<N: Notifier>(&self, n: u32, front: &Bell<N>) {
        self.n.fetch_max(n, Ordering::SeqCst);
        front.ring();
    }

    /// front:求めを取り出す。応えられなかった分は [`Demand::put_back`] で戻す。
    pub fn take(&self) -> u32 {
        self.n.swap(0, Ordering::SeqCst)
    }

    /// front:応えられなかった求めを戻す。front 自身が次の起床で見る。
    pub fn put_back(&self, n: u32) {
        if n > 0 {
            self.n.fetch_max(n, Ordering::SeqCst);
        }
    }

    /// front が眠る前の読み直し:求めが残っているか。
    pub fn pending(&self) -> bool {
        self.n.load(Ordering::SeqCst) != 0
    }
}

/// 世代の終わりの印。どれかのスレッドが終わる時に立て、全員を起こす (L6)。
#[derive(Debug, Default)]
pub struct Ending {
    ended: AtomicBool,
}

impl Ending {
    /// 印を立て、`bells` の全員を起こす。
    pub fn end<'a, N: Notifier + 'a>(&self, bells: impl IntoIterator<Item = &'a Bell<N>>) {
        self.ended.store(true, Ordering::SeqCst);
        for b in bells {
            b.ring();
        }
    }

    /// 印が立っているか。眠る前の読み直しにも使う。
    pub fn is_ended(&self) -> bool {
        self.ended.load(Ordering::SeqCst)
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize as Count;

    #[derive(Default)]
    struct Counting(Count);

    impl Notifier for Counting {
        fn notify_one(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn the_ring_is_fifo_and_bounded() {
        let r = Ring::new(2);
        assert!(r.push(1).is_ok());
        assert!(r.push(2).is_ok());
        assert_eq!(r.push(3), Err(3));
        assert!(r.has_items());
        assert_eq!(r.pop(), Some(1));
        assert!(r.push(3).is_ok());
        assert_eq!(r.pop(), Some(2));
        assert_eq!(r.pop(), Some(3));
        assert_eq!(r.pop(), None);
        assert!(!r.has_items());
    }

    #[test]
    fn a_bell_wakes_only_a_sleeper() {
        let b = Bell::<Counting>::default();
        b.ring();
        assert_eq!(b.notifier().0.load(Ordering::SeqCst), 0);
        let seen = b.prepare();
        b.ring();
        assert!(!b.sleep(seen), "a ring since prepare: read the work again");
        let seen = b.prepare();
        assert!(b.sleep(seen));
        b.ring();
        assert_eq!(b.notifier().0.load(Ordering::SeqCst), 1);
        b.awake();
        b.ring();
        assert_eq!(b.notifier().0.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn demand_keeps_the_largest_ask() {
        let front = Bell::<Counting>::default();
        let d = Demand::default();
        d.ask(3, &front);
        d.ask(2, &front);
        assert!(d.pending());
        assert_eq!(d.take(), 3);
        assert!(!d.pending());
        d.put_back(5);
        assert_eq!(d.take(), 5);
    }
}
