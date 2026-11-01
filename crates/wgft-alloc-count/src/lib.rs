//! 確保と解放の byte を数える割り当て器です (docs/design/v2/wgstack-rs.md の「保持の量の測り方」)。
//!
//! 試験の build だけが使う道具で、製品のバイナリに入りません。試験の crate は `#[global_allocator]` に
//! [`CountingAlloc`] を置き、核の操作の前後で生きている byte を読みます。GC が無いので、生きている byte の差は
//! 核が持つ保持をそのまま表します。数えるのは要求の大きさで、割り当て器の丸めは含みません。
//!
//! 数えは 2 つあります。
//!
//! - プロセスの数え ([`live_bytes`]、[`peak_bytes`]):すべてのスレッドの確保を数えます。並行に動く試験の確保も
//!   混ざるので、測る試験は 1 つの試験のバイナリに 1 つだけ置くか、cargo-nextest のように試験ごとにプロセスを
//!   分けて流します。測る対象が複数のスレッドで動く試験 (tokio の実行環境の上の中継など) はこちらを使います
//! - スレッドの数え ([`ThreadWindow`]):窓を開いたスレッドの確保と解放だけを数えます。libtest は試験を別の
//!   スレッドで動かし、main のスレッドは試験を起動した後に結果を待つ登録 (チャネルの待ちの記録と、macOS では
//!   遅延して作る pthread の mutex の箱) を確保します。この確保は試験の測りの窓と並行に起こるので、プロセスの
//!   数えでは測りの値に混ざることがあります。スレッドを持たない核 (wgstack) を試験のスレッドから駆動して測る
//!   試験はこちらを使います

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// スレッドの数えです。const の初期値で Drop を持たない型なので、読み書きは確保もデストラクタの登録もせず、
// 割り当て器の中から使えます。他のスレッドが確保した領域をこのスレッドが解放すると負になるので符号付きです。
std::thread_local! {
    static THREAD_LIVE: Cell<isize> = const { Cell::new(0) };
    static THREAD_PEAK: Cell<isize> = const { Cell::new(0) };
}

/// システムの割り当て器を包み、生きている byte と最大値を数える割り当て器です。
#[derive(Debug, Default, Clone, Copy)]
pub struct CountingAlloc;

fn grew(n: usize) {
    let now = LIVE.fetch_add(n, Ordering::Relaxed) + n;
    PEAK.fetch_max(now, Ordering::Relaxed);
    // Layout の大きさは isize::MAX 以下です。
    let now = THREAD_LIVE.get().wrapping_add(n.cast_signed());
    THREAD_LIVE.set(now);
    if now > THREAD_PEAK.get() {
        THREAD_PEAK.set(now);
    }
}

fn shrank(n: usize) {
    LIVE.fetch_sub(n, Ordering::Relaxed);
    THREAD_LIVE.set(THREAD_LIVE.get().wrapping_sub(n.cast_signed()));
}

// SAFETY: 各メソッドは呼び手の約束をそのまま System に渡し、成功した確保と解放の大きさだけを数えます。
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: 呼び手が GlobalAlloc::alloc の約束を守ります。
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: 呼び手が GlobalAlloc::alloc_zeroed の約束を守ります。
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: 呼び手が、この割り当て器で同じ layout で確保した ptr を渡します。
        unsafe { System.dealloc(ptr, layout) };
        shrank(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: 呼び手が GlobalAlloc::realloc の約束を守ります。
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            shrank(layout.size());
            grew(new_size);
        }
        p
    }
}

/// 今生きている確保の byte (要求の大きさの和) です。
pub fn live_bytes() -> usize {
    LIVE.load(Ordering::Relaxed)
}

/// [`reset_peak`] の後の生きている byte の最大値です。
pub fn peak_bytes() -> usize {
    PEAK.load(Ordering::Relaxed)
}

/// 最大値を今の値に戻します。
pub fn reset_peak() {
    PEAK.store(live_bytes(), Ordering::Relaxed);
}

/// 開いたスレッドの確保だけを数える測りの窓です。
///
/// 窓を開いた時の値からの増分を返します。他のスレッドの確保と解放は数えません。窓は開いたスレッドの上でだけ
/// 使えます。
#[derive(Debug)]
pub struct ThreadWindow {
    base: isize,
    /// 開いたスレッドの外へ送らないための印です。
    _not_send: core::marker::PhantomData<*const ()>,
}

impl ThreadWindow {
    /// 今のスレッドの数えで窓を開き、最大値を今の値に戻します。
    pub fn open() -> Self {
        let base = THREAD_LIVE.get();
        THREAD_PEAK.set(base);
        Self {
            base,
            _not_send: core::marker::PhantomData,
        }
    }

    /// 窓を開いた後にこのスレッドで増えた生きている byte です。
    ///
    /// # Panics
    ///
    /// このスレッドが窓を開いた後に、確保した量より多くを解放していると止まります。
    pub fn grown(&self) -> usize {
        self.since(THREAD_LIVE.get())
    }

    /// 窓を開いた後か [`ThreadWindow::reset_peak`] の後の、増分の最大値です。
    ///
    /// # Panics
    ///
    /// [`ThreadWindow::grown`] と同じ条件で止まります。
    pub fn peak(&self) -> usize {
        self.since(THREAD_PEAK.get())
    }

    /// 最大値を今の値に戻します。
    pub fn reset_peak(&self) {
        THREAD_PEAK.set(THREAD_LIVE.get());
    }

    fn since(&self, now: isize) -> usize {
        let d = now - self.base;
        usize::try_from(d).unwrap_or_else(|_| {
            panic!(
                "the thread freed {} bytes more than it allocated since the window opened",
                d.unsigned_abs()
            )
        })
    }
}
