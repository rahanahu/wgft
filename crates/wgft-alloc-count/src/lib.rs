//! 確保と解放の byte を数える割り当て器です (docs/design/v2/wgstack-rs.md の「保持の量の測り方」)。
//!
//! 試験の build だけが使う道具で、製品のバイナリに入りません。試験の crate は `#[global_allocator]` に
//! [`CountingAlloc`] を置き、核の操作の前後で [`live_bytes`] を読みます。GC が無いので、生きている byte の差は
//! 核が持つ保持をそのまま表します。数えるのは要求の大きさで、割り当て器の丸めは含みません。
//! 数はプロセスで 1 つなので、並行に動く試験の確保も混ざります。測る試験は 1 つの試験のバイナリに 1 つだけ
//! 置くか、cargo-nextest のように試験ごとにプロセスを分けて流します。

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// システムの割り当て器を包み、生きている byte と最大値を数える割り当て器です。
#[derive(Debug, Default, Clone, Copy)]
pub struct CountingAlloc;

fn grew(n: usize) {
    let now = LIVE.fetch_add(n, Ordering::Relaxed) + n;
    PEAK.fetch_max(now, Ordering::Relaxed);
}

fn shrank(n: usize) {
    LIVE.fetch_sub(n, Ordering::Relaxed);
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
