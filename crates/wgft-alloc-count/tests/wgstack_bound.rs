//! wgstack の核の確保が上界の内にあり、閉じて `Budget` を捨てると元に戻ることを、確保の数えで確かめます。
//! 数えるのは試験のスレッドの確保だけです (`ThreadWindow`)。核はスレッドを持たないので、核の確保はすべて
//! このスレッドで起こります。libtest の main のスレッドが並行にする確保は数えません。

use core::net::Ipv4Addr;
use wgft_alloc_count::{CountingAlloc, ThreadWindow};
use wgft_wgstack::{Budget, Config, Limits, NoHook, Stack, Time};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

#[test]
fn stack_allocations_stay_within_the_bound() {
    for k in [64, Limits::DEFAULT_MAX_FLOWS] {
        let config = Config {
            limits: Limits::with_max_flows(k),
            ..Config::new(Ipv4Addr::new(10, 9, 0, 1), 1420)
        };
        let w = ThreadWindow::open();
        let budget = Budget::new().expect("budget");
        let budget_bytes = w.grown();
        let stack = Stack::new(config, budget, &[7; 64], NoHook).expect("stack");
        let bound = stack.bound();
        let used = w.grown();
        assert!(
            budget_bytes as u64 <= bound.boost,
            "K {k}: the budget allocates {budget_bytes} bytes over its term {}",
            bound.boost
        );
        // 作ったばかりの核の確保は、固定の項と boost の配列と再組み立ての表と UDP と ping の項の内にあります。
        // UDP の項の中身の予算は chunk を受けた時に使うので、作った時は管理の配列だけを持ちます。
        let fixed = bound.fix + bound.boost + bound.frag + bound.udp_rx + bound.udp_tx + bound.ping;
        assert!(used as u64 <= fixed, "K {k}: {used} bytes over {fixed}");
        assert!(
            w.peak() as u64 <= bound.total,
            "K {k}: the peak exceeds the bound"
        );
        stack.check_invariants().expect("invariants");
        let closed = stack.close(Time::ZERO);
        assert!(closed.held.is_zero());
        assert_eq!(
            w.grown(),
            budget_bytes,
            "K {k}: closing returns every table"
        );
        drop(closed);
        assert_eq!(w.grown(), 0, "K {k}: dropping the budget returns the rest");
    }
}
