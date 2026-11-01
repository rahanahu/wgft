//! wgstack の核の確保が上界の内にあり、閉じて `Budget` を捨てると元に戻ることを、確保の数えで確かめます。
//! 数えはプロセスで 1 つなので、このファイルには試験を 1 つだけ置きます。

use core::net::Ipv4Addr;
use wgft_alloc_count::{CountingAlloc, live_bytes, peak_bytes, reset_peak};
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
        let base = live_bytes();
        reset_peak();
        let budget = Budget::new().expect("budget");
        let budget_bytes = live_bytes() - base;
        let stack = Stack::new(config, budget, &[7; 64], NoHook).expect("stack");
        let bound = stack.bound();
        let used = live_bytes() - base;
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
            (peak_bytes() - base) as u64 <= bound.total,
            "K {k}: the peak exceeds the bound"
        );
        stack.check_invariants().expect("invariants");
        let closed = stack.close(Time::ZERO);
        assert!(closed.held.is_zero());
        assert_eq!(
            live_bytes() - base,
            budget_bytes,
            "K {k}: closing returns every table"
        );
        drop(closed);
        assert_eq!(
            live_bytes(),
            base,
            "K {k}: dropping the budget returns the rest"
        );
    }
}
