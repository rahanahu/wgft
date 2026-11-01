//! packet、時刻の進み、アプリケーションの操作の列を核に与えます (Go の `FuzzCore` に当たります)。
#![no_main]

use libfuzzer_sys::fuzz_target;

// 入力の間で核の表を使い回します (docs/design/v2/wgstack-rs.md の「核の使い回し」)。
fuzz_target!(
    init: {
        wgft_wgstack_dut::fuzz::set_options(wgft_wgstack_dut::fuzz::Options::FUZZ);
    },
    |data: &[u8]| wgft_wgstack_dut::fuzz::core(data)
);
