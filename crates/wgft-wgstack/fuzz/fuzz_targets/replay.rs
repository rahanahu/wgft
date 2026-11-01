//! DUT の口の要求の列を Rust の wgstack に流します。種は Go の wgstack の記録の要求の列です。
#![no_main]

use libfuzzer_sys::fuzz_target;

// 入力の間で核の表を使い回します (docs/design/v2/wgstack-rs.md の「核の使い回し」)。
fuzz_target!(
    init: {
        wgft_wgstack_dut::fuzz::set_options(wgft_wgstack_dut::fuzz::Options::FUZZ);
    },
    |data: &[u8]| wgft_wgstack_dut::fuzz::replay(data)
);
