//! 嘘を混ぜる相手に stream を送らせます。入力の先頭の 8 byte が種です (Go の `FuzzAdversarialSender` に当たります)。
#![no_main]

use libfuzzer_sys::fuzz_target;

// 入力の間で核の表を使い回します (docs/design/v2/wgstack-rs.md の「核の使い回し」)。
fuzz_target!(
    init: {
        wgft_wgstack_dut::fuzz::set_options(wgft_wgstack_dut::fuzz::Options::FUZZ);
    },
    |data: &[u8]| wgft_wgstack_dut::fuzz::adversarial_sender(data)
);
