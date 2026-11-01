//! 嘘を混ぜる相手に stream を送らせます。入力の先頭の 8 byte が種です (Go の `FuzzAdversarialSender` に当たります)。
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| wgft_wgstack_dut::fuzz::adversarial_sender(data));
