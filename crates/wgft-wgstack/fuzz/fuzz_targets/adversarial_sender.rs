//! 嘘を混ぜる相手に stream を送らせます。入力の先頭の 8 byte が種です (Go の `FuzzAdversarialSender` に当たります)。
#![no_main]

wgft_wgstack_dut::fuzz_entry!(wgft_wgstack_dut::fuzz::adversarial_sender);
