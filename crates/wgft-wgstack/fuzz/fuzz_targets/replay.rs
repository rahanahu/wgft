//! DUT の口の要求の列を Rust の wgstack に流します。種は Go の wgstack の記録の要求の列です。
#![no_main]

wgft_wgstack_dut::fuzz_entry!(wgft_wgstack_dut::fuzz::replay);
