//! DUT の口の要求の列を Rust の wgstack に流します。種は Go の wgstack の記録の要求の列です。
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| wgft_wgstack_dut::fuzz::replay(data));
