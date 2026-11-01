//! packet、時刻の進み、アプリケーションの操作の列を核に与えます (Go の `FuzzCore` に当たります)。
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| wgft_wgstack_dut::fuzz::core(data));
