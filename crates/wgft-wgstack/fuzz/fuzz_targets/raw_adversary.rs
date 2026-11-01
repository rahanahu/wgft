//! 状態を持つ生の packet の敵です。SYN cookie、乱れた segment、ICMP、UDP、断片、アプリケーションの操作、
//! 時刻の跳びを混ぜ、各段で不変条件と保持の上界を確かめます。
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| wgft_wgstack_dut::fuzz::raw_adversary(data));
