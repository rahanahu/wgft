//! 状態を持つ生の packet の敵です。SYN cookie、乱れた segment、ICMP、UDP、断片、アプリケーションの操作、
//! 時刻の跳びを混ぜ、各段で不変条件と保持の上界を確かめます。
#![no_main]

wgft_wgstack_dut::fuzz_entry!(wgft_wgstack_dut::fuzz::raw_adversary);
