//! 状態を持つ生の packet の敵です。SYN cookie、乱れた segment、ICMP、UDP、断片、アプリケーションの操作、
//! 時刻の跳びを混ぜ、各段で不変条件と保持の上界を確かめます。
#![no_main]

use libfuzzer_sys::fuzz_target;

// 入力の間で核の表を使い回します (docs/design/v2/wgstack-rs.md の「核の使い回し」)。
fuzz_target!(
    init: {
        wgft_wgstack_dut::fuzz::set_options(wgft_wgstack_dut::fuzz::Options::FUZZ);
    },
    |data: &[u8]| wgft_wgstack_dut::fuzz::raw_adversary(data)
);
