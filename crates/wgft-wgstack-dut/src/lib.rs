//! Rust の wgstack を試験の道具に出す DUT です (`docs/design/v2/test-tooling.md`)。製品のバイナリに入らず、
//! 配布しません。
//!
//! - [`dut`]:Rust の wgstack を [`wgft_tcpharness::dut::ClockedDut`] に合わせる adapter
//! - [`serve`]:3 節の口の server。バイナリ `wgstack-dut` の中身です
//! - [`rec`]:凍結した Go の wgstack の記録の読み込みと照合
//!
//! 試験の道具はこの crate と `wgft-tcpharness` にあり、Rust の wgstack の公開の API だけを使います。

#![forbid(unsafe_code)]

pub mod dut;
pub mod rec;
pub mod serve;
