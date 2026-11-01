//! wgft の agent。
//!
//! 接続文字列と登録、認証情報 (`agent.json`)、stream、全体状態の適用、ハートビート、TCP と UDP の中継、
//! 制御ソケットを持つ。WireGuard の device の層と Rust の wgstack の核は、`tunnel` が世代ごとに立てる
//! `dataplane` のスレッドが動かす。TUN は使わない。作りは `docs/design/v2/agent-control.md` と
//! `docs/design/v2/agent-parity.md` に書く。

pub mod batching;
pub mod config;
mod control;
pub mod controlapi;
pub mod credentials;
mod ctlserver;
mod dataplane;
pub mod enroll;
mod error;
pub mod flowpool;
pub mod hostaddr;
pub mod logging;
pub mod memory;
pub mod oserror;
pub mod platform;
mod relay;
mod run;
mod stream;
pub mod targets;
pub mod tunnel;

pub use error::{AgentError, Refusal};
pub use run::{Options, run};

/// 単体の試験の確保を数える。メモリの上界と実際の保持を比べる試験 (`relay::held_tests`) が読む。
/// cargo-nextest は試験ごとにプロセスを分けるので、数は試験ごとである。
#[cfg(test)]
#[global_allocator]
static ALLOC: wgft_alloc_count::CountingAlloc = wgft_alloc_count::CountingAlloc;
