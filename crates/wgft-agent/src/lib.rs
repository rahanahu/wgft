//! Rust の agent の制御プレーンの試作。
//!
//! 接続文字列と登録、認証情報 (`agent.json`)、stream、全体状態の適用、ハートビート、TCP の中継を
//! 持つ。WireGuard の device の層は、試作の TUN の経路では `tunnel` が、TUN を使わない経路では
//! `dataplane` が扱う。作りは `docs/design/v2/agent-control.md` に書く。

pub mod config;
mod control;
pub mod controlapi;
pub mod credentials;
mod ctlserver;
pub mod dataplane;
pub mod enroll;
pub mod error;
pub mod flowpool;
pub mod hostaddr;
pub mod logging;
pub mod memory;
pub mod platform;
pub mod relay;
mod run;
mod stream;
pub mod targets;
pub mod tunnel;

pub use error::{AgentError, Refusal};
pub use run::{Options, run};
