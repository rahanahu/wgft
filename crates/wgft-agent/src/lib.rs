//! Rust の agent の制御プレーンの試作。
//!
//! 接続文字列と登録、認証情報 (`agent.json`)、stream、全体状態の適用、ハートビート、TCP の中継を
//! 持つ。WireGuard の device の層は `tunnel` だけが扱う。作りは `docs/design/v2/agent-control.md` に書く。

pub mod credentials;
pub mod enroll;
pub mod error;
pub mod hostaddr;
pub mod inbound;
pub mod logging;
pub mod relay;
mod run;
mod stream;
pub mod tunnel;

pub use error::{AgentError, Refusal};
pub use run::{Options, run};
