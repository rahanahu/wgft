//! wgstack の fuzz の target の本体です (`docs/design/v2/test-tooling.md` の 6 節)。
//!
//! cargo-fuzz の target (`crates/wgft-wgstack/fuzz/`) はここの関数を呼ぶだけで、stable の試験
//! (`tests/fuzz_corpus.rs`) も同じ関数で corpus と見つけた落ちる入力を流します。どの関数も、確かめが破れたら
//! panic します。
//!
//! - [`core`]:Go の `FuzzCore` の op の解釈器と相手の模型を、同じ byte が同じ op になるように写したもの
//! - [`adversarial_sender`]:Go の `FuzzAdversarialSender` (`runAudit`) を、核の公開の API で写したもの
//! - [`replay`]:3 節の要求の列を `wgstack-dut` の adapter に流すもの。種は Go の wgstack の記録の要求の列です
//!
//! 核の内部に触れず、公開の API だけを使います。Go の試験が内部の欄で確かめていたこと (SND.UNA と SND.MAX の
//! 順序、scoreboard の数え直しなど) は、核の `check_invariants` と、外から見える出力の確かめに替えます。
//!
//! 入力ごとの準備を軽くするため、boost の枠の集まり (`Budget`) はスレッドごとに 1 つ作り、核を閉じるたびに
//! 取り戻して次の入力に渡します。製品と同じく、閉じた核の `Budget` は借りが 0 です。

mod adversary;
mod core;
mod net;
mod peer;
mod replay;

pub use adversary::{AdversaryCfg, adversarial_sender, adversarial_sender_seed};
pub use core::core;
pub use net::{DUT, MTU, Net, PEER, fuzz_limits, small_limits};
pub use peer::{PeerConn, SackPeer};
pub use replay::{replay, replay_seed};
