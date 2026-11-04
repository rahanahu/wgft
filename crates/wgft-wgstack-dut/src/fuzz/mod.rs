//! wgstack の fuzz の target の本体です (`docs/design/v2/test-tooling.md` の 6 節)。
//!
//! cargo-fuzz の target (`crates/wgft-wgstack/fuzz/`) はここの関数を呼ぶだけで、stable の試験
//! (`tests/fuzz_corpus.rs`) も同じ関数で corpus と見つけた落ちる入力を流します。どの関数も、確かめが破れたら
//! panic します。
//!
//! - [`core`]:Go の `FuzzCore` の op の解釈器と相手の模型を、同じ byte が同じ op になるように写したもの
//! - [`adversarial_sender`]:Go の `FuzzAdversarialSender` (`runAudit`) を、核の公開の API で写したもの
//! - [`replay`]:3 節の要求の列を `wgstack-dut` の adapter に流すもの。種は Go の wgstack の記録の要求の列です
//! - [`raw_adversary`]:状態を持つ生の packet の敵。Go に元の試験は無く、SYN cookie、断片、ICMP、UDP、
//!   アプリケーションの操作、長い時刻の跳びを混ぜます
//!
//! 核の内部に触れず、公開の API だけを使います。Go の試験が内部の欄で確かめていたこと (SND.UNA と SND.MAX の
//! 順序、scoreboard の数え直しなど) は、核の `check_invariants` と、外から見える出力の確かめに替えます。
//!
//! 入力ごとの準備を軽くするため、boost の枠の集まり (`Budget`) はスレッドごとに 1 つ作り、核を閉じるたびに
//! 取り戻して次の入力に渡します。製品と同じく、閉じた核の `Budget` は借りが 0 です。`Net` を使う target は、
//! ポートの数の行を持つ表も作成の時の値に戻して次の入力の核に渡します (`Stack::close_keeping`)。

mod adversary;
mod core;
mod net;
mod peer;
mod raw;
mod replay;

pub use adversary::{AdversaryCfg, adversarial_sender, adversarial_sender_seed};
pub use core::core;
pub use net::{
    Check, DUT, HarnessOptions, MTU, Net, PEER, fuzz_limits, last_digest, put_spare, send_turn_for,
    set_options, small_limits, take_spare, with_send_turn_for,
};
pub use peer::{PeerConn, SackPeer};
pub use raw::{raw_adversary, raw_adversary_input, raw_adversary_seed};
pub use replay::{replay, replay_seed};

/// 環境変数 `WGFT_FUZZ_OVERFLOW_CHECKS` (`on` か `off`) が決める期待を、核 (`wgft-wgstack`) の中で溢れさせて確かめる
/// [`wgft_wgstack::overflow_checks_enabled`] と照らします。設定は crate ごとに効くので、この crate ではなく核の
/// 設定を見ます。
/// 変数が無ければ何もしません。食い違えば、fuzz が意図した build でない流れを黙って続けないよう、panic します。
pub fn expect_overflow_checks() {
    let Ok(want) = std::env::var("WGFT_FUZZ_OVERFLOW_CHECKS") else {
        return;
    };
    let want_on = match want.as_str() {
        "on" => true,
        "off" => false,
        other => panic!("WGFT_FUZZ_OVERFLOW_CHECKS must be on or off, got {other:?}"),
    };
    assert_eq!(
        wgft_wgstack::overflow_checks_enabled(),
        want_on,
        "this build has overflow checks {} but WGFT_FUZZ_OVERFLOW_CHECKS={want}",
        if want_on { "off" } else { "on" }
    );
}

/// 表を使い回す cargo-fuzz の target を宣言します。入力の間で核の表を使い回す選び方
/// (`HarnessOptions::FUZZ`) をここだけに置き、target を足す時に付け忘れないようにします
/// (docs/design/v2/wgstack-rs.md の「核の使い回し」)。呼び手の crate が `libfuzzer-sys` を持ちます。
#[macro_export]
macro_rules! fuzz_entry {
    ($body:path) => {
        ::libfuzzer_sys::fuzz_target!(
            init: {
                $crate::fuzz::expect_overflow_checks();
                $crate::fuzz::set_options($crate::fuzz::HarnessOptions::FUZZ);
            },
            |data: &[u8]| $body(data)
        );
    };
}
