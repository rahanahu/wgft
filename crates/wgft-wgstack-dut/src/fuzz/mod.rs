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
    Check, DUT, HarnessOptions, MTU, Net, PEER, fuzz_limits, last_digest, put_spare, set_options,
    small_limits, take_spare,
};
pub use peer::{PeerConn, SackPeer};
pub use raw::{raw_adversary, raw_adversary_input, raw_adversary_seed};
pub use replay::{replay, replay_seed};

/// この build が整数の溢れを検査するかを、実際に溢れさせて確かめます。検査ありなら溢れの足し算が panic し、
/// 検査なしなら回り込んで返ります。`RUSTFLAGS='-C overflow-checks=off'` が cargo-fuzz の build に本当に効いたかを
/// 判じる canary です。足し算は `black_box` で畳み込みを防ぎ、panic は呼び手の hook (fuzz の target では abort)
/// を一時的に外して受けます。
#[must_use]
pub fn overflow_checks_enabled() -> bool {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let panicked = std::panic::catch_unwind(|| {
        std::hint::black_box(std::hint::black_box(u32::MAX) + std::hint::black_box(1))
    })
    .is_err();
    std::panic::set_hook(prev);
    panicked
}

/// 環境変数 `WGFT_FUZZ_OVERFLOW_CHECKS` (`on` か `off`) が決める期待を、[`overflow_checks_enabled`] と照らします。
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
        overflow_checks_enabled(),
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
