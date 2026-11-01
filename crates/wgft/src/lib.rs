//! wgft のコマンドの組み立て。移行の間は Rust の agent のコマンドだけを持つ。
//!
//! 設定の層は `wgft_agent::config` にあり、ここは clap への接続 (`cli`)、設定を読んで入口を通す手順
//! (`agent_run`)、失敗と終了コード (`failure`) を持つ。

pub mod agent_keys;
pub mod agent_run;
pub mod cli;
pub mod doctor;
pub mod failure;

/// この crate の版。
///
/// ```
/// assert!(!wgft::VERSION.is_empty());
/// ```
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// ビルドした wgft の版。ビルドの時に環境変数 `BUILD_RELEASE_VERSION` で埋める。無ければ crate の版から作る。
/// この変数はビルドだけが読み、実行時の `WGFT_*` の設定とは関係がない。
///
/// ```
/// assert!(wgft::version().ends_with(wgft::VERSION) || option_env!("BUILD_RELEASE_VERSION").is_some());
/// ```
#[must_use]
pub fn version() -> String {
    option_env!("BUILD_RELEASE_VERSION")
        .filter(|v| !v.is_empty())
        .map_or_else(|| format!("dev-rust-{VERSION}"), str::to_owned)
}

/// `wgft version` の出力。1 行目は版、2 行目はこのバイナリが扱う wire の版の範囲である。
#[must_use]
pub fn version_text() -> String {
    format!(
        "{}\nprotocol range: v{}-v{}\n",
        version(),
        wgft_proto::SUPPORTED_PROTOCOL.min,
        wgft_proto::SUPPORTED_PROTOCOL.max
    )
}
