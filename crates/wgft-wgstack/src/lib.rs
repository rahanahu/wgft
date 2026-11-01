//! wgft の TCP/IP の stack、wgstack の Rust 版の核です。
//!
//! 核は sans-IO です。入力は時刻、packet、アプリケーションの操作で、出力は packet、次に起こす時刻、
//! 知らせです。核の中にスレッド、実時間のタイマー、ソケット、OS の乱数を置きません。
//! 設計は `docs/design/v2/wgstack-rs.md` にあり、振る舞いの正本は凍結した Go の wgstack
//! (`internal/wgstack`) とその設計文書です。移行の間は Go の wgstack と同じ入力に同じ packet を返します。
//!
//! 核は段を踏んで作ります。今の段は packet の解釈と組み立て、checksum、IPv4 の再組み立ての表、
//! SipHash、ChaCha8、時刻の型までで、核の API はまだありません。
//!
//! 依存と確保の規則:この crate は標準ライブラリだけに依り、unsafe を使いません。
//! 可変長の保持は容量を作成の時に決める配列だけで持ち、容量を自動で伸ばす API を使いません。
//! この規則は `clippy.toml` の禁止の一覧と、source を走査する試験が確かめます。

#![forbid(unsafe_code)]

// 核を組む前の段なので、部品の多くはまだ crate の中から使われません。核の段で使われるにつれて外します。
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the core that uses FixedVec lands in a later stage"
    )
)]
mod fixed_vec;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the core that uses the reassembly table lands in a later stage"
    )
)]
mod frag;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the core that draws random numbers lands in a later stage"
    )
)]
mod rng;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the tables that hash tuples land in a later stage"
    )
)]
mod siphash;
mod time;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the core that parses and builds packets lands in a later stage"
    )
)]
mod wire;

pub use time::Time;

/// cargo-fuzz の target が呼ぶ入口です。`--cfg fuzzing` の build だけにあり、製品の API ではありません。
#[cfg(fuzzing)]
pub mod fuzz {
    /// `parse` の target:packet の解釈と checksum と再組み立ての表に任意の bytes を通します。
    pub fn parse(data: &[u8]) {
        crate::wire::fuzz_parse(data);
    }
}

#[cfg(test)]
mod golden_tests;
#[cfg(test)]
mod scan_tests;
