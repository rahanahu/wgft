//! wgstack の Rust 版を確かめる試験の道具です。製品のバイナリに入らず、配布しません。
//!
//! 設計は `docs/design/v2/test-tooling.md` にあります。今の中身は次のとおりです。
//!
//! - [`script`]:適合の台本の言語 (`.scn`) の構文解析器と静的な検査。Go の構文解析器
//!   (`internal/tcpharness/script_parse.go`) と同じ構文木を作り、正規化した構文木の JSON は
//!   `internal/tcpharness/scripts/testdata/` の fixture と byte の単位で一致します
//! - [`rng`]:台本の乱数。Go の `math/rand/v2` の PCG と `Uint32`、`IntN` の写しと、harness が台本の種から
//!   相手のポート、ISN、timestamp の起点を取る順序
//! - [`gojson`]:Go の `encoding/json` と同じ bytes を書く JSON の書き手と、小さな読み手
//! - [`frame`]:3 節の DUT の口の frame の符号。Go の `internal/dutproto` と同じ bytes を作ります
//! - [`packet`] と [`ip`]:試験台の IPv4、TCP、UDP、ICMP の組み立てと読み取り
//! - [`dut`]:手で進める時計の DUT の trait [`dut::ClockedDut`]、transcript を書く包み [`dut::Recorded`]、
//!   別のプロセスを叩く [`dut::ProcessDut`]
//! - [`chacha8`]:HELLO の 64 byte の種
//!
//! この crate は標準ライブラリだけに依ります。

#![forbid(unsafe_code)]

pub mod chacha8;
pub mod dut;
pub mod frame;
pub mod gojson;
pub mod ip;
pub mod packet;
pub mod rng;
pub mod script;
