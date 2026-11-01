//! fuzz の `raw_adversary` の target の種を書きます (`docs/design/v2/test-tooling.md` の 6 節)。
//!
//! ```text
//! cargo run -p wgft-wgstack-dut --example raw_seeds -- OUT_DIR [COUNT] [BYTES]
//! ```
//!
//! 種 1 から `COUNT` (既定は 16) の入力を、`raw-<種>` の名前で `BYTES` (既定は 16000) byte ずつ書きます。
//! 中身は stable の試験 (`tests/fuzz_corpus.rs`) が流す入力と同じ作り方です。短い入力から始めると握手の途中の
//! 表が満ちず、SYN cookie の確かめに届かないので、長い入力を種にします。

use std::path::PathBuf;
use std::{env, fs};

use wgft_wgstack_dut::fuzz::raw_adversary_input;

fn main() {
    let mut args = env::args().skip(1);
    let out = PathBuf::from(
        args.next()
            .expect("usage: raw_seeds OUT_DIR [COUNT] [BYTES]"),
    );
    let count: u64 = args
        .next()
        .map_or(16, |v| v.parse().expect("COUNT is a number"));
    let bytes: usize = args
        .next()
        .map_or(16_000, |v| v.parse().expect("BYTES is a number"));
    fs::create_dir_all(&out).unwrap_or_else(|e| panic!("{}: {e}", out.display()));
    for seed in 1..=count {
        let p = out.join(format!("raw-{seed}"));
        fs::write(&p, raw_adversary_input(seed, bytes))
            .unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    }
}
