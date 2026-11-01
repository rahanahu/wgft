//! `wgstack-dut`:Rust の wgstack を 3 節の DUT の口で出すバイナリです (`docs/design/v2/test-tooling.md`)。
//!
//! 引数は `--clock fake` だけを受け付けます。標準入力で要求を受け、標準出力で応答を返し、標準エラーにログを
//! 書きます。

use std::io;
use std::process::ExitCode;

use wgft_wgstack_dut::serve::{EXIT_PROTOCOL, serve};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let fake = matches!(
        args.iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice(),
        ["--clock", "fake"] | ["--clock=fake"]
    );
    if !fake {
        eprintln!("usage: wgstack-dut --clock fake; only the fake clock is implemented");
        return ExitCode::from(EXIT_PROTOCOL);
    }
    let code = serve(io::stdin().lock(), io::stdout().lock(), io::stderr().lock());
    ExitCode::from(code)
}
