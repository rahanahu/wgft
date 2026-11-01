//! `wgstack-dut`:Rust の wgstack を 3 節の DUT の口で出すバイナリです (`docs/design/v2/test-tooling.md`)。
//!
//! - `--clock fake`:手で進める時計です。標準入力で要求を受け、標準出力で応答を返し、標準エラーにログを書きます
//! - `--clock real`:qbench の engine です (Linux だけ)。packet は fd 3 の `SOCK_SEQPACKET` の socketpair を通ります
//! - `--relay A B`:Unix ソケット A と B の間を中継するだけの形です (Linux だけ)。qbench が中継の 1 段を測ります

use std::io;
use std::process::ExitCode;

use wgft_wgstack_dut::serve::{EXIT_PROTOCOL, serve};

const USAGE: &str = "usage: wgstack-dut --clock fake|real, or wgstack-dut --relay SOCKET SOCKET";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let code = match args.as_slice() {
        ["--clock", "fake"] | ["--clock=fake"] => {
            serve(io::stdin().lock(), io::stdout().lock(), io::stderr().lock())
        }
        #[cfg(target_os = "linux")]
        ["--clock", "real"] | ["--clock=real"] => match linux::packet_socket() {
            Ok(s) => wgft_wgstack_dut::real::serve_real(s, io::stdin(), io::stdout().lock()),
            Err(e) => {
                eprintln!("wgstack-dut: --clock real needs the packet socketpair on fd 3: {e}");
                EXIT_PROTOCOL
            }
        },
        #[cfg(target_os = "linux")]
        ["--relay", a, b] => wgft_wgstack_dut::real::relay_only(a, b),
        _ => {
            eprintln!("{USAGE}");
            EXIT_PROTOCOL
        }
    };
    ExitCode::from(code)
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::net::UnixDatagram;

    /// 親が fd 3 に渡した packet の socketpair の片方を取ります。
    pub(super) fn packet_socket() -> io::Result<UnixDatagram> {
        // fd 3 が開いた socket であることを確かめてから持ち主になる。閉じた fd や別の物を持つと、後で別の値を閉じうる
        let target = std::fs::read_link("/proc/self/fd/3")?;
        if !target.to_string_lossy().starts_with("socket:") {
            return Err(io::Error::other(format!(
                "fd 3 is {}, not a socket",
                target.display()
            )));
        }
        // SAFETY: fd 3 は親が起動の時に渡した socket で、上で開いていることを確かめた。このプロセスの中でほかに
        // fd 3 を持つ値は無く、ここで 1 回だけ持ち主になる。
        let fd = unsafe { OwnedFd::from_raw_fd(3) };
        // std の UnixDatagram の recv と send は recv(2) と send(2) なので、接続した SOCK_SEQPACKET の socket にも
        // 使え、1 回の呼び出しが 1 つの message を運ぶ
        Ok(UnixDatagram::from(fd))
    }
}
