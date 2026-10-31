//! A lab tool that runs the wgft WireGuard device over a Linux TUN device, for interop tests
//! against Linux WireGuard and wireguard-go. Not shipped.

use std::process::ExitCode;

#[cfg(target_os = "linux")]
mod cli;

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    cli::run()
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("wgft-wireguard-tun: runs only on Linux");
    ExitCode::FAILURE
}
