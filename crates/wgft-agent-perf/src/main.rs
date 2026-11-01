//! Measures the agent's tunnel socket path on the host, for `perf stat` before and after a change.
//!
//! The lab VMs do not virtualise the PMU, so cache misses and instruction counts are taken here, on
//! a host that has one. The tool drives the WireGuard device layer (`wgft-wireguard`) and a UDP
//! socket opened like the data plane's, between two UDP sockets on the loopback of the network
//! namespace it runs in, with a fixed-size packet generator in place of the wgstack core. It needs
//! neither root nor a TUN device; `scripts/agent-perf-stat.sh` runs it in an unprivileged user and
//! network namespace (`unshare -rn`) under `perf stat`.
//!
//! Two modes, one measured end each:
//!
//! - `send`: the measured thread is the agent. It hands bursts of inner packets to the device
//!   layer, which encrypts them, and sends each datagram with `sendto`. A second thread plays the
//!   server and decrypts.
//! - `recv`: the measured thread is the server end. It reads datagrams with `recvfrom` and passes
//!   them to the device layer, which decrypts them. A second thread plays the agent and encrypts.
//!
//! Only the measured thread counts. Run the tool under `perf stat --no-inherit` so that the
//! second thread stays out of the counters; the script does. The tool prints one `RESULT` line
//! with the packet and byte counts, the measured thread's CPU time over the bursts' send or receive work (not the waits between them), and the data-path system calls
//! it made itself. Bursts are separated by a hand-off with the second thread over a channel; those
//! futex calls are neither counted as data-path calls nor inside `cpu_ns`, but `perf stat` sees
//! their user-space instructions, a small constant share per burst.
//!
//! What the numbers include and leave out:
//!
//! - `perf_event_paranoid` above 1 lets an unprivileged process count its own user space only, so
//!   the instruction and cache counts do not include the kernel's UDP and loopback work. The CPU
//!   time (`cpu_ns`, `user_ns`, `sys_ns`) and the system call counts do.
//! - The socket is opened like `dataplane::socket::open` without the `FORCE` buffer options, which
//!   need `CAP_NET_ADMIN` in the initial user namespace, so the buffer is capped by
//!   `net.core.rmem_max` of the new namespace. Bursts are sized to fit.
//! - Loopback delivers inline in the sender's `sendto`, so the send mode's CPU time includes the
//!   receiving socket's queueing, as the lab's veth path includes the softirq after a send.
//!
//! (The code is in `linux.rs`.)
//!
//! Batching. By default each end uses the data plane's batch store and system calls from
//! `wgft-udp-batch`, the code the agent runs: a burst's packets are copied into the store's packet
//! slots as the core writes them, sealed by the device layer into its send slots, laid out into
//! messages that join runs of one length with UDP GSO, and sent with `sendmmsg`; datagrams are
//! read with `recvmmsg` with UDP GRO on and decrypted, segment by segment, into the store's
//! plaintext area. `data_syscalls` counts one per batch call. `--one-by-one` keeps the earlier
//! path, one `sendto` or `recvfrom` per datagram, for a comparison inside one build; a base build
//! from before the batching runs that path by itself. The workload (sizes, burst, packet pattern)
//! stays the same, so a base build and a head build stay comparable. In `recv` mode the second
//! thread sends with the same path, so with batching the measured end reads GRO buffers that
//! loopback hands over whole.

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::main()
}

/// The tool counts with Linux's `perf` and uses Linux system calls; elsewhere it only has to build.
#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("error: wgft-agent-perf runs on Linux only");
    std::process::ExitCode::FAILURE
}
