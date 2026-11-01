//! メモリの上界の行 (agent-parity.md の「メモリの上界の行」)。
//!
//! `agent run` は起動の時に、プロセスが持つバイトの上界を `memory bound: <N> MiB, ...` の 1 行に書く。
//! 値はフロー数の上限 (`WGFT_MAX_UDP_FLOWS` と `WGFT_MAX_TCP_FLOWS`) から導く。カーネルのメモリ
//! (WireGuard のソケット、宛先のソケットの受信と送信のバッファ) は数えない。`agent doctor` の
//! `host.platform` も同じ値を示す。
//!
//! 項の大きさは、型の大きさと確保の要求の大きさから決める。tokio の task と I/O の登録の大きさは
//! tokio の内部の型なので、試験で確かめた余裕のある定数にする。

use std::task::Waker;

use wgft_netstack::{LanSockets, Netstack};
use wgft_wgstack::{Bound, Limits as CoreLimits, MAX_MTU};

use crate::flowpool;
use crate::relay::{BULK_BUF, BULK_KEEP, LanConn, REPLY_SLOTS, UDP_BUF};
use crate::targets::resolve::{ENDPOINT_PERMITS, TARGET_PERMITS};

/// The fixed base: the executable's pages, the tokio runtimes and their threads, the control
/// socket's threads, the stream and TLS state. It is the RSS measured in the lab right after start
/// with the tunnel and two listeners open (32 MiB at the caps UDP 4096 and TCP 1024, 37 MiB at the
/// default caps), rounded up. That RSS also holds the touched part of the core's and the netstack's
/// tables, which their own terms count again, so the base overcounts.
pub const BASE: usize = 40 << 20;

/// One tokio task's own allocation beyond its future: the header, the scheduler's handle and the
/// trailer, aligned to a cache line pair. Tests check the future sizes; this covers tokio's part.
pub const TASK_OVERHEAD: usize = 512;

/// One socket's registration with tokio's I/O driver (its `ScheduledIo`, aligned to a cache line
/// pair, and the handle).
pub const IO_OVERHEAD: usize = 512;

/// The future of one TCP relay task: two idle buffers inline and the state of both directions.
/// A test checks the real size stays below it.
pub const TCP_RELAY_FUTURE: usize = 8 << 10;

/// The future of one UDP session's reply task. A test checks the real size stays below it.
pub const UDP_REPLY_FUTURE: usize = 1 << 10;

/// One UDP session's entry in its listener's table, with the table's spare capacity (the table
/// keeps at most four times its sessions plus a small slack), and its shared socket and clock
/// cells. A test checks the real size stays below it.
pub const UDP_SESSION_ENTRY: usize = 512;

/// One TCP relay's term without its bulk buffers: its task and its socket's registration.
pub const TCP_RELAY_CONN: usize = TCP_RELAY_FUTURE + TASK_OVERHEAD + IO_OVERHEAD;

/// One UDP session's term: its table entry, its socket's registration and its reply task.
pub const UDP_SESSION: usize = UDP_SESSION_ENTRY + UDP_REPLY_FUTURE + TASK_OVERHEAD + IO_OVERHEAD;

/// One resolver thread: Rust's default thread stack and the work area of `getaddrinfo`.
pub const RESOLVER_THREAD: usize = (2 << 20) + (64 << 10);

/// The WireGuard device's queues at the largest MTU, for the agent's one peer: staged packets,
/// datagrams to send and packets to deliver, with a vector header per queued item, and the one
/// datagram buffer a call uses while it decrypts.
pub(crate) fn device_bytes() -> usize {
    let l = wgft_wireguard::Limits::default();
    let item = size_of::<Vec<u8>>() + size_of::<std::net::SocketAddr>();
    l.staged_packets * (MAX_MTU + item)
        + l.transmit_bytes
        + l.transmit_packets * item
        + l.deliver_bytes
        + l.deliver_packets * item
        + l.events * 64
        + UDP_BUF
}

/// The memory bound and its terms, in bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryBound {
    /// [`BASE`].
    pub base: usize,
    /// The core's bound (`Stack::bound`) at the largest MTU.
    pub core: usize,
    /// The part of [`Self::core`] the core makes when it is created and keeps whatever the flows
    /// do: its structure, connection slots and tables (`Bound::fix`).
    pub core_fixed: usize,
    /// The netstack's waker table and the LAN socket table the core's hook keeps.
    pub tables: usize,
    /// The data plane driver's list of wakers to wake, at most twice the table's rows.
    pub driver: usize,
    /// The WireGuard device's queues and the data plane's buffers.
    pub device: usize,
    /// The TCP relay without its bulk buffers: per connection its task and socket.
    pub tcp: usize,
    /// The TCP relay's bulk buffers: both directions' per connection, and the ones the data plane
    /// thread keeps for reuse. A relay borrows them only while data flows.
    pub tcp_bulk: usize,
    /// The UDP relay: the reply buffers and per session its entry, socket and reply task.
    pub udp: usize,
    /// The resolver threads.
    pub resolver: usize,
    /// The sum.
    pub total: usize,
}

impl MemoryBound {
    /// The bound for the flow caps `limits`, with the core's tables that `WGFT_MAX_TCP_FLOWS`
    /// makes.
    #[must_use]
    pub fn for_limits(limits: flowpool::Limits) -> Self {
        Self::with_core(limits, CoreLimits::with_max_flows(limits.tcp))
    }

    /// The bound for the flow caps `limits` over a core with the tables `core_limits`, at the
    /// largest MTU. Tests use it with their small cores.
    #[must_use]
    pub fn with_core(limits: flowpool::Limits, core_limits: CoreLimits) -> Self {
        let conns = core_limits.conns();
        let core_bound = Bound::for_limits(&core_limits, MAX_MTU);
        let core = usize::try_from(core_bound.total).unwrap_or(usize::MAX);
        let core_fixed = usize::try_from(core_bound.fix).unwrap_or(usize::MAX);
        let tables = Netstack::<wgft_wgstack::NoHook>::waker_bound(conns)
            + LanSockets::<LanConn>::table_bytes(conns);
        let driver = 2 * Netstack::<wgft_wgstack::NoHook>::waker_slots(conns) * size_of::<Waker>();
        // データプレーンの受信のバッファと、MTU の長さの送り出しのバッファ
        let device = device_bytes() + UDP_BUF + MAX_MTU;
        // 接続ごとの項と、データプレーンのスレッドが使い回しのために残す大きいバッファ
        let tcp = limits.tcp.saturating_mul(TCP_RELAY_CONN);
        let tcp_bulk = limits
            .tcp
            .saturating_mul(2 * BULK_BUF)
            .saturating_add(BULK_KEEP * BULK_BUF);
        let udp = REPLY_SLOTS * UDP_BUF + limits.udp.saturating_mul(UDP_SESSION);
        let resolver = (TARGET_PERMITS + ENDPOINT_PERMITS) * RESOLVER_THREAD;
        let parts = [
            BASE, core, tables, driver, device, tcp, tcp_bulk, udp, resolver,
        ];
        Self {
            base: BASE,
            core,
            core_fixed,
            tables,
            driver,
            device,
            tcp,
            tcp_bulk,
            udp,
            resolver,
            total: parts.into_iter().fold(0, usize::saturating_add),
        }
    }

    /// The bound in MiB, rounded up.
    #[must_use]
    pub fn mib(&self) -> usize {
        self.total.div_ceil(1 << 20)
    }

    /// The second start line, with the terms in MiB rounded up. The core's term is split into
    /// its fixed part and the rest, and the TCP relay's into its per-connection part and its bulk
    /// buffers, so that the lab can compare the RSS growth under a flood of idle connections and
    /// small datagrams with the terms such a flood can fill. Its form is not guaranteed.
    #[must_use]
    pub fn terms_line(&self) -> String {
        let m = |b: usize| b.div_ceil(1 << 20);
        format!(
            "memory bound terms: base {} MiB, core fixed {} MiB, core flows {} MiB, tables {} MiB, driver {} MiB, device {} MiB, tcp relay {} MiB, tcp bulk {} MiB, udp relay {} MiB, resolver {} MiB",
            m(self.base),
            m(self.core_fixed),
            m(self.core.saturating_sub(self.core_fixed)),
            m(self.tables),
            m(self.driver),
            m(self.device),
            m(self.tcp),
            m(self.tcp_bulk),
            m(self.udp),
            m(self.resolver)
        )
    }

    /// The start line.
    #[must_use]
    pub fn line(&self) -> String {
        format!(
            "memory bound: {} MiB, derived from the flow caps; it counts what the process holds, not the kernel socket buffers",
            self.mib()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_line_has_the_lab_s_form_and_grows_with_the_caps() {
        let small = MemoryBound::for_limits(flowpool::Limits {
            udp: 4096,
            tcp: 1024,
        });
        let big = MemoryBound::for_limits(flowpool::Limits::default());
        assert!(small.line().starts_with("memory bound: "));
        assert!(
            small
                .line()
                .contains(&format!("{} MiB, derived from the flow caps", small.mib()))
        );
        assert!(big.total > small.total);
        assert_eq!(
            small.total,
            small.base
                + small.core
                + small.tables
                + small.driver
                + small.device
                + small.tcp
                + small.tcp_bulk
                + small.udp
                + small.resolver
        );
    }

    #[test]
    fn the_relay_futures_fit_their_terms() {
        let (tcp, udp) = crate::relay::future_sizes();
        assert!(
            tcp <= TCP_RELAY_FUTURE,
            "the TCP relay future is {tcp} bytes"
        );
        assert!(
            udp <= UDP_REPLY_FUTURE,
            "the UDP reply future is {udp} bytes"
        );
        let entry = crate::relay::udp_session_bytes();
        assert!(
            entry <= UDP_SESSION_ENTRY,
            "a UDP session entry is {entry} bytes"
        );
    }
}
