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
use wgft_proto::{STATE_HELD_FACTOR, STREAM_READ_LIMIT};

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

/// The size of one per-flow allocation as the bound counts it: the requested bytes, rounded up to
/// 64 bytes. The allocator's own rounding is not counted; it falls into the margin the lab checks
/// add. The rounding only makes the generated table drift less often, since the compiler can lay
/// out the futures a few bytes apart in the test and the release build.
const fn per_flow(bytes: usize) -> usize {
    bytes.next_multiple_of(64)
}

/// The future of one TCP relay task: two idle buffers inline and the state of both directions,
/// read from the future's type.
#[must_use]
pub fn tcp_relay_future() -> usize {
    per_flow(crate::relay::future_sizes().0)
}

/// The future of one UDP session's reply task, read from the future's type.
#[must_use]
pub fn udp_reply_future() -> usize {
    per_flow(crate::relay::future_sizes().1)
}

/// One UDP session's entry in its listener's table, with the table's spare capacity (the table
/// keeps at most four times its sessions plus a small slack), and its shared socket and clock
/// cells, read from their types.
#[must_use]
pub fn udp_session_entry() -> usize {
    per_flow(crate::relay::udp_session_bytes())
}

/// One TCP listener: its entry in the relay's table, its state shared with its relays, its budget
/// entry, its accept task and its netstack registration, and the failure text of its last probe,
/// which is clipped at the reason's length cap and held in an allocation of its exact length. The
/// rule ID and the target host are shared by every listener of a rule, and identical failure texts of
/// neighbouring listeners share one allocation. The term also covers a probe round in flight: its
/// entry and result per listener, with a new failure text of the longest form before it replaces the
/// old one, and a status read's row per listener taken at the same time. A test measures that worst
/// case at 2.3 KiB on Linux. The core's port table is part of the core's term.
pub const LISTENER_TCP: usize = 5 << 9;

/// One UDP listener: its receive buffer of the largest datagram (Go's relay has the same per
/// listener), its task, its session table and the shared parts of a TCP listener. A test measures
/// the buffer plus 2.9 KiB with a status read's rows.
pub const LISTENER_UDP: usize = UDP_BUF + (4 << 10);

/// One TCP relay's term without its bulk buffers: its task and its socket's registration.
#[must_use]
pub fn tcp_relay_conn() -> usize {
    tcp_relay_future() + TASK_OVERHEAD + IO_OVERHEAD
}

/// One UDP session's term: its table entry, its socket's registration and its reply task.
#[must_use]
pub fn udp_session() -> usize {
    udp_session_entry() + udp_reply_future() + TASK_OVERHEAD + IO_OVERHEAD
}

/// How many decoded full states the agent holds at once at most: the applied one (`last_state`),
/// the one kept for a rebuild retry, the copy of `last_state` a tunnel rebuild or a key rotation
/// applies, and the next one the stream decoded while it waits for the agent's lock.
pub const STATE_COPIES: usize = 4;

/// The stream's buffers around one message: the WebSocket's read buffer, which keeps the capacity
/// of the largest frame, and the text of the message being applied.
pub const STREAM_BUFFERS: usize = 2 * STREAM_READ_LIMIT;

/// The full states' term: the decoded copies at the largest message, each at most
/// [`STATE_HELD_FACTOR`] times the message's length, and the stream's buffers. `agent.json` is
/// written straight to its file and needs no buffer of its length.
pub const STATE: usize = STATE_COPIES * STATE_HELD_FACTOR * STREAM_READ_LIMIT + STREAM_BUFFERS;

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

/// The tunnel batching's buffers: what one receive batch and one send batch of the WireGuard socket
/// hold (`recvmmsg` and `sendmmsg`, UDP GRO and GSO) beyond the data plane's one receive buffer and
/// one send buffer, which [`MemoryBound::device`] counts. The data plane reads and writes one
/// datagram at a time, so the term is 0; batching fills it in the same change that adds the buffers
/// (`docs/design/v2/agent-parity.md`, the memory bound line).
pub(crate) const fn batch_bytes() -> usize {
    0
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
    /// The part of [`Self::core`] every connection slot holds from its first use on, data or not:
    /// its floor send record ring and interval table (`Bound::floor_arrays`).
    pub core_arrays: usize,
    /// The netstack's waker table and the LAN socket table the core's hook keeps.
    pub tables: usize,
    /// The data plane driver's list of wakers to wake, at most twice the table's rows.
    pub driver: usize,
    /// The WireGuard device's queues and the data plane's buffers.
    pub device: usize,
    /// The tunnel batching's buffers ([`batch_bytes`]).
    pub batch: usize,
    /// The TCP relay without its bulk buffers: per connection its task and socket.
    pub tcp: usize,
    /// The TCP relay's bulk buffers: both directions' per connection, and the ones the data plane
    /// thread keeps for reuse. A relay borrows them only while data flows.
    pub tcp_bulk: usize,
    /// The UDP relay: the reply buffers and per session its entry, socket and reply task.
    pub udp: usize,
    /// The resolver threads.
    pub resolver: usize,
    /// The full states from the server ([`STATE`]).
    pub state: usize,
    /// The open listeners, [`LISTENER_TCP`] and [`LISTENER_UDP`] each. The server's full state
    /// decides their number and the agent caps it only by the ports, so the start line counts none;
    /// [`MemoryBound::with_listeners`] adds them after an apply.
    pub listeners: usize,
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
        let core_arrays = usize::try_from(core_bound.floor_arrays).unwrap_or(usize::MAX);
        let tables = Netstack::<wgft_wgstack::NoHook>::waker_bound(conns)
            + LanSockets::<LanConn>::table_bytes(conns);
        let driver = 2 * Netstack::<wgft_wgstack::NoHook>::waker_slots(conns) * size_of::<Waker>();
        // データプレーンの受信のバッファと、MTU の長さの送り出しのバッファ
        let device = device_bytes() + UDP_BUF + MAX_MTU;
        let batch = batch_bytes();
        // 接続ごとの項と、データプレーンのスレッドが使い回しのために残す大きいバッファ
        let tcp = limits.tcp.saturating_mul(tcp_relay_conn());
        let tcp_bulk = limits
            .tcp
            .saturating_mul(2 * BULK_BUF)
            .saturating_add(BULK_KEEP * BULK_BUF);
        let udp = REPLY_SLOTS * UDP_BUF + limits.udp.saturating_mul(udp_session());
        let resolver = (TARGET_PERMITS + ENDPOINT_PERMITS) * RESOLVER_THREAD;
        let parts = [
            BASE, core, tables, driver, device, batch, tcp, tcp_bulk, udp, resolver, STATE,
        ];
        Self {
            base: BASE,
            core,
            core_fixed,
            core_arrays,
            tables,
            driver,
            device,
            batch,
            tcp,
            tcp_bulk,
            udp,
            resolver,
            state: STATE,
            listeners: 0,
            total: parts.into_iter().fold(0, usize::saturating_add),
        }
    }

    /// The bound with `tcp` TCP and `udp` UDP listeners open.
    #[must_use]
    pub fn with_listeners(mut self, tcp: usize, udp: usize) -> Self {
        let listeners = tcp
            .saturating_mul(LISTENER_TCP)
            .saturating_add(udp.saturating_mul(LISTENER_UDP));
        self.total = self
            .total
            .saturating_sub(self.listeners)
            .saturating_add(listeners);
        self.listeners = listeners;
        self
    }

    /// The bound in MiB, rounded up.
    #[must_use]
    pub fn mib(&self) -> usize {
        self.total.div_ceil(1 << 20)
    }

    /// The terms in the order of the terms line, with their names there.
    #[must_use]
    pub fn terms(&self) -> [(&'static str, usize); 13] {
        [
            ("base", self.base),
            ("core fixed", self.core_fixed),
            ("core arrays", self.core_arrays),
            (
                "core flows",
                self.core
                    .saturating_sub(self.core_fixed)
                    .saturating_sub(self.core_arrays),
            ),
            ("tables", self.tables),
            ("driver", self.driver),
            ("device", self.device),
            ("batch", self.batch),
            ("tcp relay", self.tcp),
            ("tcp bulk", self.tcp_bulk),
            ("udp relay", self.udp),
            ("resolver", self.resolver),
            ("state", self.state),
        ]
    }

    /// The second start line, with the terms in MiB rounded up. The core's term is split into
    /// its fixed part, the arrays every used connection slot keeps and the rest, and the TCP
    /// relay's into its per-connection part and its bulk buffers, so that the lab can compare the
    /// RSS growth under a flood of idle connections and small datagrams with the terms such a flood
    /// can fill. Its form is not guaranteed.
    #[must_use]
    pub fn terms_line(&self) -> String {
        let terms = self
            .terms()
            .map(|(name, b)| format!("{name} {} MiB", b.div_ceil(1 << 20)))
            .join(", ");
        format!(
            "memory bound terms: {terms}; per listener, not in the line: tcp {} KiB, udp {} KiB",
            LISTENER_TCP.div_ceil(1 << 10),
            LISTENER_UDP.div_ceil(1 << 10)
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

    /// The line an apply writes when the number of listeners changed.
    #[must_use]
    pub fn listeners_line(&self, tcp: usize, udp: usize) -> String {
        format!(
            "memory bound with {tcp} TCP and {udp} UDP listeners: {} MiB",
            self.mib()
        )
    }
}

#[cfg(test)]
mod tests;
