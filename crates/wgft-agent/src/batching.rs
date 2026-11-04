//! トンネルのバッチの大きさ。`WGFT_AGENT_BATCH_MIB` の意味の正本は `docs/design/v2/agent-throughput.md` の
//! 「WGFT_AGENT_BATCH_MIB の意味」と「バッチの作りの規則」で、この module はそれを実装する。
//!
//! - 予算はトンネルの受信と送信の両方の向きのバッチの buffer の全体で、起動の時に 1 回だけ読む
//! - 予算から、1 回の system call で読み書きする枠の数 (向きごとに同じ数) を導く。枠の大きさは MTU を
//!   知らない起動の時に決めるので、受け付ける最大の MTU で数える
//! - `0` は両方の向きのバッチを切り、1 つずつ送受信する。空は v1 と同じくフロー数の上限から導く
//! - Linux だけがバッチを使う。ほかの OS は 1 つずつ送受信し、枠は 1 つである

use std::sync::OnceLock;

use crate::flowpool;

/// The crypto workers of this process's data plane, read once at start
/// (`wgft_udp_batch::pool::worker_count`): the slot count, the memory bound and the data plane all
/// follow it, so a host without workers counts no second stores.
pub fn crypto_workers() -> usize {
    static WORKERS: OnceLock<usize> = OnceLock::new();
    *WORKERS.get_or_init(wgft_udp_batch::pool::worker_count)
}

/// The most slots per direction: datagrams one `recvmmsg` or `sendmmsg` call may carry. The
/// wake-up's latency budget ends a batch long before this at the lab's per-packet cost, and it is
/// also the most segments one UDP GSO send carries on every kernel that has GSO.
pub const MAX_SLOTS: usize = wgft_udp_batch::MAX_SLOTS;

/// The share of the flow caps' memory figure that the derived budget takes: β = 3/20, the v1
/// agent's value, kept as an integer ratio so the result does not depend on the platform.
const SHARE_NUM: u64 = 3;
const SHARE_DEN: u64 = 20;

/// How the tunnel batches its WireGuard socket's receive and send, fixed at start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Batching {
    /// One datagram per system call, in one slot.
    Off,
    /// `recvmmsg`, `sendmmsg`, UDP GRO and GSO on Linux.
    On {
        /// Slots per direction, at least 1.
        slots: usize,
        /// Where the budget came from.
        source: Source,
        /// The crypto workers of the host this was derived for. The slot count and the memory
        /// bound count the second receive and send stores and the crypto lanes only when this is
        /// above 0, which is when the data plane runs the workers.
        workers: usize,
    },
}

impl Default for Batching {
    /// The batching derived from the default flow caps.
    fn default() -> Self {
        Self::derived(flowpool::Limits::default())
    }
}

/// Where a [`Batching`] came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Derived from the flow caps; `WGFT_AGENT_BATCH_MIB` is unset or empty.
    Derived,
    /// From `WGFT_AGENT_BATCH_MIB`.
    Set,
    /// From `WGFT_AGENT_BATCH_MIB`, lowered to the most this build uses.
    Lowered,
}

impl Batching {
    /// Batching off: one datagram per system call, in one slot.
    pub const OFF: Self = Self::Off;

    /// The batching for the setting `mib` (`WGFT_AGENT_BATCH_MIB`, `None` when unset or empty) and
    /// the flow caps `limits`.
    #[must_use]
    pub fn new(mib: Option<i64>, limits: flowpool::Limits) -> Self {
        Self::for_workers(mib, limits, crypto_workers())
    }

    /// [`Batching::new`] for a host that runs `workers` crypto workers
    /// (`wgft_udp_batch::pool::workers_for` of its CPUs).
    #[must_use]
    pub fn for_workers(mib: Option<i64>, limits: flowpool::Limits, workers: usize) -> Self {
        match mib {
            None => Self::from_bytes(derived_budget(limits), Source::Derived, workers),
            Some(n) if n <= 0 => Self::OFF,
            Some(n) => {
                let bytes = u64::try_from(n).unwrap_or(0).saturating_mul(1 << 20);
                let b = Self::from_bytes(bytes, Source::Set, workers);
                if bytes > store_of(MAX_SLOTS, workers) {
                    Self::from_bytes(bytes, Source::Lowered, workers)
                } else {
                    b
                }
            }
        }
    }

    /// The batching derived from the flow caps, as when `WGFT_AGENT_BATCH_MIB` is unset.
    #[must_use]
    pub fn derived(limits: flowpool::Limits) -> Self {
        Self::new(None, limits)
    }

    fn from_bytes(bytes: u64, source: Source, workers: usize) -> Self {
        // 枠の組の数で割った後、2 つ以上の枠が持つ作業の領域の分を引いて収まる数まで減らす。
        // 作業者の無いホストは 2 つ目の置き場を持たないので、数えない
        let mut slots = usize::try_from(bytes / store_of(1, workers).max(1))
            .unwrap_or(MAX_SLOTS)
            .clamp(1, MAX_SLOTS);
        while slots > 1 && store_of(slots, workers) > bytes {
            slots -= 1;
        }
        Self::On {
            slots,
            source,
            workers,
        }
    }

    /// What this build runs: the batching itself on Linux, [`Batching::OFF`] elsewhere.
    #[must_use]
    pub fn running(self) -> Self {
        if cfg!(target_os = "linux") {
            self
        } else {
            Self::Off
        }
    }

    /// Slots per direction.
    #[must_use]
    pub fn slots(self) -> usize {
        match self {
            Self::Off => 1,
            Self::On { slots, .. } => slots,
        }
    }

    /// Whether batching is on.
    #[must_use]
    pub fn is_on(self) -> bool {
        matches!(self, Self::On { .. })
    }

    /// Where the budget came from; `None` when batching is off.
    #[must_use]
    pub fn source(self) -> Option<Source> {
        match self {
            Self::Off => None,
            Self::On { source, .. } => Some(source),
        }
    }

    /// The bytes of the batch buffers this host allocates for it, at the largest MTU and with the
    /// crypto lanes of the host's workers: the memory bound's `batch` term. A host without workers
    /// has one lane and no second stores.
    #[must_use]
    pub fn bytes(self) -> usize {
        crate::dataplane::batch::all_store_bytes(
            self.running(),
            wgft_wgstack::MAX_MTU,
            self.bound_lanes(),
        )
    }

    /// The crypto lanes the bound counts: those of the workers this batching was derived for.
    fn bound_lanes(self) -> usize {
        crate::dataplane::batch::crypto_lanes(self.running(), self.workers())
    }

    /// The crypto workers this batching was derived for; 0 when batching is off.
    #[must_use]
    pub fn workers(self) -> usize {
        match self {
            Self::Off => 0,
            Self::On { workers, .. } => workers,
        }
    }

    /// The bytes the crypto workers hold beyond the batch store, with the workers of the host:
    /// their stacks, their places and the lanes' job lists. The memory bound's `crypto` term.
    #[must_use]
    pub fn crypto_bytes(self) -> usize {
        match self.bound_lanes() {
            1 => 0,
            lanes => wgft_udp_batch::crypto::Crypto::bytes(lanes),
        }
    }

    /// The crypto lanes the data plane runs with: those of the host's [`crypto_workers`], which
    /// this batching was derived for.
    #[must_use]
    pub fn crypto_lanes(self) -> usize {
        self.bound_lanes()
    }

    /// The start line that says what the setting does, after the memory bound lines.
    #[must_use]
    pub fn line(self) -> String {
        if !cfg!(target_os = "linux") {
            return "tunnel batching: unused on this OS, where the tunnel reads and sends one datagram per system call; WGFT_AGENT_BATCH_MIB is kept so the same agent.env works on Linux".to_owned();
        }
        let Self::On { slots, source, .. } = self else {
            return "tunnel batching: off, WGFT_AGENT_BATCH_MIB=0; the tunnel reads and sends one datagram per system call".to_owned();
        };
        let source = match source {
            Source::Derived => "derived from the flow caps; set WGFT_AGENT_BATCH_MIB to override",
            Source::Set => "from WGFT_AGENT_BATCH_MIB",
            Source::Lowered => "from WGFT_AGENT_BATCH_MIB, lowered to the most this build uses",
        };
        format!(
            "tunnel batching: up to {} messages per receive and per send system call, {:.1} MiB of buffers; {source}",
            slots,
            mib_tenths(self.bytes())
        )
    }
}

/// `bytes` in MiB for a line with one decimal.
#[expect(
    clippy::cast_precision_loss,
    reason = "a figure for a log line, at most a few hundred MiB"
)]
fn mib_tenths(bytes: usize) -> f64 {
    bytes as f64 / f64::from(1u32 << 20)
}

/// The memory figure the v1 agent derives from the flow caps: 32 MiB, 12 KiB per UDP flow and
/// 44 KiB per TCP flow.
fn flow_caps_memory(limits: flowpool::Limits) -> u64 {
    let udp = u64::try_from(limits.udp).unwrap_or(u64::MAX);
    let tcp = u64::try_from(limits.tcp).unwrap_or(u64::MAX);
    (32u64 << 20)
        .saturating_add(udp.saturating_mul(12 << 10))
        .saturating_add(tcp.saturating_mul(44 << 10))
}

/// The budget derived from the flow caps, in bytes: β of `flow_caps_memory`, the v1 agent's
/// default for `WGFT_AGENT_BATCH_MIB`.
#[must_use]
pub fn derived_budget(limits: flowpool::Limits) -> u64 {
    flow_caps_memory(limits).saturating_mul(SHARE_NUM) / SHARE_DEN
}

/// The batch stores of `slots` slots per direction with batching on, at the largest MTU and with
/// the crypto lanes of a host with `workers` workers: what the setting's budget must hold.
fn store_of(slots: usize, workers: usize) -> u64 {
    let b = Batching::On {
        slots,
        source: Source::Set,
        workers,
    };
    // 作業者を使うホストだけ、作業者と重ねる道の 2 つ目の置き場も含めて、予算の内に収める
    let lanes = crate::dataplane::batch::crypto_lanes(b, workers);
    let bytes = crate::dataplane::batch::all_store_bytes(b, wgft_wgstack::MAX_MTU, lanes);
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_setting_maps_to_slots() {
        let caps = flowpool::Limits::default();
        assert_eq!(Batching::new(Some(0), caps), Batching::OFF);
        assert!(!Batching::new(Some(0), caps).is_on());
        let one = Batching::new(Some(1), caps);
        assert!(one.is_on());
        assert!(one.slots() >= 1 && one.slots() < MAX_SLOTS, "{one:?}");
        assert_eq!(one.source(), Some(Source::Set));
        // 1 MiB の予算は、最大の MTU の枠の組をその数だけ持つ
        assert!(store_fits(one, 1 << 20));
        let big = Batching::new(Some(i64::MAX), caps);
        assert_eq!(big.slots(), MAX_SLOTS);
        assert_eq!(big.source(), Some(Source::Lowered));
        // 既定の上限から導く予算は、最大の枠の数に届く
        let derived = Batching::new(None, caps);
        assert_eq!(derived.source(), Some(Source::Derived));
        assert_eq!(derived.slots(), MAX_SLOTS);
        // (32 MiB + 8192 × 12 KiB + 2048 × 44 KiB) × 3 / 20
        assert_eq!(derived_budget(caps), 33_973_862);
    }

    fn store_fits(b: Batching, budget: usize) -> bool {
        let workers = b.workers();
        u64::try_from(budget).is_ok_and(|budget| {
            store_of(b.slots(), workers) <= budget && store_of(b.slots() + 1, workers) > budget
        })
    }

    #[test]
    fn the_setting_bounds_every_batch_store() {
        let caps = flowpool::Limits::default();
        for mib in 1..=48 {
            let b = Batching::new(Some(mib), caps);
            let budget = usize::try_from(mib).unwrap() << 20;
            if cfg!(target_os = "linux") {
                assert!(b.bytes() <= budget, "{mib} MiB: {} bytes", b.bytes());
            }
            // 減らしたと書くのは、最大の枠の数の置き場でも予算に余るときだけ
            let full = u64::try_from(budget).unwrap() > store_of(MAX_SLOTS, b.workers());
            assert_eq!(b.source() == Some(Source::Lowered), full, "{mib} MiB");
        }
    }

    /// What the Inline build (before the crypto workers) derived and counted: one lane, no second
    /// stores, whatever the host.
    fn inline_store(slots: usize) -> usize {
        let mtu = wgft_wgstack::MAX_MTU;
        wgft_udp_batch::store_bytes(slots, true, mtu, mtu + wgft_wireguard::DATA_OVERHEAD, 1, 1)
    }

    fn inline_slots(budget: u64) -> usize {
        (1..=MAX_SLOTS)
            .rev()
            .find(|&n| u64::try_from(inline_store(n)).unwrap() <= budget)
            .unwrap_or(1)
    }

    const BUDGETS_MIB: [Option<i64>; 3] = [Some(1), Some(4), None];

    fn budget_bytes(mib: Option<i64>, caps: flowpool::Limits) -> u64 {
        mib.map_or_else(|| derived_budget(caps), |m| u64::try_from(m).unwrap() << 20)
    }

    #[test]
    fn a_host_without_workers_derives_what_inline_derived() {
        let caps = flowpool::Limits::default();
        for mib in BUDGETS_MIB {
            let b = Batching::for_workers(mib, caps, 0);
            let budget = budget_bytes(mib, caps);
            assert_eq!(b.slots(), inline_slots(budget), "{mib:?}");
            assert_eq!(store_of(b.slots(), 0), inline_store(b.slots()) as u64);
            assert_eq!(b.crypto_bytes(), 0, "{mib:?}");
            if cfg!(target_os = "linux") {
                assert_eq!(b.bytes(), inline_store(b.slots()), "{mib:?}");
                assert_eq!(b.crypto_lanes(), 1, "{mib:?}");
            }
        }
        // 数値でも固定する: 4 MiB は Inline と同じ枠の数である
        assert_eq!(Batching::for_workers(Some(4), caps, 0).slots(), 27);
    }

    #[test]
    fn a_host_with_workers_counts_the_second_stores() {
        let caps = flowpool::Limits::default();
        let workers = wgft_udp_batch::pool::MAX_WORKERS;
        assert_eq!(wgft_udp_batch::pool::workers_for(2), 0);
        assert_eq!(wgft_udp_batch::pool::workers_for(4), workers);
        for mib in BUDGETS_MIB {
            let b = Batching::for_workers(mib, caps, workers);
            let none = Batching::for_workers(mib, caps, 0);
            let budget = budget_bytes(mib, caps);
            assert!(b.slots() <= none.slots(), "{mib:?}");
            assert_eq!(b.workers(), workers);
            if cfg!(target_os = "linux") {
                assert!(
                    u64::try_from(b.bytes()).unwrap() <= budget,
                    "{mib:?}: {} bytes",
                    b.bytes()
                );
                if b.slots() > workers {
                    assert_eq!(b.crypto_lanes(), workers + 1, "{mib:?}");
                    assert!(b.crypto_bytes() > 0, "{mib:?}");
                }
            }
        }
        // 4 MiB の予算は、2 つ目の置き場を数えると枠が約半分になる
        assert_eq!(Batching::for_workers(Some(4), caps, workers).slots(), 13);
        // 既定の上限では、どちらも最大の枠の数に届く
        assert_eq!(
            Batching::for_workers(None, caps, workers).slots(),
            MAX_SLOTS
        );
        assert_eq!(Batching::for_workers(None, caps, 0).slots(), MAX_SLOTS);
    }

    #[test]
    fn the_slot_count_follows_the_cpus() {
        let caps = flowpool::Limits::default();
        for cpus in 1..=8 {
            let workers = wgft_udp_batch::pool::workers_for(cpus);
            let b = Batching::for_workers(Some(4), caps, workers);
            let want = if cpus <= 2 { 27 } else { 13 };
            assert_eq!(b.slots(), want, "{cpus} CPUs");
        }
    }

    #[test]
    fn the_line_names_the_source() {
        let caps = flowpool::Limits::default();
        let line = Batching::new(None, caps).line();
        if cfg!(target_os = "linux") {
            assert!(
                line.starts_with("tunnel batching: up to 64 messages"),
                "{line}"
            );
            assert!(
                line.ends_with("derived from the flow caps; set WGFT_AGENT_BATCH_MIB to override"),
                "{line}"
            );
            assert!(
                Batching::new(Some(0), caps)
                    .line()
                    .starts_with("tunnel batching: off")
            );
        } else {
            assert!(line.contains("unused on this OS"), "{line}");
        }
        assert!(!line.contains('('), "{line}");
    }
}
