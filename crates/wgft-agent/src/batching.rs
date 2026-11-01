//! トンネルのバッチの大きさ。`WGFT_AGENT_BATCH_MIB` の意味の正本は `docs/design/v2/agent-throughput.md` の
//! 「WGFT_AGENT_BATCH_MIB の意味」と「バッチの作りの規則」で、この module はそれを実装する。
//!
//! - 予算はトンネルの受信と送信の両方の向きのバッチの buffer の全体で、起動の時に 1 回だけ読む
//! - 予算から、1 回の system call で読み書きする枠の数 (向きごとに同じ数) を導く。枠の大きさは MTU を
//!   知らない起動の時に決めるので、受け付ける最大の MTU で数える
//! - `0` は両方の向きのバッチを切り、1 つずつ送受信する。空は v1 と同じくフロー数の上限から導く
//! - Linux だけがバッチを使う。ほかの OS は 1 つずつ送受信し、枠は 1 つである

use crate::flowpool;

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
pub struct Batching {
    /// Slots per direction, at least 1.
    slots: usize,
    /// Whether batching is on: `recvmmsg`, `sendmmsg`, UDP GRO and GSO on Linux.
    on: bool,
    /// Where the budget came from.
    source: Source,
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
    pub const OFF: Self = Self {
        slots: 1,
        on: false,
        source: Source::Set,
    };

    /// The batching for the setting `mib` (`WGFT_AGENT_BATCH_MIB`, `None` when unset or empty) and
    /// the flow caps `limits`.
    #[must_use]
    pub fn new(mib: Option<i64>, limits: flowpool::Limits) -> Self {
        match mib {
            None => Self::from_bytes(derived_budget(limits), Source::Derived),
            Some(n) if n <= 0 => Self::OFF,
            Some(n) => {
                let bytes = u64::try_from(n).unwrap_or(0).saturating_mul(1 << 20);
                let b = Self::from_bytes(bytes, Source::Set);
                if bytes > store_of(MAX_SLOTS) {
                    Self {
                        source: Source::Lowered,
                        ..b
                    }
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

    fn from_bytes(bytes: u64, source: Source) -> Self {
        // 枠の組の数で割った後、2 つ以上の枠が持つ作業の領域の分を引いて収まる数まで減らす
        let mut slots = usize::try_from(bytes / store_of(1).max(1))
            .unwrap_or(MAX_SLOTS)
            .clamp(1, MAX_SLOTS);
        while slots > 1 && store_of(slots) > bytes {
            slots -= 1;
        }
        Self {
            slots,
            on: true,
            source,
        }
    }

    /// What this build runs: the batching itself on Linux, [`Batching::OFF`] elsewhere.
    #[must_use]
    pub fn running(self) -> Self {
        if cfg!(target_os = "linux") {
            self
        } else {
            Self {
                source: self.source,
                ..Self::OFF
            }
        }
    }

    /// Slots per direction.
    #[must_use]
    pub fn slots(self) -> usize {
        self.slots
    }

    /// Whether batching is on.
    #[must_use]
    pub fn is_on(self) -> bool {
        self.on
    }

    /// Where the budget came from.
    #[must_use]
    pub fn source(self) -> Source {
        self.source
    }

    /// The bytes of the batch buffers this build allocates for it, at the largest MTU: the memory
    /// bound's `batch` term.
    #[must_use]
    pub fn bytes(self) -> usize {
        crate::dataplane::batch::store_bytes(self.running(), wgft_wgstack::MAX_MTU)
    }

    /// The start line that says what the setting does, after the memory bound lines.
    #[must_use]
    pub fn line(self) -> String {
        let run = self.running();
        if !cfg!(target_os = "linux") {
            return "tunnel batching: unused on this OS, where the tunnel reads and sends one datagram per system call; WGFT_AGENT_BATCH_MIB is kept so the same agent.env works on Linux".to_owned();
        }
        if !run.on {
            return "tunnel batching: off, WGFT_AGENT_BATCH_MIB=0; the tunnel reads and sends one datagram per system call".to_owned();
        }
        let source = match self.source {
            Source::Derived => "derived from the flow caps; set WGFT_AGENT_BATCH_MIB to override",
            Source::Set => "from WGFT_AGENT_BATCH_MIB",
            Source::Lowered => "from WGFT_AGENT_BATCH_MIB, lowered to the most this build uses",
        };
        format!(
            "tunnel batching: up to {} messages per receive and per send system call, {:.1} MiB of buffers; {source}",
            run.slots,
            mib_tenths(run.bytes())
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

/// The budget derived from the flow caps, in bytes: β of [`flow_caps_memory`], the v1 agent's
/// default for `WGFT_AGENT_BATCH_MIB`.
#[must_use]
pub fn derived_budget(limits: flowpool::Limits) -> u64 {
    flow_caps_memory(limits).saturating_mul(SHARE_NUM) / SHARE_DEN
}

/// The batch store of `slots` slots per direction with batching on, at the largest MTU.
fn store_of(slots: usize) -> u64 {
    let b = Batching {
        slots,
        on: true,
        source: Source::Set,
    };
    let bytes = crate::dataplane::batch::store_bytes(b, wgft_wgstack::MAX_MTU);
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
        assert_eq!(one.source(), Source::Set);
        // 1 MiB の予算は、最大の MTU の枠の組をその数だけ持つ
        assert!(store_fits(one, 1 << 20));
        let big = Batching::new(Some(i64::MAX), caps);
        assert_eq!(big.slots(), MAX_SLOTS);
        assert_eq!(big.source(), Source::Lowered);
        // 既定の上限から導く予算は、最大の枠の数に届く
        let derived = Batching::new(None, caps);
        assert_eq!(derived.source(), Source::Derived);
        assert_eq!(derived.slots(), MAX_SLOTS);
        // (32 MiB + 8192 × 12 KiB + 2048 × 44 KiB) × 3 / 20
        assert_eq!(derived_budget(caps), 33_973_862);
    }

    fn store_fits(b: Batching, budget: usize) -> bool {
        let next = Batching {
            slots: b.slots() + 1,
            ..b
        };
        crate::dataplane::batch::store_bytes(b, wgft_wgstack::MAX_MTU) <= budget
            && crate::dataplane::batch::store_bytes(next, wgft_wgstack::MAX_MTU) > budget
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
