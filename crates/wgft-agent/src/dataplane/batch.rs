//! 起床の時間の予算と、バッチの置き場 (`wgft-udp-batch`) の大きさ。規則の正本は
//! `docs/design/v2/agent-throughput.md` の「バッチの作りの規則」と「バッチの作り」である。
//!
//! [`WAKE_BUDGET`] が 1 回の起床の仕事を区切る。バッチの枠の数は、前のバッチで測った 1 つあたりの時間から、
//! 残りの予算に収まる数にする ([`Pace`])。

use std::time::Duration;

pub(super) use wgft_udp_batch::{RX_SLOT, RxBatch, RxMeta, TxBatch, each_packet};

use crate::batching::Batching;

/// The latency budget of one wake-up of the data plane: the receive and send batches of one
/// wake-up end once this much time has passed since it began. The one place the value lives;
/// `docs/design/v2/agent-throughput.md` gives the reasons for it.
pub(super) const WAKE_BUDGET: Duration = Duration::from_micros(50);

/// The bytes of the batch store for `b` with the tunnel MTU `mtu`: what the data plane allocates
/// once at start. The memory bound counts it at the largest MTU.
pub(crate) fn store_bytes(b: Batching, mtu: usize) -> usize {
    wgft_udp_batch::store_bytes(
        b.slots(),
        b.is_on(),
        mtu,
        mtu + wgft_wireguard::DATA_OVERHEAD,
    )
}

/// The store's receive side for `b`, whose slots hold the peer's longest datagram,
/// `max_datagram` bytes, one after the other.
pub(super) fn rx_store(b: Batching, max_datagram: usize) -> RxBatch {
    RxBatch::new(
        b.slots(),
        b.is_on() && cfg!(target_os = "linux"),
        max_datagram,
    )
}

/// The store's send side for `b`, for packets of up to `mtu` bytes sealed into datagrams of up to
/// `max_datagram` bytes.
pub(super) fn tx_store(b: Batching, mtu: usize, max_datagram: usize) -> TxBatch {
    TxBatch::new(
        b.slots(),
        b.is_on() && cfg!(target_os = "linux"),
        mtu,
        max_datagram,
    )
}

/// The measured cost of one unit of a batch (a receive slot, a sent packet), for sizing the next
/// batch to the budget left. It keeps the last batch's figure only: no smoothing to tune.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Pace {
    nanos_per_unit: u64,
}

impl Pace {
    /// How many units fit in `share`: at least 1 and at most `slots`. Before the first measurement
    /// a batch takes one unit, which measures the cost.
    pub(super) fn units(self, share: Duration, slots: usize) -> usize {
        if self.nanos_per_unit == 0 {
            return 1;
        }
        let share = u64::try_from(share.as_nanos()).unwrap_or(u64::MAX);
        usize::try_from(share / self.nanos_per_unit)
            .unwrap_or(slots)
            .clamp(1, slots)
    }

    /// Records a batch of `units` that took `took`.
    pub(super) fn record(&mut self, took: Duration, units: usize) {
        if units == 0 {
            return;
        }
        let took = u64::try_from(took.as_nanos()).unwrap_or(u64::MAX);
        self.nanos_per_unit = (took / units as u64).max(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flowpool;

    #[test]
    fn the_running_store_is_what_the_bound_counts() {
        let mtu = wgft_wgstack::MAX_MTU;
        for b in [
            Batching::OFF,
            Batching::new(Some(1), flowpool::Limits::default()),
            Batching::default(),
        ] {
            let b = b.running();
            let rx = rx_store(b, mtu + wgft_wireguard::DATA_OVERHEAD);
            let tx = tx_store(b, mtu, mtu + wgft_wireguard::DATA_OVERHEAD);
            assert_eq!(rx.slots(), b.slots());
            assert_eq!(tx.slots(), b.slots());
            assert_eq!(rx.batched(), b.is_on());
            assert_eq!(b.bytes(), store_bytes(b, mtu));
        }
    }

    #[test]
    fn a_pace_fits_the_share() {
        let mut p = Pace::default();
        assert_eq!(p.units(Duration::from_micros(50), 64), 1);
        p.record(Duration::from_micros(30), 10);
        assert_eq!(p.units(Duration::from_micros(50), 64), 16);
        assert_eq!(p.units(Duration::ZERO, 64), 1);
        assert_eq!(p.units(Duration::from_secs(1), 64), 64);
        p.record(Duration::from_micros(30), 0);
        assert_eq!(p.units(Duration::from_micros(50), 64), 16);
    }
}
