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

/// The time one batch is sized for: half the wake-up budget, so that a phase takes about two
/// batches and its last batch runs past the budget by at most this much. Sizing each batch for the
/// budget left instead made the last batch of nearly every wake-up a batch of one datagram.
pub(super) const BATCH_TIME: Duration = WAKE_BUDGET.checked_div(2).expect("2 is not 0");

/// The lanes of the batch store for `b` with `workers` crypto workers: one more than the workers
/// when `b` batches and has more slots than workers, else one. `docs/design/v2/agent-crypto-workers.md`
/// has the rules.
pub(crate) fn crypto_lanes(b: Batching, workers: usize) -> usize {
    if b.is_on() && workers > 0 && b.slots() > workers {
        workers + 1
    } else {
        1
    }
}

/// The bytes of the batch store for `b` with the tunnel MTU `mtu` and `lanes` crypto lanes: what the
/// data plane allocates once at start. The memory bound counts it at the largest MTU. The receive
/// side's plaintext area and the send side's sealed area are cut into the lanes.
pub(crate) fn store_bytes(b: Batching, mtu: usize, lanes: usize) -> usize {
    wgft_udp_batch::store_bytes(
        b.slots(),
        b.is_on(),
        mtu,
        mtu + wgft_wireguard::DATA_OVERHEAD,
        lanes,
        lanes,
    )
}

/// The bytes of every batch store the data plane allocates for `b` with `lanes` crypto lanes: the
/// store of [`store_bytes`] and, with the workers (`lanes > 1`), the second receive and send stores
/// of the pipelined receive and send. `WGFT_AGENT_BATCH_MIB` bounds this sum.
pub(crate) fn all_store_bytes(b: Batching, mtu: usize, lanes: usize) -> usize {
    let second = if lanes > 1 {
        wgft_udp_batch::rx_store_bytes(b.slots(), b.is_on(), lanes)
            + wgft_udp_batch::tx_store_bytes(
                b.slots(),
                b.is_on(),
                mtu,
                mtu + wgft_wireguard::DATA_OVERHEAD,
                lanes,
            )
    } else {
        0
    };
    store_bytes(b, mtu, lanes) + second
}

/// The store's receive side for `b`, whose slots hold the peer's longest datagram,
/// `max_datagram` bytes, one after the other, with its plaintext area cut into `lanes` lanes.
pub(super) fn rx_store(b: Batching, max_datagram: usize, lanes: usize) -> RxBatch {
    RxBatch::new(
        b.slots(),
        b.is_on() && cfg!(target_os = "linux"),
        max_datagram,
        lanes,
    )
}

/// The store's send side for `b`, for packets of up to `mtu` bytes sealed into datagrams of up to
/// `max_datagram` bytes, with its sealed area cut into `lanes` lanes.
pub(super) fn tx_store(b: Batching, mtu: usize, max_datagram: usize, lanes: usize) -> TxBatch {
    TxBatch::new(
        b.slots(),
        b.is_on() && cfg!(target_os = "linux"),
        mtu,
        max_datagram,
        lanes,
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
            let lanes = crypto_lanes(b, wgft_udp_batch::pool::MAX_WORKERS);
            let rx = rx_store(b, mtu + wgft_wireguard::DATA_OVERHEAD, lanes);
            let tx = tx_store(b, mtu, mtu + wgft_wireguard::DATA_OVERHEAD, lanes);
            assert_eq!(rx.slots(), b.slots());
            assert_eq!(tx.slots(), b.slots());
            assert_eq!(rx.batched(), b.is_on());
            assert_eq!(rx.plain.len(), lanes);
            assert_eq!(tx.sealed.len(), lanes);
            let second = if lanes > 1 {
                wgft_udp_batch::rx_store_bytes(b.slots(), b.is_on(), lanes)
                    + wgft_udp_batch::tx_store_bytes(
                        b.slots(),
                        b.is_on(),
                        mtu,
                        mtu + wgft_wireguard::DATA_OVERHEAD,
                        lanes,
                    )
            } else {
                0
            };
            assert_eq!(b.bytes(), store_bytes(b, mtu, lanes) + second);
            assert_eq!(b.bytes(), all_store_bytes(b, mtu, lanes));
            // 作業者の少ないホストの置き場は、上界が数える置き場より大きくならない
            for workers in 0..wgft_udp_batch::pool::MAX_WORKERS {
                assert!(store_bytes(b, mtu, crypto_lanes(b, workers)) <= b.bytes());
            }
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
