//! 使ったことのある接続の枠の数を書く行。ラボの `lifecycle.sh` だけが読むので、`lab-observe` の feature を
//! 付けた build だけが動かす。製品の build は 1 秒ごとの起床も、データプレーンのスレッドへの呼び出しも持たない。

/// 使ったことのある接続の枠の数を書く行の刻みの下限です。
#[cfg(any(test, feature = "lab-observe"))]
#[cfg(any(test, feature = "lab-observe"))]
const SLOT_STEP_MIN: usize = 64;

/// 行の数の上限です。`slot_watch` は `Tunnel::start` ごとに最後に書いた値 `shown` を 0 から始めるので、トンネルを立てるたびに最大この行数です。刻みは接続の枠の数をこの値で割って決めます。
#[cfg(any(test, feature = "lab-observe"))]
const SLOT_LINES_MAX: usize = 32;

/// 使ったことのある接続の枠の数を書く行の刻みです。接続の枠の数を [`SLOT_LINES_MAX`] で割って切り上げた値と
/// [`SLOT_STEP_MIN`] の大きい方を、64 の倍数に切り上げます。行は数をこの倍数に切り上げて書くので、行の値は
/// 数の上界で、行の数はトンネルを立てるたびに、上限によらず [`SLOT_LINES_MAX`] までです (洪水で数が一気に増えても行が増えすぎない)。
#[cfg(any(test, feature = "lab-observe"))]
pub(super) const fn slot_step(conns: usize) -> usize {
    let want = conns.div_ceil(SLOT_LINES_MAX);
    let want = if want > SLOT_STEP_MIN {
        want
    } else {
        SLOT_STEP_MIN
    };
    want.next_multiple_of(SLOT_STEP_MIN)
}

/// 核の接続の枠のうち floor の配列を持つ枠 (核を作ってから使ったことのある枠) の数を 1 秒ごとに読み (核が数えて
/// 持つ値で、枠をたどらない)、
/// [`slot_step`] の倍数に切り上げた値が増えたときだけ、その値と配列の byte を 1 行に書く。配列は枠が持ち続けるので、
/// 数は減らない。ラボの `lifecycle.sh` の check 5 と 5b は、洪水が満たした配列の量をこの行から読む
/// (agent-parity.md の「メモリの上界の行」)。行の形は保証の外。
#[cfg(feature = "lab-observe")]
pub(super) async fn slot_watch(
    dp: crate::dataplane::Handle<super::Stack>,
    limits: wgft_wgstack::Limits,
) {
    use crate::logf;
    use std::time::Duration;

    let conns = limits.conns();
    let arrays = wgft_wgstack::Bound::for_limits(&limits, wgft_wgstack::MAX_MTU).floor_arrays;
    let per_slot = usize::try_from(arrays).unwrap_or(usize::MAX) / conns.max(1);
    let step = slot_step(conns);
    let mut shown = 0;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tick.tick().await;
        let Ok(used) = dp.call(|net| net.with(|ns| ns.core().slots_used())).await else {
            return;
        };
        let up = used.next_multiple_of(step).min(conns);
        if up > shown {
            shown = up;
            logf!(
                "memory: connection slots used so far: at most {up} of {conns}; their floor arrays hold {} KiB",
                (up * per_slot).div_ceil(1 << 10)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_step_scales_and_bounds_the_lines() {
        assert_eq!(slot_step(1), 64);
        assert_eq!(slot_step(2048), 64);
        assert_eq!(slot_step(65_536), 2048);
        for conns in [
            1,
            63,
            64,
            1000,
            2048,
            2049,
            4096,
            10_000,
            65_536,
            65_600,
            100_000,
            1 << 20,
        ] {
            let step = slot_step(conns);
            assert!(
                step >= 64 && step.is_multiple_of(64),
                "conns {conns} step {step}"
            );
            // 数が 0 から上限まで 1 ずつ増えたときに書く行の数
            let (mut shown, mut lines) = (0, 0);
            for used in 0..=conns {
                let up = used.next_multiple_of(step).min(conns);
                if up > shown {
                    shown = up;
                    lines += 1;
                }
            }
            assert!(lines <= SLOT_LINES_MAX, "conns {conns} wrote {lines} lines");
            assert_eq!(shown, conns);
        }
    }
}
