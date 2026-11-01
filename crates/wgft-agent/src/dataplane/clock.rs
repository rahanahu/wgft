//! データプレーンの時計。device の層と上の層に渡す時刻と、データプレーンのタイマーは、すべてこの
//! 時計から取る (`docs/design/v2/wgstack-rs.md` のデータプレーンの駆動)。
//!
//! v1 の agent と同じ時機で作り直すため、Linux と macOS ではホストの一時停止の間に止まる時計を、
//! Windows ではスリープの間も進む時計を使う (仕様 tunnel.md のサスペンドの間の時計)。Linux と
//! macOS の `Instant` はそのまま前者に当たる。Windows の `Instant` は `QueryPerformanceCounter` で、
//! スリープの間に進むかを確かめていないので、`QueryInterruptTimePrecise` の経過を最初に読んだ
//! `Instant` に足した値を返す。返す値は `Instant` だが、Windows では `Instant::now()` とずれうる。
//! このため、この時計の時刻と比べる時刻もこの時計から取り、待ちは [`sleep_until`] で行う。

#[cfg(windows)]
use std::time::Duration;
use std::time::Instant;

/// The current time on the data plane's clock.
#[cfg(not(windows))]
#[must_use]
pub fn now() -> Instant {
    Instant::now()
}

/// The current time on the data plane's clock: the interrupt time, which keeps counting while the
/// host sleeps, added to the `Instant` of the first call.
#[cfg(windows)]
#[must_use]
pub fn now() -> Instant {
    use std::sync::LazyLock;
    static ANCHOR: LazyLock<(Instant, u64)> = LazyLock::new(|| (Instant::now(), interrupt_time()));
    let (base, at) = *ANCHOR;
    // 割り込みの時刻は 100 ns の単位で数える
    let ticks = interrupt_time().saturating_sub(at);
    base + Duration::from_nanos(ticks.saturating_mul(100))
}

#[cfg(windows)]
fn interrupt_time() -> u64 {
    let mut t = 0u64;
    // SAFETY: 書き先は呼び出しの間生きている u64 で、関数はそこに 1 つの値を書くだけである
    unsafe {
        windows_sys::Win32::System::WindowsProgramming::QueryInterruptTimePrecise(&raw mut t);
    }
    t
}

/// Waits until [`now`] reaches `deadline`.
///
/// tokio's timer runs on `Instant`. On Windows this clock can run ahead of `Instant` after the
/// host slept, so the wait is a sleep for the time left on this clock, repeated until it is over.
/// On Windows each sleep lasts at most [`WINDOWS_SLEEP_CHUNK`], so that a wait that spans a host
/// sleep ends within that time after the host resumes, even if `Instant` stood still meanwhile.
pub async fn sleep_until(deadline: Instant) {
    loop {
        let left = deadline.saturating_duration_since(now());
        if left.is_zero() {
            return;
        }
        #[cfg(windows)]
        let left = left.min(WINDOWS_SLEEP_CHUNK);
        tokio::time::sleep(left).await;
    }
}

/// The longest single sleep of [`sleep_until`] on Windows.
#[cfg(windows)]
pub const WINDOWS_SLEEP_CHUNK: Duration = Duration::from_secs(5);

/// Waits until `deadline`, or forever without one.
pub(crate) async fn sleep_until_some(deadline: Option<Instant>) {
    match deadline {
        Some(at) => sleep_until(at).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn the_clock_does_not_go_back() {
        let a = now();
        let b = now();
        assert!(b >= a);
    }

    #[tokio::test]
    async fn sleep_until_waits_on_this_clock() {
        let start = now();
        sleep_until(start + Duration::from_millis(30)).await;
        assert!(now() >= start + Duration::from_millis(30));
        // 過ぎた時刻はすぐに戻る
        sleep_until(start).await;
    }
}
