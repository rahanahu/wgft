//! データプレーンの時計。device の層と上の層に渡す時刻と、データプレーンのタイマーは、すべてこの
//! 時計から取る (`docs/design/v2/wgstack-rs.md` のデータプレーンの駆動)。
//!
//! v1 の agent と同じ時機で作り直すため、Linux と macOS ではホストの一時停止の間に止まる時計を、
//! Windows ではスリープの間も進む時計を使う (仕様 tunnel.md のサスペンドの間の時計)。Linux と
//! macOS の `Instant` はそのまま前者に当たる。Windows の `Instant` は `QueryPerformanceCounter` で、
//! スリープの間に進むかを確かめていないので、`QueryInterruptTimePrecise` の経過を最初に読んだ
//! `Instant` に足した値を返す。返す値は `Instant` だが、Windows では `Instant::now()` とずれうる。
//! このため、この時計の時刻と比べる時刻もこの時計から取り、待ちは [`sleep_until`] か
//! [`sleep_until_some`] で行う。後者は Linux と macOS で、起床の中で読んだ時刻から 1 ms より先の期限を
//! 時計を読み直さずに tokio に渡す (この時計と tokio の `Instant` が同じだから)。

#[cfg(windows)]
use std::time::Duration;
use std::time::Instant;

/// The current time on the data plane's clock.
#[cfg(not(windows))]
#[must_use]
pub(crate) fn now() -> Instant {
    Instant::now()
}

/// The current time on the data plane's clock: the interrupt time, which keeps counting while the
/// host sleeps, added to the `Instant` of the first call.
#[cfg(windows)]
#[must_use]
pub(crate) fn now() -> Instant {
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
pub(crate) async fn sleep_until(deadline: Instant) {
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
pub(crate) const WINDOWS_SLEEP_CHUNK: Duration = Duration::from_secs(5);

/// How far ahead of a reading of this clock a deadline must lie for [`sleep_until_some`] to trust
/// that reading instead of reading the clock again: one tick of tokio's timer.
#[cfg(not(windows))]
const NEAR: std::time::Duration = std::time::Duration::from_millis(1);

/// Waits until `deadline`, or forever without one. `read` is a reading of this clock taken before
/// the call, in the same wake-up.
///
/// A deadline at or before `read` has passed, and the call returns at once, as [`sleep_until`]
/// does. Outside Windows, `Instant` is this clock and tokio's timer never ends a sleep before its
/// deadline, so a deadline more than one timer tick ([`NEAR`]) after `read` goes to tokio as it
/// is, without reading the clock again. A closer deadline goes through [`sleep_until`], which reads
/// the clock, so that a deadline that passed after `read` still ends the wait at once. On Windows
/// every wait reads the clock.
///
/// In a time-limited wake-up `read` is taken after the last batch, far less than a tick before the
/// call. In a count-limited wake-up (macOS, and Linux with `WGFT_AGENT_BATCH_MIB=0`) it is the
/// start of the wake-up, which can trail the call by a whole wake-up of single datagrams. A
/// far deadline that has passed by then still ends the wait at tokio's next timer turn, never
/// early, and the next wake-up reads the clock afresh.
pub(crate) async fn sleep_until_some(deadline: Option<Instant>, read: Instant) {
    match deadline {
        Some(at) if at <= read => {}
        #[cfg(not(windows))]
        Some(at) if at > read + NEAR => tokio::time::sleep_until(at.into()).await,
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

    #[tokio::test]
    async fn sleep_until_some_never_ends_before_the_deadline() {
        let read = now();
        // 過ぎた期限はすぐに戻る
        sleep_until_some(Some(read), read).await;
        // 時計を読み直さない遠い期限と、読み直す近い期限
        for ahead in [Duration::from_millis(30), Duration::from_micros(300)] {
            let read = now();
            sleep_until_some(Some(read + ahead), read).await;
            assert!(now() >= read + ahead, "{ahead:?}");
        }
    }
}
