//! 核の時刻。

use core::fmt;
use core::ops::{Add, Sub};
use core::time::Duration;

/// 核の時刻。任意の起点からの単調な nanosecond の数です。
///
/// 核は時計を読まず、呼び手がすべての操作に `Time` を渡します。
/// 起点は呼び手が決め、駆動の層は作成の時の `Instant` からの経過を渡します。
/// Go の wgstack の核の時刻 (起点からの int64 の ns) と同じ値を持てるので、記録の時刻をそのまま渡せます。
///
/// 時間の足し算と引き算は飽和します。核の中で panic を起こさないためです。
///
/// ```
/// use core::time::Duration;
/// use wgft_wgstack::Time;
///
/// let t = Time::from_nanos(1_500);
/// assert_eq!((t + Duration::from_micros(1)).as_nanos(), 2_500);
/// assert_eq!(t - Time::from_nanos(500), Duration::from_nanos(1_000));
/// assert_eq!(Time::ZERO - t, Duration::ZERO);
/// ```
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Time(u64);

impl Time {
    /// 起点の時刻です。
    pub const ZERO: Self = Self(0);

    /// 表せる最も遅い時刻です。
    pub const MAX: Self = Self(u64::MAX);

    /// 起点からの nanosecond の数から時刻を作ります。
    pub const fn from_nanos(ns: u64) -> Self {
        Self(ns)
    }

    /// 起点からの nanosecond の数を返します。
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// `ns` nanosecond 後の時刻を返します。表せない時刻は [`Time::MAX`] にします。
    #[must_use]
    pub const fn saturating_add_nanos(self, ns: u64) -> Self {
        Self(self.0.saturating_add(ns))
    }

    /// `earlier` からの経過の nanosecond を返します。`earlier` の方が遅ければ 0 です。
    pub const fn nanos_since(self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

/// `Duration` を nanosecond の `u64` にします。表せない長さは `u64::MAX` にします。
pub(crate) fn duration_nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

impl Add<Duration> for Time {
    type Output = Self;

    fn add(self, d: Duration) -> Self {
        self.saturating_add_nanos(duration_nanos(d))
    }
}

impl Sub for Time {
    type Output = Duration;

    fn sub(self, earlier: Self) -> Duration {
        Duration::from_nanos(self.nanos_since(earlier))
    }
}

impl fmt::Debug for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Time({}ns)", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saturates_instead_of_panicking() {
        assert_eq!(Time::MAX + Duration::from_secs(1), Time::MAX);
        assert_eq!(Time::ZERO + Duration::MAX, Time::MAX);
        assert_eq!(Time::from_nanos(3) - Time::from_nanos(5), Duration::ZERO);
        assert_eq!(Time::from_nanos(5).nanos_since(Time::from_nanos(3)), 2);
    }

    #[test]
    fn orders_by_nanos() {
        assert!(Time::from_nanos(1) < Time::from_nanos(2));
        assert_eq!(
            Time::from_nanos(7).max(Time::from_nanos(3)),
            Time::from_nanos(7)
        );
    }
}
