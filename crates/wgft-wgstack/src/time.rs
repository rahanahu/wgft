//! 核の時刻。

use core::fmt;
use core::ops::{Add, Sub};
use core::time::Duration;

/// The stack's time: a monotonic count of nanoseconds from an arbitrary origin.
///
/// The stack never reads a clock; the caller passes a `Time` to every operation. The caller chooses the origin, for
/// example the time elapsed since an `Instant` taken at creation.
///
/// Addition and subtraction of durations saturate, so they never panic inside the stack.
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
    /// The origin.
    pub const ZERO: Self = Self(0);

    /// The latest representable time.
    pub const MAX: Self = Self(u64::MAX);

    /// Creates a time from a count of nanoseconds since the origin.
    pub const fn from_nanos(ns: u64) -> Self {
        Self(ns)
    }

    /// Returns the count of nanoseconds since the origin.
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// Returns the time `ns` nanoseconds later; a time that cannot be represented becomes [`Time::MAX`].
    #[must_use]
    pub const fn saturating_add_nanos(self, ns: u64) -> Self {
        Self(self.0.saturating_add(ns))
    }

    /// Returns the nanoseconds elapsed since `earlier`, or 0 if `earlier` is later.
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
