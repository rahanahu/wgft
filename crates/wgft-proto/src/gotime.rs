//! Go の `time.Time` の JSON の形。
//!
//! Go は `time.Time` を RFC 3339 (ナノ秒まで、末尾の 0 を落とす) で書き、`omitempty` を付けても零の値
//! `0001-01-01T00:00:00Z` を書く。ここでは零の値を `None` で表し、書くときは同じ文字列に戻す。

use std::fmt;
use std::time::SystemTime;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Go の零の `time.Time` が JSON に書く文字列。
pub const GO_ZERO_TIME: &str = "0001-01-01T00:00:00Z";

/// Go の `time.Time` に当たる値。中の `None` は Go の零の値である。Go の零の値と同じ瞬間は、
/// どの作り方でも `None` に揃える。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GoTime(Option<OffsetDateTime>);

/// Go の零の値の瞬間 (0001-01-01T00:00:00Z) の Unix 時刻の秒。
const GO_ZERO_UNIX: i64 = -62_135_596_800;

impl GoTime {
    /// 零の値。
    pub const ZERO: GoTime = GoTime(None);

    /// `SystemTime` から作る。UTC で表す。
    #[must_use]
    pub fn from_system(t: SystemTime) -> Self {
        GoTime::from_offset(OffsetDateTime::from(t))
    }

    /// `OffsetDateTime` から作る。Go の零の値と同じ瞬間は零の値にする。
    #[must_use]
    pub fn from_offset(t: OffsetDateTime) -> Self {
        if t.unix_timestamp_nanos() == i128::from(GO_ZERO_UNIX) * 1_000_000_000 {
            GoTime(None)
        } else {
            GoTime(Some(t))
        }
    }

    /// 中の時刻。零の値なら `None`。
    #[must_use]
    pub fn get(&self) -> Option<OffsetDateTime> {
        self.0
    }

    /// 零の値かどうか。
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.is_none()
    }

    /// RFC 3339 の文字列にする。零の値は [`GO_ZERO_TIME`] になる。
    #[must_use]
    pub fn to_rfc3339(&self) -> String {
        match self.0 {
            // Rfc3339 の書式は 0 年から 9999 年までを書ける。SystemTime から作った値は範囲に入る
            Some(t) => t
                .format(&Rfc3339)
                .unwrap_or_else(|_| GO_ZERO_TIME.to_owned()),
            None => GO_ZERO_TIME.to_owned(),
        }
    }

    /// RFC 3339 の文字列を読む。Go の零の値を表す瞬間は `None` にする。
    ///
    /// # Errors
    ///
    /// RFC 3339 として読めない文字列は誤りにする。
    pub fn parse(s: &str) -> Result<Self, time::error::Parse> {
        Ok(GoTime::from_offset(OffsetDateTime::parse(s, &Rfc3339)?))
    }
}

impl Serialize for GoTime {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_rfc3339())
    }
}

impl<'de> Deserialize<'de> for GoTime {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = GoTime;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an RFC 3339 time string")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<GoTime, E> {
                GoTime::parse(v).map_err(E::custom)
            }
            // Go の encoding/json は time.Time への null を読み飛ばし、零の値のままにする
            fn visit_unit<E: de::Error>(self) -> Result<GoTime, E> {
                Ok(GoTime::ZERO)
            }
        }
        d.deserialize_any(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_round_trips_as_go_writes_it() {
        assert_eq!(GoTime::ZERO.to_rfc3339(), GO_ZERO_TIME);
        assert_eq!(GoTime::parse(GO_ZERO_TIME).unwrap(), GoTime::ZERO);
        assert_eq!(
            serde_json::to_string(&GoTime::ZERO).unwrap(),
            "\"0001-01-01T00:00:00Z\""
        );
    }

    #[test]
    fn nanoseconds_drop_trailing_zeros_like_go() {
        let t = GoTime::parse("2026-11-01T12:34:56.120Z").unwrap();
        assert_eq!(t.to_rfc3339(), "2026-11-01T12:34:56.12Z");
        let t = GoTime::parse("2026-11-01T12:34:56Z").unwrap();
        assert_eq!(t.to_rfc3339(), "2026-11-01T12:34:56Z");
    }

    #[test]
    fn reads_offsets_go_writes_for_local_time() {
        let t = GoTime::parse("2026-11-01T21:00:00.5+09:00").unwrap();
        assert_eq!(t, GoTime::parse("2026-11-01T12:00:00.5Z").unwrap());
    }

    #[test]
    fn zero_instant_is_zero_however_made() {
        let t = OffsetDateTime::parse("0001-01-01T09:00:00+09:00", &Rfc3339).unwrap();
        assert!(GoTime::from_offset(t).is_zero());
        assert!(
            GoTime::parse("0001-01-01T09:00:00+09:00")
                .unwrap()
                .is_zero()
        );
    }

    #[test]
    fn null_is_zero() {
        let t: GoTime = serde_json::from_str("null").unwrap();
        assert!(t.is_zero());
    }
}
