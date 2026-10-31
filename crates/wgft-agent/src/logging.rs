//! Go の `log.Printf` と同じ形の 1 行のログ (`2006/01/02 15:04:05 msg`) を標準エラーに書く。

use std::io::Write;

use time::OffsetDateTime;
use time::macros::format_description;

/// 1 行を書く。時刻はホストの時差で書き、時差を読めなければ UTC で書く。
pub fn line(msg: &str) {
    let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
    let stamp = now
        .format(format_description!(
            "[year]/[month]/[day] [hour]:[minute]:[second]"
        ))
        .unwrap_or_default();
    let mut err = std::io::stderr().lock();
    let _ = writeln!(err, "{stamp} {msg}");
}

/// `format!` の形で 1 行を書く。
#[macro_export]
macro_rules! logf {
    ($($arg:tt)*) => {
        $crate::logging::line(&format!($($arg)*))
    };
}
