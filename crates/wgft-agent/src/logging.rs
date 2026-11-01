//! Go の `log.Printf` と同じ形の 1 行のログ (`2006/01/02 15:04:05 msg`) を標準エラーに書く。

use std::io::Write;
use std::sync::OnceLock;

use time::macros::format_description;
use time::{OffsetDateTime, UtcOffset};

static OFFSET: OnceLock<UtcOffset> = OnceLock::new();

/// ホストの時差を読んで覚える。時差の読みはスレッドが 1 つの間でないと失敗しうるので、`main` が
/// 非同期の実行環境を作る前に呼ぶ。読めなければ UTC で書く。
pub fn init() {
    let _ = OFFSET.set(UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC));
}

/// 1 行を書く。
pub fn line(msg: &str) {
    let offset = OFFSET.get().copied().unwrap_or(UtcOffset::UTC);
    let stamp = OffsetDateTime::now_utc()
        .to_offset(offset)
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
