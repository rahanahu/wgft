//! Go の `log.Printf` と同じ形の 1 行のログ (`2006/01/02 15:04:05 msg`) を標準エラーに書く。
//!
//! 文は表示できない文字を `sanitize_for_terminal` で置き換えてから書く。ログの文は server が配る
//! 文字列 (ルール ID、宛先、wg の endpoint、登録の応答) と、宛先と名前の解決の誤りの文を含み、制御の
//! 文字が端末を操作したり、改行が偽の行を作ったりしないためである。Go の agent は置き換えない。

use std::borrow::Cow;
use std::io::Write;
use std::sync::OnceLock;

use time::macros::format_description;
use time::{OffsetDateTime, UtcOffset};
use wgft_proto::textsafe::{is_unsafe, sanitize_for_terminal};

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
    let _ = writeln!(err, "{stamp} {}", terminal_safe(msg));
}

/// 表示できない文字を置き換えた文。置き換える文字が無ければ写さない。
#[must_use]
pub fn terminal_safe(msg: &str) -> Cow<'_, str> {
    if msg.chars().any(is_unsafe) {
        Cow::Owned(sanitize_for_terminal(msg))
    } else {
        Cow::Borrowed(msg)
    }
}

/// `format!` の形で 1 行を書く。
#[macro_export]
macro_rules! logf {
    ($($arg:tt)*) => {
        $crate::logging::line(&format!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_and_line_breaks_are_escaped() {
        assert!(matches!(terminal_safe("rule r_1 ok"), Cow::Borrowed(_)));
        assert_eq!(
            terminal_safe("rule \u{1b}[2Jx\nfake line\u{2028}"),
            "rule \\x1b[2Jx\\nfake line\\u2028"
        );
    }
}
