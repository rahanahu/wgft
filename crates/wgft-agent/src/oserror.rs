//! OS の誤りの文を Go の誤りの文の形に寄せる部品。
//!
//! Rust の `std::io::Error` の文は OS の文の後ろに ` (os error N)` を付け、Unix の `strerror` の文は先頭が
//! 大文字である。Go の `syscall.Errno` の文は接尾辞を持たず、先頭が小文字である。呼び手は、Go と同じ文を
//! 出す所でこの 2 つの違いをどこまで埋めるかを選ぶ。

use std::io;

/// OS の文の末尾の ` (os error N)` を除いた文。接尾辞が無ければ `None` を返す。
#[must_use]
pub fn strip_os_suffix(s: &str) -> Option<&str> {
    let i = s.rfind(" (os error ")?;
    s.ends_with(')').then(|| &s[..i])
}

/// `e` の文から ` (os error N)` の接尾辞を除いた文。
#[must_use]
pub fn os_text(e: &io::Error) -> String {
    let s = e.to_string();
    strip_os_suffix(&s).map_or_else(|| s.clone(), str::to_owned)
}

/// 先頭の 1 文字を小文字にした文。
#[must_use]
pub fn lower_first(s: &str) -> String {
    let mut cs = s.chars();
    cs.next()
        .map(|c| c.to_lowercase().chain(cs).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_os_suffix_is_stripped_only_at_the_end() {
        assert_eq!(
            strip_os_suffix("Connection refused (os error 111)"),
            Some("Connection refused")
        );
        assert_eq!(strip_os_suffix("Connection refused"), None);
        assert_eq!(strip_os_suffix("odd (os error 1) tail"), None);
        assert_eq!(
            os_text(&io::Error::other("Odd Thing")),
            "Odd Thing",
            "a message without the suffix stays as it is"
        );
    }

    #[test]
    fn only_the_first_character_is_lowered() {
        assert_eq!(lower_first("No Such file"), "no Such file");
        assert_eq!(lower_first("Énorme"), "énorme");
        assert_eq!(lower_first(""), "");
    }
}
