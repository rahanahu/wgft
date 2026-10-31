//! ハートビートの理由の整形 (Go の `internal/textsafe` の `SanitizeAndClip`)。
//!
//! Go は `unicode.IsGraphic` でない文字を `strconv.QuoteRune` の形に置き換える。この版は同じ判定を
//! `unicode-general-category` の一般カテゴリの表で行う。表の Unicode の版は [`UNICODE_VERSION`] で、
//! Go の `unicode` の版と違うことがある。差は、片方の版だけで割り当てのある文字の扱いだけで、
//! 割り当ての無い文字 (Cn) は表示できない文字として置き換える。差の大きさは
//! `testdata/spec/text/non-graphic.json` との照合で確かめる。

use std::fmt::Write;

/// 長さの上限を超えたときに後ろに付ける印。
pub const CLIP_MARK: &str = "... truncated";

pub use unicode_general_category::UNICODE_VERSION;

/// Go の `unicode.IsGraphic` の否定。L、M、N、P、S と Zs だけが表示できる文字である。
#[must_use]
pub fn is_unsafe(c: char) -> bool {
    use unicode_general_category::GeneralCategory as G;
    !matches!(
        unicode_general_category::get_general_category(c),
        G::UppercaseLetter
            | G::LowercaseLetter
            | G::TitlecaseLetter
            | G::ModifierLetter
            | G::OtherLetter
            | G::NonspacingMark
            | G::SpacingMark
            | G::EnclosingMark
            | G::DecimalNumber
            | G::LetterNumber
            | G::OtherNumber
            | G::ConnectorPunctuation
            | G::DashPunctuation
            | G::OpenPunctuation
            | G::ClosePunctuation
            | G::InitialPunctuation
            | G::FinalPunctuation
            | G::OtherPunctuation
            | G::MathSymbol
            | G::CurrencySymbol
            | G::ModifierSymbol
            | G::OtherSymbol
            | G::SpaceSeparator
    )
}

fn escape(c: char, out: &mut String) {
    match c {
        '\u{07}' => out.push_str("\\a"),
        '\u{08}' => out.push_str("\\b"),
        '\u{0C}' => out.push_str("\\f"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        '\u{0B}' => out.push_str("\\v"),
        c if (c as u32) < 0x80 => {
            let _ = write!(out, "\\x{:02x}", c as u32);
        }
        c if (c as u32) <= 0xFFFF => {
            let _ = write!(out, "\\u{:04x}", c as u32);
        }
        c => {
            let _ = write!(out, "\\U{:08x}", c as u32);
        }
    }
}

/// 表示できない文字を置き換える。
#[must_use]
pub fn sanitize_for_terminal(s: &str) -> String {
    if !s.chars().any(is_unsafe) {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if is_unsafe(c) {
            escape(c, &mut out);
        } else {
            out.push(c);
        }
    }
    out
}

/// `max` byte を超えれば、文字の境目で切って印を付ける。
#[must_use]
pub fn clip_text(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let mut n = max;
    while n > 0 && !s.is_char_boundary(n) {
        n -= 1;
    }
    format!("{}{CLIP_MARK}", &s[..n])
}

/// 置き換えてから切る。
#[must_use]
pub fn sanitize_and_clip(s: &str, max: usize) -> String {
    clip_text(&sanitize_for_terminal(s), max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_like_quote_rune() {
        assert_eq!(
            sanitize_for_terminal("a\nb\x00c\u{2028}d"),
            "a\\nb\\x00c\\u2028d"
        );
        assert_eq!(sanitize_for_terminal("ok ñ 日本"), "ok ñ 日本");
    }

    #[test]
    fn clips_on_a_char_boundary() {
        let s = "あ".repeat(200); // 600 byte
        let c = clip_text(&s, 512);
        assert!(c.ends_with(CLIP_MARK));
        assert_eq!(c.len(), 510 + CLIP_MARK.len());
        assert_eq!(clip_text("short", 512), "short");
    }
}
