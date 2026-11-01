//! Go の標準ライブラリの解釈のうち、設定の値と誤りの文面に現れるものの写し。
//!
//! 仕様 `cli-config.md` の「Go の性質」が定める 4 つを持つ。`%q` の引用 (`strconv.Quote`)、整数のフラグの
//! 解釈 (`strconv.ParseInt` の基数 0)、環境変数と dotenv の整数 (`strconv.Atoi`)、真偽値 (`strconv.ParseBool`)。

use std::fmt::Write;

use unicode_general_category::{GeneralCategory as G, get_general_category};

/// Go の `strconv.IsPrint`。文字、記号、数字、句読点、結合文字と ASCII の空白だけが印字できる。
/// `unicode.IsGraphic` と違い、ASCII 以外の空白 (Zs) は印字できない文字である。
fn is_print(c: char) -> bool {
    if c == ' ' {
        return true;
    }
    !matches!(
        get_general_category(c),
        G::Control
            | G::Format
            | G::Surrogate
            | G::PrivateUse
            | G::Unassigned
            | G::SpaceSeparator
            | G::LineSeparator
            | G::ParagraphSeparator
    )
}

/// Go の `%q` (`strconv.Quote`) と同じ引用。
#[must_use]
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{07}' => out.push_str("\\a"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0B}' => out.push_str("\\v"),
            c if is_print(c) => out.push(c),
            c if u32::from(c) < 0x20 || u32::from(c) == 0x7f => {
                let _ = write!(out, "\\x{:02x}", u32::from(c));
            }
            c if u32::from(c) < 0x10000 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => {
                let _ = write!(out, "\\U{:08x}", u32::from(c));
            }
        }
    }
    out.push('"');
    out
}

/// 整数の解釈の誤り。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntError {
    /// 書き方の誤り。
    Syntax,
    /// 64 bit の符号付き整数に収まらない。
    Range,
}

impl IntError {
    /// Go の `strconv.NumError` の文。flag の誤りの文に入る。
    #[must_use]
    pub fn go_text(self, input: &str) -> String {
        let why = match self {
            IntError::Syntax => "invalid syntax",
            IntError::Range => "value out of range",
        };
        format!("strconv.ParseInt: parsing {}: {why}", quote(input))
    }
}

/// 64 bit の符号付き整数の絶対値の境目。
const CUTOFF: u64 = 1 << 63;

/// `strconv.ParseInt(s, 0, 64)`。
pub fn parse_int(s: &str) -> Result<i64, IntError> {
    parse_signed(s, 0)
}

/// `strconv.ParseInt(s, 10, 64)`。接頭辞と `_` を受けない。
pub fn parse_int_base10(s: &str) -> Result<i64, IntError> {
    parse_signed(s, 10)
}

/// `strconv.ParseInt(s, base, 64)`。`base` は 0 か 10。符号を外してから `ParseUint` に渡し、符号を見て範囲を決める。
fn parse_signed(s: &str, base: u64) -> Result<i64, IntError> {
    if s.is_empty() {
        return Err(IntError::Syntax);
    }
    let (neg, digits) = match s.as_bytes()[0] {
        b'+' => (false, &s[1..]),
        b'-' => (true, &s[1..]),
        _ => (false, s),
    };
    let un = match parse_uint(digits, base) {
        Ok(n) => n,
        Err(IntError::Range) => u64::MAX,
        Err(e) => return Err(e),
    };
    if (!neg && un >= CUTOFF) || (neg && un > CUTOFF) {
        return Err(IntError::Range);
    }
    // neg で un == CUTOFF のときは i64::MIN になる
    Ok(if neg {
        0i64.wrapping_sub_unsigned(un)
    } else {
        i64::try_from(un).map_err(|_| IntError::Range)?
    })
}

/// `strconv.ParseUint(s, base, 64)`。`base` が 0 なら接頭辞と `_` を受ける。
fn parse_uint(s: &str, base: u64) -> Result<u64, IntError> {
    let s0 = s.as_bytes();
    if s0.is_empty() {
        return Err(IntError::Syntax);
    }
    let base0 = base == 0;
    let mut body = s0;
    let mut base = base;
    if base0 {
        base = 10;
        if body[0] == b'0' {
            match body.get(1).map(u8::to_ascii_lowercase) {
                Some(b'b') if body.len() >= 3 => {
                    base = 2;
                    body = &body[2..];
                }
                Some(b'o') if body.len() >= 3 => {
                    base = 8;
                    body = &body[2..];
                }
                Some(b'x') if body.len() >= 3 => {
                    base = 16;
                    body = &body[2..];
                }
                _ => {
                    base = 8;
                    body = &body[1..];
                }
            }
        }
    }
    let mut underscores = false;
    let mut n: u64 = 0;
    for &c in body {
        let d = match c {
            b'_' if base0 => {
                underscores = true;
                continue;
            }
            b'0'..=b'9' => u64::from(c - b'0'),
            c if c.is_ascii_alphabetic() => u64::from(c.to_ascii_lowercase() - b'a') + 10,
            _ => return Err(IntError::Syntax),
        };
        if d >= base {
            return Err(IntError::Syntax);
        }
        // 溢れは、この先の文字が誤りでも範囲の誤りとして返す (Go と同じ)
        n = n
            .checked_mul(base)
            .and_then(|m| m.checked_add(d))
            .ok_or(IntError::Range)?;
    }
    if underscores && !underscore_ok(s0) {
        return Err(IntError::Syntax);
    }
    Ok(n)
}

/// Go の `underscoreOK`。`_` は桁の間か、基数の接頭辞の直後にだけ置ける。
fn underscore_ok(s: &[u8]) -> bool {
    let mut s = s;
    if let Some((b'+' | b'-', rest)) = s.split_first() {
        s = rest;
    }
    // '^' 先頭、'0' 桁、'_' 区切り、'!' それ以外
    let mut saw = b'^';
    let mut i = 0;
    let mut hex = false;
    if s.len() >= 2 && s[0] == b'0' && matches!(s[1].to_ascii_lowercase(), b'b' | b'o' | b'x') {
        i = 2;
        saw = b'0';
        hex = s[1].eq_ignore_ascii_case(&b'x');
    }
    while i < s.len() {
        let c = s[i];
        i += 1;
        if c.is_ascii_digit() || (hex && matches!(c.to_ascii_lowercase(), b'a'..=b'f')) {
            saw = b'0';
            continue;
        }
        if c == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
            continue;
        }
        if saw == b'_' {
            return false;
        }
        saw = b'!';
    }
    saw != b'_'
}

/// `strconv.Atoi`。10 進で、先頭の `+` と `-` と先頭の 0 を受け、空白、`_`、基数の接頭辞を受けない。
#[must_use]
pub fn atoi(s: &str) -> Option<i64> {
    s.parse::<i64>().ok()
}

/// `strconv.ParseBool`。
pub fn parse_bool(s: &str) -> Result<bool, String> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        _ => Err(format!(
            "strconv.ParseBool: parsing {}: invalid syntax",
            quote(s)
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_follows_go() {
        assert_eq!(quote("plain"), "\"plain\"");
        assert_eq!(quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(
            quote("\t\n\r\u{7}\u{8}\u{b}\u{c}"),
            "\"\\t\\n\\r\\a\\b\\v\\f\""
        );
        assert_eq!(quote("\u{0}\u{1f}\u{7f}"), "\"\\x00\\x1f\\x7f\"");
        assert_eq!(quote("wg\u{e0}"), "\"wg\u{e0}\"");
        // 印字できない非 ASCII は \u と \U になる
        assert_eq!(quote("\u{a0}\u{200b}"), "\"\\u00a0\\u200b\"");
        assert_eq!(quote("\u{e000}\u{10ffff}"), "\"\\ue000\\U0010ffff\"");
        assert_eq!(quote("日本語 ok"), "\"日本語 ok\"");
    }

    #[test]
    fn parse_int_accepts_the_go_forms() {
        for (s, want) in [
            ("0", 0),
            ("16", 16),
            ("+16", 16),
            ("-16", -16),
            ("016", 14),
            ("0o16", 14),
            ("0O16", 14),
            ("0x400", 1024),
            ("0X4a", 74),
            ("0b101", 5),
            ("1_000", 1000),
            ("0_7", 7),
            ("0x_ff", 255),
            ("-0x10", -16),
            ("9223372036854775807", i64::MAX),
            ("-9223372036854775808", i64::MIN),
        ] {
            assert_eq!(parse_int(s), Ok(want), "{s}");
        }
    }

    #[test]
    fn parse_int_rejects_the_go_forms() {
        for s in [
            "", "+", "-", "abc", " 1", "1 ", "1.5", "0x", "0b", "0b2", "08", "1__0", "_1", "1_",
            "0x_", "0_", "1e3", "--1", "+-1",
        ] {
            assert_eq!(parse_int(s), Err(IntError::Syntax), "{s:?}");
        }
        for s in [
            "9223372036854775808",
            "-9223372036854775809",
            "99999999999999999999",
            "99999999999999999999x",
        ] {
            assert_eq!(parse_int(s), Err(IntError::Range), "{s:?}");
        }
    }

    #[test]
    fn base_10_has_no_prefix_or_underscore_and_scans_like_go() {
        assert_eq!(parse_int_base10("+016"), Ok(16));
        assert_eq!(parse_int_base10("-0"), Ok(0));
        for s in ["0x10", "1_0", "", "+", "1.5", " 4", "4MiB"] {
            assert_eq!(parse_int_base10(s), Err(IntError::Syntax), "{s:?}");
        }
        // 溢れが先に見つかれば範囲の誤り、後ろの誤りが先なら書き方の誤り
        assert_eq!(
            parse_int_base10("9223372036854775808"),
            Err(IntError::Range)
        );
        assert_eq!(
            parse_int_base10("9223372036854775808x"),
            Err(IntError::Syntax)
        );
        assert_eq!(
            parse_int_base10("99999999999999999999x"),
            Err(IntError::Range)
        );
    }

    #[test]
    fn go_text_matches_pflag() {
        assert_eq!(
            parse_int("abc").unwrap_err().go_text("abc"),
            "strconv.ParseInt: parsing \"abc\": invalid syntax"
        );
        assert_eq!(
            IntError::Range.go_text("999999999999999999999"),
            "strconv.ParseInt: parsing \"999999999999999999999\": value out of range"
        );
    }

    #[test]
    fn atoi_is_plain_decimal() {
        assert_eq!(atoi("016"), Some(16));
        assert_eq!(atoi("+16"), Some(16));
        assert_eq!(atoi("-0"), Some(0));
        for s in ["", " 100", "100 ", "0x400", "1_000", "1e3", "+", "-"] {
            assert_eq!(atoi(s), None, "{s:?}");
        }
        assert_eq!(atoi("99999999999999999999"), None);
    }

    #[test]
    fn parse_bool_is_the_go_set() {
        for s in ["1", "t", "T", "TRUE", "true", "True"] {
            assert_eq!(parse_bool(s), Ok(true));
        }
        for s in ["0", "f", "F", "FALSE", "false", "False"] {
            assert_eq!(parse_bool(s), Ok(false));
        }
        for s in ["", "yes", "tRUE", "on", "2"] {
            assert!(parse_bool(s).is_err(), "{s:?}");
        }
        assert_eq!(
            parse_bool("x").unwrap_err(),
            "strconv.ParseBool: parsing \"x\": invalid syntax"
        );
    }
}
