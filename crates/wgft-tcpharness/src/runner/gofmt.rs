//! 結果の行と観察の文字列が Go の harness と同じになるように、Go の書式を写した関数です。

use std::fmt::Write as _;

use crate::gojson::decode_rune;

/// Go の `time.Duration.String` です (`1.5s`、`300ms`、`2m0s`、`0s`)。`ns` は nanosecond です。
pub fn duration(ns: i64) -> String {
    let neg = ns < 0;
    let mut u = ns.unsigned_abs();
    let mut out = String::new();
    if u < 1_000_000_000 {
        let (prec, unit) = match u {
            0 => return "0s".to_owned(),
            1..1_000 => (0, "ns"),
            1_000..1_000_000 => (3, "\u{b5}s"),
            _ => (6, "ms"),
        };
        let (frac, rest) = frac_part(u, prec);
        u = rest;
        let _ = write!(out, "{u}{frac}{unit}");
    } else {
        let (frac, rest) = frac_part(u, 9);
        u = rest;
        let secs = u % 60;
        u /= 60;
        if u > 0 {
            let mins = u % 60;
            u /= 60;
            if u > 0 {
                let _ = write!(out, "{u}h");
            }
            let _ = write!(out, "{mins}m");
        }
        let _ = write!(out, "{secs}{frac}s");
    }
    if neg {
        out.insert(0, '-');
    }
    out
}

/// Go の `fmtFrac` です。`v / 10^prec` の小数部を、末尾の 0 を落として `.123` の形で返します。小数部が 0 なら
/// 点も書きません。
fn frac_part(mut v: u64, prec: u32) -> (String, u64) {
    let mut digits = Vec::new();
    let mut print = false;
    for _ in 0..prec {
        let d = v % 10;
        print = print || d != 0;
        if print {
            digits.push(char::from(b'0' + u8::try_from(d).expect("a digit")));
        }
        v /= 10;
    }
    if !print {
        return (String::new(), v);
    }
    digits.reverse();
    (format!(".{}", digits.into_iter().collect::<String>()), v)
}

/// Go の `strconv.Quote` です。ASCII と UTF-8 として読めない byte は Go と同じに書きます。
/// ASCII でない文字は、制御文字、空白、私用の領域、U+00AD を `\u` で書き、ほかはそのまま書きます。Go の
/// `unicode.IsPrint` の表の写しではないので、ASCII でない文字では Go と違いうります (設計の 9 節)。
pub fn quote(s: &[u8]) -> String {
    let mut out = String::from("\"");
    let mut i = 0;
    while i < s.len() {
        let Some((c, n)) = decode_rune(&s[i..]) else {
            let _ = write!(out, "\\x{:02x}", s[i]);
            i += 1;
            continue;
        };
        i += n;
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ' '..='~' => out.push(c),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            '\0'..='\u{1f}' | '\u{7f}' => {
                let _ = write!(out, "\\x{:02x}", u32::from(c));
            }
            c if printable(c) => out.push(c),
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

fn printable(c: char) -> bool {
    let u = u32::from(c);
    !(c.is_control()
        || c.is_whitespace()
        || u == 0xad
        || (0xe000..=0xf8ff).contains(&u)
        || (0xfff9..=0xfffb).contains(&u)
        || (0x200b..=0x200f).contains(&u)
        || (0x2060..=0x2064).contains(&u)
        || u == 0xfeff
        || u >= 0xf0000)
}

/// Go の `strconv.FormatFloat(v, 'f', prec, 64)` です。どちらも 2 進の値から正しく丸めます。
pub fn float_f(v: f64, prec: usize) -> String {
    format!("{v:.prec$}")
}

/// Go の `% x` です。byte を空白で区切った 16 進で書きます。
pub(crate) fn hex_spaced(b: &[u8]) -> String {
    let parts: Vec<String> = b.iter().map(|x| format!("{x:02x}")).collect();
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_like_go() {
        let ms = 1_000_000;
        assert_eq!(duration(0), "0s");
        assert_eq!(duration(1), "1ns");
        assert_eq!(duration(1_500), "1.5\u{b5}s");
        assert_eq!(duration(30 * ms), "30ms");
        assert_eq!(duration(1_500 * ms), "1.5s");
        assert_eq!(duration(35_000 * ms), "35s");
        assert_eq!(duration(120_000 * ms), "2m0s");
        assert_eq!(duration(3_723_000 * ms + 1), "1h2m3.000000001s");
        assert_eq!(duration(-2 * ms), "-2ms");
    }

    #[test]
    fn quote_like_go() {
        assert_eq!(quote(b"more"), "\"more\"");
        assert_eq!(
            quote(b"a\"\\\n\x00\x7f\xff"),
            "\"a\\\"\\\\\\n\\x00\\x7f\\xff\""
        );
        assert_eq!(quote("\u{e9}\u{a0}".as_bytes()), "\"\u{e9}\\u00a0\"");
    }
}
