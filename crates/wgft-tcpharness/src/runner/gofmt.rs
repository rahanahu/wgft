//! 結果の行と観察の文字列が Go の harness と同じになるように、Go の書式を写した関数です。

use std::cmp::Ordering;
use std::fmt::Write as _;

use super::goprint::PRINT;
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

/// Go の `strconv.Quote` です。UTF-8 として読めない byte は `\x` で書き、ASCII でない文字は Go の
/// `strconv.IsPrint` の表 (`goprint.rs`、Go の試験が書いたもの) に入る文字をそのまま、ほかを `\u` か `\U` で
/// 書きます。
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

/// Go の `strconv.IsPrint` です。
fn printable(c: char) -> bool {
    let u = u32::from(c);
    PRINT
        .binary_search_by(|&(lo, hi)| {
            if hi < u {
                Ordering::Less
            } else if lo > u {
                Ordering::Greater
            } else {
                Ordering::Equal
            }
        })
        .is_ok()
}

/// Go の `strconv.FormatFloat(v, 'f', prec, 64)` です。どちらも 2 進の値から正しく丸めます。`prec` が負なら、
/// Go と同じく同じ `f64` に読み戻せる最も短い形で、Rust の `Display` がその形を指数なしで書きます。
pub fn float_f(v: f64, prec: i64) -> String {
    match usize::try_from(prec) {
        Ok(prec) => format!("{v:.prec$}"),
        Err(_) => format!("{v}"),
    }
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

    #[test]
    fn print_table_is_sorted_and_disjoint() {
        for w in PRINT.windows(2) {
            assert!(w[0].0 <= w[0].1 && w[0].1 + 1 < w[1].0, "{w:x?}");
        }
    }

    /// 表が Go の試験が書いたものと同じことを、`vectors.json` の digest (範囲を little endian の u32 の対に
    /// した列の FNV-1a 64) で確かめます。Go の無い環境でも、表を手で直したことが分かります。
    #[test]
    fn print_table_matches_go() {
        use crate::gojson::{self, Json};
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../internal/tcpharness/rustdut/testdata/vectors.json");
        let v = gojson::parse(&std::fs::read(&p).expect("vectors.json")).expect("JSON");
        let print = v.get("print").expect("print");
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &(lo, hi) in PRINT {
            for b in lo.to_le_bytes().into_iter().chain(hi.to_le_bytes()) {
                h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
            }
        }
        assert_eq!(
            print.get("unicode").and_then(Json::as_str),
            Some(super::super::GO_UNICODE_VERSION)
        );
        assert_eq!(
            print.get("ranges").and_then(Json::as_u64),
            u64::try_from(PRINT.len()).ok()
        );
        assert_eq!(
            print.get("fnv64a").and_then(Json::as_str),
            Some(format!("{h:016x}").as_str()),
            "goprint.rs is not the table vectors.json names; run the Go test TestRustVectors with -update"
        );
    }
}
