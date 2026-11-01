//! Go の `encoding/json` と同じ byte 列を書く。
//!
//! Go の `json.Marshal` と `json.Encoder` は、文字列の `<`、`>`、`&`、U+2028、U+2029 を `\u` と 4 桁の 16 進の形で
//! 書く。serde_json は書かないので、文字列の断片だけを置き換える formatter で包む。字下げは
//! `json.MarshalIndent(v, "", "  ")` と `Encoder.SetIndent("", "  ")` に当たる 2 文字の空白だけを持つ。
//! 制御文字の書き方 (`\b`、`\f`、`\n`、`\r`、`\t` と `\u00XX` の小文字の 16 進) は serde_json と Go で
//! 同じである。

use std::io::{self, Write};

use serde::Serialize;
use serde_json::ser::{CompactFormatter, Formatter, PrettyFormatter};

/// Go の書き方で文字列を逃がす formatter。他は中の formatter に任せる。
struct GoEscape<F>(F);

macro_rules! delegate {
    ($($name:ident($($arg:ident: $ty:ty),*);)*) => {
        $(
            fn $name<W: ?Sized + Write>(&mut self, w: &mut W $(, $arg: $ty)*) -> io::Result<()> {
                self.0.$name(w $(, $arg)*)
            }
        )*
    };
}

impl<F: Formatter> Formatter for GoEscape<F> {
    fn write_string_fragment<W: ?Sized + Write>(
        &mut self,
        w: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        let mut start = 0;
        for (i, c) in fragment.char_indices() {
            let esc = match c {
                '<' => "\\u003c",
                '>' => "\\u003e",
                '&' => "\\u0026",
                '\u{2028}' => "\\u2028",
                '\u{2029}' => "\\u2029",
                _ => continue,
            };
            w.write_all(&fragment.as_bytes()[start..i])?;
            w.write_all(esc.as_bytes())?;
            start = i + c.len_utf8();
        }
        w.write_all(&fragment.as_bytes()[start..])
    }

    delegate! {
        begin_array();
        end_array();
        begin_array_value(first: bool);
        end_array_value();
        begin_object();
        end_object();
        begin_object_key(first: bool);
        begin_object_value();
        end_object_value();
    }
}

/// Go の `json.Marshal` と同じ 1 行。改行は付けない。
///
/// # Errors
///
/// 書けない値があれば誤りを返す。
pub fn to_vec_compact<T: Serialize + ?Sized>(v: &T) -> serde_json::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut out, GoEscape(CompactFormatter));
    v.serialize(&mut ser)?;
    Ok(out)
}

/// Go の `json.MarshalIndent(v, "", "  ")` と同じ byte 列。改行は付けない。
///
/// # Errors
///
/// 書けない値があれば誤りを返す。
pub fn to_vec_indent<T: Serialize + ?Sized>(v: &T) -> serde_json::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(
        &mut out,
        GoEscape(PrettyFormatter::with_indent(b"  ")),
    );
    v.serialize(&mut ser)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html_characters_like_go() {
        let v = serde_json::json!({"a": "x<y>&z\u{2028}\u{2029}\n\u{1b}"});
        assert_eq!(
            String::from_utf8(to_vec_compact(&v).unwrap()).unwrap(),
            "{\"a\":\"x\\u003cy\\u003e\\u0026z\\u2028\\u2029\\n\\u001b\"}"
        );
        assert_eq!(
            String::from_utf8(to_vec_indent(&v).unwrap()).unwrap(),
            "{\n  \"a\": \"x\\u003cy\\u003e\\u0026z\\u2028\\u2029\\n\\u001b\"\n}"
        );
    }

    #[test]
    fn empty_containers_are_written_like_go() {
        let v = serde_json::json!({"a": [], "b": {}});
        assert_eq!(
            String::from_utf8(to_vec_indent(&v).unwrap()).unwrap(),
            "{\n  \"a\": [],\n  \"b\": {}\n}"
        );
    }
}
