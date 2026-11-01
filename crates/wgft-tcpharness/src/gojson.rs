//! Go の `encoding/json` の `Marshal` と同じ bytes を書く、小さな JSON の値と書き手です。
//!
//! Go の構文解析器の fixture は `json.Marshal` が書いたもので、Rust の側は同じ bytes を作って比べます。
//! そのため、Go の規則をそのまま写します。
//!
//! - object の鍵は byte の順に並べます (Go は map の鍵を並べて書きます)
//! - 文字列は `"` と `\` と制御文字を escape し、`\b`、`\f`、`\n`、`\r`、`\t` 以外の制御文字は `\u00XX` にします
//! - HTML に安全でない `<`、`>`、`&` と、U+2028、U+2029 も `\uXXXX` にします
//! - UTF-8 として読めない byte は 1 byte ごとに `�` にします

use std::collections::BTreeMap;

/// JSON の値です。object は鍵の順に並ぶ [`BTreeMap`] で持ちます。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
    /// 鍵を書いた順に並べる object です。Go の struct の欄の順に当たります
    Struct(Vec<(String, Json)>),
}

impl Json {
    /// 鍵と値の組から object を作ります。
    pub fn obj<const N: usize>(pairs: [(&str, Json); N]) -> Self {
        Self::Obj(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
    }

    /// 欄の順を保つ object を作ります。
    pub fn fields<const N: usize>(pairs: [(&str, Json); N]) -> Self {
        Self::Struct(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
    }

    /// 空白の無い 1 行の JSON にします。Go の `json.Marshal` の出力と同じ bytes です。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Self::Null => out.extend_from_slice(b"null"),
            Self::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
            Self::Int(n) => out.extend_from_slice(n.to_string().as_bytes()),
            Self::Uint(n) => out.extend_from_slice(n.to_string().as_bytes()),
            Self::Str(s) => write_string(out, s.as_bytes()),
            Self::Arr(items) => {
                out.push(b'[');
                for (i, v) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    v.write(out);
                }
                out.push(b']');
            }
            Self::Obj(m) => write_object(out, m.iter()),
            Self::Struct(fields) => write_object(out, fields.iter().map(|(k, v)| (k, v))),
        }
    }
}

fn write_object<'a>(out: &mut Vec<u8>, pairs: impl Iterator<Item = (&'a String, &'a Json)>) {
    out.push(b'{');
    for (i, (k, v)) in pairs.enumerate() {
        if i > 0 {
            out.push(b',');
        }
        write_string(out, k.as_bytes());
        out.push(b':');
        v.write(out);
    }
    out.push(b'}');
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Go の `encoding/json` の `appendString` (HTML の escape あり) と同じ規則で、文字列を書きます。
#[expect(
    clippy::many_single_char_names,
    reason = "the names follow the Go encoder, so the two read side by side"
)]
pub fn write_string(out: &mut Vec<u8>, s: &[u8]) {
    out.push(b'"');
    let mut i = 0;
    while i < s.len() {
        let b = s[i];
        if b < 0x80 {
            match b {
                b'"' => out.extend_from_slice(b"\\\""),
                b'\\' => out.extend_from_slice(b"\\\\"),
                0x08 => out.extend_from_slice(b"\\b"),
                0x0c => out.extend_from_slice(b"\\f"),
                b'\n' => out.extend_from_slice(b"\\n"),
                b'\r' => out.extend_from_slice(b"\\r"),
                b'\t' => out.extend_from_slice(b"\\t"),
                b'<' | b'>' | b'&' | 0x00..0x20 => {
                    out.extend_from_slice(b"\\u00");
                    out.push(HEX[usize::from(b >> 4)]);
                    out.push(HEX[usize::from(b & 0xf)]);
                }
                _ => out.push(b),
            }
            i += 1;
            continue;
        }
        let Some((c, n)) = decode_rune(&s[i..]) else {
            out.extend_from_slice(b"\\ufffd");
            i += 1;
            continue;
        };
        match c {
            '\u{2028}' => out.extend_from_slice(b"\\u2028"),
            '\u{2029}' => out.extend_from_slice(b"\\u2029"),
            _ => out.extend_from_slice(&s[i..i + n]),
        }
        i += n;
    }
    out.push(b'"');
}

/// `s` の先頭の 1 文字と、その byte 数を返します。UTF-8 として読めなければ `None` で、Go の
/// `utf8.DecodeRune` が `(RuneError, 1)` を返す場合に当たります。
pub(crate) fn decode_rune(s: &[u8]) -> Option<(char, usize)> {
    let n = match *s.first()? {
        0x00..0x80 => 1,
        0xc2..0xe0 => 2,
        0xe0..0xf0 => 3,
        0xf0..0xf5 => 4,
        _ => return None,
    };
    let head = s.get(..n)?;
    let c = std::str::from_utf8(head).ok()?.chars().next()?;
    Some((c, n))
}

/// bytes を文字列にします。UTF-8 として読めない byte は 1 byte ごとに U+FFFD にします。Go の
/// `encoding/json` が書く文字列と同じ値になります (Rust の `from_utf8_lossy` は続く byte をまとめて 1 つにします)。
pub fn lossy(s: &[u8]) -> String {
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if let Some((c, n)) = decode_rune(&s[i..]) {
            out.push(c);
            i += n;
        } else {
            out.push('\u{fffd}');
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_like_go() {
        let mut out = Vec::new();
        write_string(
            &mut out,
            b"a<b>&\"\\\x08\x0c\n\r\t\x01\x7f\xe2\x80\xa8\xe2\x80\xa9\xff\xe3\x81\x82",
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "\"a\\u003cb\\u003e\\u0026\\\"\\\\\\b\\f\\n\\r\\t\\u0001\x7f\\u2028\\u2029\\ufffd\u{3042}\""
        );
    }

    #[test]
    fn lossy_replaces_each_byte() {
        assert_eq!(lossy(b"a\xe2\x80b\xff"), "a\u{fffd}\u{fffd}b\u{fffd}");
        // surrogate は Go と同じく読めない
        assert_eq!(lossy(b"\xed\xa0\x80"), "\u{fffd}\u{fffd}\u{fffd}");
    }

    #[test]
    fn sorted_keys() {
        let v = Json::obj([
            ("b", Json::Int(-1)),
            ("a", Json::Arr(vec![Json::Null, Json::Uint(u64::MAX)])),
        ]);
        assert_eq!(
            v.to_bytes(),
            b"{\"a\":[null,18446744073709551615],\"b\":-1}"
        );
    }
}
