//! Go の `encoding/json` の `Marshal` と同じ bytes を書く、小さな JSON の値と書き手です。
//! Go の試験が書いた例と一覧を読む、整数だけの小さな読み手 ([`parse`]) も持ちます。
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

/// JSON の text を読みます。数は整数だけを受け付けます。試験の道具が Go の書いた例と一覧を読むための
/// 小さな読み手で、object は鍵の順の [`Json::Obj`] になります。
pub fn parse(src: &[u8]) -> Result<Json, String> {
    let mut r = Reader { s: src, i: 0 };
    let v = r.value()?;
    r.ws();
    if r.i != r.s.len() {
        return Err(format!("trailing data at byte {}", r.i));
    }
    Ok(v)
}

struct Reader<'a> {
    s: &'a [u8],
    i: usize,
}

impl Reader<'_> {
    fn ws(&mut self) {
        while self.s.get(self.i).is_some_and(u8::is_ascii_whitespace) {
            self.i += 1;
        }
    }

    fn err<T>(&self, what: &str) -> Result<T, String> {
        Err(format!("{what} at byte {}", self.i))
    }

    fn lit(&mut self, word: &[u8], v: Json) -> Result<Json, String> {
        if self.s[self.i..].starts_with(word) {
            self.i += word.len();
            Ok(v)
        } else {
            self.err("bad literal")
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        self.ws();
        match self.s.get(self.i) {
            None => self.err("unexpected end"),
            Some(b'n') => self.lit(b"null", Json::Null),
            Some(b't') => self.lit(b"true", Json::Bool(true)),
            Some(b'f') => self.lit(b"false", Json::Bool(false)),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b'[') => {
                self.i += 1;
                let mut items = Vec::new();
                self.ws();
                if self.s.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(Json::Arr(items));
                }
                loop {
                    items.push(self.value()?);
                    self.ws();
                    match self.s.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Json::Arr(items));
                        }
                        _ => return self.err("expected , or ]"),
                    }
                }
            }
            Some(b'{') => {
                self.i += 1;
                let mut m = BTreeMap::new();
                self.ws();
                if self.s.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(Json::Obj(m));
                }
                loop {
                    self.ws();
                    if self.s.get(self.i) != Some(&b'"') {
                        return self.err("expected a key");
                    }
                    let k = self.string()?;
                    self.ws();
                    if self.s.get(self.i) != Some(&b':') {
                        return self.err("expected :");
                    }
                    self.i += 1;
                    let v = self.value()?;
                    m.insert(k, v);
                    self.ws();
                    match self.s.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Json::Obj(m));
                        }
                        _ => return self.err("expected , or }"),
                    }
                }
            }
            Some(b'-' | b'0'..=b'9') => {
                let start = self.i;
                self.i += 1;
                while self.s.get(self.i).is_some_and(u8::is_ascii_digit) {
                    self.i += 1;
                }
                let t = std::str::from_utf8(&self.s[start..self.i]).expect("ASCII digits");
                if t.starts_with('-') {
                    t.parse().map(Json::Int).map_err(|e| e.to_string())
                } else {
                    t.parse().map(Json::Uint).map_err(|e| e.to_string())
                }
            }
            Some(_) => self.err("unexpected byte"),
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let Some(h) = self.s.get(self.i..self.i + 4) else {
            return self.err("short \\u escape");
        };
        let v = std::str::from_utf8(h)
            .ok()
            .and_then(|t| u32::from_str_radix(t, 16).ok());
        let Some(v) = v else {
            return self.err("bad \\u escape");
        };
        self.i += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, String> {
        self.i += 1;
        let mut out = String::new();
        loop {
            let Some(&b) = self.s.get(self.i) else {
                return self.err("unterminated string");
            };
            self.i += 1;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let Some(&e) = self.s.get(self.i) else {
                        return self.err("unterminated escape");
                    };
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let mut c = self.hex4()?;
                            if (0xd800..0xdc00).contains(&c) && self.s[self.i..].starts_with(b"\\u")
                            {
                                self.i += 2;
                                let lo = self.hex4()?;
                                c = 0x10000
                                    + ((c - 0xd800) << 10)
                                    + (lo.wrapping_sub(0xdc00) & 0x3ff);
                            }
                            out.push(char::from_u32(c).unwrap_or('\u{fffd}'));
                        }
                        _ => return self.err("bad escape"),
                    }
                }
                _ => {
                    let start = self.i - 1;
                    let mut end = self.i;
                    while self.s.get(end).is_some_and(|c| *c != b'"' && *c != b'\\') {
                        end += 1;
                    }
                    out.push_str(&lossy(&self.s[start..end]));
                    self.i = end;
                }
            }
        }
    }
}

impl Json {
    /// object の欄です。object でなければ `None` です。
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Obj(m) => m.get(key),
            Self::Struct(f) => f.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// 文字列の値です。
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    /// 0 以上の整数の値です。
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Uint(n) => Some(*n),
            Self::Int(n) => u64::try_from(*n).ok(),
            _ => None,
        }
    }

    /// 真偽の値です。
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// 配列の要素です。
    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Arr(v) => Some(v),
            _ => None,
        }
    }
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
    fn reads_what_it_writes() {
        let v = Json::obj([
            (
                "a",
                Json::Arr(vec![Json::Null, Json::Bool(true), Json::Int(-3)]),
            ),
            ("b", Json::Str("x\u{3042}\"\n<".to_owned())),
            ("c", Json::Uint(7)),
        ]);
        assert_eq!(parse(&v.to_bytes()).unwrap(), v);
        assert_eq!(
            parse(b" { \"k\" : \"\\ud83d\\ude00\" } ").unwrap(),
            Json::obj([("k", Json::Str("\u{1f600}".to_owned()))])
        );
        assert!(parse(b"{\"a\":1,}").is_err());
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
