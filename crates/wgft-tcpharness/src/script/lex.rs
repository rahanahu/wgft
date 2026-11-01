//! 式の字句の解析です。Go の `lex` と同じ規則です。

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Tok {
    Int,
    Dur,
    Str,
    Ident,
    Op,
}

#[derive(Debug, Clone)]
pub(super) struct Token {
    pub(super) kind: Tok,
    /// 元の字句 (名前と演算子は ASCII)
    pub(super) text: String,
    pub(super) val: i64,
    pub(super) bytes: Vec<u8>,
    /// 前に空白があったか
    pub(super) space: bool,
}

impl Token {
    pub(super) fn is_op(&self, op: &str) -> bool {
        self.kind == Tok::Op && self.text == op
    }
}

/// 長いものから試す演算子の列です。Go の `ops` と同じ順です。
const OPS: &[&str] = &[
    "||", "&&", "==", "!=", "<=", ">=", "->", "<", ">", "!", "|", "+", "-", "*", "/", "%", "(",
    ")", "[", "]", ",", ".", "=", ":",
];

const DUR_UNITS: &[(&[u8], i64)] = &[
    (b"ns", 1),
    (b"us", 1_000),
    (b"ms", 1_000_000),
    (b"s", 1_000_000_000),
];

/// 1 つの文か 1 つの `{式}` の字句の数の上限です。Go の `maxTokens` と同じ値です。`a + b + ...` の構文木の
/// 深さを抑え、構文木をたどる再帰が stack を溢れさせないようにします。
const MAX_TOKENS: usize = 256;

pub(super) fn is_ident_byte(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphabetic()
}

fn text(s: &[u8]) -> String {
    crate::gojson::lossy(s)
}

#[expect(
    clippy::many_single_char_names,
    reason = "the names follow the Go lexer, so the two read side by side"
)]
pub(super) fn lex(s: &[u8]) -> Result<Vec<Token>, String> {
    let mut out = Vec::new();
    let mut space = false;
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if c == b' ' {
            space = true;
            i += 1;
            continue;
        }
        if c.is_ascii_digit() {
            let hex = s[i..].starts_with(b"0x");
            let mut j = if hex { i + 2 } else { i };
            while j < s.len()
                && (if hex {
                    s[j].is_ascii_hexdigit()
                } else {
                    s[j].is_ascii_digit()
                })
            {
                j += 1;
            }
            let digits =
                std::str::from_utf8(&s[if hex { i + 2 } else { i }..j]).expect("ASCII digits");
            let v = i64::from_str_radix(digits, if hex { 16 } else { 10 })
                .ok()
                .ok_or_else(|| format!("bad number {:?}", text(&s[i..j])))?;
            let mut kind = Tok::Int;
            let mut val = v;
            for &(name, ns) in DUR_UNITS {
                let rest = &s[j..];
                if rest.starts_with(name) && rest.get(name.len()).is_none_or(|&b| !is_ident_byte(b))
                {
                    if v > i64::MAX / ns {
                        return Err(format!(
                            "duration {}{} overflows",
                            text(&s[i..j]),
                            text(name)
                        ));
                    }
                    kind = Tok::Dur;
                    val = v * ns;
                    j += name.len();
                    break;
                }
            }
            if j < s.len() && is_ident_byte(s[j]) {
                return Err(format!("bad number {:?}", text(&s[i..=j])));
            }
            out.push(Token {
                kind,
                text: text(&s[i..j]),
                val,
                bytes: Vec::new(),
                space,
            });
            i = j;
        } else if c == b'"' {
            let (b, n) = lex_string(&s[i..])?;
            out.push(Token {
                kind: Tok::Str,
                text: text(&s[i..i + n]),
                val: 0,
                bytes: b,
                space,
            });
            i += n;
        } else if is_ident_byte(c) {
            let mut j = i;
            while j < s.len() && (is_ident_byte(s[j]) || s[j].is_ascii_digit()) {
                j += 1;
            }
            out.push(Token {
                kind: Tok::Ident,
                text: text(&s[i..j]),
                val: 0,
                bytes: Vec::new(),
                space,
            });
            i = j;
        } else {
            let Some(op) = OPS.iter().find(|op| s[i..].starts_with(op.as_bytes())) else {
                return Err(format!("unexpected character {:?}", char::from(c)));
            };
            out.push(Token {
                kind: Tok::Op,
                text: (*op).to_owned(),
                val: 0,
                bytes: Vec::new(),
                space,
            });
            i += op.len();
        }
        space = false;
        if out.len() > MAX_TOKENS {
            return Err(format!("more than {MAX_TOKENS} tokens"));
        }
    }
    Ok(out)
}

/// `s` の先頭の文字列の literal を読み、その bytes と literal の長さを返します。
#[expect(
    clippy::many_single_char_names,
    reason = "the names follow the Go lexer, so the two read side by side"
)]
fn lex_string(s: &[u8]) -> Result<(Vec<u8>, usize), String> {
    let mut b = Vec::new();
    let mut i = 1;
    while i < s.len() {
        match s[i] {
            b'"' => return Ok((b, i + 1)),
            b'\\' => {
                if i + 1 >= s.len() {
                    return Err("unterminated string".to_owned());
                }
                i += 1;
                match s[i] {
                    c @ (b'\\' | b'"') => b.push(c),
                    b'n' => b.push(b'\n'),
                    b't' => b.push(b'\t'),
                    b'x' => {
                        if i + 2 >= s.len() {
                            return Err("bad \\x escape".to_owned());
                        }
                        let (h, l) = (s[i + 1], s[i + 2]);
                        let (Some(h), Some(l)) = (hex_val(h), hex_val(l)) else {
                            return Err("bad \\x escape".to_owned());
                        };
                        b.push(h << 4 | l);
                        i += 2;
                    }
                    c => return Err(format!("unknown escape \\{}", char::from(c))),
                }
            }
            c => b.push(c),
        }
        i += 1;
    }
    Err("unterminated string".to_owned())
}

fn hex_val(c: u8) -> Option<u8> {
    char::from(c)
        .to_digit(16)
        .and_then(|d| u8::try_from(d).ok())
}
