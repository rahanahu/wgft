//! 行と文と式の構文解析です。Go の `parser` と `exprParser` と同じ規則で、同じ誤りを同じ順に返します。

use std::collections::BTreeMap;

use super::lex::{Tok, Token, lex};
use super::{
    BIND_FIRST, EXPR_VERBS, ErrorKind, Expr, ID_VERBS, Script, ScriptError, Stmt, TMPL_VERBS,
    TmplPart, VERBS,
};
use crate::gojson::{decode_rune, lossy};

struct SrcLine<'a> {
    n: usize,
    indent: usize,
    /// 字下げと注釈を除いた行
    text: &'a [u8],
}

struct Parser<'a> {
    file: &'a str,
    ls: Vec<SrcLine<'a>>,
    i: usize,
    /// 今の行を囲む `if` の数
    depth: usize,
}

/// `if` の中の `if` の段の上限です。Go の `maxIfDepth` と同じ値で、同じ誤りで止めます。
const MAX_IF_DEPTH: usize = 64;
/// 括弧、呼び出し、添字、単項の演算子の入れ子の上限です。Go の `maxExprDepth` と同じ値です。
/// 再帰の深さを入力に依らず抑え、どの入力でも stack が溢れないようにします。
const MAX_EXPR_DEPTH: usize = 128;

pub(super) fn parse(file: &str, src: &[u8]) -> Result<Script, ScriptError> {
    let mut p = Parser {
        file,
        ls: Vec::new(),
        i: 0,
        depth: 0,
    };
    p.lines(src)?;
    p.script()
}

fn err(file: &str, line: usize, kind: ErrorKind, msg: impl Into<String>) -> ScriptError {
    ScriptError {
        file: file.to_owned(),
        line,
        kind,
        msg: msg.into(),
    }
}

/// Go の `unicode.IsSpace` です。
fn is_go_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{85}' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}'
    )
}

/// Go の `strings.TrimSpace` です。UTF-8 として読めない byte は空白として扱いません。
pub(super) fn trim_space(s: &[u8]) -> &[u8] {
    let mut start = 0;
    while let Some((c, n)) = decode_rune(&s[start..])
        && is_go_space(c)
    {
        start += n;
    }
    let mut end = s.len();
    'outer: while end > start {
        // 最後の文字を後ろから探す
        for n in 1..=4.min(end - start) {
            if let Some((c, m)) = decode_rune(&s[end - n..end])
                && m == n
            {
                if is_go_space(c) {
                    end -= n;
                    continue 'outer;
                }
                break 'outer;
            }
        }
        break;
    }
    &s[start..end]
}

fn trim_left_byte(mut s: &[u8], b: u8) -> &[u8] {
    while let [first, rest @ ..] = s
        && *first == b
    {
        s = rest;
    }
    s
}

fn trim_right_bytes<'a>(mut s: &'a [u8], set: &[u8]) -> &'a [u8] {
    while let [rest @ .., last] = s
        && set.contains(last)
    {
        s = rest;
    }
    s
}

/// Go の `strings.Cut(s, " ")` です。
fn cut_space(s: &[u8]) -> (&[u8], &[u8], bool) {
    match s.iter().position(|&b| b == b' ') {
        Some(i) => (&s[..i], &s[i + 1..], true),
        None => (s, &[], false),
    }
}

/// `#` で始まる注釈を文字列の literal の外で切り、行の終わりで literal が閉じていないかを返します。
fn strip_comment(s: &[u8]) -> (&[u8], bool) {
    let mut inside = false;
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'\\' if inside => i += 1,
            b'"' => inside = !inside,
            b'#' if !inside => return (&s[..i], false),
            _ => {}
        }
        i += 1;
    }
    (s, inside)
}

impl<'a> Parser<'a> {
    fn err(&self, line: usize, kind: ErrorKind, msg: impl Into<String>) -> ScriptError {
        err(self.file, line, kind, msg)
    }

    fn lines(&mut self, src: &'a [u8]) -> Result<(), ScriptError> {
        for (i, raw) in src.split(|&b| b == b'\n').enumerate() {
            let raw = trim_right_bytes(raw, b" \t\r");
            if std::str::from_utf8(raw).is_err() {
                return Err(self.err(i + 1, ErrorKind::Layout, "the line is not valid UTF-8"));
            }
            if raw.contains(&b'\t') {
                return Err(self.err(
                    i + 1,
                    ErrorKind::Layout,
                    "tab character; indent with spaces",
                ));
            }
            let (text, open) = strip_comment(raw);
            if open {
                return Err(self.err(
                    i + 1,
                    ErrorKind::Layout,
                    "a string literal is not closed on this line; a \" in what: or got: text needs its pair",
                ));
            }
            let trimmed = trim_left_byte(text, b' ');
            if trim_space(trimmed).is_empty() {
                continue;
            }
            self.ls.push(SrcLine {
                n: i + 1,
                indent: text.len() - trimmed.len(),
                text: trim_right_bytes(trimmed, b" "),
            });
        }
        Ok(())
    }

    fn script(&mut self) -> Result<Script, ScriptError> {
        let Some(l) = self.ls.get(self.i) else {
            return Err(self.err(1, ErrorKind::Header, "empty script"));
        };
        let name = l.text.strip_prefix(b"scenario ").map(trim_space);
        let Some(name) = name.filter(|n| !n.is_empty() && !n.contains(&b' ')) else {
            return Err(self.err(
                l.n,
                ErrorKind::Header,
                "the script starts with: scenario NAME",
            ));
        };
        let name = lossy(name);
        let first = l.n;
        self.i += 1;
        let Some(l) = self.ls.get(self.i) else {
            return Err(self.err(
                first,
                ErrorKind::Header,
                "a refs: line follows the scenario line",
            ));
        };
        let Some(refs) = l.text.strip_prefix(b"refs:") else {
            return Err(self.err(
                l.n,
                ErrorKind::Header,
                "a refs: line follows the scenario line",
            ));
        };
        let refs = lossy(trim_space(refs));
        self.i += 1;
        let mut linux = Vec::new();
        while let Some(l) = self.ls.get(self.i)
            && let Some(kv) = l.text.strip_prefix(b"linux:")
        {
            let kv = trim_space(kv);
            let (k, v) = match kv.iter().position(|&b| b == b'=') {
                Some(i) => (trim_space(&kv[..i]), trim_space(&kv[i + 1..])),
                None => (&[][..], &[][..]),
            };
            if k.is_empty() || v.is_empty() {
                return Err(self.err(l.n, ErrorKind::Header, "a linux: line is linux: PATH=VALUE"));
            }
            linux.push((lossy(k), lossy(v)));
            self.i += 1;
        }
        let (body, end) = self.block()?;
        if let Some(end) = end {
            return Err(self.err(
                self.ls[self.i - 1].n,
                ErrorKind::Block,
                format!("{end} without if"),
            ));
        }
        Ok(Script {
            name,
            refs,
            linux,
            body,
        })
    }

    /// 入力の終わりか、`else` か `end` の行までの文を読みます。`else` と `end` の行は読み進め、2 つ目の値で返します。
    fn block(&mut self) -> Result<(Vec<Stmt>, Option<&'static str>), ScriptError> {
        let mut out = Vec::new();
        while let Some(l) = self.ls.get(self.i) {
            let (verb, rest, _) = cut_space(l.text);
            let end = match verb {
                b"else" => Some("else"),
                b"end" => Some("end"),
                _ => None,
            };
            if let Some(end) = end {
                if !trim_space(rest).is_empty() {
                    return Err(self.err(
                        l.n,
                        ErrorKind::Block,
                        format!("{end} takes nothing after it"),
                    ));
                }
                self.i += 1;
                return Ok((out, Some(end)));
            }
            if l.text.starts_with(b"what:") || l.text.starts_with(b"got:") {
                return Err(self.err(
                    l.n,
                    ErrorKind::Template,
                    "a what: or got: line belongs right after check or require",
                ));
            }
            let at = l.n;
            let mut st = self.stmt(l)?;
            self.i += 1;
            if TMPL_VERBS.contains(&st.verb.as_str()) {
                self.templates(&mut st, at)?;
            }
            if st.verb == "if" {
                if self.depth == MAX_IF_DEPTH {
                    return Err(self.err(
                        at,
                        ErrorKind::Block,
                        format!("if blocks nest deeper than {MAX_IF_DEPTH}"),
                    ));
                }
                self.depth += 1;
                let (then, end) = self.block()?;
                st.then = then;
                match end {
                    Some("else") => {
                        let (els, end2) = self.block()?;
                        if end2 != Some("end") {
                            return Err(self.err(at, ErrorKind::Block, "if without end"));
                        }
                        st.els = els;
                    }
                    Some("end") => {}
                    _ => return Err(self.err(at, ErrorKind::Block, "if without end")),
                }
                self.depth -= 1;
            }
            out.push(st);
        }
        Ok((out, None))
    }

    fn templates(&mut self, st: &mut Stmt, at: usize) -> Result<(), ScriptError> {
        for key in ["what:", "got:"] {
            let Some(l) = self.ls.get(self.i) else {
                return Err(self.err(
                    at,
                    ErrorKind::Template,
                    format!("{} needs a {key} line", st.verb),
                ));
            };
            let text = match l.text.strip_prefix(key.as_bytes()) {
                Some(t) if l.indent > 0 => t,
                _ => {
                    return Err(self.err(
                        l.n,
                        ErrorKind::Template,
                        format!("{} needs an indented {key} line", st.verb),
                    ));
                }
            };
            let text = text.strip_prefix(b" ").unwrap_or(text);
            let t = parse_template(text).map_err(|e| self.err(l.n, ErrorKind::Template, e))?;
            if key == "what:" {
                st.what = t;
            } else {
                st.got = t;
            }
            self.i += 1;
        }
        Ok(())
    }

    fn stmt(&self, l: &SrcLine<'_>) -> Result<Stmt, ScriptError> {
        let (verb, rest, _) = cut_space(l.text);
        let mut rest = trim_left_byte(rest, b' ');
        let verb_s = lossy(verb);
        if !VERBS.contains(&verb_s.as_str()) {
            return Err(self.err(
                l.n,
                ErrorKind::UnknownStatement,
                format!("unknown statement {verb_s:?}"),
            ));
        }
        let mut st = Stmt::new(l.n, verb_s);
        let syntax = |msg: String| self.err(l.n, ErrorKind::Syntax, msg);
        let verb = st.verb.as_str();
        if ID_VERBS.contains(&verb) {
            let (id, r, _) = cut_space(rest);
            if id.is_empty() {
                return Err(syntax(format!("{verb} needs an ID")));
            }
            st.id = Some(lossy(id));
            rest = trim_left_byte(r, b' ');
        }
        match verb {
            "stop" => {
                if !rest.is_empty() {
                    return Err(syntax("stop takes nothing after it".to_owned()));
                }
                return Ok(st);
            }
            "log" => {
                st.what =
                    parse_template(rest).map_err(|e| self.err(l.n, ErrorKind::Template, e))?;
                return Ok(st);
            }
            _ => {}
        }
        let toks = lex(rest).map_err(syntax)?;
        let mut ep = ExprParser::new(&toks);
        if verb == "let" || verb == "set" {
            let target = ep.target(verb == "set").map_err(syntax)?;
            if !ep.accept("=") {
                return Err(syntax(format!("{verb} {target} needs = and an expression")));
            }
            let e = ep.full().map_err(syntax)?;
            st.bind = Some(target);
            st.args = vec![e];
            return Ok(st);
        }
        if EXPR_VERBS.contains(&verb) {
            st.args = vec![ep.full().map_err(syntax)?];
            return Ok(st);
        }
        while !ep.done() && !ep.peek("->") {
            if ep.named_ahead() {
                let name = ep.next().text.clone();
                ep.next(); // =
                if ep.done() || ep.toks[ep.i].space {
                    return Err(syntax(format!(
                        "{name}= is followed by its value with no space"
                    )));
                }
                let e = ep.atom().map_err(syntax)?;
                if st.named.contains_key(&name) {
                    return Err(self.err(
                        l.n,
                        ErrorKind::NamedArgument,
                        format!("{name}= given twice"),
                    ));
                }
                st.named.insert(name, e);
                continue;
            }
            if !st.named.is_empty() {
                return Err(self.err(
                    l.n,
                    ErrorKind::NamedArgument,
                    "a positional argument after a named one",
                ));
            }
            st.args.push(ep.atom().map_err(syntax)?);
        }
        if ep.accept("->") {
            let bind_err = || self.err(l.n, ErrorKind::Bind, "-> is followed by one name");
            if ep.done() {
                return Err(bind_err());
            }
            let t = ep.next();
            if t.kind != Tok::Ident || !ep.done() {
                return Err(bind_err());
            }
            st.bind = Some(t.text.clone());
        }
        if BIND_FIRST.contains(&verb) && !matches!(st.args.first(), Some(Expr::Name(_))) {
            return Err(self.err(
                l.n,
                ErrorKind::Bind,
                format!("{verb} binds its first argument, which is a name"),
            ));
        }
        Ok(st)
    }
}

/// template を文の部分と `{式}` の部分に分けます。`{{` と `}}` は括弧そのものです。
pub(super) fn parse_template(text: &[u8]) -> Result<Vec<TmplPart>, String> {
    let mut out = Vec::new();
    let mut lit = Vec::new();
    let mut i = 0;
    while i < text.len() {
        let c = text[i];
        let next = text.get(i + 1).copied();
        if (c == b'{' && next == Some(b'{')) || (c == b'}' && next == Some(b'}')) {
            lit.push(c);
            i += 2;
            continue;
        }
        match c {
            b'}' => return Err("a } without {".to_owned()),
            b'{' => {
                let Some(end) = matching_brace(text, i) else {
                    return Err("a { without }".to_owned());
                };
                let toks = lex(&text[i + 1..end])?;
                let e = ExprParser::new(&toks).full()?;
                if !lit.is_empty() {
                    out.push(TmplPart::Text(lossy(&lit)));
                    lit.clear();
                }
                out.push(TmplPart::Expr(e));
                i = end + 1;
            }
            _ => {
                lit.push(c);
                i += 1;
            }
        }
    }
    if !lit.is_empty() {
        out.push(TmplPart::Text(lossy(&lit)));
    }
    Ok(out)
}

/// `i` の `{` を閉じる `}` の位置を、文字列の literal を飛ばして探します。
fn matching_brace(s: &[u8], i: usize) -> Option<usize> {
    let mut inside = false;
    let mut j = i + 1;
    while j < s.len() {
        match s[j] {
            b'\\' if inside => j += 1,
            b'"' => inside = !inside,
            b'}' if !inside => return Some(j),
            _ => {}
        }
        j += 1;
    }
    None
}

const CMP_OPS: [&str; 6] = ["==", "!=", "<=", ">=", "<", ">"];

struct ExprParser<'t> {
    toks: &'t [Token],
    i: usize,
    depth: usize,
}

fn bin(op: &'static str, l: Expr, r: Expr) -> Expr {
    Expr::Bin {
        op,
        l: Box::new(l),
        r: Box::new(r),
    }
}

impl<'t> ExprParser<'t> {
    fn new(toks: &'t [Token]) -> Self {
        Self {
            toks,
            i: 0,
            depth: 0,
        }
    }

    /// 入れ子を 1 段数えて `f` を呼びます。上限を超えれば誤りです。
    fn nested<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T, String>) -> Result<T, String> {
        if self.depth == MAX_EXPR_DEPTH {
            return Err(format!("the expression nests deeper than {MAX_EXPR_DEPTH}"));
        }
        self.depth += 1;
        let r = f(self);
        self.depth -= 1;
        r
    }

    fn done(&self) -> bool {
        self.i >= self.toks.len()
    }

    fn next(&mut self) -> &'t Token {
        let t = &self.toks[self.i];
        self.i += 1;
        t
    }

    fn peek(&self, op: &str) -> bool {
        self.toks.get(self.i).is_some_and(|t| t.is_op(op))
    }

    fn peek_kind(&self, kind: Tok) -> bool {
        self.toks.get(self.i).is_some_and(|t| t.kind == kind)
    }

    fn accept(&mut self, op: &str) -> bool {
        let ok = self.peek(op);
        if ok {
            self.i += 1;
        }
        ok
    }

    /// 次が空白を挟まない `名前=` で、名前つきの引数の始まりかを返します。
    fn named_ahead(&self) -> bool {
        matches!(self.toks.get(self.i..self.i + 2), Some([a, b])
            if a.kind == Tok::Ident && b.is_op("=") && !b.space)
    }

    /// `let` の左辺 (名前) か `set` の左辺 (`名前.欄`) を読みます。
    fn target(&mut self, field: bool) -> Result<String, String> {
        if !self.peek_kind(Tok::Ident) {
            return Err("a name is expected".to_owned());
        }
        let name = self.next().text.clone();
        if !field {
            return Ok(name);
        }
        if !self.accept(".") || !self.peek_kind(Tok::Ident) {
            return Err("set takes NAME.FIELD".to_owned());
        }
        Ok(format!("{name}.{}", self.next().text))
    }

    /// 残りの字句のすべてを 1 つの式として読みます。
    fn full(&mut self) -> Result<Expr, String> {
        let e = self.or()?;
        if let Some(t) = self.toks.get(self.i) {
            return Err(format!("unexpected {:?} after the expression", t.text));
        }
        Ok(e)
    }

    /// 1 つの引数を読みます。括弧の外に空白を持たない式です。
    fn atom(&mut self) -> Result<Expr, String> {
        let start = self.i;
        let mut end = self.i;
        let mut depth = 0_i32;
        while let Some(t) = self.toks.get(end) {
            if end > start && t.space && depth == 0 {
                break;
            }
            if t.kind == Tok::Op {
                match t.text.as_str() {
                    "(" | "[" => depth += 1,
                    ")" | "]" => depth -= 1,
                    "->" if depth == 0 => break,
                    _ => {}
                }
            }
            end += 1;
        }
        let e = ExprParser::new(&self.toks[start..end]).full()?;
        self.i = end;
        Ok(e)
    }

    fn or(&mut self) -> Result<Expr, String> {
        self.nested(|p| {
            let mut l = p.and()?;
            while p.accept("||") {
                l = bin("||", l, p.and()?);
            }
            Ok(l)
        })
    }

    fn and(&mut self) -> Result<Expr, String> {
        let mut l = self.not()?;
        while self.accept("&&") {
            l = bin("&&", l, self.not()?);
        }
        Ok(l)
    }

    fn not(&mut self) -> Result<Expr, String> {
        if self.accept("!") {
            let x = self.nested(Self::not)?;
            return Ok(Expr::Un {
                op: "!",
                x: Box::new(x),
            });
        }
        self.cmp()
    }

    fn cmp(&mut self) -> Result<Expr, String> {
        let l = self.bitor()?;
        let Some(op) = CMP_OPS.into_iter().find(|op| self.peek(op)) else {
            return Ok(l);
        };
        self.i += 1;
        let r = self.bitor()?;
        if CMP_OPS.iter().any(|op| self.peek(op)) {
            return Err("comparisons do not chain; use &&".to_owned());
        }
        Ok(bin(op, l, r))
    }

    fn bitor(&mut self) -> Result<Expr, String> {
        let mut l = self.add()?;
        while self.accept("|") {
            l = bin("|", l, self.add()?);
        }
        Ok(l)
    }

    fn add(&mut self) -> Result<Expr, String> {
        let mut l = self.mul()?;
        while let Some(op) = ["+", "-"].into_iter().find(|op| self.peek(op)) {
            self.i += 1;
            l = bin(op, l, self.mul()?);
        }
        Ok(l)
    }

    fn mul(&mut self) -> Result<Expr, String> {
        let mut l = self.unary()?;
        while let Some(op) = ["*", "/", "%"].into_iter().find(|op| self.peek(op)) {
            self.i += 1;
            l = bin(op, l, self.unary()?);
        }
        Ok(l)
    }

    fn unary(&mut self) -> Result<Expr, String> {
        if self.accept("-") {
            let x = self.nested(Self::unary)?;
            return Ok(Expr::Un {
                op: "-",
                x: Box::new(x),
            });
        }
        self.postfix()
    }

    fn postfix(&mut self) -> Result<Expr, String> {
        let mut x = self.primary()?;
        loop {
            if self.accept(".") {
                if !self.peek_kind(Tok::Ident) {
                    return Err("a field name follows the dot".to_owned());
                }
                x = Expr::Field {
                    of: Box::new(x),
                    name: self.next().text.clone(),
                };
            } else if self.accept("[") {
                let lo = if self.peek(":") {
                    None
                } else {
                    Some(Box::new(self.or()?))
                };
                if self.accept(":") {
                    let hi = if self.peek("]") {
                        None
                    } else {
                        Some(Box::new(self.or()?))
                    };
                    if !self.accept("]") {
                        return Err("] expected".to_owned());
                    }
                    x = Expr::Slice {
                        of: Box::new(x),
                        lo,
                        hi,
                    };
                    continue;
                }
                let (true, Some(index)) = (self.accept("]"), lo) else {
                    return Err("] expected".to_owned());
                };
                x = Expr::Index {
                    of: Box::new(x),
                    index,
                };
            } else {
                return Ok(x);
            }
        }
    }

    fn primary(&mut self) -> Result<Expr, String> {
        if self.done() {
            return Err("an expression is expected".to_owned());
        }
        let t = self.next();
        match t.kind {
            Tok::Int => Ok(Expr::Int(t.val)),
            Tok::Dur => Ok(Expr::Dur(t.val)),
            Tok::Str => Ok(Expr::Str(t.bytes.clone())),
            Tok::Ident => {
                if !self.accept("(") {
                    return Ok(Expr::Name(t.text.clone()));
                }
                let name = &t.text;
                let mut args = Vec::new();
                let mut named = BTreeMap::new();
                while !self.accept(")") {
                    if args.len() + named.len() > 0 && !self.accept(",") {
                        return Err(format!(", or ) expected in the call of {name}"));
                    }
                    if self.named_ahead() {
                        let n = self.next().text.clone();
                        self.next();
                        if self.done() || self.toks[self.i].space {
                            return Err(format!("{n}= is followed by its value with no space"));
                        }
                        if named.contains_key(&n) {
                            return Err(format!("{n}= given twice in the call of {name}"));
                        }
                        let e = self.or()?;
                        named.insert(n, e);
                        continue;
                    }
                    if !named.is_empty() {
                        return Err(format!(
                            "a positional argument after a named one in the call of {name}"
                        ));
                    }
                    args.push(self.or()?);
                }
                Ok(Expr::Call {
                    name: name.clone(),
                    args,
                    named,
                })
            }
            Tok::Op if t.text == "(" => {
                let e = self.or()?;
                if !self.accept(")") {
                    return Err(") expected".to_owned());
                }
                Ok(e)
            }
            Tok::Op => Err(format!("unexpected {:?}", t.text)),
        }
    }
}
