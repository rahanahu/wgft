//! 正規化した構文木です。Go の `ScriptAST` と同じ値を作り、[`Json::to_bytes`] で同じ bytes になります。

use std::collections::BTreeMap;

use super::{Expr, Script, ScriptError, Stmt, TmplPart};
use crate::gojson::Json;

impl Script {
    /// 正規化した構文木です。Go の `ScriptAST` です。
    pub fn ast(&self) -> Json {
        let linux = self
            .linux
            .iter()
            .map(|(k, v)| Json::Arr(vec![Json::Str(k.clone()), Json::Str(v.clone())]))
            .collect();
        Json::obj([
            ("scenario", Json::Str(self.name.clone())),
            ("refs", Json::Str(self.refs.clone())),
            ("linux", Json::Arr(linux)),
            ("body", stmts(&self.body)),
        ])
    }
}

impl ScriptError {
    /// 誤りの fixture の値です。行と種類だけを持ちます。
    pub fn ast(&self) -> Json {
        Json::obj([(
            "error",
            Json::obj([
                ("line", Json::Uint(self.line as u64)),
                ("kind", Json::Str(self.kind.as_str().to_owned())),
            ]),
        )])
    }
}

fn stmts(body: &[Stmt]) -> Json {
    Json::Arr(body.iter().map(stmt).collect())
}

fn stmt(st: &Stmt) -> Json {
    let mut m = BTreeMap::new();
    m.insert("line".to_owned(), Json::Uint(st.line as u64));
    m.insert("verb".to_owned(), Json::Str(st.verb.clone()));
    if let Some(id) = &st.id {
        m.insert("id".to_owned(), Json::Str(id.clone()));
    }
    if !st.args.is_empty() {
        m.insert("args".to_owned(), exprs(&st.args));
    }
    if !st.named.is_empty() {
        m.insert("named".to_owned(), named(&st.named));
    }
    if let Some(b) = &st.bind {
        m.insert("bind".to_owned(), Json::Str(b.clone()));
    }
    if st.verb == "if" {
        m.insert("then".to_owned(), stmts(&st.then));
        if !st.els.is_empty() {
            m.insert("else".to_owned(), stmts(&st.els));
        }
    }
    if !st.what.is_empty() {
        m.insert("what".to_owned(), tmpl(&st.what));
    }
    if !st.got.is_empty() {
        m.insert("got".to_owned(), tmpl(&st.got));
    }
    Json::Obj(m)
}

fn tmpl(parts: &[TmplPart]) -> Json {
    Json::Arr(
        parts
            .iter()
            .map(|p| match p {
                TmplPart::Text(t) => Json::obj([("text", Json::Str(t.clone()))]),
                TmplPart::Expr(e) => Json::obj([("expr", expr(e))]),
            })
            .collect(),
    )
}

fn exprs(es: &[Expr]) -> Json {
    Json::Arr(es.iter().map(expr).collect())
}

fn named(m: &BTreeMap<String, Expr>) -> Json {
    Json::Obj(m.iter().map(|(k, e)| (k.clone(), expr(e))).collect())
}

fn opt(e: Option<&Expr>) -> Json {
    e.map_or(Json::Null, expr)
}

/// 整数は 10 進の文字列で書きます。UTF-8 でない文字列の literal は 16 進で書きます。
fn expr(e: &Expr) -> Json {
    match e {
        Expr::Int(n) => Json::obj([("int", Json::Str(n.to_string()))]),
        Expr::Dur(n) => Json::obj([("dur", Json::Str(n.to_string()))]),
        Expr::Str(b) => match std::str::from_utf8(b) {
            Ok(s) => Json::obj([("str", Json::Str(s.to_owned()))]),
            Err(_) => Json::obj([("hex", Json::Str(hex(b)))]),
        },
        Expr::Name(n) => Json::obj([("name", Json::Str(n.clone()))]),
        Expr::Call {
            name,
            args,
            named: n,
        } => {
            let mut m = BTreeMap::new();
            m.insert("call".to_owned(), Json::Str(name.clone()));
            m.insert("args".to_owned(), exprs(args));
            if !n.is_empty() {
                m.insert("named".to_owned(), named(n));
            }
            Json::Obj(m)
        }
        Expr::Field { of, name } => {
            Json::obj([("field", Json::Str(name.clone())), ("of", expr(of))])
        }
        Expr::Index { of, index } => Json::obj([("index", expr(index)), ("of", expr(of))]),
        Expr::Slice { of, lo, hi } => Json::obj([
            (
                "slice",
                Json::Arr(vec![opt(lo.as_deref()), opt(hi.as_deref())]),
            ),
            ("of", expr(of)),
        ]),
        Expr::Bin { op, l, r } => Json::obj([
            ("op", Json::Str((*op).to_owned())),
            ("l", expr(l)),
            ("r", expr(r)),
        ]),
        Expr::Un { op, x } => Json::obj([("op", Json::Str((*op).to_owned())), ("x", expr(x))]),
    }
}

fn hex(b: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    b.iter()
        .flat_map(|x| [DIGITS[usize::from(x >> 4)], DIGITS[usize::from(x & 0xf)]])
        .map(char::from)
        .collect()
}
