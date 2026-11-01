//! 適合の台本の言語 (`docs/design/v2/test-tooling.md` の 1 節) の構文解析器と静的な検査です。
//!
//! Go の構文解析器 (`internal/tcpharness/script_parse.go` と `script_check.go`) の写しで、同じ入力に同じ
//! 構文木と同じ誤り (行と種類) を返します。正規化した構文木 ([`Script::ast_json`]) は Go の `ScriptAST` を
//! `json.Marshal` で書いたものと byte の単位で同じです。誤りの英語の文は Go と違ってよく、比べません。
//!
//! 台本は UTF-8 の text で、UTF-8 として読めない行は `layout` の誤りです。文字列の literal は `\xHH` の
//! escape で任意の bytes を持てるので、bytes のまま持ちます。

mod ast;
mod check;
mod lex;
mod parse;

use std::collections::BTreeMap;
use std::fmt;

/// 構文解析した 1 つの台本です。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Script {
    /// `scenario` の行の名前
    pub name: String,
    /// `refs:` の行の文
    pub refs: String,
    /// `linux:` の行の sysctl の組
    pub linux: Vec<(String, String)>,
    /// 文の列
    pub body: Vec<Stmt>,
}

/// 1 つの文です。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stmt {
    /// ファイルの中の行 (1 から)
    pub line: usize,
    /// 先頭の語
    pub verb: String,
    /// `check`、`require`、`measure`、`alive`、`delivered` の確かめの ID
    pub id: Option<String>,
    /// 位置の引数。`let` と `set` は右辺、`if`、`check`、`require`、`measure` は行の残りの式
    pub args: Vec<Expr>,
    /// 名前つきの引数
    pub named: BTreeMap<String, Expr>,
    /// `->` の後の名前。`let` は結ぶ名前、`set` は `名前.欄`
    pub bind: Option<String>,
    /// `if` の真の枝
    pub then: Vec<Stmt>,
    /// `if` の偽の枝。空の `else` と `else` の無い `if` は同じく空です
    pub els: Vec<Stmt>,
    /// `check` と `require` の `what:`、`log` の template
    pub what: Vec<TmplPart>,
    /// `check` と `require` の `got:`
    pub got: Vec<TmplPart>,
}

impl Stmt {
    fn new(line: usize, verb: String) -> Self {
        Self {
            line,
            verb,
            id: None,
            args: Vec::new(),
            named: BTreeMap::new(),
            bind: None,
            then: Vec::new(),
            els: Vec::new(),
            what: Vec::new(),
            got: Vec::new(),
        }
    }
}

/// template の 1 つの部分です。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TmplPart {
    /// そのまま書く文
    Text(String),
    /// `{式}` で埋め込む式
    Expr(Expr),
}

/// 式です。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// 整数
    Int(i64),
    /// 時間 (nanosecond)
    Dur(i64),
    /// 文字列の literal の bytes
    Str(Vec<u8>),
    /// 名前
    Name(String),
    /// 関数の呼び出し
    Call {
        name: String,
        args: Vec<Expr>,
        named: BTreeMap<String, Expr>,
    },
    /// `x.欄`
    Field { of: Box<Expr>, name: String },
    /// `x[i]`
    Index { of: Box<Expr>, index: Box<Expr> },
    /// `x[a:b]`。省いた端は `None`
    Slice {
        of: Box<Expr>,
        lo: Option<Box<Expr>>,
        hi: Option<Box<Expr>>,
    },
    /// 2 項の演算。`op` は `||`、`&&`、`==`、`!=`、`<`、`<=`、`>`、`>=`、`|`、`+`、`-`、`*`、`/`、`%`
    Bin {
        op: &'static str,
        l: Box<Expr>,
        r: Box<Expr>,
    },
    /// 単項の演算。`op` は `!` か `-`
    Un { op: &'static str, x: Box<Expr> },
}

impl Expr {
    /// Go の `Expr.Args` と同じ順の子の式です。静的な検査が誤りを探す順を Go と揃えます。
    fn children(&self) -> Vec<&Expr> {
        match self {
            Self::Int(_) | Self::Dur(_) | Self::Str(_) | Self::Name(_) => Vec::new(),
            Self::Call { args, .. } => args.iter().collect(),
            Self::Field { of, .. } => vec![of],
            Self::Index { of, index } => vec![of, index],
            Self::Slice { of, lo, hi } => {
                let mut v: Vec<&Expr> = vec![of];
                v.extend(lo.as_deref());
                v.extend(hi.as_deref());
                v
            }
            Self::Bin { l, r, .. } => vec![l, r],
            Self::Un { x, .. } => vec![x],
        }
    }
}

/// 構文と静的な検査の誤りの種類です。言語に依らない名前を持ち、構文の fixture が比べます。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// tab、UTF-8 でない行、行の終わりで閉じない文字列
    Layout,
    /// `scenario`、`refs:`、`linux:` の行
    Header,
    /// `if`、`else`、`end`
    Block,
    /// `what:` と `got:` の行と `{式}`
    Template,
    /// 字句と式
    Syntax,
    /// 文でない先頭の語
    UnknownStatement,
    /// 無い関数の呼び出し
    UnknownFunction,
    /// 位置の引数の数
    Arity,
    /// 受け付けない名前つきの引数、2 度の名前つきの引数
    NamedArgument,
    /// 結果を持たない文の `->`、名前でない最初の引数
    Bind,
    /// すべての経路で結ばれていない名前の読み取り
    Unbound,
    /// `stop` の後の文
    Unreachable,
}

impl ErrorKind {
    /// fixture に書く名前です。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Layout => "layout",
            Self::Header => "header",
            Self::Block => "block",
            Self::Template => "template",
            Self::Syntax => "syntax",
            Self::UnknownStatement => "unknown-statement",
            Self::UnknownFunction => "unknown-function",
            Self::Arity => "arity",
            Self::NamedArgument => "named-argument",
            Self::Bind => "bind",
            Self::Unbound => "unbound",
            Self::Unreachable => "unreachable",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 構文か静的な検査の誤りです。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptError {
    /// 誤りの文に出すファイルの名前
    pub file: String,
    /// 誤りの行 (1 から)
    pub line: usize,
    /// 種類
    pub kind: ErrorKind,
    /// 英語の文
    pub msg: String,
}

impl fmt::Display for ScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.file, self.line, self.msg)
    }
}

impl std::error::Error for ScriptError {}

/// 1 つの台本を構文解析し、静的な検査をします。`file` は誤りの文に出す名前です。
pub fn parse_script(file: &str, src: &[u8]) -> Result<Script, ScriptError> {
    let script = parse::parse(file, src)?;
    check::check_static(file, &script.body)?;
    check::check_bindings(file, &script.body)?;
    Ok(script)
}

/// 文の動詞です。言語の文のすべてで、Go の `scriptVerbs` と同じ集まりです。
pub const VERBS: &[&str] = &[
    "let",
    "set",
    "if",
    "else",
    "end",
    "stop",
    "listen",
    "connect",
    "handshake",
    "accept",
    "peer",
    "reincarnate",
    "adopt",
    "send",
    "send_data",
    "send_ack",
    "send_fin",
    "send_fresh_ack",
    "await",
    "quiet",
    "quiet_since",
    "collect",
    "write",
    "read",
    "close",
    "close_write",
    "abort",
    "check",
    "require",
    "measure",
    "log",
    "alive",
    "delivered",
    "recv",
    "collect_flow",
    "flight",
    "burst",
    "at_once",
    "listen_udp",
    "udp_read",
    "udp_write",
    "inject_ip",
    "inject_icmp_error",
    "await_ip",
    "await_datagram",
    "echo",
];

/// 台本が結ばずに読める名前です。Go の `scriptConsts` です。
pub const CONSTS: &[&str] = &[
    "SYN",
    "FIN",
    "RST",
    "PSH",
    "ACK",
    "PEER_ADDR",
    "DUT_ADDR",
    "MTU",
    "DUT_MTU",
    "now",
    "prompt",
    "none",
    "true",
    "false",
];

/// 最初の引数が確かめの ID の文です。
const ID_VERBS: &[&str] = &["check", "require", "measure", "alive", "delivered"];
/// ID の後の行の残りを 1 つの式として読む文です。
const EXPR_VERBS: &[&str] = &["check", "require", "measure", "if"];
/// 最初の引数に名前を結ぶ文です。最初の引数は名前でなければなりません。
pub const BIND_FIRST: &[&str] = &[
    "listen",
    "connect",
    "handshake",
    "peer",
    "accept",
    "reincarnate",
    "listen_udp",
];
/// `what:` と `got:` の行を持つ文です。
const TMPL_VERBS: &[&str] = &["check", "require"];
/// 候補ごとに `s` を結んで評価する名前つきの引数です。
pub const PREDICATE_NAMED: &[&str] = &["match", "until"];

/// 関数ごとに、要素ごとに `s` を結んで評価する引数の位置です。
pub fn predicate_arg(func: &str) -> Option<usize> {
    matches!(func, "first" | "filter" | "any" | "max_of" | "sum_of").then_some(1)
}

#[cfg(test)]
mod tests;
