//! 構文解析の後、流す前の静的な検査です。Go の `checkStatic` と `checkBindings` と同じ規則で、
//! 同じ順に誤りを探します。

use std::collections::BTreeSet;

use super::{
    BIND_FIRST, CONSTS, ErrorKind, Expr, PREDICATE_NAMED, ScriptError, Stmt, TmplPart,
    predicate_arg,
};

/// 文の形です。ID の後の位置の引数の数の範囲、受け付ける名前つきの引数、`->` で結べる結果を持つかです。
#[derive(Debug, Clone, Copy)]
pub(crate) struct VerbSig {
    pub(crate) min: usize,
    pub(crate) max: usize,
    pub(crate) named: &'static [&'static str],
    pub(crate) result: bool,
}

const DIAL_NAMED: &[&str] = &["syn", "window", "syn_window", "ack_delay"];

const fn sig(min: usize, max: usize, named: &'static [&'static str], result: bool) -> VerbSig {
    VerbSig {
        min,
        max,
        named,
        result,
    }
}

/// 引数を持つ文の形です。Go の `verbSigs` です。`let`、`set`、`if`、`else`、`end`、`stop`、`check`、
/// `require`、`measure`、`log` は自分の構文を持ち、ここにありません。
pub(crate) const VERB_SIGS: &[(&str, VerbSig)] = &[
    ("listen", sig(2, 2, &[], true)),
    ("connect", sig(3, 3, DIAL_NAMED, false)),
    ("handshake", sig(2, 2, DIAL_NAMED, false)),
    ("accept", sig(2, 2, &[], false)),
    ("peer", sig(2, 2, &[], false)),
    ("reincarnate", sig(2, 2, &["iss", "ts_base"], false)),
    ("adopt", sig(3, 3, &[], false)),
    ("send", sig(2, 2, &[], false)),
    ("send_data", sig(2, 2, &[], false)),
    ("send_ack", sig(1, 1, &[], false)),
    ("send_fin", sig(1, 2, &[], false)),
    ("send_fresh_ack", sig(1, 1, &[], true)),
    ("await", sig(2, 2, &["match"], true)),
    ("quiet", sig(2, 2, &[], true)),
    ("quiet_since", sig(5, 5, &[], true)),
    ("collect", sig(1, 1, &[], true)),
    ("write", sig(2, 2, &[], true)),
    ("read", sig(3, 3, &[], true)),
    ("close", sig(1, 1, &[], false)),
    ("close_write", sig(1, 1, &[], false)),
    ("abort", sig(1, 1, &[], false)),
    ("alive", sig(2, 2, &[], false)),
    ("delivered", sig(1, 1, &[], false)),
    ("recv", sig(3, 3, &[], true)),
    ("collect_flow", sig(2, 2, &["until"], true)),
    ("flight", sig(4, 4, &[], true)),
    ("burst", sig(1, 1, &[], true)),
    ("at_once", sig(1, 1, &[], true)),
    ("listen_udp", sig(2, 2, &[], false)),
    ("udp_read", sig(2, 2, &[], true)),
    ("udp_write", sig(2, 2, &["to"], true)),
    ("inject_ip", sig(1, 1, &[], false)),
    ("inject_icmp_error", sig(1, 1, &[], false)),
    ("await_ip", sig(1, 1, &["match"], true)),
    ("await_datagram", sig(1, 1, &["match"], true)),
    ("echo", sig(4, 4, &["cuts"], true)),
];

pub(crate) fn verb_sig(verb: &str) -> Option<VerbSig> {
    VERB_SIGS.iter().find(|(v, _)| *v == verb).map(|(_, s)| *s)
}

const MANY: usize = 1 << 16;

/// 関数の位置の引数の数の範囲です。Go の `funcSigs` です。名前つきの引数は `with` だけが取ります。
pub(crate) const FUNC_SIGS: &[(&str, usize, usize)] = &[
    ("yes_no", 3, 3),
    ("clocked", 2, 2),
    ("is_data", 1, 1),
    ("is_pure_ack", 1, 1),
    ("is_fin", 1, 1),
    ("is_rst", 1, 1),
    ("is_synack", 1, 1),
    ("has", 2, 2),
    ("acks", 2, 2),
    ("len", 1, 1),
    ("count", 1, 1),
    ("first", 2, 2),
    ("filter", 2, 2),
    ("any", 2, 2),
    ("max_of", 2, 2),
    ("sum_of", 2, 2),
    ("pattern", 2, 2),
    ("seq", 1, 1),
    ("int", 1, 1),
    ("text", 1, 1),
    ("ms", 1, 1),
    ("block", 2, 2),
    ("ts", 2, 2),
    ("ts_val", 1, 1),
    ("opts_standard", 0, 0),
    ("opts_nosack", 0, 0),
    ("opts_none", 0, 0),
    ("segment", 3, 4),
    ("raw", 3, 3),
    ("syn", 2, 2),
    ("with", 1, 1),
    ("seg_desc", 1, 2),
    ("ack_desc", 2, 3),
    ("sack_desc", 2, 3),
    ("synack_desc", 2, 3),
    ("err_kind", 1, 1),
    ("err_string", 1, 1),
    ("quote", 1, 1),
    ("list", 0, MANY),
    ("max", 2, 2),
    ("zeros", 1, 1),
    ("addr", 1, 1),
    ("addrport", 2, 2),
    ("with_port", 2, 2),
    ("seg_size", 1, 1),
    ("wire", 1, 1),
    ("wire_len", 1, 1),
    ("udp", 4, 4),
    ("icmp", 7, 7),
    ("fragments", 1, MANY),
    ("fragments_every", 2, 2),
    ("frag", 3, 3),
    ("frag_needed", 3, 3),
    ("corrupt", 3, 3),
    ("set_bytes", 3, 3),
    ("to_peer", 1, 1),
    ("icmp_type", 1, 1),
    ("parse_udp", 1, 1),
    ("parse_icmp", 1, 1),
    ("parse_quote", 1, 1),
    ("reply_desc", 3, 3),
    ("pmtu_desc", 1, 1),
    ("seg_descs", 1, 1),
    ("seconds_text", 2, 2),
];

pub(crate) fn func_sig(name: &str) -> Option<(usize, usize)> {
    FUNC_SIGS
        .iter()
        .find(|(f, ..)| *f == name)
        .map(|&(_, min, max)| (min, max))
}

/// 文が欠かせない名前つきの引数です。Go の `requiredNamed` です。
fn required_named(verb: &str) -> Option<&'static str> {
    const REQUIRED: &[(&str, &str)] = &[
        ("reincarnate", "iss"),
        ("udp_write", "to"),
        ("await_ip", "match"),
        ("await_datagram", "match"),
    ];
    REQUIRED.iter().find(|(v, _)| *v == verb).map(|(_, n)| *n)
}

fn template_exprs(st: &Stmt) -> impl Iterator<Item = &Expr> {
    st.what.iter().chain(&st.got).filter_map(|p| match p {
        TmplPart::Expr(e) => Some(e),
        TmplPart::Text(_) => None,
    })
}

pub(super) fn check_static(file: &str, body: &[Stmt]) -> Result<(), ScriptError> {
    for st in body {
        let err = |kind, msg: String| ScriptError {
            file: file.to_owned(),
            line: st.line,
            kind,
            msg,
        };
        if let Some(sig) = verb_sig(&st.verb) {
            let n = st.args.len();
            if n < sig.min || n > sig.max {
                let range = if sig.min == sig.max {
                    format!("{}", sig.min)
                } else {
                    format!("{} to {}", sig.min, sig.max)
                };
                return Err(err(
                    ErrorKind::Arity,
                    format!("{} takes {range} arguments; got {n}", st.verb),
                ));
            }
            if let Some(k) = st.named.keys().find(|k| !sig.named.contains(&k.as_str())) {
                return Err(err(
                    ErrorKind::NamedArgument,
                    format!("{} does not take {k}=", st.verb),
                ));
            }
            if st.bind.is_some() && !sig.result {
                return Err(err(
                    ErrorKind::Bind,
                    format!("{} gives no result to bind with ->", st.verb),
                ));
            }
        }
        if let Some(need) = required_named(&st.verb)
            && !st.named.contains_key(need)
        {
            return Err(err(
                ErrorKind::NamedArgument,
                format!("{} needs {need}=", st.verb),
            ));
        }
        for e in st
            .args
            .iter()
            .chain(st.named.values())
            .chain(template_exprs(st))
        {
            if let Some((kind, msg)) = check_calls(e) {
                return Err(err(kind, msg));
            }
        }
        check_static(file, &st.then)?;
        check_static(file, &st.els)?;
    }
    Ok(())
}

/// `e` の中の呼び出しのすべてを確かめ、最初の誤りを返します。
fn check_calls(e: &Expr) -> Option<(ErrorKind, String)> {
    if let Expr::Call { name, args, named } = e {
        let Some((min, max)) = func_sig(name) else {
            return Some((
                ErrorKind::UnknownFunction,
                format!("unknown function {name}"),
            ));
        };
        let n = args.len();
        if n < min || n > max {
            let range = if min == max {
                format!("{min}")
            } else {
                format!("{min} to {max}")
            };
            return Some((
                ErrorKind::Arity,
                format!("{name} takes {range} arguments; got {n}"),
            ));
        }
        if !named.is_empty() && name != "with" {
            return Some((
                ErrorKind::NamedArgument,
                format!("{name} takes no named arguments"),
            ));
        }
        return args.iter().chain(named.values()).find_map(check_calls);
    }
    e.children().into_iter().find_map(check_calls)
}

/// 結びの静的な検査です。名前の読み取りのすべてが、そこに至るすべての経路で先に結ばれていることを確かめます。
pub(super) fn check_bindings(file: &str, body: &[Stmt]) -> Result<(), ScriptError> {
    bind_block(file, body, &BTreeSet::new()).map(|_| ())
}

type Names = BTreeSet<String>;

/// `body` の後に結ばれている名前を返します。`body` が必ず止まるなら `None` です。
fn bind_block(file: &str, body: &[Stmt], bound: &Names) -> Result<Option<Names>, ScriptError> {
    let mut cur = Some(bound.clone());
    for st in body {
        let err = |kind, msg: String| ScriptError {
            file: file.to_owned(),
            line: st.line,
            kind,
            msg,
        };
        let Some(names) = cur.as_mut() else {
            return Err(err(
                ErrorKind::Unreachable,
                "statement after stop is never reached".to_owned(),
            ));
        };
        let unbound = |name: &str| {
            err(
                ErrorKind::Unbound,
                format!("{name} is not bound on every path to here"),
            )
        };
        let bind_first = BIND_FIRST.contains(&st.verb.as_str());
        if st.verb == "set"
            && let Some(target) = &st.bind
        {
            let obj = target.split_once('.').map_or(target.as_str(), |(o, _)| o);
            if !names.contains(obj) {
                return Err(unbound(obj));
            }
        }
        let args = if bind_first {
            &st.args[1..]
        } else {
            &st.args[..]
        };
        for a in args {
            if let Some(n) = unbound_name(a, names, false) {
                return Err(unbound(n));
            }
        }
        for (k, e) in &st.named {
            if let Some(n) = unbound_name(e, names, PREDICATE_NAMED.contains(&k.as_str())) {
                return Err(unbound(n));
            }
        }
        for e in template_exprs(st) {
            if let Some(n) = unbound_name(e, names, false) {
                return Err(unbound(n));
            }
        }
        match st.verb.as_str() {
            "if" => {
                let a = bind_block(file, &st.then, names)?;
                let b = bind_block(file, &st.els, names)?;
                cur = match (a, b) {
                    (None, x) | (x, None) => x,
                    (Some(a), Some(b)) => Some(a.intersection(&b).cloned().collect()),
                };
            }
            "stop" => cur = None,
            "let" => {
                names.extend(st.bind.clone());
            }
            _ => {
                if bind_first && let Some(Expr::Name(n)) = st.args.first() {
                    names.insert(n.clone());
                }
                if st.verb != "set"
                    && let Some(b) = &st.bind
                {
                    names.insert(b.clone());
                }
            }
        }
    }
    Ok(cur)
}

/// `e` が読む名前のうち、結ばれておらず、`s` (述語の中で `s_bound` のとき) でも定数でもない最初の名前を返します。
fn unbound_name<'e>(e: &'e Expr, bound: &Names, s_bound: bool) -> Option<&'e str> {
    match e {
        Expr::Name(n) => {
            let ok = bound.contains(n) || (s_bound && n == "s") || CONSTS.contains(&n.as_str());
            (!ok).then_some(n.as_str())
        }
        Expr::Call { name, args, named } => {
            let pred = predicate_arg(name);
            args.iter()
                .enumerate()
                .find_map(|(i, a)| unbound_name(a, bound, s_bound || pred == Some(i)))
                .or_else(|| named.values().find_map(|a| unbound_name(a, bound, s_bound)))
        }
        _ => e
            .children()
            .into_iter()
            .find_map(|a| unbound_name(a, bound, s_bound)),
    }
}
