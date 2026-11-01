//! 依存と sans-IO と確保の規則を、manifest と source の文字列で確かめる試験です
//! (wgstack-rs.md の「依存と隔離の検査」)。
//!
//! 主な検査は `clippy.toml` の禁止の一覧で、clippy は型と経路を解決して確かめます。
//! この試験はその補いです。clippy の一覧から項目が消えていないこと、crate が依存を持たないこと、clippy が
//! 見ない cfg (`fuzzing`、故障の注入) の中のコードも禁止の語を使わないことを確かめます。
//! 文字列の照合なので、注釈と試験の module (`#[cfg(test)]` の行より後ろと `tests.rs`) は見ません。

#![expect(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "tests may hold growing collections"
)]

use std::path::{Path, PathBuf};

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// 核の source で使わない語と、その理由です。`fixed_vec.rs` は `FIXED_VEC_ONLY` の語を使えます。
const FORBIDDEN: &[(&str, &str)] = &[
    ("Instant", "the core is sans-IO: the caller passes the time"),
    (
        "SystemTime",
        "the core is sans-IO: the caller passes the time",
    ),
    ("thread::", "the core owns no threads"),
    ("std::net", "the core owns no sockets"),
    ("UdpSocket", "the core owns no sockets"),
    ("TcpStream", "the core owns no sockets"),
    ("std::fs", "the core touches no files"),
    ("std::env", "the core reads no environment"),
    ("std::process", "the core starts no processes"),
    ("std::io::std", "the core writes no standard streams"),
    ("RandomState", "the core reads no OS randomness"),
    ("getrandom", "the core reads no OS randomness"),
    ("HashMap", "grows; use the fixed tables"),
    ("HashSet", "grows; use the fixed tables"),
    ("BTreeMap", "grows; use the fixed tables"),
    ("BTreeSet", "grows; use the fixed tables"),
    ("VecDeque", "grows; use a fixed ring"),
    ("BinaryHeap", "grows; use the timer wheel"),
    ("LinkedList", "allocates per node"),
    ("Rc<", "allocates and aborts on failure"),
    ("Arc<", "allocates and aborts on failure"),
    ("Box<", "allocates and aborts on failure"),
    ("Box::", "allocates and aborts on failure"),
    ("vec!", "allocates and aborts on failure"),
    (".push(", "grows the capacity"),
    (".extend(", "grows the capacity"),
    (".collect", "allocates and grows"),
    (".to_vec(", "allocates and aborts on failure"),
    (".to_owned(", "allocates and aborts on failure"),
    (".to_string(", "allocates and aborts on failure"),
    (".into_owned(", "allocates and aborts on failure"),
    ("String", "the core builds no strings"),
    ("format!", "the core builds no strings"),
    ("println!", "the core writes no logs"),
    ("eprintln!", "the core writes no logs"),
    ("extern crate", "edition 2024 needs no extern crate"),
    ("unsafe", "the crate forbids unsafe code"),
];

/// `fixed_vec.rs` だけが使える語です。
const FIXED_VEC_ONLY: &[&str] = &[".push(", "Box<", "Box::"];

/// 一覧の項目のうち、clippy の設定に無ければならないものです。
const CLIPPY_REQUIRED: &[&str] = &[
    "std::time::Instant::now",
    "std::time::SystemTime::now",
    "std::thread::spawn",
    "std::vec::Vec::push",
    "std::vec::Vec::with_capacity",
    "std::vec::Vec::try_reserve_exact",
    "std::vec::Vec::into_boxed_slice",
    "std::iter::Iterator::collect",
    "std::iter::Extend::extend",
    "std::boxed::Box::new",
    "slice::to_vec",
    "alloc::string::ToString::to_string",
    "std::borrow::Cow::into_owned",
    "std::io::stdin",
    "std::io::stdout",
    "std::io::stderr",
    "std::env::var",
    "std::process::exit",
    "std::fs::read",
    "std::vec::Vec\"",
    "std::boxed::Box\"",
    "std::rc::Rc\"",
    "std::sync::Arc\"",
    "std::fs::File\"",
    "std::process::Command\"",
    "std::collections::HashMap",
    "std::collections::VecDeque",
    "std::net::UdpSocket",
    "std::string::String\"",
    "std::vec\"",
    "std::format",
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// 試験の module を除いた、注釈を外した行を返します。`#[cfg(test)]` の次の行が `mod` で始まるところで止めます。
fn product_lines(text: &str) -> Vec<(usize, &str)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        let next_is_mod = lines.get(i + 1).is_some_and(|n| {
            let n = n.trim_start();
            n.starts_with("mod ") || n.starts_with("pub(crate) mod ")
        });
        if l.trim() == "#[cfg(test)]" && next_is_mod {
            break;
        }
        out.push((i + 1, l.split_once("//").map_or(*l, |(code, _)| code)));
    }
    out
}

/// `FixedVec` の一部でない `Vec<` か `Vec::` があるかを返します。
fn bare_vec(line: &str) -> bool {
    ["Vec<", "Vec::"].iter().any(|pat| {
        line.match_indices(pat).any(|(i, _)| {
            let before = &line[..i];
            !before.ends_with("Fixed")
                && !before.ends_with(|c: char| c.is_alphanumeric() || c == '_')
        })
    })
}

#[test]
fn product_source_uses_no_forbidden_names() {
    let mut files = Vec::new();
    rust_files(&crate_dir().join("src"), &mut files);
    assert!(files.len() > 3);
    let mut bad = Vec::new();
    for f in &files {
        let name = f.file_name().unwrap().to_str().unwrap();
        if name == "tests.rs" || name.ends_with("_tests.rs") {
            continue;
        }
        let text = std::fs::read_to_string(f).unwrap();
        for (n, line) in product_lines(&text) {
            for (word, why) in FORBIDDEN {
                // forbid(unsafe_code) の宣言と、FixedVec の実装の中の確保は許します。
                if (*word == "unsafe" && line.contains("forbid(unsafe_code)"))
                    || (name == "fixed_vec.rs" && FIXED_VEC_ONLY.contains(word))
                {
                    continue;
                }
                if line.contains(word) {
                    bad.push(format!("{}:{n}: {word}: {why}", f.display()));
                }
            }
            if name != "fixed_vec.rs" && bare_vec(line) {
                bad.push(format!(
                    "{}:{n}: Vec: variable-length holdings use FixedVec",
                    f.display()
                ));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "forbidden names in the core:\n{}",
        bad.join("\n")
    );
}

#[test]
fn scanner_rules() {
    assert!(bare_vec("let v: Vec<u8>"));
    assert!(bare_vec("(Vec::new())"));
    assert!(!bare_vec("FixedVec<u8> and FixedVec::new()"));
    assert!(bare_vec("FixedVec<u8>, Vec<u8>"));
    assert!(!bare_vec("MyVec<u8>"));
    let text = "a\n#[cfg(test)]\nfn helper() {}\nb // c\n#[cfg(test)]\nmod tests;\nd\n";
    let lines: Vec<_> = product_lines(text)
        .into_iter()
        .map(|(_, l)| l.trim())
        .collect();
    assert_eq!(lines, ["a", "#[cfg(test)]", "fn helper() {}", "b"]);
}

#[test]
fn clippy_config_keeps_the_lists() {
    let text = std::fs::read_to_string(crate_dir().join("clippy.toml")).unwrap();
    for item in CLIPPY_REQUIRED {
        assert!(text.contains(item), "clippy.toml lost {item}");
    }
}

#[test]
fn manifest_has_no_dependencies() {
    // Windows の checkout は改行を CRLF にしえます。
    let text = std::fs::read_to_string(crate_dir().join("Cargo.toml"))
        .unwrap()
        .replace("\r\n", "\n");
    let mut table = String::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            table = line.to_string();
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        assert!(
            !table.contains("dependencies"),
            "wgft-wgstack depends only on std, found `{line}` under {table}"
        );
    }
    assert!(
        text.contains("[lints]\nworkspace = true"),
        "the crate inherits the workspace lints"
    );
}
