//! agent のコマンドのフラグの表 (名前、型、既定の値) と 1 行の説明を、Go が生成した `docs/cli.md` と比べる試験。
//! 長い説明と使用例は Rust の agent を説明するので比べない。設計は `docs/design/v2/agent-parity.md` の
//! 「docs/cli.md の照合」。既定のパスが OS で変わるので、Go の試験と同じく Linux でだけ比べる。

#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsString;

use wgft_agent::config::Defaults;

/// 比べるコマンド。`docs/design/v2/agent-parity.md` の「Rust のビルドが持つコマンド」の表のうち、
/// `docs/cli.md` に節を持つもの。
const AGENT_COMMANDS: &[&str] = &[
    "agent run",
    "agent pubkey",
    "agent rotate-key",
    "agent doctor",
    "agent teardown",
    "version",
];

/// Rust のビルドがまだ持たない、または Go と違うことを承知している差。ここだけに書く。
///
/// 試験は実際の差の集合とこの表が一致することを求める。新しい差が出れば落ち、段が入って差が消えたのに
/// この表に残っていても落ちる。段を入れたら該当する行を消す。
const EXPECTED_DIFFERENCES: &[&str] = &[
    // agent doctor の骨組みの段で入る
    "missing command: agent doctor",
];

#[derive(Debug, PartialEq, Eq)]
struct Flag {
    short: Option<char>,
    /// `string`、`int`、真偽値は空
    ty: String,
    default: Option<String>,
}

type Flags = BTreeMap<String, Flag>;

fn read_doc() -> String {
    let path = format!("{}/../../docs/cli.md", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// `## wgft <path>` の節の本文。
fn section<'a>(doc: &'a str, path: &str) -> Option<&'a str> {
    let head = format!("## wgft {path}\n");
    let start = doc.find(&format!("\n{head}"))? + 1 + head.len();
    let rest = &doc[start..];
    Some(rest.find("\n## ").map_or(rest, |i| &rest[..=i]))
}

/// 冒頭の「Commands」の表から、コマンドごとの 1 行の説明。
fn shorts(doc: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for line in doc.lines() {
        let Some(rest) = line.strip_prefix("| [`wgft ") else {
            continue;
        };
        let Some((path, rest)) = rest.split_once("`](") else {
            continue;
        };
        let Some((_, short)) = rest.split_once(") | ") else {
            continue;
        };
        m.insert(path.to_owned(), short.trim_end_matches(" |").to_owned());
    }
    m
}

/// 節の `Flags:` の次のコードブロックを読む。
fn go_flags(section: &str) -> Flags {
    let mut flags = Flags::new();
    let Some((_, after)) = section.split_once("\nFlags:\n\n```text\n") else {
        return flags;
    };
    let block = after.split("\n```").next().unwrap_or_default();
    for line in block.lines() {
        let line = line.trim_start();
        let (short, line) = match line.as_bytes() {
            [b'-', c, b',', b' ', ..] if *c != b'-' => (Some(char::from(*c)), &line[4..]),
            _ => (None, line),
        };
        let line = line
            .strip_prefix("--")
            .unwrap_or_else(|| panic!("unexpected flag line: {line}"));
        let (spec, desc) = line.split_once("  ").unwrap_or((line, ""));
        let (name, ty) = spec.split_once(' ').unwrap_or((spec, ""));
        let desc = desc.trim();
        let default = desc
            .strip_suffix(')')
            .and_then(|d| d.rsplit_once(" (default "))
            .map(|(_, v)| v.trim_matches('"').to_owned());
        flags.insert(
            name.to_owned(),
            Flag {
                short,
                ty: ty.to_owned(),
                default,
            },
        );
    }
    flags
}

fn rust_type(arg: &clap::Arg) -> String {
    use std::any::TypeId;
    if matches!(arg.get_action(), clap::ArgAction::SetTrue) {
        return String::new();
    }
    let id = arg.get_value_parser().type_id();
    if id == TypeId::of::<bool>() {
        String::new()
    } else if id == TypeId::of::<i64>() {
        "int".to_owned()
    } else if id == TypeId::of::<String>() || id == TypeId::of::<OsString>() {
        "string".to_owned()
    } else {
        panic!(
            "flag --{} has a value type this test does not map",
            arg.get_id()
        )
    }
}

/// clap のコマンドの葉から、`agent run` の形のパスで引いた (1 行の説明、フラグ) の表。
fn rust_commands() -> BTreeMap<String, (String, Flags)> {
    let defaults = Defaults::for_host(&HashMap::<String, OsString>::new());
    let mut root = wgft::cli::command_with(&defaults);
    root.build();
    let mut out = BTreeMap::new();
    let mut stack = vec![(String::new(), &root)];
    while let Some((path, cmd)) = stack.pop() {
        let subs: Vec<_> = cmd
            .get_subcommands()
            .filter(|c| c.get_name() != "help")
            .collect();
        if subs.is_empty() {
            let mut flags = Flags::new();
            for arg in cmd.get_arguments() {
                let Some(name) = arg.get_long() else { continue };
                if name == "help" {
                    continue;
                }
                let help = arg.get_help().map(ToString::to_string).unwrap_or_default();
                let default = help
                    .strip_suffix(']')
                    .and_then(|h| h.rsplit_once(" [default: "))
                    .map(|(_, v)| v.to_owned());
                flags.insert(
                    name.to_owned(),
                    Flag {
                        short: arg.get_short(),
                        ty: rust_type(arg),
                        default,
                    },
                );
            }
            let about = cmd.get_about().map(ToString::to_string).unwrap_or_default();
            out.insert(path, (about, flags));
            continue;
        }
        for sub in subs {
            let p = if path.is_empty() {
                sub.get_name().to_owned()
            } else {
                format!("{path} {}", sub.get_name())
            };
            stack.push((p, sub));
        }
    }
    out
}

fn differences() -> BTreeSet<String> {
    let doc = read_doc();
    let go_shorts = shorts(&doc);
    let rust = rust_commands();
    let mut diff = BTreeSet::new();
    for path in rust.keys() {
        if !AGENT_COMMANDS.contains(&path.as_str()) {
            diff.insert(format!("extra command: {path}"));
        }
    }
    for &path in AGENT_COMMANDS {
        let go_section = section(&doc, path)
            .unwrap_or_else(|| panic!("docs/cli.md has no section for wgft {path}"));
        let Some((about, flags)) = rust.get(path) else {
            diff.insert(format!("missing command: {path}"));
            continue;
        };
        let go_short = go_shorts
            .get(path)
            .unwrap_or_else(|| panic!("docs/cli.md lists no summary for wgft {path}"));
        if about != go_short {
            diff.insert(format!(
                "short differs: {path}: go {go_short:?}, rust {about:?}"
            ));
        }
        let go = go_flags(go_section);
        for (name, g) in &go {
            let Some(r) = flags.get(name) else {
                diff.insert(format!("missing flag: {path} --{name}"));
                continue;
            };
            if r.ty != g.ty {
                diff.insert(format!(
                    "flag type differs: {path} --{name}: go {:?}, rust {:?}",
                    g.ty, r.ty
                ));
            }
            if r.default != g.default {
                diff.insert(format!(
                    "flag default differs: {path} --{name}: go {:?}, rust {:?}",
                    g.default, r.default
                ));
            }
            if r.short != g.short {
                diff.insert(format!(
                    "flag short differs: {path} --{name}: go {:?}, rust {:?}",
                    g.short, r.short
                ));
            }
        }
        for name in flags.keys().filter(|n| !go.contains_key(*n)) {
            diff.insert(format!("extra flag: {path} --{name}"));
        }
    }
    diff
}

#[test]
fn agent_commands_match_cli_doc() {
    let actual = differences();
    let expected: BTreeSet<String> = EXPECTED_DIFFERENCES
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let new: Vec<_> = actual.difference(&expected).collect();
    let stale: Vec<_> = expected.difference(&actual).collect();
    assert!(
        new.is_empty() && stale.is_empty(),
        "docs/cli.md and the Rust help disagree.\nnew differences, fix the Rust help or list them in EXPECTED_DIFFERENCES:\n{new:#?}\nlisted but gone, remove them from EXPECTED_DIFFERENCES:\n{stale:#?}"
    );
}

/// 読み取りの自己確認。Go の文書から `agent run` の表が取れていること。
#[test]
fn reads_the_go_flag_table() {
    let doc = read_doc();
    let flags = go_flags(section(&doc, "agent run").expect("agent run section"));
    assert_eq!(flags["max-tcp-flows"].ty, "int");
    assert_eq!(flags["max-tcp-flows"].default.as_deref(), Some("2048"));
    assert_eq!(
        flags["config"].default.as_deref(),
        Some("/etc/wgft/agent.env")
    );
    assert!(flags["join"].default.is_none());
    let teardown = go_flags(section(&doc, "agent teardown").expect("agent teardown section"));
    assert_eq!(teardown["dry-run"].ty, "");
    assert_eq!(shorts(&doc)["agent run"], "Run the agent");
}
