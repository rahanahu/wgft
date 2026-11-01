//! 仕様の fixture `testdata/spec/config/` のうち、入口での検査、有効な設定の行、拒否の文面と終了コード。
//! dotenv の読み取りと宛先の許可一覧は `wgft-agent` の試験にある。

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;

use serde::Deserialize;
use wgft::agent_run::{Prepared, prepare_door};
use wgft::cli::{self, Parsed};
use wgft::failure::Failure;
use wgft_agent::config::LogLine;
use wgft_agent::{AgentError, Refusal};

fn fixture<T: serde::de::DeserializeOwned>(name: &str) -> T {
    let path = format!(
        "{}/../../testdata/spec/config/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// `wgft agent run <args>` を解釈して入口を通す。
fn door(
    args: &[String],
    env: &BTreeMap<String, String>,
    os: &str,
) -> (Result<Prepared, AgentError>, Vec<LogLine>) {
    let mut argv: Vec<OsString> = ["wgft", "agent", "run"].map(OsString::from).to_vec();
    argv.extend(args.iter().map(OsString::from));
    let Ok(Parsed::AgentRun { global, run }) = cli::parse(argv) else {
        panic!("arguments {args:?} do not parse as agent run");
    };
    let env: HashMap<String, OsString> = env
        .iter()
        .map(|(k, v)| (k.clone(), OsString::from(v)))
        .collect();
    let mut early = Vec::new();
    let r = prepare_door(&global, &run, &env, os, &mut early);
    (r, early)
}

#[derive(Deserialize)]
struct ValuesFile {
    cases: Vec<ValueCase>,
}

#[derive(Deserialize)]
struct ValueCase {
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    args: Vec<String>,
    goos: Option<String>,
    message: Option<String>,
}

#[test]
fn the_door_judges_values_like_the_spec() {
    let f: ValuesFile = fixture("values.json");
    assert!(!f.cases.is_empty());
    let dir = tempfile::tempdir().unwrap();
    for c in f.cases {
        let mut env = c.env.clone();
        // dotenv は無く、データディレクトリは新しい。ホストの `/etc/wgft/agent.env` を読まない
        env.insert(
            "WGFT_CONFIG".into(),
            dir.path().join("none.env").display().to_string(),
        );
        env.entry("WGFT_DATA_DIR".into())
            .or_insert_with(|| dir.path().join("data").display().to_string());
        let (r, _) = door(&c.args, &env, c.goos.as_deref().unwrap_or("linux"));
        let label = format!("env {:?} args {:?} goos {:?}", c.env, c.args, c.goos);
        match (r, c.message) {
            (Ok(_), None) => {}
            (Ok(_), Some(m)) => panic!("{label}: passed, want {m:?}"),
            (Err(e), None) => panic!("{label}: refused: {e}"),
            (Err(e), Some(m)) => {
                assert_eq!(e.to_string(), m, "{label}");
                assert_eq!(e.exit_code(), 3, "{label}");
            }
        }
    }
}

#[derive(Deserialize)]
struct EffectiveFile {
    cases: Vec<EffectiveCase>,
}

#[derive(Deserialize)]
struct EffectiveCase {
    name: String,
    config: String,
    dotenv: Option<String>,
    env: BTreeMap<String, String>,
    args: Vec<String>,
    want: String,
}

#[test]
fn the_effective_config_block_matches_the_spec() {
    let f: EffectiveFile = fixture("effective-config.json");
    assert!(!f.cases.is_empty());
    for c in f.cases {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.env");
        if let Some(text) = &c.dotenv {
            std::fs::write(&path, text).unwrap();
        }
        let mut env = c.env.clone();
        let mut args = c.args.clone();
        match c.config.as_str() {
            "flag" => args.extend(["--config".to_owned(), path.display().to_string()]),
            "env" => {
                env.insert("WGFT_CONFIG".into(), path.display().to_string());
            }
            other => panic!("{}: config {other}", c.name),
        }
        let (r, _) = door(&args, &env, "linux");
        let p = r.unwrap_or_else(|e| panic!("{}: {e}", c.name));
        let mut got = String::from("effective config:\n");
        for l in p.config.effective_lines() {
            got.push_str(&l);
            got.push('\n');
        }
        assert_eq!(got, c.want, "{}", c.name);
        // 起動の行の先頭も同じ塊で始まる
        let lines = p.startup_lines();
        assert_eq!(lines[0], LogLine::Plain("effective config:".into()));
        assert_eq!(
            lines[1..=10],
            c.want
                .lines()
                .skip(1)
                .map(|l| LogLine::Plain(l.to_owned()))
                .collect::<Vec<_>>()[..],
            "{}",
            c.name
        );
    }
}

#[derive(Deserialize)]
struct RefusalFile {
    cases: Vec<RefusalCase>,
}

#[derive(Deserialize)]
struct RefusalCase {
    name: String,
    kind: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    subject: String,
    reason: String,
    hint: Option<String>,
    #[serde(default)]
    one_shot: bool,
    wrap: Option<String>,
    message: String,
    exit: u8,
}

#[test]
fn refusals_become_messages_and_exit_codes_like_the_spec() {
    let f: RefusalFile = fixture("refusals.json");
    assert!(!f.cases.is_empty());
    for c in f.cases {
        let failure = match c.kind.as_str() {
            "refusal" => {
                let mut r = match c.category.as_str() {
                    "config" => Refusal::config(&c.subject, &c.reason),
                    "prerequisite" => Refusal::prerequisite(&c.subject, &c.reason),
                    "conflict" => Refusal::conflict(&c.subject, &c.reason),
                    "mode-gate" => Refusal::mode_gate(&c.subject, &c.reason),
                    other => panic!("{}: category {other}", c.name),
                };
                if let Some(h) = &c.hint {
                    r = r.hint(h);
                }
                if c.one_shot {
                    r = r.one_shot();
                }
                if let Some(w) = &c.wrap {
                    let ctx: &'static str =
                        Box::leak(w.trim_end_matches(": ").to_owned().into_boxed_str());
                    r = r.context(ctx);
                }
                Failure::from(AgentError::from(r))
            }
            "unavailable" => Failure::unavailable(&c.reason),
            "error" => Failure::from(AgentError::Other(c.reason.clone())),
            other => panic!("{}: kind {other}", c.name),
        };
        assert_eq!(failure.message, c.message, "{}", c.name);
        assert_eq!(failure.code, c.exit, "{}", c.name);
    }
}

#[test]
fn a_set_allowlist_and_kernel_mode_are_refused_after_the_door() {
    let dir = tempfile::tempdir().unwrap();
    let base = |extra: &[(&str, &str)]| {
        let mut env = BTreeMap::new();
        env.insert(
            "WGFT_CONFIG".to_owned(),
            dir.path().join("n").display().to_string(),
        );
        env.insert("WGFT_DATA_DIR".to_owned(), dir.path().display().to_string());
        for (k, v) in extra {
            env.insert((*k).to_owned(), (*v).to_owned());
        }
        env
    };
    let try_prepare = |env: &BTreeMap<String, String>| {
        let Ok(Parsed::AgentRun { global, run }) =
            cli::parse(["wgft", "agent", "run"].map(OsString::from))
        else {
            panic!("parse");
        };
        let env: HashMap<String, OsString> = env
            .iter()
            .map(|(k, v)| (k.clone(), OsString::from(v)))
            .collect();
        wgft::agent_run::prepare(&global, &run, &env, "linux", &mut Vec::new())
    };
    let e = try_prepare(&base(&[("WGFT_MODE", "kernel")])).unwrap_err();
    assert_eq!(
        e.to_string(),
        "refusing to start [prerequisite WGFT_MODE]: this build does not include the agent's kernel mode yet, so it cannot start in kernel mode; use a build that includes it"
    );
    assert_eq!(e.exit_code(), 3);
    let e = try_prepare(&base(&[("WGFT_AGENT_ALLOW_TARGETS", "10.0.0.1:80")])).unwrap_err();
    assert!(
        e.to_string().starts_with(
            "refusing to start [prerequisite WGFT_AGENT_ALLOW_TARGETS]: is set to 10.0.0.1/32:80, and this build does not enforce"
        ),
        "{e}"
    );
    assert_eq!(e.exit_code(), 3);
    // 値の誤りは、この版が持たない機能の拒否より先に出る
    let e = try_prepare(&base(&[
        ("WGFT_MODE", "kernel"),
        ("WGFT_MAX_UDP_FLOWS", "1"),
    ]))
    .unwrap_err();
    assert!(e.to_string().contains("WGFT_MAX_UDP_FLOWS"), "{e}");
    assert!(try_prepare(&base(&[])).is_ok());
}
