//! 仕様の fixture `testdata/spec/config/` のうち、dotenv の読み取りと宛先の許可一覧の解釈。

use std::collections::BTreeMap;

use serde::Deserialize;
use wgft_agent::config::{allow_targets, dotenv};

fn fixture<T: serde::de::DeserializeOwned>(name: &str) -> T {
    let path = format!(
        "{}/../../testdata/spec/config/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

#[derive(Deserialize)]
struct DotenvFile {
    ok: Vec<DotenvOk>,
    error: Vec<DotenvErr>,
}

#[derive(Deserialize)]
struct DotenvOk {
    name: String,
    input: Option<String>,
    want: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct DotenvErr {
    name: String,
    input: String,
    line: usize,
    reason: String,
    must_not_contain: Vec<String>,
}

/// 内容を書いたファイルを `dotenv::read` で読む。`None` は存在しないファイル。
fn read_input(
    input: Option<&str>,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    Result<dotenv::Map, dotenv::ReadError>,
) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.env");
    if let Some(text) = input {
        std::fs::write(&path, text).unwrap();
    }
    let r = dotenv::read(&path);
    (dir, path, r)
}

#[test]
fn dotenv_reads_what_the_spec_reads() {
    let f: DotenvFile = fixture("dotenv.json");
    assert!(!f.ok.is_empty());
    for c in f.ok {
        let (_d, _p, r) = read_input(c.input.as_deref());
        let got: BTreeMap<String, String> = r
            .unwrap_or_else(|e| panic!("{}: {e:?}", c.name))
            .values
            .into_iter()
            .collect();
        assert_eq!(got, c.want, "{}", c.name);
    }
}

#[test]
fn dotenv_refuses_what_the_spec_refuses() {
    let f: DotenvFile = fixture("dotenv.json");
    assert!(!f.error.is_empty());
    for c in f.error {
        let (_d, path, r) = read_input(Some(&c.input));
        let Err(dotenv::ReadError::Syntax(refusal)) = r else {
            panic!("{}: expected a syntax refusal", c.name);
        };
        let want = format!(
            "refusing to start [config {}:{}]: {}",
            path.display(),
            c.line,
            c.reason
        );
        assert_eq!(refusal.to_string(), want, "{}", c.name);
        assert_eq!(
            wgft_agent::AgentError::from(refusal.clone()).exit_code(),
            3,
            "{}",
            c.name
        );
        assert_eq!(
            refusal.one_shot().to_string(),
            want.replacen("refusing to start", "cannot continue", 1),
            "{}",
            c.name
        );
        for bad in &c.must_not_contain {
            assert!(!want.contains(bad.as_str()), "{}: {bad}", c.name);
        }
    }
}

#[derive(Deserialize)]
struct AllowFile {
    ok: Vec<AllowOk>,
    error: Vec<AllowErr>,
}

#[derive(Deserialize)]
struct AllowOk {
    input: String,
    normalized: Option<String>,
}

#[derive(Deserialize)]
struct AllowErr {
    input: String,
    error: String,
}

#[test]
fn allow_targets_normalise_like_the_spec() {
    let f: AllowFile = fixture("allow-targets.json");
    for c in f.ok {
        let got = allow_targets::parse(&c.input)
            .unwrap_or_else(|e| panic!("{:?}: {e}", c.input))
            .map(|l| l.to_string());
        assert_eq!(got, c.normalized, "{:?}", c.input);
    }
}

#[test]
fn allow_targets_fail_with_the_spec_message() {
    let f: AllowFile = fixture("allow-targets.json");
    for c in f.error {
        assert_eq!(
            allow_targets::parse(&c.input).unwrap_err(),
            c.error,
            "{:?}",
            c.input
        );
    }
}
