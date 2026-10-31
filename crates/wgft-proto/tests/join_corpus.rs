//! Go の `ParseJoin` の結果の一覧 `testdata/spec/join/join-corpus.json` と照らす。一覧は Go の試験
//! `internal/agent/enroll` の `TestJoinCorpus` が作る。

use serde::Deserialize;
use wgft_proto::Join;

#[derive(Deserialize)]
struct Case {
    input: String,
    #[serde(default)]
    endpoint: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    pin: String,
    #[serde(default)]
    err: String,
    #[serde(default)]
    utf8: Option<bool>,
}

#[test]
fn matches_go_parse_join() {
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("../../../testdata/spec/join/join-corpus.json")).unwrap();
    assert!(cases.len() > 1000);
    let mut diffs = Vec::new();
    for c in &cases {
        let got = Join::parse(&c.input);
        let ok = match (&got, c.err.as_str(), c.utf8) {
            // Go が受けたが値が UTF-8 でない入力。Rust は拒む (意図した差)
            (Err(e), "", Some(false)) => {
                e.to_string() == "join string must look like wgft://host:port/token#sha256:HASH"
            }
            (Ok(j), "", None) => {
                j.endpoint == c.endpoint && j.token == c.token && j.pin_hex() == c.pin
            }
            (Err(e), want, _) if !want.is_empty() => e.to_string() == want,
            _ => false,
        };
        if !ok {
            diffs.push(format!(
                "{:?}: go {:?} rust {:?}",
                c.input,
                if c.err.is_empty() { "accept" } else { &c.err },
                got.map(|j| j.endpoint)
            ));
        }
    }
    assert!(
        diffs.is_empty(),
        "{} of {} differ:\n{}",
        diffs.len(),
        cases.len(),
        diffs.join("\n")
    );
}
