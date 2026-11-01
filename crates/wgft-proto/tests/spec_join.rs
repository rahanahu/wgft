//! 仕様の fixture `testdata/spec/join/` の接続文字列の例と、登録の要求と応答の形と照らす。

use serde::Deserialize;
use wgft_proto::{Join, RegisterRequest, RegisterResponse};

fn fixture(name: &str) -> String {
    let path = format!(
        "{}/../../testdata/spec/join/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{path}: {e}"))
        .replace("\r\n", "\n")
}

#[derive(Deserialize)]
struct JoinCase {
    name: String,
    input: String,
    #[serde(default)]
    endpoint: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    pin: String,
    #[serde(default)]
    error: String,
}

#[test]
fn join_strings_match_the_spec() {
    let cases: Vec<JoinCase> = serde_json::from_str(&fixture("join-strings.json")).unwrap();
    assert!(!cases.is_empty());
    for c in cases {
        match Join::parse(&c.input) {
            Ok(j) => {
                assert_eq!(c.error, "", "{}", c.name);
                assert_eq!(
                    (j.endpoint.as_str(), j.token.as_str(), j.pin_hex().as_str()),
                    (c.endpoint.as_str(), c.token.as_str(), c.pin.as_str()),
                    "{}",
                    c.name
                );
            }
            Err(e) => assert_eq!(e.to_string(), c.error, "{}", c.name),
        }
    }
}

#[test]
fn register_bodies_round_trip_byte_for_byte() {
    for name in ["register-request.json", "register-request-noname.json"] {
        let text = fixture(name);
        let r: RegisterRequest = serde_json::from_str(&text).unwrap();
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            text.trim_end(),
            "{name}"
        );
    }
    let text = fixture("register-response.json");
    let r: RegisterResponse = serde_json::from_str(&text).unwrap();
    assert_eq!(serde_json::to_string(&r).unwrap(), text.trim_end());
}
