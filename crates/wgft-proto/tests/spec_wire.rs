//! 仕様の fixture `testdata/spec/wire/` と照らす。fixture は Go の v1 の型で読み書きして byte 列が
//! 戻ることを、Go の試験 (`proto/spec_test.go`) が確かめている。

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use wgft_proto::Message;
use wgft_proto::textsafe::sanitize_and_clip;
use wgft_proto::{CloseCode, REASON_MAX_BYTES};

fn fixture(name: &str) -> String {
    let path = format!(
        "{}/../../testdata/spec/wire/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let s = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    // Windows の checkout は改行を CRLF にすることがある
    s.replace("\r\n", "\n")
}

/// メッセージの fixture は、Rust で読んで書くと同じ byte 列に戻る。fixture の文字列は HTML の
/// ための書き換えに当たる文字を含まないので、serde_json の書き方でも同じになる。
#[test]
fn messages_round_trip_byte_for_byte() {
    for name in [
        "pubkey.json",
        "pubkey-legacy.json",
        "state.json",
        "state-legacy.json",
        "state-disabled.json",
        "heartbeat.json",
        "heartbeat-no-tunnel.json",
    ] {
        let text = fixture(name);
        let text = text.trim_end();
        let m = Message::decode(text).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(serde_json::to_string(&m).unwrap(), text, "{name}");
    }
}

#[derive(Deserialize)]
struct Quirk {
    name: String,
    #[serde(default)]
    input: Option<String>,
    /// 不正な UTF-8 を含む入力の base64
    #[serde(default)]
    input_base64: Option<String>,
    /// Go が読んで書き直した形。Go が誤りにする例には無い
    #[serde(default)]
    want: Option<String>,
    /// Go が誤りにする例
    #[serde(default)]
    error: bool,
    rust: String,
}

/// must-accept の例は Go と同じ値に読む。may-reject の例は、拒むか、受けるなら Go と同じ値に読む。
/// Go と同じ値かは、Go が読んで書き直した `want` を Rust が読んだ値と比べる。Go が誤りにする例は
/// Rust も拒む。
#[test]
fn quirks_follow_the_two_tier_rule() {
    let quirks: Vec<Quirk> = serde_json::from_str(&fixture("quirks.json")).unwrap();
    assert!(!quirks.is_empty());
    for q in quirks {
        let got = match (&q.input, &q.input_base64) {
            (Some(i), _) => Message::decode(i),
            (None, Some(b)) => Message::decode_bytes(&STANDARD.decode(b).unwrap()),
            (None, None) => panic!("{}: no input", q.name),
        };
        if q.error {
            assert!(
                got.is_err(),
                "{}: Go rejects it, Rust accepted {got:?}",
                q.name
            );
            continue;
        }
        let want = Message::decode(
            q.want
                .as_deref()
                .unwrap_or_else(|| panic!("{}: no want", q.name)),
        );
        match q.rust.as_str() {
            "must-accept" => {
                let got = got.unwrap_or_else(|e| panic!("{}: must accept: {e}", q.name));
                assert_eq!(Some(&got), want.as_ref().ok(), "{}", q.name);
            }
            "may-reject" => {
                if let Ok(got) = got {
                    assert_eq!(
                        Some(&got),
                        want.as_ref().ok(),
                        "{}: accepted with another value than Go",
                        q.name
                    );
                }
            }
            other => panic!("{}: unknown tier {other}", q.name),
        }
    }
}

#[derive(Deserialize)]
struct Reason {
    name: String,
    /// 入力。不正な UTF-8 の例は `in_base64` だけを持ち、Rust の文字列は持てないので照らさない
    #[serde(rename = "in", default)]
    input: Option<String>,
    out: String,
}

#[test]
fn reasons_are_clipped_like_go() {
    let reasons: Vec<Reason> = serde_json::from_str(&fixture("reasons.json")).unwrap();
    assert!(!reasons.is_empty());
    let mut checked = 0;
    for r in reasons {
        let Some(input) = r.input else { continue };
        assert_eq!(
            sanitize_and_clip(&input, REASON_MAX_BYTES),
            r.out,
            "{}",
            r.name
        );
        checked += 1;
    }
    assert!(checked > 0);
}

#[derive(Deserialize)]
struct Close {
    case: String,
    code: i64,
}

/// close の fixture の符号は、Rust が知る符号か、WebSocket の 1008 か、close のフレームが無いこと (-1) の
/// どれかである。
#[test]
fn close_codes_are_known() {
    let closes: Vec<Close> = serde_json::from_str(&fixture("close.json")).unwrap();
    for c in closes {
        let known = c.code == -1
            || c.code == i64::from(wgft_proto::CLOSE_POLICY_VIOLATION)
            || c.code == 1011
            || u16::try_from(c.code)
                .ok()
                .and_then(CloseCode::from_code)
                .is_some();
        assert!(known, "{}: {}", c.case, c.code);
    }
}
