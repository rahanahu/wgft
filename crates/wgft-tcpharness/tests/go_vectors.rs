//! Go のコードの写しを、Go の試験 (`TestRustVectors`) が書いた `internal/tcpharness/rustdut/testdata/vectors.json`
//! と照らします。HELLO の種 (`math/rand/v2` の ChaCha8)、`strconv.Quote`、`strconv.FormatFloat` の 'f' です。

use std::fs;
use std::path::Path;

use wgft_tcpharness::chacha8::hello_seed;
use wgft_tcpharness::gojson::{self, Json};
use wgft_tcpharness::runner::{go_float_f, go_quote};

fn vectors() -> Json {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../internal/tcpharness/rustdut/testdata/vectors.json");
    gojson::parse(&fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))).expect("JSON")
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        use std::fmt::Write as _;
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn items<'a>(v: &'a Json, k: &str) -> &'a [Json] {
    v.get(k).and_then(Json::as_array).expect("array")
}

#[test]
fn hello_seed_matches_go() {
    let v = vectors();
    for s in items(&v, "seeds") {
        let seed = s.get("seed").and_then(Json::as_u64).expect("seed");
        let want = s.get("hello").and_then(Json::as_str).expect("hello");
        assert_eq!(hex(&hello_seed(seed)), want, "seed {seed}");
    }
}

#[test]
fn quote_matches_go() {
    let v = vectors();
    for q in items(&v, "quote") {
        let input = unhex(q.get("in").and_then(Json::as_str).expect("in"));
        let want = q.get("out").and_then(Json::as_str).expect("out");
        assert_eq!(go_quote(&input), want, "input {input:02x?}");
    }
}

#[test]
fn format_float_matches_go() {
    let v = vectors();
    for f in items(&v, "float") {
        let nanos = match f.get("nanos").expect("nanos") {
            Json::Int(n) => *n,
            Json::Uint(n) => i64::try_from(*n).expect("i64"),
            other => panic!("nanos {other:?}"),
        };
        let prec =
            usize::try_from(f.get("prec").and_then(Json::as_u64).expect("prec")).expect("usize");
        let want = f.get("out").and_then(Json::as_str).expect("out");
        // Go の Duration.Seconds と同じ式
        #[expect(clippy::cast_precision_loss, reason = "Go's Duration.Seconds")]
        let secs = (nanos / 1_000_000_000) as f64 + (nanos % 1_000_000_000) as f64 / 1e9;
        assert_eq!(
            go_float_f(secs, prec),
            want,
            "{nanos} ns with {prec} digits"
        );
    }
}
