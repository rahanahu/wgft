//! Go のコードの写しを、Go の試験 (`TestRustVectors`) が書いた `internal/tcpharness/rustdut/testdata/vectors.json`
//! と照らします。HELLO の種 (`math/rand/v2` の ChaCha8) です。

use std::fs;
use std::path::Path;

use wgft_tcpharness::chacha8::hello_seed;
use wgft_tcpharness::gojson::{self, Json};

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
