//! 台本の乱数の写しを、Go の試験 (`TestScriptRNGVectors`) が書いた `scripts/testdata/rng.json` と照らします。
//! 実行の種と台本の名前の組は Go の試験と同じで、Rust の側が同じ bytes の JSON を作ります。

use std::fs;
use std::path::Path;

use wgft_tcpharness::gojson::Json;
use wgft_tcpharness::rng::{ScriptRng, scenario_seed};

#[test]
fn rng_matches_go() {
    // Go の TestScriptRNGVectors と同じ組。変えるときは両方を直す
    let runs = [0, 1, 5, 0x9e37_79b9_7f4a_7c15, u64::MAX];
    let names = ["fin-passive-close", "handshake-options", ""];
    let mut out = Vec::new();
    for run in runs {
        for name in names {
            let seed = scenario_seed(run, name);
            let mut rng = ScriptRng::new(seed);
            let peers = (0..4)
                .map(|_| {
                    let p = rng.new_peer();
                    Json::fields([
                        ("port", Json::Uint(p.port.into())),
                        ("iss", Json::Uint(p.iss.into())),
                        ("ts_base", Json::Uint(p.ts_base.into())),
                    ])
                })
                .collect();
            out.push(Json::fields([
                ("run_seed", Json::Str(run.to_string())),
                ("scenario", Json::Str(name.to_owned())),
                ("scenario_seed", Json::Str(seed.to_string())),
                ("peers", Json::Arr(peers)),
            ]));
        }
    }
    let mut got = Json::Arr(out).to_bytes();
    got.push(b'\n');
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../internal/tcpharness/scripts/testdata/rng.json");
    let want: Vec<u8> = fs::read(&path)
        .unwrap()
        .into_iter()
        .filter(|&b| b != b'\r')
        .collect();
    assert_eq!(
        String::from_utf8(got).unwrap(),
        String::from_utf8(want).unwrap()
    );
}
