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

/// `IntN` の棄却の枝を、Go の試験 (`TestScriptRNGIntN`) が書いた `scripts/testdata/rng-intn.json` と照らします。
/// 最初の行は、最初の `IntN(20000)` の値が棄却される状態から始まります。
#[test]
fn int_n_rejection_matches_go() {
    use wgft_tcpharness::rng::Pcg;
    let cases: [(u64, u64, u64); 4] = [
        (6_951_352_846_511_211_335, 15_097_960_536_887_720_410, 20000),
        (1, 2, 3 << 61),
        (5, 7, (1 << 62) + 1),
        (0, 0, i64::MAX.unsigned_abs()),
    ];
    // 最初の行が本当に棄却の枝を通ることを、同じ状態の最初の値から確かめる
    let (s1, s2, n) = cases[0];
    let x = Pcg::new(s1, s2).uint64();
    let lo = u128::from(x) * u128::from(n) % (1 << 64);
    assert!(
        lo < u128::from(n.wrapping_neg() % n),
        "the first draw is not rejected"
    );
    let rows = cases
        .iter()
        .map(|&(s1, s2, n)| {
            let mut pcg = Pcg::new(s1, s2);
            let draws = (0..8)
                .map(|_| Json::Str(pcg.int_n(n).to_string()))
                .collect();
            Json::fields([
                ("seed1", Json::Str(s1.to_string())),
                ("seed2", Json::Str(s2.to_string())),
                ("n", Json::Str(n.to_string())),
                ("draws", Json::Arr(draws)),
                ("uint32_after", Json::Uint(pcg.uint32().into())),
            ])
        })
        .collect();
    let mut got = Json::Arr(rows).to_bytes();
    got.push(b'\n');
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../internal/tcpharness/scripts/testdata/rng-intn.json");
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
