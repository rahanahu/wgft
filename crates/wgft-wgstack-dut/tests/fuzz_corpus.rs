//! fuzz の target の種と見つけた落ちる入力を stable の build で流します (`docs/design/v2/test-tooling.md` の
//! 6 節)。nightly と cargo-fuzz の無い CI でも、見つけた入力の回帰を確かめるためです。
//!
//! 入力のファイルごとに 1 つの試験です。対象は `crates/wgft-wgstack/fuzz/` の `corpus/<target>/` と
//! `regressions/<target>/` のすべてのファイルです。`core` と `adversarial_sender` の `corpus` は Go の種と、Go
//! の corpus から写した値で、Go の試験 `TestRustFuzzSeeds` が書き出します。`replay` の `corpus` は git の記録の
//! うち `fuzzcore` の記録から example の `replay_seeds` が書いた種です。
//!
//! 敵対的な送り手の種の範囲を、環境変数 `WGFT_WGSTACK_AUDIT_SEEDS` (種の数) と `WGFT_WGSTACK_AUDIT_START`
//! (最初の種、既定は 1) で足せます (Go の `TestAdversarialSender` と同じ名前です)。既定は 0 で、corpus の
//! 種 1 から 8 だけを流します。1 つの種は debug の build で 3 秒ほどかかるので、多くの種はホストの関門が
//! release の build で流します (`scripts/wgstack-gate.sh` の `wgstack-rs-adversarial`)。

use std::path::{Path, PathBuf};
use std::{env, fs};

use libtest_mimic::{Arguments, Trial};
use wgft_wgstack_dut::fuzz;

/// fuzz の target の本体です。
type Body = fn(&[u8]);

/// fuzz の target と本体です。
const TARGETS: [(&str, Body); 3] = [
    ("core", fuzz::core),
    ("adversarial_sender", fuzz::adversarial_sender),
    ("replay", fuzz::replay),
];

/// 既定で足す敵対的な送り手の種の数です。
const AUDIT_SEEDS: u64 = 0;

fn fuzz_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../wgft-wgstack/fuzz")
}

fn files(dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = rd
        .map(|e| e.expect("directory entry").path())
        .filter(|p| p.is_file())
        .collect();
    out.sort();
    out
}

fn env_u64(name: &str, default: u64) -> u64 {
    env::var(name).map_or(default, |v| {
        v.parse()
            .unwrap_or_else(|e| panic!("{name}={v:?} is not a whole number: {e}"))
    })
}

fn main() {
    let args = Arguments::from_args();
    let root = fuzz_dir();
    let mut trials = Vec::new();
    for (target, body) in TARGETS {
        let corpus = files(&root.join("corpus").join(target));
        // 種が無ければ Go の書き出しを忘れた木なので落とす
        assert!(
            !corpus.is_empty(),
            "no seeds under {}; see the module documentation for how they are written",
            root.join("corpus").join(target).display()
        );
        for kind in ["corpus", "regressions"] {
            for p in files(&root.join(kind).join(target)) {
                let name = format!(
                    "{target}/{kind}/{}",
                    p.file_name().expect("file name").to_string_lossy()
                );
                trials.push(Trial::test(name, move || {
                    let data = fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?;
                    body(&data);
                    Ok(())
                }));
            }
        }
    }
    let start = env_u64("WGFT_WGSTACK_AUDIT_START", 1);
    let seeds = env_u64("WGFT_WGSTACK_AUDIT_SEEDS", AUDIT_SEEDS);
    for seed in start..start + seeds {
        trials.push(Trial::test(
            format!("adversarial_sender/seed/{seed}"),
            move || {
                fuzz::adversarial_sender_seed(seed);
                Ok(())
            },
        ));
    }
    libtest_mimic::run(&args, trials).exit();
}
