//! 凍結した Go の wgstack の記録を Rust の wgstack で照らします (`docs/design/v2/test-tooling.md` の 4 節)。
//!
//! 記録ごとに 1 つの試験です。`HELLO` から Rust の wgstack を作り、要求を 1 つずつ同じプロセスの server の処理に
//! 渡し、応答の frame を記録と byte の単位で比べ、最初に食い違った所で止めます。
//!
//! 照らすのは、印がすべて Rust の wgstack が入れた段 (`stages.json` の `landed`) の印の中にある記録だけです。
//! 残りの記録は ignored の試験として数え、`cargo nextest run -p wgft-wgstack-dut --run-ignored all`
//! (`cargo test -p wgft-wgstack-dut` では `-- --include-ignored`) で照らせます。意図した違いの一覧 (`testdata/wgstack-rec/divergences.json`) と同じ
//! 位置で同じ応答に食い違った記録は、既知の違いとして通します。
//!
//! 環境変数 `WGFT_WGSTACK_REPLAY_DIR` で、git の集まりの代わりに手元の cache の集まりを照らせます。Go の
//! `TestRecordingsReplay` と同じ変数です。`WGFT_WGSTACK_REPLAY_SHARD=i/n` (0 ≤ i < n) は、名前の順の記録の
//! うち番号を n で割った余りが i のものだけを照らします。大きな集まりを関門の段に分けるためです。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use std::{env, fs};

use libtest_mimic::{Arguments, Failed, Trial};
use wgft_wgstack_dut::rec::{self, Divergence, Stages, TagFilter};

/// 手元の cache の集まりの directory の環境変数です。Go の `TestRecordingsReplay` と同じです。
const DIR_ENV: &str = "WGFT_WGSTACK_REPLAY_DIR";

/// 照らす記録を分ける `i/n` の環境変数です。
const SHARD_ENV: &str = "WGFT_WGSTACK_REPLAY_SHARD";

/// `i/n` を読みます。無ければ `(0, 1)` です。
fn shard() -> (usize, usize) {
    let Some(v) = env::var_os(SHARD_ENV) else {
        return (0, 1);
    };
    let v = v.to_string_lossy();
    let parsed = v
        .split_once('/')
        .and_then(|(i, n)| Some((i.parse::<usize>().ok()?, n.parse::<usize>().ok()?)));
    match parsed {
        Some((i, n)) if i < n => (i, n),
        _ => panic!("{SHARD_ENV}={v:?} is not i/n with 0 <= i < n"),
    }
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `dir` の下の記録 (`*.rec.gz`) のパスを、directory を深さを問わずたどって名前の順に返します。
fn recordings(dir: &Path) -> Vec<PathBuf> {
    fn walk(d: &Path, out: &mut Vec<PathBuf>) {
        for e in fs::read_dir(d).unwrap_or_else(|e| panic!("{}: {e}", d.display())) {
            let p = e.expect("entry").path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.to_string_lossy().ends_with(".rec.gz") {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, &mut out);
    out.sort();
    out
}

fn one(path: &Path, divs: &[Divergence]) -> Result<(), Failed> {
    let r = rec::read_file(path)?;
    let start = Instant::now();
    let out = rec::replay(&r)?;
    let took = start.elapsed();
    let verdict = rec::judge(&r, &out, divs)?;
    println!("{verdict} in {took:.1?}");
    Ok(())
}

fn main() {
    let args = Arguments::from_args();
    let root = repo();
    let dir = env::var_os(DIR_ENV).map_or_else(|| root.join("testdata/wgstack-rec"), PathBuf::from);
    let stages_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("stages.json");
    let stages = Stages::parse(&fs::read(&stages_path).expect("read stages.json"))
        .unwrap_or_else(|e| panic!("{}: {e}", stages_path.display()));
    let filter = TagFilter::Only(stages.tags());
    let divs = Arc::new(
        rec::parse_divergences(
            &fs::read(root.join("testdata/wgstack-rec/divergences.json"))
                .expect("read divergences.json"),
        )
        .expect("divergences.json"),
    );

    let mut skipped: BTreeMap<String, usize> = BTreeMap::new();
    let mut trials = Vec::new();
    let (part, parts) = shard();
    let paths: Vec<PathBuf> = recordings(&dir)
        .into_iter()
        .enumerate()
        .filter(|(i, _)| i % parts == part)
        .map(|(_, p)| p)
        .collect();
    let total = paths.len();
    // 空の directory を照らして通る実行を防ぐ
    assert!(total > 0, "no recordings under {}", dir.display());
    let known = stages.all_tags();
    for p in paths {
        let meta = rec::read_meta(&p).unwrap_or_else(|e| panic!("{e}"));
        // どの段にも無い印は、段の表を足し忘れた印か、記録の作り方の変化
        let unknown: Vec<&String> = meta
            .tags
            .iter()
            .filter(|t| !known.contains(*t) && !t.starts_with("proto-"))
            .collect();
        assert!(
            unknown.is_empty(),
            "{}: tags {unknown:?} are in no stage of stages.json",
            p.display()
        );
        let missing = filter.missing(&meta.tags);
        if !missing.is_empty() {
            *skipped.entry(missing.join(",")).or_default() += 1;
        }
        let divs = divs.clone();
        trials.push(
            Trial::test(format!("{}/{}", meta.source, meta.name), move || {
                one(&p, &divs)
            })
            .with_ignored_flag(!missing.is_empty()),
        );
    }
    let n_skipped: usize = skipped.values().sum();
    eprintln!(
        "replay: {} of {total} recordings in {} have only the tags of the landed stages {:?}",
        total - n_skipped,
        dir.display(),
        stages.landed
    );
    for (tags, n) in &skipped {
        eprintln!("replay: {n} ignored for tags not landed: {tags}");
    }
    libtest_mimic::run(&args, trials).exit();
}
