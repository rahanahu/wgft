//! 手元の完全な記録の集まりを Rust の wgstack で照らし、Go と違う記録から完全な集まりの意図した違いの一覧
//! (`testdata/wgstack-rec/divergences-full.json`) を作り直します (`docs/design/v2/test-tooling.md` の 4 節)。
//!
//! ```text
//! WGFT_WGSTACK_REPLAY_DIR=DIR cargo run --release -p wgft-wgstack-dut --example divergences_full -- \
//!     [--check] [--prune] [--reason TEXT] [--report FILE]
//! ```
//!
//! 照らすのは、照合 (`tests/replay.rs`) と同じく印が入った段の中にある記録だけです。食い違った記録ごとに、名前か
//! frame の列の SHA-256、最初に食い違う要求、Rust の応答の SHA-256 を求め、今の一覧の行と比べます。
//!
//! - kept:今の一覧と同じ位置と応答の行です。理由を引き継ぎます
//! - new:一覧に行の無い違いです
//! - changed:一覧の行と位置か応答が違います
//! - invariant:核の不変条件が破れました。一覧には載せられないので、いつも失敗にします
//! - dropped:一覧の行の記録が、今は Go と一致します
//! - absent:hash で引く行のうち、記録が手元に無い行です。`--prune` が無ければ残します
//!
//! new と changed の行は、分類 (意図した違いか退行か) を人が決めてから `--reason` で理由を渡します。
//! `--reason` が無ければ一覧を書かずに 1 で終えます。`--check` は一覧を書かず、作り直した一覧が今の一覧と
//! 違えば 1 で終えます。標準出力には、食い違ったすべての記録を `<鍵>\t<要求>\t<応答の SHA-256>\t<状態>` の
//! 1 行ずつで、鍵の順に出します (`--report` はそのファイルにも書きます)。鍵は名前か `sha256:<hash>` です。
//! 基の核と変えた核で同じ集まりを照らした出力を比べると、変更で生じた違いが分かります。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{env, fs, process, thread};

use wgft_wgstack_dut::rec::{self, FullDivergence, FullDivergences, Outcome, Stages, TagFilter};

const LIST: &str = "testdata/wgstack-rec/divergences-full.json";

fn walk(d: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(d).unwrap_or_else(|e| panic!("{}: {e}", d.display())) {
        let p = e.expect("directory entry").path();
        if p.is_dir() {
            walk(&p, out);
        } else if p.to_string_lossy().ends_with(".rec.gz") {
            out.push(p);
        }
    }
}

/// 1 つの記録を照らした結果です。
struct Seen {
    id: String,
    /// `fuzzcore/cache-*` の記録の frame の列の SHA-256
    sha256: Option<String>,
    /// 食い違った要求、応答の SHA-256、不変条件の破れ
    diverged: Option<(usize, String, Option<String>)>,
}

struct Args {
    check: bool,
    prune: bool,
    reason: Option<String>,
    report: Option<PathBuf>,
}

fn args() -> Args {
    let mut a = Args {
        check: false,
        prune: false,
        reason: None,
        report: None,
    };
    let mut it = env::args().skip(1);
    while let Some(x) = it.next() {
        match x.as_str() {
            "--check" => a.check = true,
            "--prune" => a.prune = true,
            "--reason" => a.reason = Some(it.next().expect("--reason needs a text")),
            "--report" => a.report = Some(PathBuf::from(it.next().expect("--report needs a file"))),
            _ => {
                eprintln!(
                    "usage: divergences_full [--check] [--prune] [--reason TEXT] [--report FILE]"
                );
                process::exit(2);
            }
        }
    }
    a
}

fn replay_all(paths: &[PathBuf]) -> Vec<Seen> {
    let next = AtomicUsize::new(0);
    let out = Mutex::new(Vec::with_capacity(paths.len()));
    let workers = thread::available_parallelism().map_or(1, usize::from);
    thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(p) = paths.get(i) else { break };
                    let r = rec::read_file(p).unwrap_or_else(|e| panic!("{e}"));
                    let id = r.id();
                    let sha256 = id
                        .starts_with(rec::FUZZ_CACHE_PREFIX)
                        .then(|| rec::frames_sha256(&r));
                    let diverged = match rec::replay(&r).unwrap_or_else(|e| panic!("{id}: {e}")) {
                        Outcome::Match { .. } => None,
                        Outcome::Diverged(m) => {
                            Some((m.request, rec::response_sha256(&m.got), m.invariant))
                        }
                    };
                    out.lock().expect("lock").push(Seen {
                        id,
                        sha256,
                        diverged,
                    });
                }
            });
        }
    });
    out.into_inner().expect("lock")
}

fn main() {
    let a = args();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let Some(dir) = env::var_os("WGFT_WGSTACK_REPLAY_DIR").map(PathBuf::from) else {
        eprintln!("divergences_full: set WGFT_WGSTACK_REPLAY_DIR to the full set");
        process::exit(2);
    };
    let list_path = root.join(LIST);
    let old_text = fs::read_to_string(&list_path).expect("read divergences-full.json");
    let old = FullDivergences::parse(old_text.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
    let stages_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("stages.json");
    let stages = Stages::parse(&fs::read(&stages_path).expect("read stages.json"))
        .unwrap_or_else(|e| panic!("{e}"));
    let filter = TagFilter::Only(stages.tags());

    let mut paths = Vec::new();
    walk(&dir, &mut paths);
    paths.sort();
    paths.retain(|p| {
        let m = rec::read_meta(p).unwrap_or_else(|e| panic!("{e}"));
        filter.missing(&m.tags).is_empty()
    });
    let seen = replay_all(&paths);

    let mut rows: Vec<FullDivergence> = Vec::new();
    let mut report: BTreeMap<String, String> = BTreeMap::new();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut present_hashes = BTreeSet::new();
    let mut present_named = BTreeSet::new();
    for s in &seen {
        let old_row = if let Some(h) = &s.sha256 {
            present_hashes.insert(h.clone());
            old.rows().find(|r| r.sha256.as_deref() == Some(h))
        } else {
            present_named.insert(s.id.clone());
            old.rows().find(|r| r.sha256.is_none() && r.record == s.id)
        };
        let key = s
            .sha256
            .as_ref()
            .map_or_else(|| s.id.clone(), |h| format!("sha256:{h}"));
        let Some((request, resp, inv)) = &s.diverged else {
            if old_row.is_some() {
                *counts.entry("dropped").or_default() += 1;
                eprintln!("dropped: {key} ({}) matches Go now", s.id);
            }
            continue;
        };
        let status = if inv.is_some() {
            "invariant"
        } else {
            match old_row {
                Some(r) if r.request == *request && r.response_sha256 == *resp => "kept",
                Some(_) => "changed",
                None => "new",
            }
        };
        *counts.entry(status).or_default() += 1;
        report.insert(key.clone(), format!("{key}\t{request}\t{resp}\t{status}"));
        if let Some(e) = inv {
            eprintln!("invariant: {} at request {request}: {e}", s.id);
            continue;
        }
        let reason = match (status, old_row, &a.reason) {
            ("kept", Some(r), _) => r.reason.clone(),
            (_, _, Some(t)) => t.clone(),
            _ => continue,
        };
        rows.push(FullDivergence {
            record: s.id.clone(),
            sha256: s.sha256.clone(),
            request: *request,
            response_sha256: resp.clone(),
            reason,
        });
    }
    // 手元に無い記録の行。hash の行は --prune が無ければ残し、名前の行は照合が落とすので残しません。
    for r in old.rows() {
        match &r.sha256 {
            Some(h) if !present_hashes.contains(h) => {
                *counts.entry("absent").or_default() += 1;
                if !a.prune {
                    rows.push(r.clone());
                }
            }
            None if !present_named.contains(&r.record) => {
                *counts.entry("dropped").or_default() += 1;
                eprintln!("dropped: {} is not in {}", r.record, dir.display());
            }
            _ => {}
        }
    }

    let mut text = String::new();
    for l in report.values() {
        text.push_str(l);
        text.push('\n');
    }
    print!("{text}");
    if let Some(p) = &a.report {
        fs::write(p, &text).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    }
    eprintln!(
        "divergences_full: {} recordings replayed from {}; {counts:?}",
        seen.len(),
        dir.display()
    );
    let new_text = rec::write_full_divergences(&rows);
    let unclassified =
        (counts.get("new").copied().unwrap_or(0) + counts.get("changed").copied().unwrap_or(0)) > 0
            && a.reason.is_none();
    if counts.contains_key("invariant") {
        eprintln!(
            "divergences_full: a core invariant broke; that is a regression, not a divergence"
        );
        process::exit(1);
    }
    if a.check {
        if new_text != old_text {
            eprintln!(
                "divergences_full: {} is not what this set and core give",
                list_path.display()
            );
            process::exit(1);
        }
        return;
    }
    if unclassified {
        eprintln!(
            "divergences_full: new or changed differences need a classification; pass --reason after classifying them"
        );
        process::exit(1);
    }
    fs::write(&list_path, new_text).unwrap_or_else(|e| panic!("{}: {e}", list_path.display()));
    eprintln!(
        "divergences_full: wrote {} rows to {}",
        rows.len(),
        list_path.display()
    );
}
