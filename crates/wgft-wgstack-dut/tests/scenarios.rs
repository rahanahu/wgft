//! 台本の言語の台本を、同じプロセスの Rust の wgstack に Rust の runner で流します
//! (`docs/design/v2/test-tooling.md` の 2 節)。台本ごとに 1 つの試験です。
//!
//! 結果は期待した差の一覧 (`internal/tcpharness/rustdut/known-wgstack-rs.json`) と照らします。
//!
//! 流すのは、台本が使う機能が Rust の wgstack に入った台本だけです。台本の使う機能は、同じ台本の Go の記録
//! (`testdata/wgstack-rec/scenarios/<台本>.seed-1.rec.gz`) の印で決め、印がすべて `stages.json` の入れた段の
//! 印の中にあれば流します。既定の記録が収まらず 4b の変種の記録 (`.seed-1.4b.rec.gz`) が収まる台本は、その
//! 変種と同じ `HELLO` (NewReno、boost を与えない) で流します。どちらも収まらない台本は ignored です。
//!
//! 台本の種は Go と同じく環境変数 `WGFT_TEST_TCPHARNESS_SEED` で固定でき、固定しなければ乱数で選んで失敗の
//! 文に出します。

use std::hash::{BuildHasher, RandomState};
use std::io;
use std::path::{Path, PathBuf};
use std::{env, fs};

use libtest_mimic::{Arguments, Failed, Trial};
use wgft_tcpharness::chacha8::hello_seed;
use wgft_tcpharness::dut::Recorded;
use wgft_tcpharness::frame::{Boost, Clock, Congestion, Hello, Msg, VERSION};
use wgft_tcpharness::rng::{SEED_ENV, scenario_seed};
use wgft_tcpharness::runner::{
    DUT_ADDR, KNOWN_WGSTACK_RS, KnownList, MTU, RunConfig, parse_known, run_script,
};
use wgft_tcpharness::script::{Script, parse_script};
use wgft_wgstack_dut::dut::{ENGINE, WgstackDut};
use wgft_wgstack_dut::rec::{self, Stages, TagFilter};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn scripts() -> Vec<(String, Script)> {
    let dir = repo().join("internal/tcpharness/scripts");
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "scn"))
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|p| {
            let name = p.file_stem().expect("stem").to_string_lossy().into_owned();
            let file = format!("scripts/{name}.scn");
            let s = parse_script(&file, &fs::read(&p).expect("read the script"))
                .unwrap_or_else(|e| panic!("{e}"));
            (name, s)
        })
        .collect()
}

/// 台本を流す `HELLO` の試験の選択か、流せない理由です。
fn choice(name: &str, filter: &TagFilter) -> Result<(Boost, Congestion), String> {
    let dir = repo().join("testdata/wgstack-rec/scenarios");
    let tags = |suffix: &str| {
        let p = dir.join(format!("{name}.seed-1{suffix}.rec.gz"));
        p.exists()
            .then(|| rec::read_meta(&p).unwrap_or_else(|e| panic!("{e}")).tags)
    };
    let Some(def) = tags("") else {
        return Err(format!("no recording of {name} tells the features it uses"));
    };
    let missing = filter.missing(&def);
    if missing.is_empty() {
        return Ok((Boost::OnDemand, Congestion::Cubic));
    }
    if let Some(v) = tags(".4b")
        && filter.missing(&v).is_empty()
    {
        return Ok((Boost::Never, Congestion::NewReno));
    }
    Err(format!("uses features not landed: {}", missing.join(",")))
}

fn run_seed() -> Result<u64, Failed> {
    match env::var(SEED_ENV) {
        Ok(v) => v
            .parse()
            .map_err(|_| format!("{SEED_ENV}={v:?} is not an unsigned integer").into()),
        Err(_) => Ok(RandomState::new().hash_one(0u8)),
    }
}

fn run(name: &str, s: &Script, (boost, congestion): (Boost, Congestion)) -> Result<(), Failed> {
    let p = repo().join(KNOWN_WGSTACK_RS);
    let known: KnownList =
        parse_known(&fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?)?;
    let run = run_seed()?;
    let seed = scenario_seed(run, name);
    let hello = Hello {
        version: VERSION,
        clock: Clock::Fake,
        addr: DUT_ADDR,
        mtu: u32::try_from(MTU).expect("small MTU"),
        seed: hello_seed(seed),
        limits: Vec::new(),
        boost,
        congestion,
    };
    let dut = WgstackDut::new(&hello).map_err(|e| format!("HELLO: {e}"))?;
    let ok = Msg::HelloOk {
        engine: ENGINE.to_owned(),
        version: VERSION,
    };
    // 別のプロセスを叩く時と同じ呼び出しの列にするため、送り直さない規則を持つ包みを通す
    let mut d = Recorded::new(dut, io::sink(), &hello, &ok).map_err(|e| e.to_string())?;
    let cfg = RunConfig {
        engine: ENGINE,
        known: &known,
        dut_addr: DUT_ADDR,
        mtu: MTU,
        seed,
    };
    let out = run_script(&mut d, &format!("scripts/{name}.scn"), s, &cfg);
    for l in &out.lines {
        println!("{l}");
    }
    let mut errs = out.failures.clone();
    for k in out.unreached(&known, name) {
        errs.push(format!(
            "known difference {k} on {ENGINE}: no check reached it; fix its key or remove it"
        ));
    }
    if out.failed && errs.is_empty() {
        errs.push("the script failed".to_owned());
    }
    if let Err(e) = d.inner().check_invariants() {
        errs.push(e);
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "run seed {run}; replay with {SEED_ENV}={run}\n{}",
            errs.join("\n")
        )
        .into())
    }
}

fn main() {
    let args = Arguments::from_args();
    let stages_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("stages.json");
    let stages = Stages::parse(&fs::read(&stages_path).expect("read stages.json"))
        .unwrap_or_else(|e| panic!("{}: {e}", stages_path.display()));
    let filter = TagFilter::Only(stages.tags());
    let mut ignored = Vec::new();
    let trials = scripts()
        .into_iter()
        .map(|(name, s)| {
            let c = choice(&name, &filter);
            if let Err(why) = &c {
                ignored.push(format!("{name}: {why}"));
            }
            let skip = c.is_err();
            // ignored の台本も --include-ignored では既定の選択で流す
            let c = c.unwrap_or((Boost::OnDemand, Congestion::Cubic));
            Trial::test(name.clone(), move || run(&name, &s, c)).with_ignored_flag(skip)
        })
        .collect();
    for i in &ignored {
        eprintln!("scenarios: ignored {i}");
    }
    libtest_mimic::run(&args, trials).exit();
}
