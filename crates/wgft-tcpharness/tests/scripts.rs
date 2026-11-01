//! 台本ごとに 1 つの試験として、Rust の runner で台本を別のプロセスの DUT に流します
//! (`docs/design/v2/test-tooling.md` の 2 節)。
//!
//! DUT のバイナリは環境変数 `WGFT_TEST_WGSTACK_DUT` で受けます。無ければ試験はすべて ignored です。
//!
//! - DUT が凍結した Go の wgstack の `dutserve` (engine の名前 `wgstack`) なら、2 つの runner の一致を
//!   確かめます。Go の試験 `TestWriteTranscripts` が `WGFT_TEST_TCPHARNESS_TRANSCRIPTS` の directory に
//!   書いた transcript と確かめの trace を、種 1 から 5 で byte の単位で照らします。Go の試験が書いた期待した
//!   差の小さな一覧 (`known.json`) に鍵を持つ台本は、その一覧を持たせた別の engine の名前で 2 回目も流し、
//!   届かなかった項目も照らします。`WGFT_TEST_TCPHARNESS_TRANSCRIPTS` を与えたら、DUT は `dutserve` でなければ
//!   なりません
//! - DUT が Rust の wgstack (`wgstack-rs`) なら、期待した差の一覧
//!   (`internal/tcpharness/rustdut/known-wgstack-rs.json`) と照らして台本の結果を確かめます

use std::fmt::Write as _;
use std::hash::{BuildHasher, RandomState};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::{env, fs};

use libtest_mimic::{Arguments, Failed, Trial};
use wgft_tcpharness::chacha8::hello_seed;
use wgft_tcpharness::dut::{ProcessDut, Recorded};
use wgft_tcpharness::frame::{self, Boost, Clock, Congestion, Hello, Msg, VERSION};
use wgft_tcpharness::rng::{SEED_ENV, scenario_seed};
use wgft_tcpharness::runner::{
    DUT_ADDR, KNOWN_WGSTACK_RS, KnownList, MTU, Outcome, RunConfig, parse_known, run_script,
};
use wgft_tcpharness::script::{Script, parse_script};

/// DUT のバイナリの環境変数です。Go の `rustdut.BinEnv` と同じです。
const BIN_ENV: &str = "WGFT_TEST_WGSTACK_DUT";
/// Go の runner の transcript の directory の環境変数です。Go の `rustdut.TranscriptDirEnv` と同じです。
const TRANSCRIPTS_ENV: &str = "WGFT_TEST_TCPHARNESS_TRANSCRIPTS";
/// 2 つの runner を照らす実行の種です。Go の `transcriptRuns` と同じです。
const TRANSCRIPT_RUNS: [u64; 5] = [1, 2, 3, 4, 5];
/// 照らす時の engine の名前です。Go の `TestWriteTranscripts` と同じです。
const COMPARE_ENGINE: &str = "go-wgstack";
/// 期待した差の一覧を持たせて照らす 2 回目の engine の名前です。Go の `transcriptKnownEngine` と同じです。
const KNOWN_ENGINE: &str = "go-wgstack-known";

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
            let src = fs::read(&p).expect("read the script");
            let s = parse_script(&file, &src).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(s.name, name, "{file}: the header names another scenario");
            (name, s)
        })
        .collect()
}

fn hello(seed: u64) -> Hello {
    Hello {
        version: VERSION,
        clock: Clock::Fake,
        addr: DUT_ADDR,
        mtu: u32::try_from(MTU).expect("small MTU"),
        seed: hello_seed(seed),
        limits: Vec::new(),
        boost: Boost::OnDemand,
        congestion: Congestion::Cubic,
    }
}

/// DUT の標準エラーの行を集めます。
type Log = Arc<Mutex<Vec<String>>>;

fn spawn(bin: &Path, seed: u64, log: &Log) -> Result<ProcessDut, Failed> {
    let l = log.clone();
    ProcessDut::spawn(bin, hello(seed), move |line| {
        l.lock().expect("log").push(line.to_owned());
    })
    .map_err(|e| format!("starting {}: {e}", bin.display()).into())
}

/// 1 回の実行です。transcript の bytes、結果、frame の数を返します。
fn run_once(
    bin: &Path,
    s: &Script,
    seed: u64,
    engine: Option<&str>,
    known: &KnownList,
) -> Result<(Vec<u8>, Outcome, u64), Failed> {
    let log = Log::default();
    let dut = spawn(bin, seed, &log)?;
    let name = engine.map_or_else(|| dut.engine().to_owned(), str::to_owned);
    let (h, ok) = (dut.hello().clone(), dut.hello_ok().clone());
    let mut rec = Recorded::new(dut, Vec::new(), &h, &ok).map_err(|e| e.to_string())?;
    let cfg = RunConfig {
        engine: &name,
        known,
        dut_addr: DUT_ADDR,
        mtu: MTU,
        seed,
    };
    let file = format!("scripts/{}.scn", s.name);
    let out = run_script(&mut rec, &file, s, &cfg);
    let frames = rec.frames();
    let (mut dut, transcript) = rec.into_parts();
    if let Err(e) = dut.close() {
        return Err(format!("{e}\nDUT log:\n{}", log.lock().expect("log").join("\n")).into());
    }
    Ok((transcript, out, frames))
}

/// transcript の frame の列です。
fn frames(b: &[u8]) -> Vec<Result<Msg, String>> {
    let mut r = b;
    let mut out = Vec::new();
    loop {
        match frame::read_frame(&mut r) {
            Ok((k, body)) => out.push(Msg::decode(k, &body).map_err(|e| e.to_string())),
            Err(frame::FrameError::Eof) => return out,
            Err(e) => {
                out.push(Err(e.to_string()));
                return out;
            }
        }
    }
}

/// 2 つの transcript の最初に違う frame とその前後です。
fn transcript_diff(want: &[u8], got: &[u8]) -> String {
    let (w, g) = (frames(want), frames(got));
    let show = |f: Option<&Result<Msg, String>>| match f {
        Some(Ok(m)) => m.to_string(),
        Some(Err(e)) => format!("bad frame: {e}"),
        None => "(end)".to_owned(),
    };
    let Some(i) = (0..w.len().max(g.len())).find(|&i| w.get(i) != g.get(i)) else {
        return format!(
            "the frames decode the same; {} and {} bytes",
            want.len(),
            got.len()
        );
    };
    let mut out = format!(
        "first difference at frame {i} of {} (Go) and {} (Rust):\n",
        w.len(),
        g.len()
    );
    for j in i.saturating_sub(4)..i {
        let _ = writeln!(out, "  both  {}", show(w.get(j)));
    }
    let _ = writeln!(
        out,
        "  Go    {}
  Rust  {}",
        show(w.get(i)),
        show(g.get(i))
    );
    out
}

fn trace_diff(want: &[u8], got: &[u8]) -> String {
    let (w, g) = (String::from_utf8_lossy(want), String::from_utf8_lossy(got));
    let i = w
        .bytes()
        .zip(g.bytes())
        .position(|(a, b)| a != b)
        .unwrap_or(w.len().min(g.len()));
    let from = i.saturating_sub(300);
    format!(
        "check traces differ at byte {i}:\n  Go   ...{}\n  Rust ...{}",
        w.get(from..(i + 200).min(w.len())).unwrap_or(""),
        g.get(from..(i + 200).min(g.len())).unwrap_or("")
    )
}

/// Go の側が書いたファイルを読みます。
fn read_go(p: &Path) -> Result<Vec<u8>, Failed> {
    fs::read(p).map_err(|e| {
        format!(
            "{}: {e}; run the Go side first (TestWriteTranscripts)",
            p.display()
        )
        .into()
    })
}

/// 1 回の実行を Go の側が `<base>.bin`、`<base>.trace.json` (と、一覧を持つ時は `<base>.unreached`) に
/// 書いたものと照らし、違いを `errs` に足します。Rust の側の結果は `<base>.rust.*` に残します。frame の数を
/// 返します。
fn compare_run(
    bin: &Path,
    s: &Script,
    seed: u64,
    base: &str,
    engine: &str,
    known: &KnownList,
    errs: &mut Vec<String>,
) -> Result<u64, Failed> {
    let file = |ext: &str| PathBuf::from(format!("{base}.{ext}"));
    let want_bin = read_go(&file("bin"))?;
    let want_trace = read_go(&file("trace.json"))?;
    let (got_bin, out, frames) = run_once(bin, s, seed, Some(engine), known)?;
    let got_trace = out.trace_json();
    let _ = fs::write(file("rust.bin"), &got_bin);
    let _ = fs::write(file("rust.trace.json"), &got_trace);
    if got_bin != want_bin {
        errs.push(format!(
            "{base}: transcripts differ\n{}",
            transcript_diff(&want_bin, &got_bin)
        ));
    }
    if got_trace != want_trace {
        errs.push(format!("{base}: {}", trace_diff(&want_trace, &got_trace)));
    }
    if !known.is_empty() {
        let want = String::from_utf8_lossy(&read_go(&file("unreached"))?).into_owned();
        let got: String = out
            .unreached(known, &s.name)
            .into_iter()
            .map(|k| k + "\n")
            .collect();
        if got != want {
            errs.push(format!(
                "{base}: unreached known differences differ\n  Go   {want:?}\n  Rust {got:?}"
            ));
        }
    }
    Ok(frames)
}

/// 2 つの runner の一致の確かめです。
fn compare(bin: &Path, dir: &Path, name: &str, s: &Script) -> Result<(), Failed> {
    // 2 回目の期待した差の一覧は Go の側が書きます
    let p = dir.join("known.json");
    let known = parse_known(&read_go(&p)?).map_err(|e| format!("{}: {e}", p.display()))?;
    let mut errs = Vec::new();
    let mut total = (0u64, std::time::Duration::ZERO);
    let listed = known.keys().any(|k| k.starts_with(&format!("{name}/")));
    for run in TRANSCRIPT_RUNS {
        let base = dir.join(name).join(run.to_string());
        let base = base.to_string_lossy();
        let seed = scenario_seed(run, name);
        let start = Instant::now();
        total.0 += compare_run(
            bin,
            s,
            seed,
            &base,
            COMPARE_ENGINE,
            &KnownList::new(),
            &mut errs,
        )?;
        total.1 += start.elapsed();
        if listed {
            compare_run(
                bin,
                s,
                seed,
                &format!("{base}.known"),
                KNOWN_ENGINE,
                &known,
                &mut errs,
            )?;
        }
    }
    let rt = total.0 / 2;
    #[expect(clippy::cast_precision_loss, reason = "a rough per round trip figure")]
    let per = total.1.as_secs_f64() * 1e6 / rt.max(1) as f64;
    println!(
        "{name}: {rt} round trips in {:.0} ms over {} runs, {per:.1} us per round trip including the runner",
        total.1.as_secs_f64() * 1e3,
        TRANSCRIPT_RUNS.len()
    );
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join("\n").into())
    }
}

fn run_seed() -> Result<u64, Failed> {
    match env::var(SEED_ENV) {
        Ok(v) => v
            .parse()
            .map_err(|_| format!("{SEED_ENV}={v:?} is not an unsigned integer").into()),
        Err(_) => Ok(RandomState::new().hash_one(0u8)),
    }
}

/// Rust の wgstack とほかの engine の実行です。
fn conform(bin: &Path, name: &str, s: &Script, engine: &str) -> Result<(), Failed> {
    let known = if engine == "wgstack-rs" {
        let p = repo().join(KNOWN_WGSTACK_RS);
        parse_known(&fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?)?
    } else {
        KnownList::new()
    };
    let run = run_seed()?;
    let seed = scenario_seed(run, name);
    let (_, out, _) = run_once(bin, s, seed, None, &known)?;
    for l in &out.lines {
        println!("{l}");
    }
    let mut errs = out.failures.clone();
    for k in out.unreached(&known, name) {
        errs.push(format!(
            "known difference {k} on {engine}: no check reached it; fix its key or remove it"
        ));
    }
    if out.failed && errs.is_empty() {
        errs.push("the script failed".to_owned());
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
    let bin = env::var_os(BIN_ENV).map(PathBuf::from);
    let dir = env::var_os(TRANSCRIPTS_ENV).map(PathBuf::from);
    let engine = Arc::new(Mutex::new(None::<String>));
    let trials = scripts()
        .into_iter()
        .map(|(name, s)| {
            let (bin, dir, engine) = (bin.clone(), dir.clone(), engine.clone());
            let ignored = bin.is_none();
            Trial::test(name.clone(), move || {
                let Some(bin) = bin else {
                    return Err(format!("set {BIN_ENV} to a DUT binary").into());
                };
                // engine の名前は最初の試験が DUT に尋ねる
                let e = {
                    let mut e = engine.lock().expect("engine");
                    if e.is_none() {
                        let log = Log::default();
                        let mut d = spawn(&bin, 1, &log)?;
                        *e = Some(d.engine().to_owned());
                        d.close().map_err(|e| e.to_string())?;
                    }
                    e.clone().unwrap_or_default()
                };
                match (e == "wgstack", dir) {
                    (true, Some(dir)) => compare(&bin, &dir, &name, &s),
                    (true, None) => Err(format!(
                        "{BIN_ENV} names the Go wgstack's dutserve: set {TRANSCRIPTS_ENV} to the directory the Go test TestWriteTranscripts wrote"
                    )
                    .into()),
                    // 照らすつもりで別の DUT を与えると、Go の transcript を照らさずに通ってしまうので断る
                    (false, Some(_)) => Err(format!(
                        "{TRANSCRIPTS_ENV} asks for the runner comparison, which needs the Go wgstack's dutserve, but {BIN_ENV} names the engine {e}"
                    )
                    .into()),
                    (false, None) => conform(&bin, &name, &s, &e),
                }
            })
            .with_ignored_flag(ignored)
        })
        .collect();
    libtest_mimic::run(&args, trials).exit();
}
