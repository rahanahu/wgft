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
//!
//! 生の packet の敵 (`raw_adversary`) は corpus を持たず、決まった種から作った入力と、`regressions/raw_adversary/`
//! の見つけた落ちる入力を流します。種の数は `WGFT_WGSTACK_RAW_SEEDS` (既定は 8) で変えられます。
//!
//! `core`、`adversarial_sender`、`raw_adversary`、`replay` の入力は 2 回流します (wgstack-rs.md の「書き換えた所だけの
//! 確かめ」と「核の使い回し」)。どちらも各段で、書き換えた枠だけの確かめとすべての枠の確かめを並べ、答えが
//! 同じことを確かめます。1 回目は新しく作った核で、2 回目はほかのポートを開いて閉じた核の表を使い回した核で
//! 流し、外から見える出力の hash が同じことと、閉じた後に戻した表が新しい表と同じ値であることを確かめます。
//! `replay` の出力の hash は要求ごとの応答と保持です。
//!
//! 環境変数 `WGFT_WGSTACK_CORPUS_DIRS` に `<target>=<directory>` を `,` で区切って渡すと、その directory の
//! ファイルも同じく流します (`raw_adversary` も渡せます)。cargo-fuzz が育てた corpus の被覆を `cargo llvm-cov` で
//! 測るために使います (`docs/design/v2/test-tooling.md` の 6 節の「被覆の地図」)。

use std::net::SocketAddrV4;
use std::path::{Path, PathBuf};
use std::{env, fs};

use libtest_mimic::{Arguments, Trial};
use wgft_wgstack::Limits;
use wgft_wgstack_dut::fuzz::{self, Check, DUT, Net, Options, PEER};

/// fuzz の target の本体です。
type Body = fn(&[u8]);

/// target の表の大きさです。
type Sizes = Option<fn() -> Limits>;

/// fuzz の target と本体と、表の大きさです。
const TARGETS: [(&str, Body, Sizes); 3] = [
    ("core", fuzz::core, Some(fuzz::fuzz_limits)),
    (
        "adversarial_sender",
        fuzz::adversarial_sender,
        Some(adversary_limits),
    ),
    ("replay", fuzz::replay, Some(fuzz::fuzz_limits)),
];

fn adversary_limits() -> Limits {
    Limits {
        udp_rx_datagrams: fuzz::fuzz_limits().udp_rx_datagrams,
        udp_tx_datagrams: fuzz::fuzz_limits().udp_tx_datagrams,
        ..fuzz::small_limits()
    }
}

/// 表の大きさ `limits` の核で、待ち受け、UDP の endpoint、ping、接続を開いて一部を閉じ、表を使い回しに渡します。
/// 次に流す入力の核は、作成の時の値に戻したこの表を使います。
fn dirty(limits: Limits) {
    let mut n = Net::new(
        Net::<wgft_wgstack::NoHook>::config(limits),
        wgft_wgstack::NoHook,
    );
    let now = n.now();
    let st = n.stack();
    let a = st
        .listen_tcp(now, SocketAddrV4::new(DUT, 7))
        .expect("listen");
    st.listen_tcp(now, SocketAddrV4::new(DUT, 81))
        .expect("listen");
    st.close_listener(now, a);
    let u = st
        .bind_udp(now, SocketAddrV4::new(DUT, 8001))
        .expect("bind");
    st.send_to(now, u, &[1; 100], SocketAddrV4::new(PEER, 9))
        .expect("send");
    st.bind_udp(now, SocketAddrV4::new(DUT, 65535))
        .expect("bind");
    st.close_udp(now, u);
    st.open_ping(now, PEER).expect("ping");
    n.check();
    n.drain();
    n.finish();
}

/// `body` に `data` を新しい核と使い回した核で流し、2 つが同じ出力を返すことを確かめます。
fn fresh_and_reused(body: Body, data: &[u8], limits: Limits) -> Result<(), libtest_mimic::Failed> {
    fuzz::set_options(Options {
        check: Check::Both,
        reuse: false,
        digest: true,
    });
    body(data);
    let fresh = fuzz::last_digest();
    fuzz::set_options(Options {
        check: Check::Both,
        reuse: true,
        digest: true,
    });
    dirty(limits);
    // 次の核が表を使い回すことを確かめてから戻します
    let dirtied = fuzz::take_spare().ok_or("no tables kept after dirty")?;
    if dirtied.kept() != 3 {
        return Err(format!("dirty kept {} tables, not 3", dirtied.kept()).into());
    }
    fuzz::put_spare(dirtied);
    body(data);
    let reused = fuzz::last_digest();
    let spare = fuzz::take_spare().ok_or("no tables kept")?;
    fuzz::set_options(Options::FUZZ);
    if fresh != reused {
        return Err("a reused stack gave other output than a new one".into());
    }
    if spare.kept() != 3 || !spare.is_fresh() {
        return Err(format!(
            "the closed stack's tables are not as made: kept {}",
            spare.kept()
        )
        .into());
    }
    Ok(())
}

/// 既定で足す敵対的な送り手の種の数です。
const AUDIT_SEEDS: u64 = 0;

/// 既定で流す生の packet の敵の種の数と、1 つの種の入力の byte 数です。
const RAW_SEEDS: u64 = 8;
const RAW_LEN: usize = 16_000;

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
    for (target, body, limits) in TARGETS {
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
                    if let Some(l) = limits {
                        return fresh_and_reused(body, &data, l());
                    }
                    body(&data);
                    Ok(())
                }));
            }
        }
    }
    for (target, dir) in env::var("WGFT_WGSTACK_CORPUS_DIRS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|e| e.split_once('='))
    {
        let (body, limits): (Body, fn() -> Limits) = match target {
            "core" => (fuzz::core, fuzz::fuzz_limits),
            "adversarial_sender" => (fuzz::adversarial_sender, adversary_limits),
            "raw_adversary" => (fuzz::raw_adversary, fuzz::small_limits),
            "replay" => (fuzz::replay, fuzz::fuzz_limits),
            _ => panic!("WGFT_WGSTACK_CORPUS_DIRS names an unknown target {target:?}"),
        };
        for p in files(Path::new(dir)) {
            let name = format!(
                "{target}/extra/{}",
                p.file_name().expect("file name").to_string_lossy()
            );
            trials.push(Trial::test(name, move || {
                let data = fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?;
                fresh_and_reused(body, &data, limits())
            }));
        }
    }
    let start = env_u64("WGFT_WGSTACK_AUDIT_START", 1);
    let seeds = env_u64("WGFT_WGSTACK_AUDIT_SEEDS", AUDIT_SEEDS);
    for seed in start..start + seeds {
        trials.push(Trial::test(
            format!("adversarial_sender/seed/{seed}"),
            move || {
                fresh_and_reused(
                    fuzz::adversarial_sender,
                    &seed.to_le_bytes(),
                    adversary_limits(),
                )
            },
        ));
    }
    // 生の packet の敵の見つけた落ちる入力は、種とは別に regressions/raw_adversary/ に置きます
    for p in files(&root.join("regressions").join("raw_adversary")) {
        let name = format!(
            "raw_adversary/regressions/{}",
            p.file_name().expect("file name").to_string_lossy()
        );
        trials.push(Trial::test(name, move || {
            let data = fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            fresh_and_reused(fuzz::raw_adversary, &data, fuzz::small_limits())
        }));
    }
    let seeds = env_u64("WGFT_WGSTACK_RAW_SEEDS", RAW_SEEDS);
    for seed in 1..=seeds {
        trials.push(Trial::test(
            format!("raw_adversary/seed/{seed}"),
            move || {
                fresh_and_reused(
                    fuzz::raw_adversary,
                    &fuzz::raw_adversary_input(seed, RAW_LEN),
                    fuzz::small_limits(),
                )
            },
        ));
    }
    libtest_mimic::run(&args, trials).exit();
}
