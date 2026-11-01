//! Go の wgstack の記録から、fuzz の `replay` の target の種を書きます (`docs/design/v2/test-tooling.md` の
//! 6 節)。
//!
//! ```text
//! cargo run -p wgft-wgstack-dut --example replay_seeds -- OUT_DIR [MAX_BYTES] [FILTER]
//! ```
//!
//! 記録は `testdata/wgstack-rec/` (環境変数 `WGFT_WGSTACK_REPLAY_DIR` で替えられます) の下のすべての記録で、
//! `FILTER` を与えると `<元>/<名前>` にその文字列を含む記録だけです。種の名前は `<元>-<名前>`、中身は印の
//! 0xff と、合わせて `MAX_BYTES` (既定は 4096) を超えない所までの要求の frame です。libFuzzer の入力の長さの
//! 上限の既定 (4096) と同じ長さに抑え、1 回の実行を短く保つためです。

use std::path::{Path, PathBuf};
use std::{env, fs};

use wgft_wgstack_dut::fuzz::replay_seed;
use wgft_wgstack_dut::rec;

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

fn main() {
    let mut args = env::args().skip(1);
    let out = PathBuf::from(
        args.next()
            .expect("usage: replay_seeds OUT_DIR [MAX_BYTES] [FILTER]"),
    );
    let max: usize = args
        .next()
        .map_or(4096, |v| v.parse().expect("MAX_BYTES is a number"));
    let filter = args.next().unwrap_or_default();
    let dir = env::var_os("WGFT_WGSTACK_REPLAY_DIR").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/wgstack-rec"),
        PathBuf::from,
    );
    let mut paths = Vec::new();
    walk(&dir, &mut paths);
    paths.sort();
    fs::create_dir_all(&out).expect("make OUT_DIR");
    let mut n = 0;
    for p in paths {
        let r = rec::read_file(&p).unwrap_or_else(|e| panic!("{e}"));
        let id = r.id();
        if !id.contains(&filter) {
            continue;
        }
        let seed = replay_seed(&r, max).unwrap_or_else(|e| panic!("{id}: {e}"));
        fs::write(out.join(id.replace('/', "-")), seed).expect("write the seed");
        n += 1;
    }
    eprintln!("replay_seeds: wrote {n} seeds to {}", out.display());
}
