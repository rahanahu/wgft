//! 構文解析器の入れ子の上限が、debug の build でも再帰を 1 MiB の stack に収めることを確かめます。
//!
//! Windows の main thread の stack は 1 MiB です。構文の fixture (上限ちょうどの `nesting.scn` と、上限を
//! 1 つ超える `err-*-depth.scn`、`err-tokens.scn` を含みます)、本物の台本、すべての上限を 1 つの台本で
//! 重ねた入力を、stack を 1 MiB にした thread で構文解析し、構文木を JSON に書いて捨てます。

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;

use wgft_tcpharness::script::parse_script;

const STACK: usize = 1 << 20;

fn scn_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.expect("directory entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "scn"))
        .collect();
    files.sort();
    files
}

/// `src` を 1 MiB の stack の thread で構文解析し、構文木を書いて捨てます。通ったかを返します。
fn parse_on_small_stack(name: String, src: Vec<u8>) -> bool {
    thread::Builder::new()
        .stack_size(STACK)
        .spawn(move || match parse_script(&name, &src) {
            Ok(s) => !s.ast().to_bytes().is_empty(),
            Err(_) => false,
        })
        .expect("spawn")
        .join()
        .expect("the parser stays within 1 MiB of stack")
}

#[test]
fn fixtures_fit_in_one_mib() {
    let scripts = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../internal/tcpharness/scripts");
    let mut files = scn_files(&scripts.join("testdata/parse"));
    files.extend(scn_files(&scripts));
    assert!(files.iter().any(|f| f.ends_with("nesting.scn")));
    for f in files {
        let ok = parse_on_small_stack(f.display().to_string(), fs::read(&f).unwrap());
        let name = f.file_name().unwrap().to_string_lossy();
        assert_eq!(ok, !name.starts_with("err-"), "{name}");
    }
}

/// すべての上限を重ねた入力です。最も深い `if` の中の文が、最も深い式と最も長い式を持ちます。
#[test]
fn every_limit_at_once_fits_in_one_mib() {
    let mut src = String::from("scenario all-limits\nrefs: test\n\n");
    for i in 0..16 {
        writeln!(src, "{}if true", "  ".repeat(i)).unwrap();
    }
    let pad = "  ".repeat(16);
    writeln!(src, "{pad}let a = {}1{}", "(".repeat(31), ")".repeat(31)).unwrap();
    writeln!(src, "{pad}let b = -1{}", "+1".repeat(126)).unwrap();
    write!(
        src,
        "{pad}check c {}true\n{pad}  what: {{{}1}}\n{pad}  got: {{{}1{}}}\n",
        "!".repeat(31),
        "-".repeat(31),
        "int(".repeat(31),
        ")".repeat(31)
    )
    .unwrap();
    for i in (0..16).rev() {
        writeln!(src, "{}end", "  ".repeat(i)).unwrap();
    }
    assert!(parse_on_small_stack(
        "all-limits.scn".to_owned(),
        src.into_bytes()
    ));
}
