//! 構文の fixture (`internal/tcpharness/scripts/testdata/`) を Go の構文解析器と同じ bytes で作れることを確かめます。
//!
//! - `parse/*.scn`:構文木か、誤りの行と種類 (`err-` で始まる名前) の `.ast.json`
//! - `../*.scn` (本物の台本):`ast/<名前>.ast.json`
//!
//! fixture は Go の試験 (`go test ./internal/tcpharness -run 'TestScriptParseFixtures|TestScriptASTs' -update`) が作ります。

use std::fs;
use std::path::{Path, PathBuf};

use wgft_tcpharness::script::parse_script;

fn scripts_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../internal/tcpharness/scripts")
}

fn scn_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.expect("directory entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "scn"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no scripts under {}", dir.display());
    files
}

/// Go の golden と同じく、Windows の checkout が書いた CRLF を LF にして読みます。
fn read_golden(path: &Path) -> Vec<u8> {
    let b = fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\r' && b.get(i + 1) == Some(&b'\n') {
            i += 1;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn compare(path: &Path, got: Vec<u8>, failures: &mut Vec<String>) {
    let mut got = got;
    got.push(b'\n');
    let want = read_golden(path);
    if want != got {
        failures.push(format!(
            "{}:\n want {}\n  got {}",
            path.display(),
            String::from_utf8_lossy(&want).trim_end(),
            String::from_utf8_lossy(&got).trim_end()
        ));
    }
}

#[test]
fn parser_fixtures() {
    let mut failures = Vec::new();
    for f in scn_files(&scripts_dir().join("testdata/parse")) {
        let name = f.file_name().unwrap().to_string_lossy().into_owned();
        let src = fs::read(&f).unwrap();
        let got = match (parse_script(&name, &src), name.starts_with("err-")) {
            (Ok(s), false) => s.ast(),
            (Err(e), true) => e.ast(),
            (Ok(_), true) => {
                failures.push(format!(
                    "{}: parsed; an err- fixture must fail",
                    f.display()
                ));
                continue;
            }
            (Err(e), false) => {
                failures.push(format!("{}: {e}", f.display()));
                continue;
            }
        };
        compare(&f.with_extension("ast.json"), got.to_bytes(), &mut failures);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn scenario_script_asts() {
    let mut failures = Vec::new();
    let dir = scripts_dir();
    for f in scn_files(&dir) {
        let name = f.file_name().unwrap().to_string_lossy().into_owned();
        let s = match parse_script(&name, &fs::read(&f).unwrap()) {
            Ok(s) => s,
            Err(e) => {
                failures.push(e.to_string());
                continue;
            }
        };
        let stem = f.file_stem().unwrap().to_string_lossy();
        if s.name != stem {
            failures.push(format!("{} names scenario {}", f.display(), s.name));
        }
        let golden = dir
            .join("testdata/ast")
            .join(format!("{}.ast.json", s.name));
        compare(&golden, s.ast().to_bytes(), &mut failures);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
