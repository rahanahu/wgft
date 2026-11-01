//! Go の `unicode.IsGraphic` の範囲の一覧 `testdata/spec/text/non-graphic.json` と、Rust の判定を比べる。
//! 一覧は Go の試験 `internal/textsafe` の `TestNonGraphicRanges` が作る。

use serde::Deserialize;
use unicode_general_category::{GeneralCategory, get_general_category};
use wgft_proto::textsafe::{UNICODE_VERSION, is_unsafe};

#[derive(Deserialize)]
struct List {
    unicode_version: String,
    ranges: Vec<[u32; 2]>,
}

#[test]
fn differs_from_go_only_where_the_unicode_versions_differ() {
    let l: List =
        serde_json::from_str(include_str!("../../../testdata/spec/text/non-graphic.json")).unwrap();
    let go_non = |c: u32| l.ranges.iter().any(|r| r[0] <= c && c <= r[1]);
    let mut other = Vec::new();
    for cp in 0..=0x10_FFFF_u32 {
        let Some(c) = char::from_u32(cp) else {
            continue;
        }; // surrogate は Rust の char に無い
        if is_unsafe(c) == go_non(cp) {
            continue;
        }
        // 版の差:一方の表で割り当てが無い (Cn) 文字。Go の版が新しければ、Go が表示できるとし Rust が
        // 割り当て無しとする文字だけが残る
        if is_unsafe(c) && get_general_category(c) == GeneralCategory::Unassigned {
            continue;
        }
        other.push(format!("U+{cp:04X}"));
    }
    assert!(
        other.is_empty(),
        "Go {} and the crate's Unicode {:?} disagree beyond newly assigned characters: {other:?}",
        l.unicode_version,
        UNICODE_VERSION
    );
}
