//! 台本の構文解析器と静的な検査に任意の bytes を通します (Go の `FuzzParseScript` に当たります)。
//!
//! panic しないこと、誤りの行が入力の行の範囲にあること、通った台本の構文木が UTF-8 の JSON に書けることを
//! 確かめます。種は本物の台本と構文の fixture で、次のように corpus の directory を並べて渡します。
//!
//! ```sh
//! cargo +nightly fuzz run parse_script corpus/parse_script \
//!     ../../../internal/tcpharness/scripts ../../../internal/tcpharness/scripts/testdata/parse
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;
use wgft_tcpharness::script::parse_script;

fuzz_target!(|data: &[u8]| {
    match parse_script("fuzz.scn", data) {
        Ok(s) => {
            let json = s.ast().to_bytes();
            assert!(
                std::str::from_utf8(&json).is_ok(),
                "the AST JSON is not UTF-8"
            );
        }
        Err(e) => {
            let lines = data.iter().filter(|&&b| b == b'\n').count() + 1;
            assert!(
                e.line >= 1 && e.line <= lines,
                "line {} of {lines}: {e}",
                e.line
            );
        }
    }
});
