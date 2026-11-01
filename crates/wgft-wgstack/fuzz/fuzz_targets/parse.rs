//! packet の解釈、checksum、IPv4 の再組み立ての表に任意の bytes を通します (Go の `FuzzParse` に当たります)。
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| wgft_wgstack::fuzz::parse(data));
