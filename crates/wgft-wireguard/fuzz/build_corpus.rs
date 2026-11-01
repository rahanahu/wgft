//! `inbound` の corpus の種を作る。
//!
//! fuzz の入力は操作の列 (inbound.rs の `op % 10`) なので、ハンドシェイクを済ませてデータを
//! 往復させる長い列を種にすると、最初から受信の経路の奥 (データの復号、中身の検査) を通る。
//!
//! `cargo run --bin build-corpus` で `corpus/inbound/` に書く。

use std::fs;
use std::path::Path;

// inbound.rs の操作の番号
const SMALL_STEP: u8 = 0;
const BIG_STEP: u8 = 1;
const A_TO_B: u8 = 2;
const B_TO_A: u8 = 3;
const RAW_TO_A: u8 = 4;
const B_SENDS: u8 = 5;
const A_SENDS: u8 = 6;
const TIMERS: u8 = 7;
const RAW_INNER: u8 = 8;
const DRAIN: u8 = 9;

/// ハンドシェイク: A が始め、B が答え、A が確かめる。
fn handshake(ops: &mut Vec<u8>) {
    ops.extend([TIMERS, A_TO_B, B_TO_A, 0, A_TO_B]);
}

fn exchange(ops: &mut Vec<u8>, len: u8, corrupt: bool) {
    ops.extend([B_SENDS, len]);
    ops.extend(std::iter::repeat_n(0x5a, usize::from(len) * 8));
    ops.extend([B_TO_A, if corrupt { 0x0b } else { 0 }]);
    if corrupt {
        ops.push(0x40);
    }
    ops.extend([A_SENDS, len]);
    ops.extend(std::iter::repeat_n(0x45, usize::from(len)));
    ops.push(A_TO_B);
}

fn main() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus/inbound");
    fs::create_dir_all(&dir).expect("create the corpus directory");
    let mut seeds: Vec<Vec<u8>> = Vec::new();

    let mut s = Vec::new();
    handshake(&mut s);
    for len in [1, 8, 60, 175] {
        exchange(&mut s, len, false);
    }
    seeds.push(s);

    let mut s = Vec::new();
    handshake(&mut s);
    for len in [2, 30, 120] {
        exchange(&mut s, len, true);
    }
    s.push(DRAIN);
    seeds.push(s);

    // 鍵の更新と期限切れの周り
    let mut s = Vec::new();
    handshake(&mut s);
    for _ in 0..6 {
        s.extend([BIG_STEP, 30, TIMERS, A_TO_B, B_TO_A, 0]);
        exchange(&mut s, 4, false);
    }
    s.extend([BIG_STEP, 250, BIG_STEP, 250, TIMERS, A_TO_B, B_TO_A, 0]);
    seeds.push(s);

    // 検査を通さない中身と任意のバイト列
    let mut s = Vec::new();
    handshake(&mut s);
    for len in [0, 10, 24, 200] {
        s.extend([RAW_INNER, len]);
        s.extend((0..u16::from(len) * 2).map(|i| (i * 7) as u8));
    }
    s.extend([RAW_TO_A, 74]);
    s.extend(std::iter::once(1).chain(std::iter::repeat_n(0x11, 147)));
    s.extend([RAW_TO_A, 16]);
    s.extend(std::iter::once(4).chain(std::iter::repeat_n(0x22, 31)));
    s.extend([SMALL_STEP, 50, DRAIN]);
    seeds.push(s);

    // 待たせた packet と溢れ
    let mut s = Vec::new();
    for _ in 0..8 {
        s.extend([A_SENDS, 40]);
        s.extend(std::iter::repeat_n(0x33, 40));
    }
    handshake(&mut s);
    for _ in 0..12 {
        s.extend([B_SENDS, 100]);
        s.extend(std::iter::repeat_n(0x44, 800));
        s.extend([B_TO_A, 0]);
    }
    seeds.push(s);

    for (i, seed) in seeds.iter().enumerate() {
        fs::write(dir.join(format!("seed-{i}")), seed).expect("write a seed");
    }
    println!("wrote {} seeds to {}", seeds.len(), dir.display());
}
