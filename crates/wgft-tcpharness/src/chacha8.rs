//! HELLO の 64 byte の種です。Go の `math/rand/v2` の `ChaCha8` の最初の 64 byte の写しです。
//!
//! `wgstackdut` は台本の種から鍵を作った `ChaCha8` を Go の wgstack の乱数の源にし、Go の wgstack は作成の時に
//! その先頭の 64 byte だけを読みます。`rustdut` はその 64 byte を HELLO の種にします ([`hello_seed`])。
//! 鍵の作り方は Go の `rustdut.Seed` と `wgstackdut.RandSource`、block の関数は Go の
//! `internal/chacha8rand` (c2sp.org/chacha8rand) です。Go の試験が書き出した値
//! (`internal/tcpharness/rustdut/testdata/vectors.json`) と照らします。

use crate::frame::SEED_LEN;

/// 台本の種から HELLO の種を作ります。Go の `rustdut.Seed` です。
pub fn hello_seed(seed: u64) -> [u8; SEED_LEN] {
    let mut key = [0u64; 4];
    for (i, k) in (0u64..).zip(key.iter_mut()) {
        *k = seed ^ i.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
    let buf = block(&key, 0);
    let mut out = [0u8; SEED_LEN];
    // Go の ChaCha8.Read は Uint64 を 8 つ little endian で並べる。最初の block の最初の 8 語
    for (dst, w) in out.as_chunks_mut::<8>().0.iter_mut().zip(buf) {
        *dst = w.to_le_bytes();
    }
    out
}

/// chacha8rand の block の関数です。4 つの ChaCha8 の block を交互に並べた 32 語を返します。
fn block(seed: &[u64; 4], counter: u32) -> [u64; 32] {
    // b[行][block]。Go の [16][4]uint32 と同じ並び
    let mut b = [[0u32; 4]; 16];
    let consts = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
    for (row, c) in consts.iter().enumerate() {
        b[row] = [*c; 4];
    }
    for (i, s) in seed.iter().enumerate() {
        #[expect(clippy::cast_possible_truncation, reason = "the halves of a seed word")]
        let (lo, hi) = (*s as u32, (*s >> 32) as u32);
        b[4 + 2 * i] = [lo; 4];
        b[5 + 2 * i] = [hi; 4];
    }
    b[12] = [counter, counter + 1, counter + 2, counter + 3];
    #[expect(
        clippy::needless_range_loop,
        reason = "i is the block's column in every row"
    )]
    for i in 0..4 {
        let mut x: [u32; 16] = std::array::from_fn(|r| b[r][i]);
        for _ in 0..4 {
            qr(&mut x, 0, 4, 8, 12);
            qr(&mut x, 1, 5, 9, 13);
            qr(&mut x, 2, 6, 10, 14);
            qr(&mut x, 3, 7, 11, 15);
            qr(&mut x, 0, 5, 10, 15);
            qr(&mut x, 1, 6, 11, 12);
            qr(&mut x, 2, 7, 8, 13);
            qr(&mut x, 3, 4, 9, 14);
        }
        for (r, v) in x.iter().enumerate() {
            if (4..12).contains(&r) {
                b[r][i] = b[r][i].wrapping_add(*v);
            } else {
                b[r][i] = *v;
            }
        }
    }
    let flat: Vec<u32> = b.iter().flatten().copied().collect();
    std::array::from_fn(|k| u64::from(flat[2 * k]) | u64::from(flat[2 * k + 1]) << 32)
}

#[expect(clippy::many_single_char_names, reason = "the quarter round's names")]
fn qr(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}
