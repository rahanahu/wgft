//! 核の乱数 (wgstack-rs.md の「時刻と乱数」)。
//!
//! 核は OS の乱数を読まず、作成の時に 64 byte の種を受け取ります。
//! 種の配分は Go の wgstack と同じです。先頭の 16 byte を ISN の鍵、次の 16 byte を表の hash の鍵、残りの
//! 32 byte を ChaCha8 の種にし、timestamp の鍵と IP の ID の始めの値を ChaCha8 から順に引きます。
//!
//! [`ChaCha8`] は C2SP の chacha8rand の仕様 (<https://c2sp.org/chacha8rand>) から書いた生成器で、Go の
//! `math/rand/v2` の `ChaCha8` の `Uint64` と同じ列を出します。一致は Go が書き出した値で確かめます。

use crate::siphash::SipKey;

/// 1 回の block の計算で作る 64 bit の値の数です。4 つの ChaCha8 の block (各 64 byte) を並べたものです。
const BUF_WORDS: usize = 32;
/// 種を作り直すまでの block の数です。
const BLOCKS_PER_SEED: u32 = 16;
/// 種の作り直しに使う、最後の計算の末尾の値の数です。この値は出力しません。
const RESEED_WORDS: usize = 4;

/// Go の `math/rand/v2` の `ChaCha8` と同じ列を出す生成器です。
pub(crate) struct ChaCha8 {
    buf: [u64; BUF_WORDS],
    key: [u64; 4],
    /// 次に返す `buf` の位置です。
    i: usize,
    /// `buf` のうち出力してよい値の数です。
    n: usize,
    /// 今の `buf` を作った block の counter の始めの値です。
    counter: u32,
}

impl core::fmt::Debug for ChaCha8 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // 状態は秘密なので出しません。
        f.debug_struct("ChaCha8").finish_non_exhaustive()
    }
}

#[inline]
#[expect(
    clippy::many_single_char_names,
    reason = "the names follow the ChaCha quarter round"
)]
fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}

/// chacha8rand の 1 回の計算です。counter から counter+3 の 4 つの block を作り、仕様の並び
/// (語 i の block j を 4i+j 番目の 32 bit の値に置く並び) で `buf` に書きます。
#[expect(
    clippy::cast_possible_truncation,
    reason = "splits 64-bit key words into their 32-bit halves"
)]
fn generate(key: &[u64; 4], counter: u32, buf: &mut [u64; BUF_WORDS]) {
    let mut words = [0u32; 64];
    let mut k = [0u32; 8];
    for (i, w) in key.iter().enumerate() {
        // 64 bit の値の下位を先の語にします (種の 32 byte を little endian の 32 bit の語として読むのと同じ)。
        k[2 * i] = *w as u32;
        k[2 * i + 1] = (*w >> 32) as u32;
    }
    for j in 0..4u32 {
        let mut init = [0u32; 16];
        init[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
        init[4..12].copy_from_slice(&k);
        init[12] = counter.wrapping_add(j);
        let mut x = init;
        for _ in 0..4 {
            quarter_round(&mut x, 0, 4, 8, 12);
            quarter_round(&mut x, 1, 5, 9, 13);
            quarter_round(&mut x, 2, 6, 10, 14);
            quarter_round(&mut x, 3, 7, 11, 15);
            quarter_round(&mut x, 0, 5, 10, 15);
            quarter_round(&mut x, 1, 6, 11, 12);
            quarter_round(&mut x, 2, 7, 8, 13);
            quarter_round(&mut x, 3, 4, 9, 14);
        }
        // 仕様は鍵の語 (4 から 11) にだけ入力を足し戻します。
        for (i, xi) in x.iter_mut().enumerate().take(12).skip(4) {
            *xi = xi.wrapping_add(init[i]);
        }
        for (i, xi) in x.iter().enumerate() {
            words[4 * i + j as usize] = *xi;
        }
    }
    for (i, out) in buf.iter_mut().enumerate() {
        *out = u64::from(words[2 * i]) | u64::from(words[2 * i + 1]) << 32;
    }
}

impl ChaCha8 {
    /// 32 byte の種から生成器を作ります。
    pub(crate) fn new(seed: [u8; 32]) -> Self {
        let mut key = [0u64; 4];
        for (k, c) in key.iter_mut().zip(seed.as_chunks::<8>().0) {
            *k = u64::from_le_bytes(*c);
        }
        let mut s = Self {
            buf: [0; BUF_WORDS],
            key,
            i: 0,
            n: BUF_WORDS,
            counter: 0,
        };
        generate(&s.key, 0, &mut s.buf);
        s
    }

    fn refill(&mut self) {
        self.counter += 4;
        if self.counter == BLOCKS_PER_SEED {
            // 前の計算の末尾の 4 つの値を新しい鍵にします (前方秘匿)。
            self.key
                .copy_from_slice(&self.buf[BUF_WORDS - RESEED_WORDS..]);
            self.counter = 0;
        }
        generate(&self.key, self.counter, &mut self.buf);
        self.i = 0;
        self.n = if self.counter == BLOCKS_PER_SEED - 4 {
            BUF_WORDS - RESEED_WORDS
        } else {
            BUF_WORDS
        };
    }

    /// 次の 64 bit の値を返します。Go の `ChaCha8.Uint64` と同じです。
    pub(crate) fn next_u64(&mut self) -> u64 {
        if self.i >= self.n {
            self.refill();
        }
        let x = self.buf[self.i];
        self.i += 1;
        x
    }

    /// `[0, n)` の値を返します。Go の wgstack の `randomU64N` と同じく、64 bit の値と `n` の積の上位の
    /// 64 bit を取ります。`n` が 0 なら 0 です。
    pub(crate) fn below(&mut self, n: u64) -> u64 {
        ((u128::from(self.next_u64()) * u128::from(n)) >> 64) as u64
    }
}

/// 64 byte の種から作る、核の鍵と生成器の組です。
#[derive(Debug)]
pub(crate) struct Seeds {
    /// ISN の鍵 (RFC 6528)。種の 0 から 15 byte です。
    pub(crate) isn_key: SipKey,
    /// 4 つ組の hash の表の鍵。種の 16 から 31 byte です。
    pub(crate) table_key: SipKey,
    /// timestamp の offset の鍵。生成器の最初の 2 つの値です。
    pub(crate) ts_key: SipKey,
    /// IP の ID の始めの値。生成器の 3 つ目の値の下位 32 bit です。
    pub(crate) ip_id: u32,
    /// 残りの乱数 (challenge ACK の揺らぎ、区間の treap の優先度の種) を引く生成器です。
    pub(crate) rng: ChaCha8,
}

impl Seeds {
    /// Go の `newStack` と同じ順で種を配分し、生成器から値を引きます。
    #[expect(
        clippy::cast_possible_truncation,
        reason = "Go keeps the low 32 bits for the IP ID"
    )]
    pub(crate) fn new(seed: &[u8; 64]) -> Self {
        let mut isn = [0u8; 16];
        let mut table = [0u8; 16];
        let mut chacha = [0u8; 32];
        isn.copy_from_slice(&seed[..16]);
        table.copy_from_slice(&seed[16..32]);
        chacha.copy_from_slice(&seed[32..]);
        let mut rng = ChaCha8::new(chacha);
        let ts_key = SipKey {
            k0: rng.next_u64(),
            k1: rng.next_u64(),
        };
        let ip_id = rng.next_u64() as u32;
        Self {
            isn_key: SipKey::from_le_bytes(isn),
            table_key: SipKey::from_le_bytes(table),
            ts_key,
            ip_id,
            rng,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn below_stays_in_range() {
        let mut r = ChaCha8::new([9; 32]);
        for n in [1u64, 2, 3, 1000, 1 << 62, u64::MAX] {
            for _ in 0..100 {
                assert!(r.below(n) < n);
            }
        }
        assert_eq!(r.below(0), 0);
    }

    #[test]
    fn reseeds_after_sixteen_blocks() {
        // 4 回の計算のうち最後は 28 個だけを出し、その後に種を作り直します。
        let mut r = ChaCha8::new([1; 32]);
        for _ in 0..(3 * BUF_WORDS + BUF_WORDS - RESEED_WORDS) {
            r.next_u64();
        }
        assert_eq!(r.counter, 12);
        r.next_u64();
        assert_eq!(r.counter, 0);
        assert_eq!(r.i, 1);
    }
}
