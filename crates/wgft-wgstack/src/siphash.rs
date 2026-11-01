//! SipHash-2-4 (Go の `siphash.go` の写し)。
//!
//! 表の hash の種と ISN の鍵 (RFC 6528) に使い、作成の時に渡された種から作ります。
//! 相手が選ぶ送信元のアドレスとポートで、hash の衝突を集められないようにするためです。
//! 入力は 16 byte (little endian の 2 語) に限ります。Go と同じ値を返すことを、Go が書き出した値で確かめます。

use crate::wire::Tuple;

/// SipHash-2-4 の 128 bit の鍵です。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SipKey {
    pub(crate) k0: u64,
    pub(crate) k1: u64,
}

#[inline]
fn round(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13);
    v[1] ^= v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16);
    v[3] ^= v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21);
    v[3] ^= v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17);
    v[1] ^= v[2];
    v[2] = v[2].rotate_left(32);
}

impl SipKey {
    /// 鍵を 16 byte の little endian の 2 語から作ります。
    pub(crate) fn from_le_bytes(b: [u8; 16]) -> Self {
        Self {
            k0: b.first_chunk::<8>().map_or(0, |c| u64::from_le_bytes(*c)),
            k1: b.last_chunk::<8>().map_or(0, |c| u64::from_le_bytes(*c)),
        }
    }

    /// 16 byte の入力 `m0`、`m1` (little endian の 2 語) の SipHash-2-4 を返します。
    pub(crate) fn sum(self, m0: u64, m1: u64) -> u64 {
        let mut v = [
            self.k0 ^ 0x736f_6d65_7073_6575,
            self.k1 ^ 0x646f_7261_6e64_6f6d,
            self.k0 ^ 0x6c79_6765_6e65_7261,
            self.k1 ^ 0x7465_6462_7974_6573,
        ];
        for m in [m0, m1, 16 << 56] {
            v[3] ^= m;
            round(&mut v);
            round(&mut v);
            v[0] ^= m;
        }
        v[2] ^= 0xff;
        for _ in 0..4 {
            round(&mut v);
        }
        v[0] ^ v[1] ^ v[2] ^ v[3]
    }

    /// 24 byte の入力 `m0`、`m1`、`m2` (little endian の 3 語) の SipHash-2-4 を返します。SYN cookie の MAC が
    /// 使います。
    pub(crate) fn sum3(self, m0: u64, m1: u64, m2: u64) -> u64 {
        let mut v = [
            self.k0 ^ 0x736f_6d65_7073_6575,
            self.k1 ^ 0x646f_7261_6e64_6f6d,
            self.k0 ^ 0x6c79_6765_6e65_7261,
            self.k1 ^ 0x7465_6462_7974_6573,
        ];
        for m in [m0, m1, m2, 24 << 56] {
            v[3] ^= m;
            round(&mut v);
            round(&mut v);
            v[0] ^= m;
        }
        v[2] ^= 0xff;
        for _ in 0..4 {
            round(&mut v);
        }
        v[0] ^ v[1] ^ v[2] ^ v[3]
    }

    /// 4 つ組の鍵付きの hash を返します。
    pub(crate) fn hash_tuple(self, t: Tuple) -> u64 {
        self.sum(
            u64::from(t.laddr) | u64::from(t.raddr) << 32,
            u64::from(t.lport) | u64::from(t.rport) << 16,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SipHash-2-4 の論文の付録の試験の値です。鍵は 0 から 15 の byte、入力は 0 から順の byte です。
    #[test]
    fn matches_the_reference_vectors() {
        let k = SipKey::from_le_bytes(core::array::from_fn(|i| u8::try_from(i).unwrap_or(0)));
        let word = |i: u8| {
            u64::from_le_bytes(core::array::from_fn(|j| {
                8 * i + u8::try_from(j).unwrap_or(0)
            }))
        };
        assert_eq!(k.sum(word(0), word(1)), 0x3f2a_cc7f_57c2_9bdb);
        assert_eq!(k.sum3(word(0), word(1), word(2)), 0xb8ad_50c6_f649_af94);
    }
}
