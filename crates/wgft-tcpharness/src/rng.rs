//! 台本の乱数です。Go の harness (`internal/tcpharness/harness.go`) と同じ値を同じ順で取ります。
//!
//! - 台本の種は、実行の種と台本の名前の FNV-1a (64 bit) の xor です ([`scenario_seed`])
//! - 乱数の源は Go の `math/rand/v2` の PCG (128 bit の LCG と DXSM の出力) で、種は
//!   `NewPCG(seed, seed ^ 0x9e3779b97f4a7c15)` です
//! - harness は作る時に `IntN(20000)` で相手のポートの起点を取り、相手を作るたびにポートを 1 つ進めて、
//!   ISN と timestamp の起点を `Uint32` で順に取ります ([`ScriptRng`])
//!
//! Go の試験が書き出した値 (`internal/tcpharness/scripts/testdata/rng.json`) と照らします。

/// 台本の種を固定する環境変数です。Go の harness と同じ名前です。
pub const SEED_ENV: &str = "WGFT_TEST_TCPHARNESS_SEED";

/// 実行の種と台本の名前から台本の種を作ります。Go の `ScenarioSeed` です。
pub fn scenario_seed(run: u64, scenario: &str) -> u64 {
    run ^ fnv1a64(scenario.as_bytes())
}

/// FNV-1a の 64 bit の hash です。Go の `hash/fnv` の `New64a` です。
pub fn fnv1a64(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// Go の `math/rand/v2` の `PCG` です。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pcg {
    state: u128,
}

impl Pcg {
    // Go の mulHi、mulLo、incHi、incLo (10 進で 2549297995355413924、4865540595714422341、
    // 6364136223846793005、1442695040888963407)
    const MUL: u128 = 0x2360_ed05_1fc6_5da4_4385_df64_9fcc_f645;
    const INC: u128 = 0x5851_f42d_4c95_7f2d_1405_7b7e_f767_814f;

    /// Go の `NewPCG(seed1, seed2)` です。`seed1` が状態の上位 64 bit です。
    pub const fn new(seed1: u64, seed2: u64) -> Self {
        Self {
            state: ((seed1 as u128) << 64) | seed2 as u128,
        }
    }

    /// Go の `PCG.Uint64` です。
    pub fn uint64(&mut self) -> u64 {
        self.state = self.state.wrapping_mul(Self::MUL).wrapping_add(Self::INC);
        let hi = (self.state >> 64) as u64;
        #[expect(clippy::cast_possible_truncation, reason = "the low half of the state")]
        let lo = self.state as u64;
        let mut x = hi ^ (hi >> 32);
        x = x.wrapping_mul(0xda94_2042_e4dd_58b5);
        x ^= x >> 48;
        x.wrapping_mul(lo | 1)
    }

    /// Go の `Rand.Uint32` です。
    pub fn uint32(&mut self) -> u32 {
        (self.uint64() >> 32) as u32
    }

    /// Go の `Rand.IntN` を 64 bit の環境で動かした値です。`n` は 0 より大きい値です。
    pub fn int_n(&mut self, n: u64) -> u64 {
        assert!(n > 0, "invalid argument to int_n");
        if n.is_power_of_two() {
            return self.uint64() & (n - 1);
        }
        let (mut hi, mut lo) = mul64(self.uint64(), n);
        if lo < n {
            let thresh = n.wrapping_neg() % n;
            while lo < thresh {
                (hi, lo) = mul64(self.uint64(), n);
            }
        }
        hi
    }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "split of a 128-bit product"
)]
fn mul64(a: u64, b: u64) -> (u64, u64) {
    let p = u128::from(a) * u128::from(b);
    ((p >> 64) as u64, p as u64)
}

/// 相手 1 つ分の乱数の値です。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerDraw {
    /// 相手の送信元のポート
    pub port: u16,
    /// 相手の ISN
    pub iss: u32,
    /// 相手の timestamp の時計の起点
    pub ts_base: u32,
}

/// harness が台本の種から取る値の列です。Go の `newH` と `NewPeer` と同じ順で取ります。
#[derive(Debug, Clone)]
pub struct ScriptRng {
    pcg: Pcg,
    next_port: u16,
}

impl ScriptRng {
    /// 台本の種から作ります。Go の `newH` と同じく、最初に相手のポートの起点を取ります。
    pub fn new(scenario_seed: u64) -> Self {
        let mut pcg = Pcg::new(scenario_seed, scenario_seed ^ 0x9e37_79b9_7f4a_7c15);
        let start = u16::try_from(pcg.int_n(20000)).expect("below 20000");
        Self {
            pcg,
            next_port: 40000 + start,
        }
    }

    /// 次の相手のポート、ISN、timestamp の起点を取ります。Go の `NewPeer` です。
    pub fn new_peer(&mut self) -> PeerDraw {
        self.next_port = self.next_port.wrapping_add(1);
        let iss = self.pcg.uint32();
        let ts_base = self.pcg.uint32();
        PeerDraw {
            port: self.next_port,
            iss,
            ts_base,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv_known_values() {
        // hash/fnv の New64a の値
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
    }

    #[test]
    fn int_n_power_of_two_masks() {
        let mut a = Pcg::new(1, 2);
        let mut b = Pcg::new(1, 2);
        assert_eq!(a.int_n(16), b.uint64() & 15);
    }
}
