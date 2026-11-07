//! IPv4 の Identification (ID) の割り当て(RFC 791、RFC 6864)。
//!
//! - DF を立てた断片でない packet (TCP、ICMP の誤り、echo request) は atomic な datagram で、ID は意味を持たず
//!   送り手が任意の値を入れてよい (RFC 6864 4.1)。核は 0 を入れるので、核の全体の送信量を ID から読めません。
//! - 断片にされうる packet (DF を下ろした UDP の datagram と ICMP の echo reply) の ID は、(送信元、宛先、protocol)
//!   の組ごとに重ならないよう管理します (RFC 791、RFC 6864 4.2 と 4.3)。送信元は核のアドレス 1 つなので、組は
//!   (宛先、protocol) で引きます。
//!
//! 組ごとの列は、鍵つき hash から作る 16 bit の置換 (Feistel) に連番を通した値です。置換は全単射なので、連番が
//! 65536 個進む間は重なりません。置換の鍵と連番の始めの値は組の hash から導くので、ほかの組の送信量にも、
//! ほかの組の列にも依りません。
//!
//! 組の状態は固定の表 (`SETS` × `WAYS` の枠) に置きます。満杯なら同じ集合から、再組み立ての寿命
//! (`frag::LIMITS.lifetime`) より長く使われていない枠を優先して追い出し、無ければ最も古い枠を追い出します。
//! 寿命を過ぎた枠の ID は相手で使い終わっているので、進みには何も足しません。
//! 寿命の内に使われた枠を追い出す時は、使った ID の数を 1024 の倍数に切り上げ、[0, 1024) の乱数を足した値を、
//! 組の hash から選ぶ `CELLS` 個の「進み」に足します。
//! 新しい組(追い出された組を含む)の連番の始めの値に、その進みを足すので、追い出された組が戻っても、
//! 追い出される前の範囲の後ろから始まり、進みが 65536 を一周するまで最近の ID を使い直しません。
//! 進みは ID の置換の鍵に隠れますが、完全には隠れません。同じ進みの位置 (256 分の 1) を共有する攻撃者が、
//! 最近使われた組の追い出しを起こせると、追い出された組の使った数の和を、1024 に切り上げて乱数を足した値で
//! 知ります。TCP の packet は ID が 0 なので影響を受けません。表の大きさは固定で、Limits に依りません。

#![expect(
    clippy::cast_possible_truncation,
    reason = "the hash is cut to the 8, 16 and 56 bit pieces on purpose"
)]

use crate::rng::ChaCha8;
use crate::siphash::SipKey;

/// ID が相手で使い終わるとみなす時間 (ns) で、再組み立ての寿命です。
const LIFETIME: i64 = crate::frag::LIMITS.lifetime.cast_signed();
/// 追い出す時に進みへ足す数の丸めの単位です。
const STEP: u32 = 1024;

/// 集合の数 (2 の冪)。
const SETS: usize = 64;
/// 集合ごとの枠の数。
const WAYS: usize = 4;
/// 追い出した枠が使った ID の数を足す「進み」の数 (2 の冪)。
const CELLS: usize = 256;

/// 組の状態の枠です。`key` が 0 なら空です。
#[derive(Clone, Copy, Debug, Default)]
struct Slot {
    /// 宛先と protocol。空と区別する印 (1 << 48) を立てます。
    key: u64,
    /// 組の hash。置換の鍵と進みの位置を導きます。
    h: u64,
    /// 連番の始めの値です。
    start: u16,
    /// この枠で使った ID の数です (一周で戻る)。
    used: u16,
    /// 最後に使った順です (集合の中で最も古い枠を追い出す)。
    tick: u32,
    /// 最後に使った時刻 (ns) です。再組み立ての寿命より長く使われていない枠を先に追い出します。
    last: i64,
}

/// 組ごとの ID の表です。
#[derive(Debug)]
pub(crate) struct IdTable {
    key: SipKey,
    slots: [Slot; SETS * WAYS],
    /// 追い出した枠が使った ID の数の和です (一周で戻る)。
    advance: [u16; CELLS],
    tick: u32,
}

/// 用途の印です。組の hash の第 2 語に入れます。
const TUPLE_TAG: u64 = 0x6469_7069; // "ipid"

/// 16 bit の置換です。上下 8 bit の Feistel 4 段で、段の鍵は `h` の 16 bit ずつです。
fn permute(h: u64, counter: u16) -> u16 {
    let (mut left, mut right) = ((counter >> 8) as u8, counter as u8);
    for i in 0..4 {
        let k = u32::from((h >> (16 * i)) as u16);
        let v = ((k << 8) | u32::from(right)).wrapping_mul(0x9e37_79b1);
        let f = (v >> 24) as u8 ^ (v >> 13) as u8;
        (left, right) = (right, left ^ f);
    }
    (u16::from(left) << 8) | u16::from(right)
}

impl IdTable {
    pub(crate) fn new(key: SipKey) -> Self {
        Self {
            key,
            slots: [Slot::default(); SETS * WAYS],
            advance: [0; CELLS],
            tick: 0,
        }
    }

    /// 宛先 `dst` への protocol `proto` の組の、次の ID です。
    pub(crate) fn next(&mut self, dst: u32, proto: u8, now: i64, rng: &mut ChaCha8) -> u16 {
        let key = u64::from(dst) | (u64::from(proto) << 32) | (1 << 48);
        let h = self.key.sum(key, TUPLE_TAG);
        let cell = (h >> 56) as usize & (CELLS - 1);
        let set = ((h >> 48) as usize & (SETS - 1)) * WAYS;
        self.tick = self.tick.wrapping_add(1);
        let tick = self.tick;
        let ways = &mut self.slots[set..set + WAYS];
        let i = if let Some(i) = ways.iter().position(|w| w.key == key) {
            i
        } else {
            {
                // 空の枠、寿命を過ぎた枠のうち最も古いもの、最も古い枠の順に使います。
                let mut i = 0;
                let mut best = (false, false, 0u32);
                for (k, w) in ways.iter().enumerate() {
                    let rank = if w.key == 0 {
                        (true, true, 0)
                    } else {
                        (
                            false,
                            now.wrapping_sub(w.last) >= LIFETIME,
                            tick.wrapping_sub(w.tick),
                        )
                    };
                    if k == 0 || rank > best {
                        (i, best) = (k, rank);
                    }
                }
                let old = ways[i];
                if old.key != 0 && !best.1 {
                    // 寿命の内に使われた枠: 使った数を粗く切り上げ、乱数を足して進みに足す
                    let old_cell = (old.h >> 56) as usize & (CELLS - 1);
                    let credit = u32::from(old.used).div_ceil(STEP) * STEP
                        + rng.below(u64::from(STEP)) as u32;
                    self.advance[old_cell] = self.advance[old_cell].wrapping_add(credit as u16);
                }
                ways[i] = Slot {
                    key,
                    h,
                    start: ((h >> 32) as u16).wrapping_add(self.advance[cell]),
                    used: 0,
                    tick,
                    last: now,
                };
                i
            }
        };
        let s = &mut ways[i];
        s.tick = tick;
        s.last = now;
        let id = permute(s.h, s.start.wrapping_add(s.used));
        s.used = s.used.wrapping_add(1);
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UDP: u8 = 17;
    const SEC: i64 = 1_000_000_000;

    fn table() -> IdTable {
        IdTable::new(SipKey {
            k0: 0x0123_4567_89ab_cdef,
            k1: 0xfedc_ba98_7654_3210,
        })
    }

    fn rng(seed: u8) -> ChaCha8 {
        ChaCha8::new([seed; 32])
    }

    fn tuple_key(dst: u32) -> u64 {
        u64::from(dst) | (u64::from(UDP) << 32) | (1 << 48)
    }

    fn hash(t: &IdTable, dst: u32) -> u64 {
        t.key.sum(tuple_key(dst), TUPLE_TAG)
    }

    fn cell(t: &IdTable, dst: u32) -> usize {
        (hash(t, dst) >> 56) as usize & (CELLS - 1)
    }

    fn slot(t: &IdTable, dst: u32) -> Option<Slot> {
        t.slots.iter().copied().find(|s| s.key == tuple_key(dst))
    }

    fn slot_mut(t: &mut IdTable, dst: u32) -> &mut Slot {
        t.slots
            .iter_mut()
            .find(|s| s.key == tuple_key(dst))
            .unwrap()
    }

    /// 同じ集合に入り、進みの位置がすべて異なる宛先を `WAYS + 1` 個返します。
    fn colliding(t: &IdTable) -> [u32; WAYS + 1] {
        let mut by_set = [[0u32; WAYS + 1]; SETS];
        let mut len = [0usize; SETS];
        for dst in 1..100_000u32 {
            let set = (hash(t, dst) >> 48) as usize & (SETS - 1);
            let found = &by_set[set][..len[set]];
            if found.iter().all(|&d| cell(t, d) != cell(t, dst)) {
                by_set[set][len[set]] = dst;
                len[set] += 1;
                if len[set] == WAYS + 1 {
                    return by_set[set];
                }
            }
        }
        unreachable!()
    }

    /// 集合を埋めます。`d[0]` が最も古く、`used0` 個の ID を使った状態です。
    fn fill(t: &mut IdTable, d: &[u32; WAYS + 1], used0: u16, r: &mut ChaCha8) {
        for &dst in &d[..WAYS] {
            t.next(dst, UDP, 0, r);
        }
        slot_mut(t, d[0]).used = used0;
    }

    #[test]
    fn an_idle_way_is_evicted_before_an_older_active_way_and_credits_nothing() {
        let mut t = table();
        let d = colliding(&t);
        let mut r = rng(1);
        fill(&mut t, &d, 5000, &mut r);
        let now = 100 * SEC;
        // d[0] は tick が最も古いが使われている。d[2] は新しいが寿命より長く使われていない。
        for (i, &dst) in d[..WAYS].iter().enumerate() {
            let s = slot_mut(&mut t, dst);
            s.used = 5000;
            s.last = now - SEC;
            s.tick = 10 + i as u32;
        }
        slot_mut(&mut t, d[0]).tick = 1;
        slot_mut(&mut t, d[2]).last = now - LIFETIME;
        t.tick = 100;
        let before = t.advance;
        t.next(d[WAYS], UDP, now, &mut r);
        assert!(slot(&t, d[2]).is_none(), "the idle way is evicted");
        for &dst in &[d[0], d[1], d[3], d[WAYS]] {
            assert!(slot(&t, dst).is_some());
        }
        assert_eq!(t.advance, before, "an idle way credits nothing");
    }

    struct Evicted {
        delta: u16,
        start0: u16,
        table: IdTable,
        d: [u32; WAYS + 1],
    }

    /// 使った数 `used`、進みの初期値 `adv` の最も古い組を追い出し、進みに足された値 (mod 65536) を返します。
    fn evict_active(used: u16, adv: u16, seed: u8) -> Evicted {
        let mut t = table();
        let d = colliding(&t);
        let mut r = rng(seed);
        fill(&mut t, &d, used, &mut r);
        let c = cell(&t, d[0]);
        t.advance[c] = adv;
        let before = t.advance;
        let start0 = slot(&t, d[0]).unwrap().start;
        t.next(d[WAYS], UDP, SEC, &mut r);
        assert!(slot(&t, d[0]).is_none(), "the oldest active way is evicted");
        for (i, (&a, &b)) in before.iter().zip(&t.advance).enumerate() {
            if i != c {
                assert_eq!(a, b, "only the evicted tuple's cell changes");
            }
        }
        Evicted {
            delta: t.advance[c].wrapping_sub(adv),
            start0,
            table: t,
            d,
        }
    }

    #[test]
    fn evicting_an_active_way_credits_used_rounded_up_plus_less_than_a_step() {
        for used in [
            0u16, 1, 1000, 1024, 1025, 2047, 40_000, 64_511, 64_513, 65_535,
        ] {
            let ceil = u32::from(used).div_ceil(STEP) * STEP;
            for seed in 0..64 {
                let e = evict_active(used, 0, seed);
                let jitter = e.delta.wrapping_sub(ceil as u16);
                assert!(
                    u32::from(jitter) < STEP,
                    "used {used} seed {seed}: credit {}, rounded {ceil}",
                    e.delta
                );
            }
        }
    }

    #[test]
    fn an_evicted_tuple_resumes_after_its_previous_range_and_within_used_plus_2047() {
        for used in [0u16, 1, 1000, 1024, 1025, 2047, 30_000, 40_000, 63_000] {
            for seed in 0..32 {
                let mut e = evict_active(used, 0, seed);
                let mut r = rng(seed.wrapping_add(100));
                let id = e.table.next(e.d[0], UDP, 2 * SEC, &mut r);
                let s = slot(&e.table, e.d[0]).unwrap();
                assert_eq!(
                    id,
                    permute(s.h, s.start),
                    "the first ID comes from the new start"
                );
                // 前の範囲は start0 から used 個
                let gap = u32::from(s.start.wrapping_sub(e.start0));
                assert!(
                    gap >= u32::from(used) && gap <= u32::from(used) + 2047,
                    "used {used} seed {seed}: resumed {gap} after the start"
                );
            }
        }
    }

    #[test]
    fn the_advance_is_correct_when_used_or_the_cell_wraps() {
        // 進みの値が 65536 を回る
        for adv in [65_000u16, 65_535, 64_513] {
            for used in [0u16, 1, 1024, 5000, 64_000] {
                for seed in 0..32 {
                    let ceil = u32::from(used).div_ceil(STEP) * STEP;
                    let e = evict_active(used, adv, seed);
                    let jitter = e.delta.wrapping_sub(ceil as u16);
                    assert!(
                        u32::from(jitter) < STEP,
                        "adv {adv} used {used} seed {seed}"
                    );
                }
            }
        }
        // 使った数の切り上げが 65536 になり、足す値が 0 から 1023 に戻る。再作成の始めも回って決まる
        for used in [64_513u16, 65_000, 65_535] {
            for seed in 0..32 {
                let mut e = evict_active(used, 65_535, seed);
                assert!(
                    u32::from(e.delta) < STEP,
                    "ceil wraps: used {used} seed {seed}"
                );
                let mut r = rng(seed);
                e.table.next(e.d[0], UDP, 2 * SEC, &mut r);
                let s = slot(&e.table, e.d[0]).unwrap();
                assert_eq!(s.start, e.start0.wrapping_add(65_535).wrapping_add(e.delta));
            }
        }
    }
}
