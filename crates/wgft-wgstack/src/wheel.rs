//! タイマーの輪 (階層の timing wheel、Go の `wheel.go` の写し)。
//!
//! 節は接続の枠に固定で埋め込んだタイマーの数だけ作成の時に確保し、張り直すときは輪の中で動かすだけで
//! 確保しません。時刻の単位は 1 ms の tick で、3 段の 64 個の桶が 64 ms、4.096 秒、262 秒を覆います。
//! それより先の期限は最上段の桶 0 に置き、次に最上段を一周したときに置き直します。
//!
//! 段 L の桶 b は、今の tick T と同じ 64^(L+1) ms の窓の中の期限 t のうち、(t >> 6L) & 63 == b のものを
//! 持ちます。T が窓の境目を越えるとき、上の段の桶を下の段へ置き直します。
//! 期限の来た節を外す順は Go と同じで、出力の順に効くので bit の一致の条件に入ります。

use crate::fixed_vec::{AllocError, FixedVec};

const LEVELS: usize = 3;
const BUCKETS: usize = LEVELS * 64;
/// 1 tick の nanosecond です。
pub(crate) const TICK_NS: u64 = 1_000_000;
/// 節が無いときに [`Wheel::next_tick`] が返す値です。
pub(crate) const NO_TICK: u64 = 1 << 62;

const NIL: u32 = u32::MAX;
const OUT: u16 = u16::MAX;

/// タイマーの輪です。
#[derive(Debug)]
pub(crate) struct Wheel {
    /// 処理を終えた tick です。
    tick: u64,
    dl: FixedVec<u64>,
    next: FixedVec<u32>,
    prev: FixedVec<u32>,
    /// 節の桶 (段 * 64 + 桶) です。`OUT` は輪の外です。
    place: FixedVec<u16>,
    heads: [u32; BUCKETS],
    bm: [u64; LEVELS],
    count: usize,
}

/// ns の期限を、早く発火しないように切り上げた tick にします。
pub(crate) fn to_tick(ns: u64) -> u64 {
    ns.div_ceil(TICK_NS)
}

/// `bm` の `from` 以上の最も小さい立った bit を返します。
fn next_bit(bm: u64, from: u64) -> Option<u64> {
    if from >= 64 {
        return None;
    }
    let m = bm >> from;
    if m == 0 {
        return None;
    }
    Some(from + u64::from(m.trailing_zeros()))
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "bucket numbers are below 192"
)]
fn bucket(level: usize, b: u64) -> u16 {
    (level * 64) as u16 + (b & 63) as u16
}

impl Wheel {
    pub(crate) fn new(nodes: usize) -> Result<Self, AllocError> {
        Ok(Self {
            tick: 0,
            dl: FixedVec::try_filled(nodes, |_| 0)?,
            next: FixedVec::try_filled(nodes, |_| NIL)?,
            prev: FixedVec::try_filled(nodes, |_| NIL)?,
            place: FixedVec::try_filled(nodes, |_| OUT)?,
            heads: [NIL; BUCKETS],
            bm: [0; LEVELS],
            count: 0,
        })
    }

    /// 確保した領域の byte 数です。
    pub(crate) fn heap_bytes(&self) -> usize {
        self.dl.heap_bytes()
            + self.next.heap_bytes()
            + self.prev.heap_bytes()
            + self.place.heap_bytes()
    }

    /// 輪に入っている節の数です。
    pub(crate) fn count(&self) -> usize {
        self.count
    }

    /// 処理を終えた tick です。
    pub(crate) fn tick(&self) -> u64 {
        self.tick
    }

    /// 節 `n` が輪に入っていれば、その期限の tick を返します。
    pub(crate) fn deadline(&self, n: u32) -> Option<u64> {
        (self.place[n as usize] != OUT).then(|| self.dl[n as usize])
    }

    fn unlink(&mut self, n: u32) {
        let b = self.place[n as usize];
        if b == OUT {
            return;
        }
        let (p, x) = (self.prev[n as usize], self.next[n as usize]);
        if p == NIL {
            self.heads[usize::from(b)] = x;
            if x == NIL {
                self.bm[usize::from(b / 64)] &= !(1 << (b % 64));
            }
        } else {
            self.next[p as usize] = x;
        }
        if x != NIL {
            self.prev[x as usize] = p;
        }
        self.place[n as usize] = OUT;
        self.count -= 1;
    }

    fn link(&mut self, n: u32, b: u16) {
        let h = self.heads[usize::from(b)];
        self.next[n as usize] = h;
        self.prev[n as usize] = NIL;
        if h != NIL {
            self.prev[h as usize] = n;
        }
        self.heads[usize::from(b)] = n;
        self.bm[usize::from(b / 64)] |= 1 << (b % 64);
        self.place[n as usize] = b;
        self.count += 1;
    }

    /// 期限 `t` の節を桶に入れます。`t` は今の tick より後です。
    fn put(&mut self, n: u32, t: u64) {
        let now = self.tick;
        let b = if t >> 6 == now >> 6 {
            bucket(0, t)
        } else if t >> 12 == now >> 12 {
            bucket(1, t >> 6)
        } else if t >> 18 == now >> 18 {
            bucket(2, t >> 12)
        } else {
            bucket(2, 0) // 次の最上段の一周で置き直します
        };
        self.link(n, b);
    }

    /// 節 `n` の期限を `ns` にします。輪に入っていれば動かします。
    pub(crate) fn set(&mut self, n: u32, ns: u64) {
        self.unlink(n);
        let t = to_tick(ns).max(self.tick + 1);
        self.dl[n as usize] = t;
        self.put(n, t);
    }

    /// 節 `n` を輪から外します。
    pub(crate) fn cancel(&mut self, n: u32) {
        self.unlink(n);
    }

    /// 桶 `b` の節をすべて外し、期限の来た節を `fired` に足し、残りを置き直します。桶の list を先に切り離すので、
    /// 同じ桶へ置き直す節 (最上段の桶 0) で繰り返しが終わらなくなることはありません。
    fn drain(&mut self, b: u16, fired: &mut FixedVec<u32>) {
        let mut n = self.heads[usize::from(b)];
        self.heads[usize::from(b)] = NIL;
        self.bm[usize::from(b / 64)] &= !(1 << (b % 64));
        while n != NIL {
            let next = self.next[n as usize];
            self.place[n as usize] = OUT;
            self.count -= 1;
            if self.dl[n as usize] <= self.tick {
                // fired の容量は節の数で、1 回の advance で同じ節は 1 度しか発火しません。
                let pushed = fired.try_push(n);
                debug_assert!(pushed.is_ok(), "the fired list holds every node");
            } else {
                self.put(n, self.dl[n as usize]);
            }
            n = next;
        }
    }

    /// 時刻を `ns` まで進め、期限の来た節を外して `fired` に足します。
    pub(crate) fn advance(&mut self, ns: u64, fired: &mut FixedVec<u32>) {
        let now = ns / TICK_NS;
        while self.tick < now {
            if self.count == 0 {
                self.tick = now;
                break;
            }
            let t0 = self.tick;
            if let Some(b) = next_bit(self.bm[0], (t0 & 63) + 1) {
                let t = (t0 & !63) | b;
                if t > now {
                    self.tick = now;
                    break;
                }
                self.tick = t;
                self.drain(bucket(0, b), fired);
                continue;
            }
            // 下の段の今の窓は空です。次に中身のある段 1 の桶の窓か、段 2 の境目へ飛びます。
            let target = match next_bit(self.bm[1], ((t0 >> 6) & 63) + 1) {
                Some(b1) => (t0 & !4095) | (b1 << 6),
                None => (t0 | 4095) + 1,
            };
            if target > now {
                self.tick = now;
                break;
            }
            self.tick = target;
            if target.trailing_zeros() >= 12 {
                self.drain(bucket(2, target >> 12), fired);
            }
            self.drain(bucket(1, target >> 6), fired);
            self.drain(bucket(0, target), fired);
        }
    }

    /// 次に節の期限が来うる最も早い tick を返します。節が無ければ [`NO_TICK`] を返します。段 1 と段 2 の値は
    /// 下限で、その時刻に置き直した後に改めて求めます。
    pub(crate) fn next_tick(&self) -> u64 {
        if self.count == 0 {
            return NO_TICK;
        }
        let t = self.tick;
        if let Some(b) = next_bit(self.bm[0], (t & 63) + 1) {
            return (t & !63) | b;
        }
        if let Some(b) = next_bit(self.bm[1], ((t >> 6) & 63) + 1) {
            return (t & !4095) | (b << 6);
        }
        if let Some(b) = next_bit(self.bm[2], ((t >> 12) & 63) + 1) {
            return (t & !262_143) | (b << 12);
        }
        (t | 262_143) + 1
    }

    /// 桶の list、印の bit、節の数が一致することを確かめます。
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        let mut total = 0;
        for (b, &head) in self.heads.iter().enumerate() {
            let bit = self.bm[b / 64] >> (b % 64) & 1 == 1;
            if bit != (head != NIL) {
                return Err("a wheel bucket bit disagrees with its list");
            }
            let mut prev = NIL;
            let mut n = head;
            while n != NIL {
                if usize::from(self.place[n as usize]) != b || self.prev[n as usize] != prev {
                    return Err("a wheel node is linked into the wrong bucket");
                }
                if self.dl[n as usize] <= self.tick {
                    return Err("a wheel node is past its deadline");
                }
                total += 1;
                if total > self.place.len() {
                    return Err("a wheel bucket list loops");
                }
                prev = n;
                n = self.next[n as usize];
            }
        }
        if total != self.count || self.place.iter().filter(|&&p| p != OUT).count() != self.count {
            return Err("the wheel count disagrees with its buckets");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::disallowed_types, reason = "the test compares with a HashMap")]

    use super::*;
    use crate::rng::ChaCha8;
    use std::collections::HashMap;

    fn fired_list(n: usize) -> FixedVec<u32> {
        FixedVec::try_with_capacity(n).unwrap()
    }

    #[test]
    fn fires_each_deadline_once() {
        let mut w = Wheel::new(8).unwrap();
        let deadlines = [5u64, 64, 65, 4096, 5000, 300_000, 1_000_000];
        for (i, d) in deadlines.iter().enumerate() {
            w.set(u32::try_from(i).unwrap(), d * TICK_NS);
        }
        let mut got: HashMap<u32, u64> = HashMap::new();
        let mut fired = fired_list(8);
        let mut now = 0;
        while now <= 1_100_000 {
            fired.clear();
            w.advance(now * TICK_NS, &mut fired);
            for &n in fired.iter() {
                got.insert(n, now);
            }
            now += 7;
        }
        for (i, &d) in deadlines.iter().enumerate() {
            let at = got.get(&u32::try_from(i).unwrap()).copied();
            assert!(
                at.is_some_and(|at| at >= d && at < d + 7),
                "node {i} deadline {d} fired at {at:?}"
            );
        }
        w.set(7, 100 * TICK_NS);
        w.cancel(7);
        assert_eq!(w.count(), 0);
    }

    /// タイマーの輪を期限の表と比べます。早く発火しないこと、期限の後の最初の advance で発火すること、
    /// next_tick が次の期限より後にならないことを確かめます。
    #[test]
    fn against_reference() {
        const NODES: u32 = 64;
        for seed in 0..200u8 {
            let mut r = ChaCha8::new([seed; 32]);
            let mut w = Wheel::new(NODES as usize).unwrap();
            let mut model: HashMap<u32, u64> = HashMap::new();
            let mut fired = fired_list(NODES as usize);
            let mut now = r.below(1 << 20);
            w.advance(now * TICK_NS, &mut fired);
            for _ in 0..3000 {
                match r.below(10) {
                    0..4 => {
                        let n = u32::try_from(r.below(u64::from(NODES))).unwrap();
                        let d = match r.below(4) {
                            0 => r.below(70),
                            1 => r.below(5000),
                            2 => r.below(300_000),
                            _ => r.below(2_000_000),
                        };
                        let at = (now + d) * TICK_NS;
                        w.set(n, at);
                        model.insert(n, to_tick(at).max(w.tick() + 1));
                        assert_eq!(w.deadline(n), model.get(&n).copied());
                    }
                    4 => {
                        let n = u32::try_from(r.below(u64::from(NODES))).unwrap();
                        w.cancel(n);
                        model.remove(&n);
                    }
                    _ => {
                        if let Some(&earliest) = model.values().min() {
                            assert!(
                                w.next_tick() <= earliest,
                                "seed {seed}: next_tick after the earliest deadline"
                            );
                        }
                        now += match r.below(3) {
                            0 => r.below(100),
                            1 => r.below(10_000),
                            _ => r.below(1_000_000),
                        };
                        fired.clear();
                        w.advance(now * TICK_NS, &mut fired);
                        for &f in fired.iter() {
                            let d = model.remove(&f).unwrap_or_else(|| {
                                panic!("seed {seed}: node {f} fired but is not armed")
                            });
                            assert!(d <= now, "seed {seed}: node {f} fired early");
                        }
                        assert!(
                            model.values().all(|&d| d > now),
                            "seed {seed}: a deadline did not fire"
                        );
                    }
                }
                w.check().unwrap();
            }
        }
    }

    #[test]
    fn empty_wheel_has_no_tick() {
        let mut w = Wheel::new(2).unwrap();
        assert_eq!(w.next_tick(), NO_TICK);
        let mut fired = fired_list(2);
        w.advance(5 * TICK_NS, &mut fired);
        assert_eq!(w.tick(), 5);
        w.set(1, 0);
        assert_eq!(
            w.deadline(1),
            Some(6),
            "a deadline in the past moves to the next tick"
        );
        assert!(w.heap_bytes() >= 2 * (8 + 4 + 4 + 2));
    }
}
