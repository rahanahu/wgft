//! 4 つ組から行の番号を引く固定の大きさの hash の表 (Go の `index.go` の写し)。
//!
//! 開番地法 (線形探索) で、削除は後ろの項目を前へ詰めます (backward-shift deletion)。墓標を持たないので、
//! 探索の長さが削除で伸びません。容量は作成の時に決め、行の数の 2 倍以上の 2 のべき乗にします。
//! hash は作成の時の種で鍵を付けます。

use crate::fixed_vec::{AllocError, FixedVec};
use crate::siphash::SipKey;
use crate::wire::Tuple;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct IndexEnt {
    tup: Tuple,
    hash: u32,
    /// 行の番号 + 1。0 は空きです。
    id: u32,
}

/// 4 つ組の hash の表です。
#[derive(Debug)]
pub(crate) struct Index {
    key: SipKey,
    mask: u32,
    ents: FixedVec<IndexEnt>,
    /// `ents` と同じ位置の世代です。接続の表だけが持ち、握手の途中と TIME_WAIT の表は空です。
    gens: FixedVec<u64>,
}

/// 行の数 `rows` の表が持つ項目の数です。
pub(crate) fn capacity_for(rows: usize) -> usize {
    (2 * rows).max(1).next_power_of_two()
}

impl Index {
    /// `with_gen` が真なら、項目ごとに 64 bit の世代を持ちます。
    pub(crate) fn new(rows: usize, key: SipKey, with_gen: bool) -> Result<Self, AllocError> {
        let n = capacity_for(rows);
        let mask = u32::try_from(n - 1).map_err(|_| AllocError)?;
        Ok(Self {
            key,
            mask,
            ents: FixedVec::try_filled(n, |_| IndexEnt::default())?,
            gens: if with_gen {
                FixedVec::try_filled(n, |_| 0)?
            } else {
                FixedVec::new()
            },
        })
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "Go keeps the low 32 bits of the hash"
    )]
    fn hash(&self, t: Tuple) -> u32 {
        self.key.hash_tuple(t) as u32
    }

    /// 確保した領域の byte 数です。
    pub(crate) fn heap_bytes(&self) -> usize {
        self.ents.heap_bytes() + self.gens.heap_bytes()
    }

    /// `t` の行の番号と、入れた時の世代を返します。世代を持たない表では世代は 0 です。
    pub(crate) fn find(&self, t: Tuple) -> Option<(u32, u64)> {
        let h = self.hash(t);
        let mut i = h & self.mask;
        loop {
            let e = &self.ents[i as usize];
            if e.id == 0 {
                return None;
            }
            if e.hash == h && e.tup == t {
                let generation = self.gens.get(i as usize).copied().unwrap_or(0);
                return Some((e.id - 1, generation));
            }
            i = (i + 1) & self.mask;
        }
    }

    /// `t` を行 `id` として入れます。同じ `t` が既にあれば入れ替えます。表は行の数の 2 倍以上の容量を
    /// 持つので満杯になりません。
    pub(crate) fn insert(&mut self, t: Tuple, id: u32, generation: u64) {
        let h = self.hash(t);
        let mut i = h & self.mask;
        loop {
            let e = &mut self.ents[i as usize];
            if e.id == 0 || (e.hash == h && e.tup == t) {
                *e = IndexEnt {
                    tup: t,
                    hash: h,
                    id: id + 1,
                };
                if let Some(g) = self.gens.get_mut(i as usize) {
                    *g = generation;
                }
                return;
            }
            i = (i + 1) & self.mask;
        }
    }

    /// `t` を外し、外したかを返します。外した位置の後ろに続く項目のうち、本来の位置が外した位置か
    /// それより前にあるものを順に詰めます。
    #[expect(
        clippy::many_single_char_names,
        reason = "the names follow the Go code"
    )]
    pub(crate) fn remove(&mut self, t: Tuple) -> bool {
        let h = self.hash(t);
        let mut i = h & self.mask;
        loop {
            let e = &self.ents[i as usize];
            if e.id == 0 {
                return false;
            }
            if e.hash == h && e.tup == t {
                break;
            }
            i = (i + 1) & self.mask;
        }
        loop {
            self.ents[i as usize] = IndexEnt::default();
            if let Some(g) = self.gens.get_mut(i as usize) {
                *g = 0;
            }
            let mut j = i;
            loop {
                j = (j + 1) & self.mask;
                let e = self.ents[j as usize];
                if e.id == 0 {
                    return true;
                }
                let home = e.hash & self.mask;
                // home が (i, j] の巡回の区間に入るなら、e は i へ動かせません。
                if (j > i && (home <= i || home > j)) || (j < i && home <= i && home > j) {
                    self.ents[i as usize] = e;
                    if !self.gens.is_empty() {
                        self.gens[i as usize] = self.gens[j as usize];
                    }
                    i = j;
                    break;
                }
            }
        }
    }

    /// 項目の数です。
    pub(crate) fn len(&self) -> usize {
        self.ents.iter().filter(|e| e.id != 0).count()
    }

    /// すべての項目を、行の番号と 4 つ組の組で順に渡します。
    pub(crate) fn for_each(&self, mut f: impl FnMut(Tuple, u32)) {
        for e in self.ents.iter().filter(|e| e.id != 0) {
            f(e.tup, e.id - 1);
        }
    }

    /// どの項目も探索で見つかること (本来の位置から空きを挟まずに届くこと) を確かめます。
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        for e in self.ents.iter() {
            if e.id == 0 {
                continue;
            }
            if e.hash != self.hash(e.tup) {
                return Err("an index entry has a stale hash");
            }
            match self.find(e.tup) {
                Some((id, _)) if id == e.id - 1 => {}
                _ => return Err("an index entry is not reachable from its home position"),
            }
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

    fn backward_shift(with_gen: bool) {
        let mut x = Index::new(64, SipKey { k0: 1, k1: 2 }, with_gen).unwrap();
        let mut r = ChaCha8::new([3; 32]);
        let mut model: HashMap<Tuple, (u32, u64)> = HashMap::new();
        for step in 0..20000 {
            let tup = Tuple {
                laddr: 1,
                raddr: u32::try_from(r.below(8)).unwrap(),
                lport: 80,
                rport: u16::try_from(r.below(16)).unwrap(),
            };
            if model.contains_key(&tup) && r.below(2) == 0 {
                assert!(x.remove(tup), "step {step}: remove failed");
                model.remove(&tup);
            } else if model.len() < 64 {
                let id = u32::try_from(r.below(1000)).unwrap();
                let g = r.next_u64();
                x.insert(tup, id, g);
                model.insert(tup, (id, if with_gen { g } else { 0 }));
            }
            for (k, v) in &model {
                assert_eq!(x.find(*k), Some(*v), "step {step}: find {k:?}");
            }
            assert_eq!(x.len(), model.len(), "step {step}");
            x.check().unwrap();
        }
        assert!(!x.remove(Tuple {
            laddr: 9,
            ..Tuple::default()
        }));
    }

    #[test]
    fn backward_shift_without_generations() {
        backward_shift(false);
    }

    #[test]
    fn backward_shift_with_generations() {
        backward_shift(true);
    }

    #[test]
    fn capacity_is_a_power_of_two_at_least_twice_the_rows() {
        assert_eq!(capacity_for(0), 1);
        assert_eq!(capacity_for(1), 2);
        assert_eq!(capacity_for(3), 8);
        assert_eq!(capacity_for(2560), 8192);
        let x = Index::new(16, SipKey::default(), true).unwrap();
        assert_eq!(x.heap_bytes(), 32 * (size_of::<IndexEnt>() + 8));
        let mut n = 0;
        x.for_each(|_, _| n += 1);
        assert_eq!(n, 0);
    }
}
