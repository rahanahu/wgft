//! 暗号鍵の経路表 (cryptokey routing の AllowedIPs)。
//!
//! 最長一致で IPv4 のアドレスからピアを引く。送信では宛先からピアを選び、受信では復号した
//! packet の送信元を引いて、送ってきたピアと一致するものだけを通す。prefix の長さごとの表を
//! 長い順に引くので、1 回の引きは高々 33 回の hash の引きで、ピアの数に依らない。

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::config::{Ipv4Prefix, mask};

#[derive(Debug)]
pub(crate) struct AllowedIps<V> {
    tables: [HashMap<u32, V>; 33],
    /// 空でない表の prefix の長さ。長い順。
    lens: Vec<u8>,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the server role removes peers at run time; the agent never does"
    )
)]
impl<V: Copy + Eq> AllowedIps<V> {
    pub(crate) fn new() -> Self {
        Self {
            tables: std::array::from_fn(|_| HashMap::new()),
            lens: Vec::new(),
        }
    }

    /// `prefix` を `owner` に割り当てる。ほかのピアが持っていた同じ prefix は移る (WireGuard と同じ)。
    pub(crate) fn insert(&mut self, prefix: Ipv4Prefix, owner: V) {
        let len = prefix.len();
        self.tables[usize::from(len)].insert(u32::from(prefix.addr()), owner);
        if let Err(at) = self.lens.binary_search_by(|l| len.cmp(l)) {
            self.lens.insert(at, len);
        }
    }

    /// `prefix` が `owner` のものなら外す。
    pub(crate) fn remove(&mut self, prefix: Ipv4Prefix, owner: V) {
        let len = prefix.len();
        let table = &mut self.tables[usize::from(len)];
        let key = u32::from(prefix.addr());
        if table.get(&key) == Some(&owner) {
            table.remove(&key);
            self.forget_empty(len);
        }
    }

    /// `owner` の prefix をすべて外す。
    pub(crate) fn remove_owner(&mut self, owner: V) {
        for len in self.lens.clone() {
            self.tables[usize::from(len)].retain(|_, v| *v != owner);
            self.forget_empty(len);
        }
    }

    fn forget_empty(&mut self, len: u8) {
        if self.tables[usize::from(len)].is_empty() {
            self.lens.retain(|l| *l != len);
        }
    }

    pub(crate) fn lookup(&self, ip: Ipv4Addr) -> Option<V> {
        let bits = u32::from(ip);
        self.lens
            .iter()
            .find_map(|&len| self.tables[usize::from(len)].get(&(bits & mask(len))))
            .copied()
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.lens.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn p(a: u8, b: u8, c: u8, d: u8, len: u8) -> Ipv4Prefix {
        Ipv4Prefix::new(Ipv4Addr::new(a, b, c, d), len).unwrap()
    }

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    // wireguard-go の TestTrieIPv4 (Linux の selftest/allowedips.h から移したもの) の場合を写す。
    #[test]
    #[expect(
        clippy::many_single_char_names,
        reason = "the peer names of the ported test"
    )]
    fn longest_prefix_cases_from_wireguard() {
        let (a, b, c, d, e, g, h) = (1, 2, 3, 4, 5, 7, 8);
        let mut t = AllowedIps::new();
        t.insert(p(192, 168, 4, 0, 24), a);
        t.insert(p(192, 168, 4, 4, 32), b);
        t.insert(p(192, 168, 0, 0, 16), c);
        t.insert(p(192, 95, 5, 64, 27), d);
        t.insert(p(192, 95, 5, 65, 27), c);
        t.insert(p(0, 0, 0, 0, 0), e);
        t.insert(p(64, 15, 112, 0, 20), g);
        t.insert(p(64, 15, 123, 211, 25), h);
        t.insert(p(10, 0, 0, 0, 25), a);
        t.insert(p(10, 0, 0, 128, 25), b);
        t.insert(p(10, 1, 0, 0, 30), a);
        t.insert(p(10, 1, 0, 4, 30), b);
        t.insert(p(10, 1, 0, 8, 29), c);
        t.insert(p(10, 1, 0, 16, 29), d);

        assert_eq!(t.lookup(ip(192, 168, 4, 20)), Some(a));
        assert_eq!(t.lookup(ip(192, 168, 4, 0)), Some(a));
        assert_eq!(t.lookup(ip(192, 168, 4, 4)), Some(b));
        assert_eq!(t.lookup(ip(192, 168, 200, 182)), Some(c));
        assert_eq!(t.lookup(ip(192, 95, 5, 68)), Some(c));
        assert_eq!(t.lookup(ip(192, 95, 5, 96)), Some(e));
        assert_eq!(t.lookup(ip(64, 15, 116, 26)), Some(g));
        assert_eq!(t.lookup(ip(64, 15, 127, 3)), Some(g));

        for first in [1, 64, 128, 192, 255] {
            t.insert(p(first, 0, 0, 0, 32), a);
        }
        for first in [1, 64, 128, 192, 255] {
            assert_eq!(t.lookup(ip(first, 0, 0, 0)), Some(a));
        }
        t.remove_owner(a);
        for first in [1, 64, 128, 192, 255] {
            assert_ne!(t.lookup(ip(first, 0, 0, 0)), Some(a));
        }

        for owner in [a, b, c, d, e, g, h] {
            t.remove_owner(owner);
        }
        assert!(t.is_empty(), "removing every owner leaves an empty table");

        t.insert(p(192, 168, 0, 0, 16), a);
        t.insert(p(192, 168, 0, 0, 24), a);
        t.remove_owner(a);
        assert_eq!(t.lookup(ip(192, 168, 0, 1)), None);

        t.insert(p(1, 0, 0, 0, 32), a);
        t.insert(p(192, 0, 0, 0, 24), a);
        assert_eq!(t.lookup(ip(1, 0, 0, 0)), Some(a));
        assert_eq!(t.lookup(ip(192, 0, 0, 1)), Some(a));
        t.remove(p(192, 0, 0, 0, 32), a);
        assert_eq!(t.lookup(ip(192, 0, 0, 1)), Some(a));
        t.remove(p(192, 0, 0, 0, 24), b);
        assert_eq!(
            t.lookup(ip(192, 0, 0, 1)),
            Some(a),
            "only the owner removes a prefix"
        );
        t.remove(p(192, 0, 0, 0, 24), a);
        assert_eq!(t.lookup(ip(192, 0, 0, 1)), None);
        t.remove(p(1, 0, 0, 0, 32), a);
        assert_eq!(t.lookup(ip(1, 0, 0, 0)), None);
    }

    #[test]
    fn inserting_an_owned_prefix_moves_it() {
        let mut t = AllowedIps::new();
        t.insert(p(10, 200, 0, 1, 32), 1);
        t.insert(p(10, 200, 0, 1, 32), 2);
        assert_eq!(t.lookup(ip(10, 200, 0, 1)), Some(2));
    }

    proptest! {
        // 素朴な最長一致の模型と同じ答えを返す。
        #[test]
        fn matches_a_linear_model(
            entries in proptest::collection::vec((any::<u32>(), 0u8..=32, 0u8..4), 0..24),
            probes in proptest::collection::vec(any::<u32>(), 1..64),
        ) {
            let mut t = AllowedIps::new();
            let mut model: Vec<(Ipv4Prefix, u8)> = Vec::new();
            for (addr, len, owner) in entries {
                let prefix = Ipv4Prefix::new(Ipv4Addr::from_bits(addr), len).unwrap();
                t.insert(prefix, owner);
                model.retain(|(q, _)| *q != prefix);
                model.push((prefix, owner));
            }
            for probe in probes {
                let probe = Ipv4Addr::from_bits(probe);
                let want = model
                    .iter()
                    .filter(|(q, _)| q.contains(probe))
                    .max_by_key(|(q, _)| q.len())
                    .map(|(_, o)| *o);
                prop_assert_eq!(t.lookup(probe), want);
            }
        }
    }
}
