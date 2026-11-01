//! Go の `parts_test.go` (受信の区間)、`intervaltree_test.go`、`intervalmodel_test.go`、`intervals_test.go` の
//! 区間の表の部分の写しです。

#![expect(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "tests compare with growing models"
)]
#![expect(
    clippy::cast_possible_truncation,
    reason = "tests cut random words into bytes and lengths"
)]

use super::super::{BOOST_INTERVALS, BOOST_SIZE, FLOOR_INTERVALS, MIN_MSS, RECV_FLOOR};
use super::*;
use crate::buf::chunk::fail_chunks_after;
use crate::rng::ChaCha8;
use crate::seq;

fn table(n: usize) -> FixedVec<Interval> {
    FixedVec::try_filled(n, |_| Interval::default()).unwrap()
}

fn blocks(b: &RecvBuf, cap: usize, base: u32) -> Vec<SackBlock> {
    let mut out = [SackBlock::default(); 4];
    let n = b.sack_blocks(&mut out[..cap], base);
    out[..n].to_vec()
}

fn intervals(b: &RecvBuf) -> Vec<(u64, u64)> {
    let mut v = Vec::new();
    b.for_each_interval(&mut |s, e| {
        v.push((s, e));
        true
    });
    v
}

#[test]
fn recv_intervals() {
    let mut p = ChunkPool::new().unwrap();
    let mut b = RecvBuf::owning(RECV_FLOOR, table(FLOOR_INTERVALS), 0);
    let limit = RECV_FLOOR;
    // 区間の上限を超える区間を作る segment は捨てます。
    for i in 0..FLOOR_INTERVALS as u64 {
        assert!(
            b.insert(100 + i * 10, &[1], limit, &mut p).ooo,
            "interval {i} not accepted"
        );
    }
    assert!(
        b.insert(100 + FLOOR_INTERVALS as u64 * 10 + 5, &[1], limit, &mut p)
            .dropped
    );
    // 既存の区間を伸ばす segment は受け入れます。
    let res = b.insert(101, &[1], limit, &mut p);
    assert!(res.ooo && !res.dropped, "{res:?}");
    // 窓の外は捨てます。
    assert!(b.insert(limit, &[1], limit, &mut p).trimmed);
    // 穴を埋めると全部取り込みます。
    let res = b.insert(0, &[0; 100], limit, &mut p);
    assert!(res.filled && b.nxt_off == 102, "{res:?} nxt {}", b.nxt_off);
    let last = 100 + (FLOOR_INTERVALS as u32 - 1) * 10;
    let bl = blocks(&b, 4, 0);
    assert_eq!(bl.len(), 4);
    assert_eq!(
        bl[0],
        SackBlock {
            left: last,
            right: last + 1
        }
    );
    assert_eq!(
        bl[1],
        SackBlock {
            left: last - 10,
            right: last - 9
        }
    );
    b.check().unwrap();
    // 数と byte の合計が木と合わないことの検出。
    b.n += 1;
    assert_eq!(b.check(), Err("an interval tree disagrees with its counts"));
    b.n -= 1;
    b.ooo += 1;
    assert_eq!(b.check(), Err("an interval tree disagrees with its counts"));
    b.ooo -= 1;
    b.check().unwrap();
    b.r.release(&mut p);
}

/// MSS の下限の segment が 1 つおきに失われても、受信のバッファが満ちるまで区間が尽きないことを確かめます。
#[test]
fn recv_intervals_cover_a_full_buffer() {
    for (cap, h) in [(RECV_FLOOR, FLOOR_INTERVALS), (BOOST_SIZE, BOOST_INTERVALS)] {
        let mut p = ChunkPool::new().unwrap();
        let mut b = RecvBuf::owning(cap, table(h), 0);
        let seg = vec![0u8; MIN_MSS as usize];
        let mut off = MIN_MSS;
        while off + MIN_MSS <= cap {
            assert!(
                !b.insert(off, &seg, cap, &mut p).dropped,
                "capacity {cap}: segment at {off} dropped"
            );
            off += 2 * MIN_MSS;
        }
        b.r.release(&mut p);
    }
}

fn height(b: &RecvBuf, t: u16) -> usize {
    if t == 0 {
        0
    } else {
        1 + height(b, b.node(t).l).max(height(b, b.node(t).r))
    }
}

/// 相手が区間を作る順によらず、木の高さが区間の数の対数の程度に留まることを確かめます。
#[test]
fn interval_tree_stays_shallow() {
    for order in ["up", "down", "zigzag"] {
        let mut p = ChunkPool::new().unwrap();
        let mut b = RecvBuf::owning(BOOST_SIZE, table(BOOST_INTERVALS), 12345);
        for i in 0..BOOST_INTERVALS {
            let k = match order {
                "down" => BOOST_INTERVALS - 1 - i,
                "zigzag" if i % 2 == 0 => i / 2,
                "zigzag" => BOOST_INTERVALS - 1 - i / 2,
                _ => i,
            };
            b.insert(2 + 2 * k as u64, &[1], BOOST_SIZE, &mut p);
        }
        assert_eq!(b.intervals_len(), BOOST_INTERVALS, "{order}");
        // 3,913 節の treap の高さの期待値は 25 程度です。60 を超えるのは木が偏ったときです。
        assert!(
            height(&b, b.root) <= 60,
            "{order}: tree height {}",
            height(&b, b.root)
        );
        b.check().unwrap();
        b.r.release(&mut p);
    }
}

#[test]
fn set_intervals_refuses_to_truncate() {
    let mut p = ChunkPool::new().unwrap();
    let mut b = RecvBuf::owning(BOOST_SIZE, table(BOOST_INTERVALS), 0);
    for i in 0..FLOOR_INTERVALS as u64 + 10 {
        b.insert(1 + 2 * i, &[1], BOOST_SIZE, &mut p);
    }
    let back = b.set_intervals(table(FLOOR_INTERVALS)).unwrap_err();
    assert_eq!(back.len(), FLOOR_INTERVALS);
    assert_eq!(
        (b.intervals_capacity(), b.intervals_len()),
        (BOOST_INTERVALS, FLOOR_INTERVALS + 10)
    );
    b.insert(
        1 + 2 * (FLOOR_INTERVALS as u64 + 10),
        &[1],
        BOOST_SIZE,
        &mut p,
    );
    b.check().unwrap();
    b.r.release(&mut p);
}

/// 取り消しは limit 以降と max_n 個目より後の区間を捨て、limit をまたぐ区間を切ります。
#[test]
fn renege_cuts_at_the_limit_and_the_count() {
    let mut p = ChunkPool::new().unwrap();
    let mut b = RecvBuf::owning(BOOST_SIZE, table(16), 0);
    for s in [10u64, 20, 30, 40] {
        b.insert(s, &[1; 5], BOOST_SIZE, &mut p);
    }
    assert_eq!(b.renege(32, 16), 3 + 5);
    assert_eq!(intervals(&b), [(10, 15), (20, 25), (30, 32)]);
    assert_eq!(b.renege(1000, 1), 2 + 5);
    assert_eq!(intervals(&b), [(10, 15)]);
    assert_eq!(b.renege(1000, 1), 0);
    assert_eq!(b.ooo_bytes(), 5);
    b.check().unwrap();
    b.r.release(&mut p);
}

#[test]
fn read_returns_in_order_bytes_and_frees_chunks() {
    let mut p = ChunkPool::new().unwrap();
    let mut b = RecvBuf::owning(RECV_FLOOR, table(4), 0);
    let data: Vec<u8> = (0..40000u32).map(|i| i as u8).collect();
    assert_eq!(b.insert(0, &data, RECV_FLOOR, &mut p).accepted, data.len());
    let mut got = vec![0u8; 40000];
    assert_eq!(b.read(&mut got[..20000], &mut p), 20000);
    assert_eq!(
        b.r.held_chunks(),
        2,
        "the chunk before the read offset is returned"
    );
    assert_eq!(b.read(&mut got[20000..], &mut p), 20000);
    assert_eq!(got, data);
    assert!(b.empty());
    assert_eq!(b.r.held_chunks(), 0);
    assert_eq!(p.held(), 0);
}

// 区間の treap を、整列した区間の list の模型と比べる試験です (Go の TestIntervalTreeAgainstModel)。

#[derive(Default)]
struct Model {
    nxt: u64,
    iv: Vec<(u64, u64)>,
    limit: usize,
}

impl Model {
    fn insert(&mut self, mut off: u64, n: usize, lim: u64) -> InsertResult {
        let mut res = InsertResult::default();
        let mut end = off + n as u64;
        if end > lim {
            if off >= lim {
                res.trimmed = n > 0;
                return res;
            }
            end = lim;
            res.trimmed = true;
        }
        if off < self.nxt {
            if end <= self.nxt {
                res.duplicate = end > off;
                (res.dup_lo, res.dup_hi) = (off, end);
                return res;
            }
            (res.dup_lo, res.dup_hi) = (off, self.nxt);
            off = self.nxt;
        }
        if end == off {
            return res;
        }
        if off == self.nxt {
            res.accepted = (end - off) as usize;
            res.advanced = true;
            let mut k = 0;
            while k < self.iv.len() && self.iv[k].0 <= end {
                if self.iv[k].0 < end && res.dup_hi <= res.dup_lo {
                    (res.dup_lo, res.dup_hi) = (self.iv[k].0, end.min(self.iv[k].1));
                }
                end = end.max(self.iv[k].1);
                k += 1;
            }
            if k > 0 {
                self.iv.drain(..k);
                res.filled = true;
            }
            self.nxt = end;
            return res;
        }
        let i = self.iv.iter().take_while(|x| x.1 < off).count();
        let j = i + self.iv[i..].iter().take_while(|x| x.0 <= end).count();
        if i == j {
            if self.iv.len() == self.limit {
                res.dropped = true;
                return res;
            }
            self.iv.insert(i, (off, end));
        } else {
            if self.iv[i].0 <= off && end <= self.iv[i].1 && j == i + 1 {
                res.duplicate = true;
                (res.dup_lo, res.dup_hi) = (off, end);
                return res;
            }
            let (lo, hi) = (off.max(self.iv[i].0), end.min(self.iv[i].1));
            if lo < hi && res.dup_hi <= res.dup_lo {
                (res.dup_lo, res.dup_hi) = (lo, hi);
            }
            let (ns, ne) = (off.min(self.iv[i].0), end.max(self.iv[j - 1].1));
            self.iv.splice(i..j, [(ns, ne)]);
        }
        res.accepted = (end - off) as usize;
        res.ooo = true;
        res
    }
}

fn pat(off: u64) -> u8 {
    (off.wrapping_mul(131).wrapping_add(off >> 9)) as u8
}

fn normalized(mut r: InsertResult) -> InsertResult {
    if r.dup_hi <= r.dup_lo {
        (r.dup_lo, r.dup_hi) = (0, 0);
    }
    r
}

#[test]
fn interval_tree_against_model() {
    let (mut block_count, mut deviate) = (0, 0);
    for seed in 1..=30u8 {
        let (b, d) = run_model(seed);
        block_count += b;
        deviate += d;
    }
    // SACK の block が新しく触れた順からずれる割合は、最近の区間の印が 4 つしかないので 0 にはなりませんが、
    // 古い印で枠を使わなければ数 % に留まります。
    assert!(
        deviate * 100 <= block_count * 8,
        "SACK blocks differ from the most-recent order in {deviate} of {block_count}"
    );
}

fn run_model(seed: u8) -> (usize, usize) {
    let mut rng = ChaCha8::new([seed; 32]);
    let mut n = |k: u64| -> u64 { rng.below(k) };
    let mut pool = ChunkPool::new().unwrap();
    let tables = [1usize, 2, 3, 5, 8, 16, FLOOR_INTERVALS];
    let mut size = tables[n(tables.len() as u64) as usize];
    let capb = if n(2) == 0 { RECV_FLOOR } else { BOOST_SIZE };
    let pri_seed = n(u64::MAX);
    let mut b = RecvBuf::owning(capb, table(size), pri_seed);
    let mut m = Model {
        limit: size,
        ..Model::default()
    };
    // 32 bit の位置の巻き戻りを通すため、始まりの offset を大きくします。
    if n(3) == 0 {
        let st = (1u64 << 32) - n(200_000);
        (b.nxt_off, b.read_off, m.nxt) = (st, st, st);
    }
    let span = 64 + n(4000);
    let max_len = 1 + n(300);
    let mut touches: Vec<u64> = Vec::new();
    let (mut block_count, mut deviate) = (0, 0);
    for op in 0..3000 {
        let ctx = format!("seed {seed} op {op} size {size}");
        let limit = b.read_off + capb;
        let off = match n(20) {
            0 => b.nxt_off,
            1 if b.nxt_off > 50 => b.nxt_off - n(50),
            2 => limit - n(30),
            3 if !m.iv.is_empty() => {
                let x = m.iv[n(m.iv.len() as u64) as usize];
                if n(2) == 0 {
                    x.1
                } else {
                    x.0 - (x.0 - b.nxt_off).min(1 + n(max_len))
                }
            }
            _ => b.nxt_off + 1 + n(span),
        };
        let len = if n(30) == 0 {
            0
        } else {
            1 + n(max_len) as usize
        };
        let data: Vec<u8> = (0..len as u64).map(|i| pat(off + i)).collect();
        let want = normalized(m.insert(off, len, limit));
        let got = b.insert(off, &data, limit, &mut pool);
        assert_eq!(
            normalized(got),
            want,
            "{ctx}: insert({off},{len}) lim {limit}"
        );
        assert_eq!(b.nxt_off, m.nxt, "{ctx}");
        b.check().unwrap_or_else(|e| panic!("{ctx}: {e}"));
        assert_eq!(intervals(&b), m.iv, "{ctx}");
        if got.ooo || (got.duplicate && off > b.nxt_off) {
            touches.push(off);
        }
        for capd in [4usize, 3, 2, 1] {
            const BASE: u32 = 1000;
            let blks = blocks(&b, capd, BASE);
            assert_eq!(
                blks.len(),
                m.iv.len().min(capd),
                "{ctx}: blocks with cap {capd}"
            );
            for (i, bl) in blks.iter().enumerate() {
                assert!(
                    m.iv.iter().any(|x| bl.left == BASE.wrapping_add(x.0 as u32)
                        && bl.right == BASE.wrapping_add(x.1 as u32)),
                    "{ctx}: {bl:?} is not an interval"
                );
                assert!(
                    !blks[..i].iter().any(|o| o.left == bl.left),
                    "{ctx}: repeated block"
                );
            }
            // 理想の順:新しく触れた順にその時の区間へ写し、重複を除いたもの。
            let mut ideal: Vec<u32> = Vec::new();
            let mut seen: Vec<u64> = Vec::new();
            for &t in touches.iter().rev() {
                if ideal.len() >= capd {
                    break;
                }
                for x in &m.iv {
                    if x.0 <= t && t < x.1 && !seen.contains(&x.0) {
                        seen.push(x.0);
                        ideal.push(BASE.wrapping_add(x.0 as u32));
                    }
                }
            }
            for x in &m.iv {
                if ideal.len() >= capd {
                    break;
                }
                if !seen.contains(&x.0) {
                    seen.push(x.0);
                    ideal.push(BASE.wrapping_add(x.0 as u32));
                }
            }
            block_count += 1;
            if blks.iter().zip(&ideal).any(|(b, i)| b.left != *i) {
                deviate += 1;
            }
            if (got.ooo || (got.duplicate && off > b.nxt_off))
                && let Some(f) = blks.first()
            {
                let x = (off as u32).wrapping_add(BASE);
                assert!(
                    seq::le(f.left, x) && seq::lt(x, f.right),
                    "{ctx}: first block {f:?} does not hold the triggering offset {off}"
                );
            }
        }
        if n(4) == 0 && b.unread() > 0 {
            let k = 1 + n(b.unread().min(2000)) as usize;
            let mut dst = vec![0u8; k];
            let ro = b.read_off;
            let got = b.read(&mut dst, &mut pool);
            for (i, &x) in dst[..got].iter().enumerate() {
                assert_eq!(x, pat(ro + i as u64), "{ctx}: read byte {i}");
            }
        }
        // boost と floor への戻りのように表を移します。
        if n(200) == 0 {
            let ns = tables[n(tables.len() as u64) as usize];
            let ok = b.set_intervals(table(ns)).is_ok();
            assert_eq!(
                ok,
                m.iv.len() <= ns,
                "{ctx}: set_intervals({ns}) with {} intervals",
                m.iv.len()
            );
            if ok {
                size = ns;
                m.limit = ns;
            }
            b.check()
                .unwrap_or_else(|e| panic!("{ctx} after resize: {e}"));
        }
    }
    b.r.release(&mut pool);
    (block_count, deviate)
}

/// 確保の失敗の後に状態が変わっていないことを比べる写しです。
fn snapshot(b: &RecvBuf, p: &ChunkPool) -> impl PartialEq + core::fmt::Debug + use<> {
    (
        (
            b.r.held_chunks(),
            b.r.cap(),
            b.read_off,
            b.nxt_off,
            p.held(),
        ),
        (b.root, b.free, b.used, b.n, b.ooo, b.ctr),
        (b.recent, b.nrecent),
        intervals(b),
    )
}

/// chunk の確保に失敗した挿入と輪の移しは、木、数、印、輪、置き場のどれも変えません。
#[test]
fn failed_allocation_changes_nothing() {
    let mut p = ChunkPool::new().unwrap();
    let mut b = RecvBuf::owning(BOOST_SIZE, table(8), 99);
    b.insert(0, &[1; 100], BOOST_SIZE, &mut p);
    b.insert(200, &[2; 50], BOOST_SIZE, &mut p);
    b.check().unwrap();
    // (offset, 長さ, 失敗までに取れる chunk の数)。どれも、取れる数より多くの新しい chunk を要します。
    let cases: [(u64, usize, usize); 5] = [
        (100, 40_000, 1),
        (40_000, 10, 0),
        (150, 50_000, 1),
        (100, 20_000, 0),
        (70_000, 40_000, 2),
    ];
    for (off, len, after) in cases {
        let before = snapshot(&b, &p);
        fail_chunks_after(Some(after));
        let res = b.insert(off, &vec![3; len], BOOST_SIZE, &mut p);
        fail_chunks_after(None);
        assert!(res.no_memory, "insert({off}, {len}) after {after}: {res:?}");
        assert_eq!(
            snapshot(&b, &p),
            before,
            "insert({off}, {len}) after {after}"
        );
        b.check().unwrap();
    }
    let before = snapshot(&b, &p);
    fail_chunks_after(Some(0));
    assert!(b.resize_ring(RECV_FLOOR, &mut p).is_err());
    fail_chunks_after(None);
    assert_eq!(snapshot(&b, &p), before, "a failed ring move");
    // 失敗しなければ同じ操作は通ります。
    assert!(b.insert(40_000, &[4; 10], BOOST_SIZE, &mut p).ooo);
    b.resize_ring(RECV_FLOOR * 2, &mut p).unwrap();
    b.check().unwrap();
    b.r.release(&mut p);
    assert_eq!(p.held(), 0);
}
