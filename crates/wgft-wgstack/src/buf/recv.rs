//! 受信のバッファと順序外の区間の treap (Go の `recv.go` の写し)。
//!
//! 順序どおりの未読のデータ [read_off, nxt_off) と順序外のデータを同じ輪の位置に置き、順序外の届いた範囲を
//! 区間の表で持ちます。区間の数の上限は受信の予約から決め、表は予約の段ごとの固定の配列です。offset は接続の
//! 受信の始め (相手の ISN + 1) から数えます。
//!
//! 区間の表は、固定の配列を節の置き場にした treap です。区間は重ならず接しないので、始まりの順と終わりの順は
//! 同じで、どちらでも探せます。優先度は接続ごとの秘密の種から作るので、相手は木の形を選べません。SACK の
//! block は最近触れた区間の始まりを [`SACK_RECENT`] 個まで覚えて選びます (RFC 2018 4 節)。
//! 節の取り方と優先度の作り方は Go と同じで、SACK の block の選び方を通して出力に効きます。

use super::chunk::ChunkPool;
use super::ring::Ring;
use crate::fixed_vec::{AllocError, FixedVec};
use crate::wire::SackBlock;

/// SACK の block を選ぶために覚える最近の区間の数です。block は高々 4 つです。
pub(crate) const SACK_RECENT: usize = 4;

/// 順序外の 1 つの区間 [start, end) と木の節です。位置は offset の下位 32 bit で持ちます。区間はどれも
/// `nxt_off` から受信の予約 (4 MiB 以下) の内側にあるので、`nxt_off` から元の offset を復元できます。空きの節
/// では `l` が次の空きの節です。節の番号は配列の位置 + 1 で、0 は無しです。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Interval {
    start: u32,
    end: u32,
    l: u16,
    r: u16,
    pri: u32,
}

/// [`RecvBuf::insert`] の結果です。
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is a separate outcome the caller counts"
)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct InsertResult {
    /// 輪に入れた byte です。
    pub(crate) accepted: usize,
    /// 上限の外の分を捨てました。
    pub(crate) trimmed: bool,
    /// 区間の上限を超える区間を作るので segment を捨てました。
    pub(crate) dropped: bool,
    /// chunk の確保に失敗したので segment を捨てました。状態は変えていません。
    pub(crate) no_memory: bool,
    /// 順序外のデータを入れました。
    pub(crate) ooo: bool,
    /// 順序外の区間を順序どおりの範囲に取り込みました。
    pub(crate) filled: bool,
    /// `nxt_off` が進みました。
    pub(crate) advanced: bool,
    /// 中身がすべて既に届いていました。
    pub(crate) duplicate: bool,
    /// 既に届いていた部分の最初の範囲 (offset) です。`dup_hi > dup_lo` のときだけ意味を持ちます。D-SACK の
    /// block にします (RFC 2883)。
    pub(crate) dup_lo: u64,
    pub(crate) dup_hi: u64,
}

/// 受信のバッファです。
/// `repr(C)` で管理の欄を前に、輪 (chunk の pointer の配列を持つ) を後ろに置きます。受信の経路が触る管理の欄を
/// 少ないキャッシュの行に収めるためです。
#[derive(Debug)]
#[repr(C)]
pub(crate) struct RecvBuf {
    /// 最も古い未読の byte です。
    pub(crate) read_off: u64,
    /// 次に順序どおりに受ける byte (RCV.NXT) です。
    pub(crate) nxt_off: u64,
    iv: FixedVec<Interval>,
    /// 使っている区間の数です。
    n: usize,
    /// 区間が持つ順序外の byte の合計です。
    ooo: u64,
    root: u16,
    free: u16,
    /// 配列のうち一度でも節に使った数です。
    used: u16,
    seed: u64,
    ctr: u64,
    /// 最近触れた区間の始まり (offset の下位 32 bit) で、新しい順です。
    recent: [u32; SACK_RECENT],
    nrecent: usize,
    pub(crate) r: Ring,
}

/// 種から優先度を作る混ぜ合わせです。
pub(crate) fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "positions are kept as the low 32 bits of the offset"
)]
fn low32(x: u64) -> u32 {
    x as u32
}

impl RecvBuf {
    /// 容量 `cap` の輪と区間の表 `iv` の空の受信のバッファです。`seed` は接続ごとの優先度の種です。
    pub(crate) fn new(cap: u64, iv: FixedVec<Interval>, seed: u64) -> Self {
        Self {
            r: Ring::new(cap),
            read_off: 0,
            nxt_off: 0,
            iv,
            n: 0,
            ooo: 0,
            root: 0,
            free: 0,
            used: 0,
            seed,
            ctr: 0,
            recent: [0; SACK_RECENT],
            nrecent: 0,
        }
    }

    /// 確立の時に、容量 `cap` の空の輪と、空の区間の表と、接続ごとの優先度の種 `seed` で始め直します。区間の表の
    /// 配列はそのまま使います。
    pub(crate) fn restart(&mut self, cap: u64, seed: u64) {
        debug_assert!(
            self.r.held_chunks() == 0,
            "a restarted buffer holds no chunks"
        );
        self.r = Ring::new(cap);
        self.read_off = 0;
        self.nxt_off = 0;
        self.clear_intervals();
        self.seed = seed;
        self.ctr = 0;
    }

    fn full(&self, x: u32) -> u64 {
        self.nxt_off + u64::from(x.wrapping_sub(low32(self.nxt_off)))
    }

    fn node(&self, k: u16) -> &Interval {
        &self.iv[usize::from(k) - 1]
    }

    fn node_mut(&mut self, k: u16) -> &mut Interval {
        &mut self.iv[usize::from(k) - 1]
    }

    fn k_start(&self, k: u16) -> u64 {
        self.full(self.node(k).start)
    }

    fn k_end(&self, k: u16) -> u64 {
        self.full(self.node(k).end)
    }

    pub(crate) fn unread(&self) -> u64 {
        self.nxt_off - self.read_off
    }

    /// 使っている区間の数です。
    pub(crate) fn intervals_len(&self) -> usize {
        self.n
    }

    /// 区間が持つ順序外の byte の合計です。
    pub(crate) fn ooo_bytes(&self) -> u64 {
        self.ooo
    }

    /// 区間の表の容量です。
    pub(crate) fn intervals_capacity(&self) -> usize {
        self.iv.len()
    }

    /// 区間の表が確保した byte 数です。
    pub(crate) fn intervals_heap_bytes(&self) -> usize {
        self.iv.heap_bytes()
    }

    /// 保持する最も右の byte の次の offset (順序外のデータを含む) です。
    pub(crate) fn rightmost(&self) -> u64 {
        if self.root == 0 {
            self.nxt_off
        } else {
            self.nxt_off.max(self.k_end(self.last_node(self.root)))
        }
    }

    /// 順序どおりの未読のデータも順序外のデータも持たないかを返します。
    pub(crate) fn empty(&self) -> bool {
        self.nxt_off == self.read_off && self.n == 0
    }

    /// 区間の表を `iv` に移し、前の表を返します。使っている区間が `iv` に入らなければ、区間を切り捨てずに今の
    /// 表を持ち続けて `iv` を返します。
    pub(crate) fn set_intervals(
        &mut self,
        iv: FixedVec<Interval>,
    ) -> Result<FixedVec<Interval>, FixedVec<Interval>> {
        if self.n > iv.len() {
            return Err(iv);
        }
        let old = core::mem::replace(&mut self.iv, iv);
        let old_root = self.root;
        self.root = 0;
        self.free = 0;
        self.used = 0;
        // 区間を始まりの順に新しい表へ入れます。Go と同じく、入れるたびに優先度の数え上げが進みます。
        walk_in(&old, old_root, &mut |s, e| {
            let k = self.alloc(s, e);
            self.root = self.merge(self.root, k);
            true
        });
        Ok(old)
    }

    /// 区間の表を取り出し、区間を空にします。
    pub(crate) fn take_intervals(&mut self) -> FixedVec<Interval> {
        self.clear_intervals();
        core::mem::take(&mut self.iv)
    }

    /// 順序外の区間をすべて捨て、木と節の置き場と最近の区間を空にします。
    pub(crate) fn clear_intervals(&mut self) {
        self.n = 0;
        self.root = 0;
        self.free = 0;
        self.used = 0;
        self.nrecent = 0;
        self.ooo = 0;
    }

    /// 順序外のデータのうち、`limit` 以降の byte と、始まりの順で `max_n` 個目より後の区間を捨てます (RFC 2018
    /// 8 節の取り消し)。`limit` をまたぐ区間は `limit` で切ります。捨てた区間の最近の印も外します。順序どおりの
    /// データは捨てません。呼び手は `nxt_off <= limit` を保証します。捨てた byte の数を返します。
    pub(crate) fn renege(&mut self, mut limit: u64, max_n: usize) -> u64 {
        if self.n > max_n
            && let Some(s) = self.nth_start(max_n)
        {
            limit = limit.min(s);
        }
        if self.root == 0 || self.rightmost() <= limit {
            return 0;
        }
        let before = self.ooo;
        // 始まりが limit より前の区間を残します。limit は 1 以上です。
        let (keep, drop) = self.split_start_up_to(self.root, limit - 1);
        self.n -= self.release(drop);
        if keep != 0 {
            let last = self.last_node(keep);
            let end = self.k_end(last);
            if end > limit {
                self.ooo -= end - limit;
                self.node_mut(last).end = low32(limit);
            }
        }
        self.root = keep;
        self.forget_recent(|x| x >= limit);
        before - self.ooo
    }

    /// 始まりの順で `i` 番目 (0 から) の区間の始まりです。
    fn nth_start(&self, i: usize) -> Option<u64> {
        let mut seen = 0;
        let mut found = None;
        self.walk(self.root, &mut |s, _| {
            if seen == i {
                found = Some(s);
                return false;
            }
            seen += 1;
            true
        });
        found
    }

    fn can_alloc(&self) -> bool {
        self.free != 0 || usize::from(self.used) < self.iv.len()
    }

    /// 節を 1 つ取り、区間 [s, e) を入れて返します。空きが無ければ 0 を返します。
    #[expect(
        clippy::cast_possible_truncation,
        reason = "Go keeps the low 32 bits of the mixed priority"
    )]
    fn alloc(&mut self, s: u64, e: u64) -> u16 {
        let k = if self.free != 0 {
            let k = self.free;
            self.free = self.node(k).l;
            k
        } else if usize::from(self.used) < self.iv.len() {
            self.used += 1;
            self.used
        } else {
            return 0;
        };
        self.ctr += 1;
        let pri = splitmix64(self.seed.wrapping_add(self.ctr)) as u32;
        *self.node_mut(k) = Interval {
            start: low32(s),
            end: low32(e),
            l: 0,
            r: 0,
            pri,
        };
        k
    }

    /// 木 `t` の節をすべて空きに返し、その数を返します。返した区間の byte を順序外の byte の合計から引きます。
    fn release(&mut self, t: u16) -> usize {
        if t == 0 {
            return 0;
        }
        let x = *self.node(t);
        self.ooo -= u64::from(x.end.wrapping_sub(x.start));
        let free = self.free;
        let n = self.node_mut(t);
        n.l = free;
        n.r = 0;
        self.free = t;
        1 + self.release(x.l) + self.release(x.r)
    }

    /// `a` のどの区間も `c` のどの区間より前にある 2 つの木をつなぎます。
    fn merge(&mut self, a: u16, c: u16) -> u16 {
        if a == 0 {
            return c;
        }
        if c == 0 {
            return a;
        }
        if self.node(a).pri >= self.node(c).pri {
            let r = self.merge(self.node(a).r, c);
            self.node_mut(a).r = r;
            a
        } else {
            let l = self.merge(a, self.node(c).l);
            self.node_mut(c).l = l;
            c
        }
    }

    /// 木 `t` を、終わりが `off` より前の区間と残りに分けます。
    fn split_end_before(&mut self, t: u16, off: u64) -> (u16, u16) {
        if t == 0 {
            return (0, 0);
        }
        let x = *self.node(t);
        if self.full(x.end) < off {
            let (l, r) = self.split_end_before(x.r, off);
            self.node_mut(t).r = l;
            (t, r)
        } else {
            let (l, r) = self.split_end_before(x.l, off);
            self.node_mut(t).l = r;
            (l, t)
        }
    }

    /// 木 `t` を、始まりが `end` 以下の区間と残りに分けます。
    fn split_start_up_to(&mut self, t: u16, end: u64) -> (u16, u16) {
        if t == 0 {
            return (0, 0);
        }
        let x = *self.node(t);
        if self.full(x.start) <= end {
            let (l, r) = self.split_start_up_to(x.r, end);
            self.node_mut(t).r = l;
            (t, r)
        } else {
            let (l, r) = self.split_start_up_to(x.l, end);
            self.node_mut(t).l = r;
            (l, t)
        }
    }

    fn first_node(&self, mut t: u16) -> u16 {
        while self.node(t).l != 0 {
            t = self.node(t).l;
        }
        t
    }

    fn last_node(&self, mut t: u16) -> u16 {
        while self.node(t).r != 0 {
            t = self.node(t).r;
        }
        t
    }

    /// offset `x` を含む区間の節を返します。無ければ 0 です。
    fn containing(&self, x: u64) -> u16 {
        let mut t = self.root;
        while t != 0 {
            if x < self.k_start(t) {
                t = self.node(t).l;
            } else if x >= self.k_end(t) {
                t = self.node(t).r;
            } else {
                return t;
            }
        }
        0
    }

    /// 区間 [s, e) を最も新しく触れた区間として覚えます。その区間の内側を指す古い印は外します。
    fn touch_recent(&mut self, s: u64, e: u64) {
        self.forget_recent(|x| x >= s && x < e);
        if self.nrecent == SACK_RECENT {
            self.nrecent -= 1;
        }
        self.recent.copy_within(..self.nrecent, 1);
        self.recent[0] = low32(s);
        self.nrecent += 1;
    }

    /// offset が `drop` に当たる最近の区間の印を順を保って外します。
    fn forget_recent(&mut self, drop: impl Fn(u64) -> bool) {
        let mut k = 0;
        for i in 0..self.nrecent {
            if !drop(self.full(self.recent[i])) {
                self.recent[k] = self.recent[i];
                k += 1;
            }
        }
        self.nrecent = k;
    }

    /// 木 `t` の区間を始まりの順に `f` に渡します。`f` が偽を返したら止め、偽を返します。
    fn walk(&self, t: u16, f: &mut dyn FnMut(u64, u64) -> bool) -> bool {
        if t == 0 {
            return true;
        }
        let x = *self.node(t);
        self.walk(x.l, f) && f(self.full(x.start), self.full(x.end)) && self.walk(x.r, f)
    }

    /// 区間を始まりの順に `f` に渡します。
    pub(crate) fn for_each_interval(&self, f: &mut dyn FnMut(u64, u64) -> bool) {
        self.walk(self.root, f);
    }

    /// 輪の中身を移す時の書いた範囲 (未読の範囲と順序外の区間) を `f` に渡します。
    pub(crate) fn for_each_written(
        &self,
        f: &mut dyn FnMut(u64, u64) -> Result<(), AllocError>,
    ) -> Result<(), AllocError> {
        if self.nxt_off > self.read_off {
            f(self.read_off, self.nxt_off)?;
        }
        let mut res = Ok(());
        self.walk(self.root, &mut |s, e| {
            res = f(s, e);
            res.is_ok()
        });
        res
    }

    /// 輪を容量 `cap` に移し、書いた範囲を写します。確保に失敗したら輪を変えずに誤りを返します。
    pub(crate) fn resize_ring(&mut self, cap: u64, pool: &mut ChunkPool) -> Result<(), AllocError> {
        let cur = self.r.cap();
        let mut ring = core::mem::replace(&mut self.r, Ring::new(cur));
        let res = ring.resize(cap, pool, |f| self.for_each_written(f));
        self.r = ring;
        res
    }

    /// offset `off` からの `data` を入れます。`limit` を超える分は捨てます。`limit` は広告した窓の右端と
    /// `read_off + cap` の小さい方です。順序外のデータで新しい区間が要り、区間が上限の数だけあるときは、
    /// segment 全体を捨てます。既存の区間を伸ばすか穴を埋める segment は受け入れます。
    #[expect(
        clippy::many_single_char_names,
        reason = "the names follow the Go code"
    )]
    pub(crate) fn insert(
        &mut self,
        mut off: u64,
        mut data: &[u8],
        limit: u64,
        pool: &mut ChunkPool,
    ) -> InsertResult {
        let mut res = InsertResult::default();
        let mut end = off + data.len() as u64;
        if end > limit {
            if off >= limit {
                res.trimmed = !data.is_empty();
                return res;
            }
            data = &data[..usize::try_from(limit - off).unwrap_or(data.len())];
            end = limit;
            res.trimmed = true;
        }
        if off < self.nxt_off {
            if end <= self.nxt_off {
                res.duplicate = !data.is_empty();
                (res.dup_lo, res.dup_hi) = (off, end);
                return res;
            }
            (res.dup_lo, res.dup_hi) = (off, self.nxt_off); // 前半だけが重複
            data = &data[usize::try_from(self.nxt_off - off).unwrap_or(0)..];
            off = self.nxt_off;
        }
        if data.is_empty() {
            return res;
        }
        if off == self.nxt_off {
            if self.r.write(off, data, pool).is_err() {
                return InsertResult {
                    no_memory: true,
                    ..InsertResult::default()
                };
            }
            res.accepted = data.len();
            res.advanced = true;
            // 届いた順序外の区間を取り込みます。区間は接しないので、end 以下で始まる区間をまとめて外せばよい。
            // 区間の位置は nxt_off を動かす前の値で復元します。
            let (m, rest) = self.split_start_up_to(self.root, end);
            if m != 0 {
                let f = self.first_node(m);
                let (st, en) = (self.k_start(f), self.k_end(f));
                if st < end && res.dup_hi <= res.dup_lo {
                    (res.dup_lo, res.dup_hi) = (st, end.min(en)); // 届いていた区間と重なる部分
                }
                end = end.max(self.k_end(self.last_node(m)));
                self.n -= self.release(m);
                res.filled = true;
                self.forget_recent(|x| x < end); // 順序どおりの範囲に入った区間の印
            }
            self.root = rest;
            self.nxt_off = end;
            return res;
        }
        // 順序外:重なるか接する区間を木から切り出します。
        let (l, rest) = self.split_end_before(self.root, off);
        let (m, r) = self.split_start_up_to(rest, end);
        if m == 0 {
            if !self.can_alloc() {
                self.root = self.merge(l, r);
                res.dropped = true;
                return res;
            }
            if self.r.reserve(off, data.len(), pool).is_err() {
                self.root = self.merge(l, r);
                return InsertResult {
                    no_memory: true,
                    ..InsertResult::default()
                };
            }
            let k = self.alloc(off, end);
            self.n += 1;
            self.ooo += end - off;
            let lk = self.merge(l, k);
            self.root = self.merge(lk, r);
            self.touch_recent(off, end);
        } else {
            let (f, g) = (self.first_node(m), self.last_node(m));
            if f == g && self.k_start(f) <= off && end <= self.k_end(f) {
                // すべて既に届いています。RFC 2018 の順のために最近の印だけ付け直します。
                let lm = self.merge(l, m);
                self.root = self.merge(lm, r);
                self.touch_recent(self.k_start(f), self.k_end(f));
                res.duplicate = true;
                (res.dup_lo, res.dup_hi) = (off, end);
                return res;
            }
            if self.r.reserve(off, data.len(), pool).is_err() {
                let lm = self.merge(l, m);
                self.root = self.merge(lm, r);
                return InsertResult {
                    no_memory: true,
                    ..InsertResult::default()
                };
            }
            let (lo, hi) = (off.max(self.k_start(f)), end.min(self.k_end(f)));
            if lo < hi && res.dup_hi <= res.dup_lo {
                (res.dup_lo, res.dup_hi) = (lo, hi); // 既存の区間と重なる部分
            }
            let (ns, ne) = (off.min(self.k_start(f)), end.max(self.k_end(g)));
            self.n -= self.release(m);
            let k = self.alloc(ns, ne); // 返したばかりの節があるので取れます
            self.n += 1;
            self.ooo += ne - ns;
            let lk = self.merge(l, k);
            self.root = self.merge(lk, r);
            self.touch_recent(ns, ne);
        }
        self.r.write_reserved(off, data);
        res.accepted = data.len();
        res.ooo = true;
        res
    }

    /// 未読のデータを `dst` に写して読んだ分を外し、写した数を返します。
    pub(crate) fn read(&mut self, dst: &mut [u8], pool: &mut ChunkPool) -> usize {
        let n = usize::try_from(self.unread()).map_or(dst.len(), |u| u.min(dst.len()));
        if n == 0 {
            return 0;
        }
        self.r.read(self.read_off, &mut dst[..n]);
        let old = self.read_off;
        self.read_off += n as u64;
        let hi = self.rightmost();
        self.r.trim(old, self.read_off, hi, pool);
        n
    }

    /// 最も新しく触れた区間を先頭に、区間を最大 `out.len()` 個の SACK の block にして `out` に書き、書いた数を
    /// 返します (RFC 2018 4 節)。最近触れた区間で足りなければ、始まりの順に残りの区間で埋めます。`base` は
    /// offset 0 のシーケンス番号です。
    pub(crate) fn sack_blocks(&self, out: &mut [SackBlock], base: u32) -> usize {
        let cap = out.len();
        let mut len = 0;
        if self.n == 0 || cap == 0 {
            return 0;
        }
        let block = |s: u64, e: u64| SackBlock {
            left: base.wrapping_add(low32(s)),
            right: base.wrapping_add(low32(e)),
        };
        let mut seen = [0u16; SACK_RECENT];
        let mut ns = 0;
        let mut i = 0;
        while i < self.nrecent && len < cap {
            let k = self.containing(self.full(self.recent[i]));
            i += 1;
            if k == 0 || seen[..ns].contains(&k) {
                continue;
            }
            seen[ns] = k;
            ns += 1;
            out[len] = block(self.k_start(k), self.k_end(k));
            len += 1;
        }
        if len < cap && len < self.n {
            let limit = cap + ns;
            let mut buf = [(0u64, 0u64); 2 * SACK_RECENT];
            let mut got = 0;
            self.walk(self.root, &mut |s, e| {
                if got >= limit || got >= buf.len() {
                    return false;
                }
                buf[got] = (s, e);
                got += 1;
                true
            });
            for &(s, e) in &buf[..got] {
                if len == cap {
                    break;
                }
                let b = block(s, e);
                if out[..len].iter().any(|o| o.left == b.left) {
                    continue;
                }
                out[len] = b;
                len += 1;
            }
        }
        len
    }

    /// 木の順序と heap の順序、区間が重ならず接しないこと、数と byte の合計、空きの list と木の節が合わせて
    /// 使った節の数になることを確かめます。
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        let used = usize::from(self.used);
        if used > self.iv.len() {
            return Err("an interval table uses more nodes than it has");
        }
        let mut seen = FixedVec::try_filled(used + 1, |_| false)
            .map_err(|_| "allocation failed while checking")?;
        let mut count = 0;
        let mut held = 0;
        let mut prev_end: Option<u64> = None;
        self.check_node(
            self.root,
            0,
            u64::MAX,
            u32::MAX,
            &mut seen,
            &mut count,
            &mut held,
            &mut prev_end,
        )?;
        if count != self.n || held != self.ooo {
            return Err("an interval tree disagrees with its counts");
        }
        let mut free = 0;
        let mut k = self.free;
        while k != 0 {
            if usize::from(k) > used || seen[usize::from(k)] {
                return Err("an interval node is both free and in the tree");
            }
            seen[usize::from(k)] = true;
            free += 1;
            k = self.node(k).l;
        }
        if free + count != used {
            return Err("free and tree interval nodes do not add up to the used nodes");
        }
        Ok(())
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the recursion carries the bounds and the tallies"
    )]
    fn check_node(
        &self,
        k: u16,
        lo: u64,
        hi: u64,
        max_pri: u32,
        seen: &mut FixedVec<bool>,
        count: &mut usize,
        held: &mut u64,
        prev_end: &mut Option<u64>,
    ) -> Result<(), &'static str> {
        if k == 0 {
            return Ok(());
        }
        if usize::from(k) >= seen.len() || seen[usize::from(k)] {
            return Err("an interval node is out of range or reached twice");
        }
        seen[usize::from(k)] = true;
        let x = *self.node(k);
        let (s, e) = (self.full(x.start), self.full(x.end));
        if x.pri > max_pri {
            return Err("the interval treap heap order is broken");
        }
        if s >= e || s < lo || e > hi {
            return Err("the interval treap search order is broken");
        }
        self.check_node(x.l, lo, s, x.pri, seen, count, held, prev_end)?;
        if prev_end.is_some_and(|p| s <= p) || s <= self.nxt_off {
            return Err("intervals overlap, touch, or reach the in-order range");
        }
        *prev_end = Some(e);
        *count += 1;
        *held += e - s;
        self.check_node(x.r, e, hi, x.pri, seen, count, held, prev_end)
    }
}

/// 配列 `iv` の木 `t` の区間を始まりの順に渡します。位置は `full` で offset に戻しません (区間の表を移す
/// 間は位置をそのまま写すためです)。
fn walk_in(iv: &FixedVec<Interval>, t: u16, f: &mut dyn FnMut(u64, u64) -> bool) -> bool {
    if t == 0 {
        return true;
    }
    let x = iv[usize::from(t) - 1];
    walk_in(iv, x.l, f) && f(u64::from(x.start), u64::from(x.end)) && walk_in(iv, x.r, f)
}

#[cfg(test)]
mod tests;
