//! 出力の組の表 (Go の `output.go` の写し)。
//!
//! 接続の組と行の組は packet を待ち行列に積まず、送るものがある枠と行の番号を順番の list に並べ、
//! `poll_transmit` の時に先頭の 1 つが packet を 1 つ作ります。list の節は固定の配列に置くので、出力の保持は
//! 接続と行の数で決まります。制御の組だけが、MTU の大きさの枠を固定の数だけ持つ輪に packet を積みます。
//! 組の選び方 (deficit round robin) は [`crate::stack`] の送り出しが持ちます。

use crate::bitset::BitSet;
use crate::fixed_vec::{AllocError, FixedVec};

/// list の節が無いことを表す番号です。
pub(crate) const NIL: u32 = u32::MAX;

/// 固定の配列の上の両方向の list です。印の bit の集合 `in_list` の bit i が、節 i が list に入っているかを
/// 示します。印を bit で持つのは、検査が節の数の bool をたどらずに 64 個ずつ数えられるようにするためです。
#[derive(Debug)]
pub(crate) struct Dlist {
    head: u32,
    tail: u32,
    next: FixedVec<u32>,
    prev: FixedVec<u32>,
    in_list: BitSet,
    n: usize,
}

impl Dlist {
    pub(crate) fn new(nodes: usize) -> Result<Self, AllocError> {
        Ok(Self {
            head: NIL,
            tail: NIL,
            next: FixedVec::try_filled(nodes, |_| NIL)?,
            prev: FixedVec::try_filled(nodes, |_| NIL)?,
            in_list: BitSet::new(nodes)?,
            n: 0,
        })
    }

    /// 節 `nodes` 個の list の配列の byte です。上界の式が使います。
    pub(crate) const fn bytes_for(nodes: usize) -> usize {
        nodes * 2 * size_of::<u32>() + BitSet::bytes_for(nodes)
    }

    #[cfg(test)]
    pub(crate) fn heap_bytes(&self) -> usize {
        self.next.heap_bytes() + self.prev.heap_bytes() + self.in_list.heap_bytes()
    }

    /// list の節を先頭から渡します。呼ぶ前に [`Dlist::check`] で list が壊れていないことを確かめます。
    pub(crate) fn for_each(&self, mut f: impl FnMut(u32)) {
        let mut i = self.head;
        for _ in 0..self.n {
            if i == NIL {
                return;
            }
            f(i);
            i = self.next[i as usize];
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.n
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.n == 0
    }

    pub(crate) fn contains(&self, i: u32) -> bool {
        self.in_list.get(i)
    }

    pub(crate) fn front(&self) -> Option<u32> {
        (self.head != NIL).then_some(self.head)
    }

    /// 節 `i` を末尾に入れます。既に入っていれば何もせず、偽を返します。
    pub(crate) fn push_back(&mut self, i: u32) -> bool {
        if self.in_list.get(i) {
            return false;
        }
        self.in_list.set(i);
        self.next[i as usize] = NIL;
        self.prev[i as usize] = self.tail;
        if self.tail == NIL {
            self.head = i;
        } else {
            self.next[self.tail as usize] = i;
        }
        self.tail = i;
        self.n += 1;
        true
    }

    /// 節 `i` を外します。入っていなければ何もしません。試験と fuzz の build では、外した節を作成の時の値 (`NIL`)
    /// に戻します。list に無い節がどれも作成の時と同じ値になり、空の list を次の核に渡せるためです
    /// ([`crate::stack::Spare`])。
    pub(crate) fn remove(&mut self, i: u32) {
        if !self.in_list.get(i) {
            return;
        }
        self.in_list.unset(i);
        let (p, x) = (self.prev[i as usize], self.next[i as usize]);
        #[cfg(any(test, feature = "harness"))]
        {
            (self.prev[i as usize], self.next[i as usize]) = (NIL, NIL);
        }
        if p == NIL {
            self.head = x;
        } else {
            self.next[p as usize] = x;
        }
        if x == NIL {
            self.tail = p;
        } else {
            self.prev[x as usize] = p;
        }
        self.n -= 1;
    }

    /// 節と印がすべて作成の時の値かを返します。手間は節の数に比例し、試験が使います。
    #[cfg(any(test, feature = "harness"))]
    pub(crate) fn is_fresh(&self) -> bool {
        self.head == NIL
            && self.tail == NIL
            && self.n == 0
            && self.in_list.count() == 0
            && self.next.iter().chain(self.prev.iter()).all(|&x| x == NIL)
    }

    /// list にある節 `i` を先頭に移します。list に無ければ何もしません。
    pub(crate) fn move_to_front(&mut self, i: u32) {
        if !self.in_list.get(i) || self.head == i {
            return;
        }
        self.remove(i);
        self.in_list.set(i);
        self.prev[i as usize] = NIL;
        self.next[i as usize] = self.head;
        if self.head == NIL {
            self.tail = i;
        } else {
            self.prev[self.head as usize] = i;
        }
        self.head = i;
        self.n += 1;
    }

    pub(crate) fn pop_front(&mut self) -> Option<u32> {
        let i = self.front()?;
        self.remove(i);
        Some(i)
    }

    /// list の向きと印と数が一致することを確かめます。たどった節はどれも印を持ち、前の節を指すので、同じ節を
    /// 2 度通りません。このため、たどった数と印の数が等しければ、印を持つ節はすべて list にあります。手間は
    /// list の長さと、印の配列の語 (節 64 個で 1 語) の数に比例します。
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        let mut count = 0;
        let mut prev = NIL;
        let mut i = self.head;
        while i != NIL {
            let Some(&p) = self.prev.get(i as usize) else {
                return Err("a list link is out of range");
            };
            if !self.in_list.get(i) || p != prev {
                return Err("a list node is linked but not marked");
            }
            count += 1;
            if count > self.next.len() {
                return Err("a list loops");
            }
            prev = i;
            i = self.next[i as usize];
        }
        if prev != self.tail || count != self.n || self.in_list.count() != self.n {
            return Err("a list count disagrees with its nodes");
        }
        Ok(())
    }
}

/// 枠の長さの欄の最上位 bit です。echo の応答の断片の枠に立てます (MTU は 2^15 より小さい)。
const ECHO_FLAG: u16 = 0x8000;

// 枠の長さは MTU 以下なので、最上位 bit の印と重ならないことを、型の上で保ちます。
const _: () = assert!(crate::config::MAX_MTU < ECHO_FLAG as usize);

/// 制御の出力の輪です。枠の数と大きさは作成の時に固定し、満杯なら新しい packet を捨てます。echo の応答の断片が
/// 同時に持てる枠は上限があり、残りは RST と ICMP の誤りのために空けます。
#[derive(Debug)]
pub(crate) struct CtlRing {
    buf: FixedVec<u8>,
    lens: FixedVec<u16>,
    size: usize,
    head: usize,
    n: usize,
    /// 輪にある echo の応答の断片の枠の数です。積む時に増やし、取り出す時に減らします。
    echo: usize,
    /// `echo` の上限です。
    echo_cap: usize,
}

impl CtlRing {
    /// 大きさ `size` の枠を `slots` 個持つ輪を確保します。echo の応答の断片の上限は `max(1, slots / 4)` です。
    pub(crate) fn new(slots: usize, size: usize) -> Result<Self, AllocError> {
        let bytes = slots.checked_mul(size).ok_or(AllocError)?;
        Ok(Self {
            buf: FixedVec::try_filled(bytes, |_| 0)?,
            lens: FixedVec::try_filled(slots, |_| 0)?,
            size,
            head: 0,
            n: 0,
            echo: 0,
            echo_cap: (slots / 4).max(1),
        })
    }

    #[cfg(test)]
    pub(crate) fn heap_bytes(&self) -> usize {
        self.buf.heap_bytes() + self.lens.heap_bytes()
    }

    pub(crate) fn len(&self) -> usize {
        self.n
    }

    /// echo の応答の断片 `k` 個を、全部まとめて積めるかを返します。輪の空きに足り、echo の応答の断片の枠が上限を
    /// 超えないときだけ真です。
    pub(crate) fn echo_room(&self, k: usize) -> bool {
        self.lens.len() - self.n >= k && self.echo + k <= self.echo_cap
    }

    /// 次に積む枠を返します。満杯なら `None` です。
    pub(crate) fn slot(&mut self) -> Option<&mut [u8]> {
        if self.n == self.lens.len() {
            return None;
        }
        let i = (self.head + self.n) % self.lens.len();
        Some(&mut self.buf[i * self.size..(i + 1) * self.size])
    }

    /// [`CtlRing::slot`] の枠に書いた長さ `n` の packet を積みます。
    pub(crate) fn commit(&mut self, n: usize) {
        let i = (self.head + self.n) % self.lens.len();
        self.lens[i] = u16::try_from(n.min(self.size)).unwrap_or(u16::MAX);
        self.n += 1;
    }

    /// [`CtlRing::commit`] と同じで、echo の応答の断片として数えます。呼ぶ前に [`CtlRing::echo_room`] で
    /// 確かめます。
    pub(crate) fn commit_echo(&mut self, n: usize) {
        let i = (self.head + self.n) % self.lens.len();
        self.commit(n);
        self.lens[i] |= ECHO_FLAG;
        self.echo += 1;
    }

    /// 積んだ packet をすべて捨てます。
    pub(crate) fn clear(&mut self) {
        self.head = 0;
        self.n = 0;
        self.echo = 0;
    }

    /// echo の応答の断片の数えが、輪の中の印の付いた枠の数と上限に合うかを確かめます。
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        let slots = self.lens.len();
        let flagged = (0..self.n)
            .filter(|k| self.lens[(self.head + k) % slots] & ECHO_FLAG != 0)
            .count();
        if flagged != self.echo {
            return Err("ctl ring: the echo count differs from the echo slots in the ring");
        }
        if self.echo > self.echo_cap {
            return Err("ctl ring: echo slots exceed their cap");
        }
        Ok(())
    }

    /// 先頭の packet を `dst` に写して外し、写した長さを返します。空なら `None` です。
    pub(crate) fn pop(&mut self, dst: &mut [u8]) -> Option<usize> {
        if self.n == 0 {
            return None;
        }
        let i = self.head;
        if self.lens[i] & ECHO_FLAG != 0 {
            self.echo -= 1;
        }
        let len = usize::from(self.lens[i] & !ECHO_FLAG).min(dst.len());
        dst[..len].copy_from_slice(&self.buf[i * self.size..i * self.size + len]);
        self.head = (self.head + 1) % self.lens.len();
        self.n -= 1;
        Some(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dlist_keeps_order_and_ignores_repeats() {
        let mut l = Dlist::new(5).unwrap();
        assert!(l.push_back(3));
        assert!(l.push_back(1));
        assert!(
            !l.push_back(3),
            "a node already in the list stays where it is"
        );
        assert!(l.push_back(4));
        l.remove(1);
        l.remove(1);
        l.check().unwrap();
        assert_eq!((l.len(), l.contains(4), l.contains(1)), (2, true, false));
        assert_eq!(l.pop_front(), Some(3));
        assert_eq!(l.pop_front(), Some(4));
        assert_eq!(l.pop_front(), None);
        assert!(l.is_empty());
        l.check().unwrap();
        // 印だけが残った節と、範囲の外の link の検出。
        l.in_list.set(2);
        assert_eq!(l.check(), Err("a list count disagrees with its nodes"));
        l.in_list.unset(2);
        l.push_back(1);
        l.next[1] = 42;
        l.tail = 42;
        assert_eq!(l.check(), Err("a list link is out of range"));
    }

    #[test]
    fn dlist_moves_a_node_to_the_front() {
        let mut l = Dlist::new(4).unwrap();
        l.move_to_front(2);
        assert!(l.is_empty(), "a node not in the list stays out");
        l.push_back(0);
        l.move_to_front(0);
        l.check().unwrap();
        l.push_back(1);
        l.push_back(2);
        l.move_to_front(2);
        l.check().unwrap();
        let order = |l: &Dlist| {
            let (mut out, mut k) = ([NIL; 4], 0);
            l.for_each(|i| {
                out[k] = i;
                k += 1;
            });
            out
        };
        assert_eq!(order(&l), [2, 0, 1, NIL]);
        l.move_to_front(1);
        l.check().unwrap();
        assert_eq!(order(&l), [1, 2, 0, NIL]);
        assert_eq!(l.len(), 3);
    }

    #[test]
    fn ctl_ring_is_fifo_and_bounded() {
        let mut r = CtlRing::new(2, 8).unwrap();
        r.slot().unwrap()[..3].copy_from_slice(b"abc");
        r.commit(3);
        r.slot().unwrap()[..2].copy_from_slice(b"xy");
        r.commit(2);
        assert!(r.slot().is_none(), "a full ring refuses a new packet");
        let mut out = [0u8; 8];
        assert_eq!(r.pop(&mut out), Some(3));
        assert_eq!(&out[..3], b"abc");
        r.slot().unwrap()[..1].copy_from_slice(b"z");
        r.commit(1);
        assert_eq!(r.pop(&mut out), Some(2));
        assert_eq!(&out[..2], b"xy");
        assert_eq!(r.pop(&mut out), Some(1));
        assert_eq!(r.pop(&mut out), None);
        assert_eq!((r.len(), r.heap_bytes()), (0, 16 + 4));
    }
}
