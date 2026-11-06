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

/// 制御の出力の輪です。枠の数と大きさは作成の時に固定し、満杯なら新しい packet を捨てます。
#[derive(Debug)]
pub(crate) struct CtlRing {
    buf: FixedVec<u8>,
    lens: FixedVec<u16>,
    size: usize,
    head: usize,
    n: usize,
}

impl CtlRing {
    /// 大きさ `size` の枠を `slots` 個持つ輪を確保します。
    pub(crate) fn new(slots: usize, size: usize) -> Result<Self, AllocError> {
        let bytes = slots.checked_mul(size).ok_or(AllocError)?;
        Ok(Self {
            buf: FixedVec::try_filled(bytes, |_| 0)?,
            lens: FixedVec::try_filled(slots, |_| 0)?,
            size,
            head: 0,
            n: 0,
        })
    }

    #[cfg(test)]
    pub(crate) fn heap_bytes(&self) -> usize {
        self.buf.heap_bytes() + self.lens.heap_bytes()
    }

    pub(crate) fn len(&self) -> usize {
        self.n
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

    /// 積んだ packet をすべて捨てます。
    pub(crate) fn clear(&mut self) {
        self.head = 0;
        self.n = 0;
    }

    /// 先頭の packet を `dst` に写して外し、写した長さを返します。空なら `None` です。
    pub(crate) fn pop(&mut self, dst: &mut [u8]) -> Option<usize> {
        if self.n == 0 {
            return None;
        }
        let i = self.head;
        let len = usize::from(self.lens[i]).min(dst.len());
        dst[..len].copy_from_slice(&self.buf[i * self.size..i * self.size + len]);
        self.head = (self.head + 1) % self.lens.len();
        self.n -= 1;
        Some(len)
    }
}

/// 中身の無い ACK の packet の最大の長さです (IPv4 と TCP の header と option の最大)。
pub(crate) const ACK_PACKET_MAX: usize =
    crate::wire::IP_HEADER_LEN + crate::wire::TCP_HEADER_LEN + crate::wire::MAX_OPTION_LEN;

/// 1 つの接続が重複した ACK の輪に積める ACK の数です。超えた分は今までどおり次の ACK と合わせます。
///
/// 8 にするのは次の理由です。送り手の高速の再送は重複した ACK を 3 つ (DupThresh) 待つので (RFC 5681 3.2、
/// RFC 6675)、1 回の起床で積む ACK が 3 つあれば足ります。8 は、適合の台本の 8 つの順序外の segment (積む 7 つと
/// 送信の相の 1 つ) と、損失の後に 1 回の起床で届く segment の数に余裕を残す値です。上限があると、1 つの接続が
/// 輪を占めず、輪に残る ACK の timestamp が古くなる量も抑えられます。
pub(crate) const ACKS_PER_CONN: u8 = 8;

/// 重複した ACK の輪の項目の持ち主と長さです。
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct AckTag {
    /// ACK を作った接続の枠と世代です。送る時に枠が別の接続に移っていれば捨てます。
    pub(crate) slot: u32,
    pub(crate) generation: u64,
    len: u16,
}

/// 順序外の segment ごとの ACK を、送信の相まで持つ輪です (wgstack-rs.md の「起床ごとの ACK の合わせ」)。
/// 枠の数は作成の時に固定し、1 枠は中身の無い ACK の最大の長さです。満杯なら呼び手は ACK を積まずに次の ACK と
/// 合わせます。
#[derive(Debug)]
pub(crate) struct AckRing {
    buf: FixedVec<u8>,
    tags: FixedVec<AckTag>,
    head: usize,
    n: usize,
}

impl AckRing {
    /// `slots` 枠の輪を確保します。
    pub(crate) fn new(slots: usize) -> Result<Self, AllocError> {
        let bytes = slots.checked_mul(ACK_PACKET_MAX).ok_or(AllocError)?;
        Ok(Self {
            buf: FixedVec::try_filled(bytes, |_| 0)?,
            tags: FixedVec::try_filled(slots, |_| AckTag::default())?,
            head: 0,
            n: 0,
        })
    }

    /// `slots` 枠の輪の配列の byte です。上界の式が使います。
    pub(crate) const fn bytes_for(slots: usize) -> usize {
        slots * (ACK_PACKET_MAX + size_of::<AckTag>())
    }

    #[cfg(test)]
    pub(crate) fn heap_bytes(&self) -> usize {
        self.buf.heap_bytes() + self.tags.heap_bytes()
    }

    pub(crate) fn len(&self) -> usize {
        self.n
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// 積んだ項目の持ち主を先頭から渡します。不変条件の確かめが使います。
    pub(crate) fn for_each_tag(&self, mut f: impl FnMut(AckTag)) {
        for k in 0..self.n {
            f(self.tags[(self.head + k) % self.tags.len()]);
        }
    }

    pub(crate) fn is_full(&self) -> bool {
        self.n == self.tags.len()
    }

    /// 接続の枠 `slot` の世代 `generation` が作った packet `pkt` を末尾に積みます。満杯か packet が枠より長ければ
    /// 積まずに偽を返します。
    pub(crate) fn enqueue(&mut self, slot: u32, generation: u64, pkt: &[u8]) -> bool {
        if self.is_full() || pkt.len() > ACK_PACKET_MAX {
            return false;
        }
        let i = (self.head + self.n) % self.tags.len();
        self.buf[i * ACK_PACKET_MAX..i * ACK_PACKET_MAX + pkt.len()].copy_from_slice(pkt);
        self.tags[i] = AckTag {
            slot,
            generation,
            len: u16::try_from(pkt.len()).unwrap_or(0),
        };
        self.n += 1;
        true
    }

    /// 先頭の項目の持ち主です。空なら `None` です。
    pub(crate) fn front(&self) -> Option<AckTag> {
        (self.n > 0).then(|| self.tags[self.head])
    }

    /// 先頭の packet を `dst` に写して外し、写した長さを返します。空なら `None` です。
    pub(crate) fn pop(&mut self, dst: &mut [u8]) -> Option<usize> {
        let tag = self.front()?;
        let i = self.head;
        let len = usize::from(tag.len).min(dst.len());
        dst[..len].copy_from_slice(&self.buf[i * ACK_PACKET_MAX..i * ACK_PACKET_MAX + len]);
        self.skip();
        Some(len)
    }

    /// 先頭の項目を送らずに外します。
    pub(crate) fn skip(&mut self) {
        if self.n > 0 {
            self.head = (self.head + 1) % self.tags.len();
            self.n -= 1;
        }
    }

    /// 積んだ packet をすべて捨てます。
    pub(crate) fn clear(&mut self) {
        self.head = 0;
        self.n = 0;
    }

    /// 積んだ項目の世代をすべて `generation` に書き換えます。枠の使い直しを写す試験が使います。
    #[cfg(test)]
    pub(crate) fn retag(&mut self, generation: u64) {
        for t in self.tags.iter_mut() {
            t.generation = generation;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_ring_is_fifo_bounded_and_tagged() {
        let mut r = AckRing::new(2).unwrap();
        assert!(r.enqueue(3, 7, b"abc"));
        assert!(r.enqueue(4, 1, b"xy"));
        assert!(r.is_full() && !r.enqueue(5, 0, b"z"), "a full ring refuses");
        assert!(
            !AckRing::new(1).unwrap().enqueue(0, 0, &[0; ACK_PACKET_MAX + 1]),
            "a packet longer than a slot is refused"
        );
        let t = r.front().unwrap();
        assert_eq!((t.slot, t.generation), (3, 7));
        let mut out = [0u8; ACK_PACKET_MAX];
        assert_eq!(r.pop(&mut out), Some(3));
        assert_eq!(&out[..3], b"abc");
        assert!(r.enqueue(5, 2, b"z"));
        r.skip();
        assert_eq!(r.front().map(|t| t.slot), Some(5));
        assert_eq!(r.pop(&mut out), Some(1));
        assert_eq!(&out[..1], b"z");
        assert!(r.is_empty() && r.pop(&mut out).is_none());
        assert!(r.enqueue(1, 1, b"q"));
        r.clear();
        assert_eq!(r.len(), 0);
        assert_eq!(r.heap_bytes(), AckRing::bytes_for(2));
    }

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
