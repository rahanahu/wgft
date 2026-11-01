//! 準備の知らせの list (wgstack-rs.md の「準備の知らせ」)。
//!
//! 知らせは待ち行列に積みません。対象ごとに「知らせることがある」印の bit と順番の list の節を固定で持ち、
//! 取り出す時に list の先頭の対象の印を 1 つずつ外します。同じ対象の同じ種類の知らせは、取り出すまで 1 つに
//! まとまります。対象を別の用途に使い直すときは [`EventList::reset`] で印と節を外します。
//! このため、知らせの保持は対象の数で決まり、呼び手が取り出さなくても増えません。

use crate::fixed_vec::{AllocError, FixedVec};
use crate::output::Dlist;

/// 対象 1 つの知らせの種類の印です。対象の種類ごとに使う bit を決めます。
pub(crate) type Bits = u8;

/// 対象ごとの印と、知らせることのある対象の順番の list です。
#[derive(Debug)]
pub(crate) struct EventList {
    bits: FixedVec<Bits>,
    order: Dlist,
}

impl EventList {
    /// `targets` 個の対象の印と節を確保します。
    pub(crate) fn new(targets: usize) -> Result<Self, AllocError> {
        Ok(Self {
            bits: FixedVec::try_filled(targets, |_| 0)?,
            order: Dlist::new(targets)?,
        })
    }

    pub(crate) fn heap_bytes(&self) -> usize {
        self.bits.heap_bytes() + self.order.heap_bytes()
    }

    /// 知らせることのある対象の数です。
    pub(crate) fn len(&self) -> usize {
        self.order.len()
    }

    /// 対象 `t` に印 `bit` を付けます。既に list にあれば順番は変えません。
    pub(crate) fn raise(&mut self, t: u32, bit: Bits) {
        debug_assert!(bit != 0, "an event needs a kind");
        self.bits[t as usize] |= bit;
        self.order.push_back(t);
    }

    /// 先頭の対象の最も小さい印を 1 つ外し、対象と印を返します。対象の印が残れば対象は先頭に残ります。
    pub(crate) fn pop(&mut self) -> Option<(u32, Bits)> {
        let t = self.order.front()?;
        let bits = &mut self.bits[t as usize];
        let bit = *bits & bits.wrapping_neg();
        *bits &= !bit;
        if *bits == 0 {
            self.order.remove(t);
        }
        Some((t, bit))
    }

    /// 対象 `t` の印をすべて外し、list から外します。対象を別の用途に使い直す前に呼びます。
    pub(crate) fn reset(&mut self, t: u32) {
        self.bits[t as usize] = 0;
        self.order.remove(t);
    }

    /// 対象 `t` の印のうち `mask` の印を外し、印が残らなければ list から外します。1 つの対象を種類の違う
    /// 持ち主が分け合うとき (同じポートの TCP の待ち受けと UDP の endpoint) に、片方だけを使い直す前に呼びます。
    pub(crate) fn clear_bits(&mut self, t: u32, mask: Bits) {
        let bits = &mut self.bits[t as usize];
        *bits &= !mask;
        if *bits == 0 {
            self.order.remove(t);
        }
    }

    /// すべての対象の印を外します。
    pub(crate) fn clear(&mut self) {
        while let Some((t, _)) = self.pop() {
            self.reset(t);
        }
    }

    /// list の対象と印のある対象が同じであることを確かめます。list の対象はどれも印を持ち、印のある対象の数が
    /// list の長さと等しいことを確かめます。list は同じ対象を 2 度持たない ([`Dlist::check`]) ので、2 つの集まりは
    /// 等しくなります。手間は list の長さと対象の数に比例しますが、印の数え上げは対象ごとの分岐を持ちません。
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        const BAD: &str = "an event target has bits but is not queued, or the other way round";
        self.order.check()?;
        let mut unmarked = false;
        self.order
            .for_each(|t| unmarked |= self.bits.get(t as usize).is_none_or(|&b| b == 0));
        // 128 個ずつ u8 で数えると、byte の比べと足し算が vector の命令になります。
        let (blocks, rest) = self.bits.as_chunks::<128>();
        let count = |c: &[u8]| usize::from(c.iter().fold(0u8, |a, &b| a + u8::from(b != 0)));
        let marked = blocks.iter().map(|c| count(c)).sum::<usize>() + count(rest);
        if unmarked || marked != self.order.len() {
            return Err(BAD);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalesces_and_keeps_order() {
        let mut e = EventList::new(4).unwrap();
        e.raise(2, 0b010);
        e.raise(0, 0b001);
        e.raise(2, 0b001);
        e.raise(2, 0b010);
        e.check().unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(e.pop(), Some((2, 0b001)));
        assert_eq!(e.pop(), Some((2, 0b010)));
        assert_eq!(e.pop(), Some((0, 0b001)));
        assert_eq!(e.pop(), None);
        e.raise(1, 0b011);
        e.clear_bits(1, 0b001);
        e.check().unwrap();
        assert_eq!(e.pop(), Some((1, 0b010)));
        e.raise(1, 0b001);
        e.clear_bits(1, 0b001);
        e.check().unwrap();
        assert_eq!(e.pop(), None);
        e.raise(3, 0b100);
        e.reset(3);
        assert_eq!(e.pop(), None, "a reset target delivers nothing");
        e.check().unwrap();
        assert!(e.heap_bytes() > 0);
        e.bits[1] = 4;
        assert_eq!(
            e.check(),
            Err("an event target has bits but is not queued, or the other way round")
        );
        // list にある対象の印を消します。
        e.bits[1] = 0;
        e.raise(2, 1);
        e.bits[2] = 0;
        assert_eq!(
            e.check(),
            Err("an event target has bits but is not queued, or the other way round")
        );
    }
}
