//! 件数とバイト数の両方に上限を持つ FIFO。

use std::collections::VecDeque;

pub(crate) trait ByteLen {
    fn byte_len(&self) -> usize;
}

/// 上限は割り当てた容量で数える。長さで数えると、短く切った大きなバッファが上限をすり抜ける。
impl ByteLen for Vec<u8> {
    fn byte_len(&self) -> usize {
        self.capacity()
    }
}

#[derive(Debug)]
pub(crate) struct BoundedQueue<T> {
    items: VecDeque<T>,
    bytes: usize,
    max_items: usize,
    max_bytes: usize,
}

impl<T: ByteLen> BoundedQueue<T> {
    pub(crate) fn new(max_items: usize, max_bytes: usize) -> Self {
        Self {
            items: VecDeque::new(),
            bytes: 0,
            max_items,
            max_bytes,
        }
    }

    /// 入れば入れて `true`、上限を超えるなら捨てて `false` を返す。
    pub(crate) fn push(&mut self, item: T) -> bool {
        let len = item.byte_len();
        if self.items.len() >= self.max_items || self.bytes + len > self.max_bytes {
            return false;
        }
        self.bytes += len;
        self.items.push_back(item);
        true
    }

    /// 入れる。上限を超えるなら古いものから捨て、捨てた数を返す。1 件で上限を超えるものは
    /// それ自体を捨てる。
    pub(crate) fn push_evicting(&mut self, item: T) -> usize {
        let len = item.byte_len();
        if len > self.max_bytes || self.max_items == 0 {
            return 1;
        }
        let mut evicted = 0;
        while self.items.len() >= self.max_items || self.bytes + len > self.max_bytes {
            self.pop();
            evicted += 1;
        }
        self.bytes += len;
        self.items.push_back(item);
        evicted
    }

    pub(crate) fn pop(&mut self) -> Option<T> {
        let item = self.items.pop_front()?;
        self.bytes -= item.byte_len();
        Some(item)
    }

    /// pop で取り出したものを先頭に戻す。上限は取り出す前に満たしていたので確かめない。
    pub(crate) fn unpop(&mut self, item: T) {
        self.bytes += item.byte_len();
        self.items.push_front(item);
    }

    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub(crate) fn clear(&mut self) -> usize {
        let n = self.items.len();
        self.items.clear();
        self.bytes = 0;
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_refuses_past_either_bound() {
        let mut q = BoundedQueue::new(2, 10);
        assert!(q.push(vec![0; 4]));
        assert!(!q.push(vec![0; 7]), "byte bound");
        assert!(q.push(vec![0; 6]));
        assert!(!q.push(vec![]), "item bound");
        assert_eq!((q.len(), q.bytes()), (2, 10));
        assert_eq!(q.pop().unwrap().len(), 4);
        assert_eq!(q.bytes(), 6);
    }

    #[test]
    fn push_evicting_drops_the_oldest() {
        let mut q = BoundedQueue::new(2, 10);
        assert_eq!(q.push_evicting(vec![1; 4]), 0);
        assert_eq!(q.push_evicting(vec![2; 4]), 0);
        assert_eq!(q.push_evicting(vec![3; 4]), 1);
        assert_eq!(q.pop().unwrap()[0], 2);
        assert_eq!(q.push_evicting(vec![4; 11]), 1, "too large on its own");
        assert_eq!(q.len(), 1);
        assert_eq!(q.clear(), 1);
        assert!(q.is_empty());
    }
}
