//! TIME_WAIT の表 (Go の `timewait.go` の表の部分)。
//!
//! 行に移る条件を満たした TIME_WAIT と FIN_WAIT_2 の接続を、バッファを持たない小さな行に移します。行は固定の
//! 配列の上の両方向の list に入れた順で並べ、先頭から期限を過ぎた行を外します。満杯のときは最も古い行を外して
//! 数えます。接続の枠で TIME_WAIT に入った後に行に移る接続は残りの期限を持って list の末尾に入るので、list は
//! 期限の順にならないことがあります。行への segment の規則は核の段 (PR 4a) が足します。

use crate::fixed_vec::{AllocError, FixedVec};
use crate::index::Index;
use crate::output::NIL;
use crate::siphash::SipKey;
use crate::time::Time;
use crate::wire::Tuple;

/// 行の状態です。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum TwState {
    #[default]
    FinWait2,
    TimeWait,
}

/// TIME_WAIT と FIN_WAIT_2 の 1 つの行です。
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TwRow {
    pub(crate) tup: Tuple,
    /// 元の接続の枠です。
    pub(crate) origin: u32,
    pub(crate) snd_nxt: u32,
    pub(crate) rcv_nxt: u32,
    pub(crate) deadline: Time,
    /// 元の接続の枠の世代です。64 bit なので、枠の使い直しで古い handle が通ることはありません。
    pub(crate) generation: u64,
    pub(crate) ts_recent: u32,
    pub(crate) ts_offset: u32,
    pub(crate) prev: u32,
    pub(crate) next: u32,
    pub(crate) wnd: u16,
    /// 広告する窓の scale です。
    pub(crate) wscale: u8,
    pub(crate) state: TwState,
    pub(crate) ts_ok: bool,
    pub(crate) used: bool,
    pub(crate) pending: bool,
}

/// TIME_WAIT の表です。
#[derive(Debug)]
pub(crate) struct TwTable {
    rows: FixedVec<TwRow>,
    idx: Index,
    free: FixedVec<u32>,
    head: u32,
    tail: u32,
    n: usize,
}

impl TwTable {
    pub(crate) fn new(n: usize, key: SipKey) -> Result<Self, AllocError> {
        let last = u32::try_from(n).map_err(|_| AllocError)?;
        Ok(Self {
            rows: FixedVec::try_filled(n, |_| TwRow {
                prev: NIL,
                next: NIL,
                ..TwRow::default()
            })?,
            idx: Index::new(n, key, false)?,
            free: FixedVec::try_filled(n, |i| last - 1 - u32::try_from(i).unwrap_or(0))?,
            head: NIL,
            tail: NIL,
            n: 0,
        })
    }

    pub(crate) fn heap_bytes(&self) -> usize {
        self.rows.heap_bytes() + self.idx.heap_bytes() + self.free.heap_bytes()
    }

    pub(crate) fn len(&self) -> usize {
        self.n
    }

    pub(crate) fn find(&self, tup: Tuple) -> Option<u32> {
        self.idx.find(tup).map(|(id, _)| id)
    }

    pub(crate) fn row(&self, id: u32) -> &TwRow {
        &self.rows[id as usize]
    }

    pub(crate) fn row_mut(&mut self, id: u32) -> &mut TwRow {
        &mut self.rows[id as usize]
    }

    /// 最も古い行です。
    pub(crate) fn head(&self) -> Option<u32> {
        (self.head != NIL).then_some(self.head)
    }

    /// 行を list の末尾に入れます。
    pub(crate) fn push_back(&mut self, id: u32) {
        let tail = self.tail;
        let r = &mut self.rows[id as usize];
        (r.prev, r.next) = (tail, NIL);
        if tail == NIL {
            self.head = id;
        } else {
            self.rows[tail as usize].next = id;
        }
        self.tail = id;
    }

    /// 行を list から外します。
    pub(crate) fn unlink(&mut self, id: u32) {
        let r = self.rows[id as usize];
        if r.prev == NIL {
            self.head = r.next;
        } else {
            self.rows[r.prev as usize].next = r.next;
        }
        if r.next == NIL {
            self.tail = r.prev;
        } else {
            self.rows[r.next as usize].prev = r.prev;
        }
        let r = &mut self.rows[id as usize];
        (r.prev, r.next) = (NIL, NIL);
    }

    /// 先頭の行の期限です。
    pub(crate) fn next_deadline(&self) -> Option<Time> {
        self.head().map(|h| self.rows[h as usize].deadline)
    }

    /// 行を外して空きに返します。
    pub(crate) fn remove(&mut self, id: u32) {
        if !self.rows[id as usize].used {
            return;
        }
        let tup = self.rows[id as usize].tup;
        self.idx.remove(tup);
        self.unlink(id);
        self.rows[id as usize].used = false;
        let pushed = self.free.try_push(id);
        debug_assert!(pushed.is_ok(), "the free list holds every row");
        self.n -= 1;
    }

    /// `row` を末尾に入れて番号を返します。満杯なら最も古い行を先に外し、外した行の番号も返します。
    /// 呼び手は外した行を数え、出力の list からも外します。
    pub(crate) fn insert(&mut self, row: TwRow) -> (u32, Option<u32>) {
        let mut evicted = None;
        if self.free.is_empty()
            && let Some(h) = self.head()
        {
            self.remove(h);
            evicted = Some(h);
        }
        let id = self.free.pop().unwrap_or(0);
        self.rows[id as usize] = TwRow {
            used: true,
            prev: NIL,
            next: NIL,
            ..row
        };
        self.idx.insert(row.tup, id, 0);
        self.push_back(id);
        self.n += 1;
        (id, evicted)
    }

    /// すべての行を外します。
    pub(crate) fn clear(&mut self) {
        while let Some(h) = self.head() {
            self.remove(h);
        }
    }

    /// 表、list、空きの list、使っている印、数が一致することを確かめます。
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        self.idx.check()?;
        let used = self.rows.iter().filter(|r| r.used).count();
        if used != self.n || used + self.free.len() != self.rows.len() || self.idx.len() != used {
            return Err("the TIME_WAIT table counts disagree");
        }
        let mut listed = 0;
        let mut prev = NIL;
        let mut id = self.head;
        while id != NIL {
            let r = &self.rows[id as usize];
            if !r.used || r.prev != prev || self.find(r.tup) != Some(id) {
                return Err("a TIME_WAIT row is linked wrongly");
            }
            listed += 1;
            if listed > self.n {
                return Err("the TIME_WAIT list loops");
            }
            prev = id;
            id = r.next;
        }
        if prev != self.tail || listed != self.n {
            return Err("the TIME_WAIT list disagrees with the count");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(rport: u16) -> TwRow {
        TwRow {
            tup: Tuple {
                laddr: 1,
                raddr: 2,
                lport: 80,
                rport,
            },
            state: TwState::TimeWait,
            ..TwRow::default()
        }
    }

    #[test]
    fn full_table_evicts_the_oldest() {
        let mut t = TwTable::new(2, SipKey { k0: 1, k1: 1 }).unwrap();
        assert_eq!(t.insert(row(1)), (0, None));
        assert_eq!(t.insert(row(2)), (1, None));
        assert_eq!(t.insert(row(3)), (0, Some(0)));
        assert_eq!(t.find(row(1).tup), None);
        assert_eq!(t.find(row(3).tup), Some(0));
        assert_eq!(t.head(), Some(1));
        // 期限を数え直す行は末尾へ移します。
        t.unlink(1);
        t.row_mut(1).deadline = Time::from_nanos(9);
        t.push_back(1);
        assert_eq!((t.head(), t.next_deadline()), (Some(0), Some(Time::ZERO)));
        t.check().unwrap();
        assert_eq!((t.len(), t.row(1).state), (2, TwState::TimeWait));
        t.clear();
        t.check().unwrap();
        assert_eq!(t.len(), 0);
        assert!(t.heap_bytes() > 0);
    }

    #[test]
    fn row_stays_small() {
        assert!(
            size_of::<TwRow>() <= 64,
            "a TIME_WAIT row is {} bytes",
            size_of::<TwRow>()
        );
    }
}
