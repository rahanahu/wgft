//! 握手の途中の表 (Go の `syn.go` の表の部分)。
//!
//! SYN-RCVD の接続を、接続の枠とは別の、バッファを持たない固定の数 N_syn の行に置きます。SYN-ACK の再送の
//! 間隔は回数ごとに一定なので、回数ごとに 1 つの順序つきの list を持ち、各 list の先頭から期限を見ます。
//! 空きの行は小さい番号から使い、返した行を先に使います。行を作り SYN-ACK を送る規則は核の段 (PR 4a) が
//! 足します。

use super::SYNACK_RETRIES;
use crate::fixed_vec::{AllocError, FixedVec};
use crate::index::Index;
use crate::output::NIL;
use crate::siphash::SipKey;
use crate::time::Time;
use crate::wire::Tuple;

/// 行が次に送るものです。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum RowSend {
    #[default]
    None,
    SynAck,
    Ack,
}

/// 握手の途中の 1 つの行です。
#[expect(
    clippy::struct_excessive_bools,
    reason = "the row keeps the negotiated options as flags, as Go does"
)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SynRow {
    pub(crate) tup: Tuple,
    /// 待ち受けのポートです。
    pub(crate) listener: u16,
    pub(crate) iss: u32,
    pub(crate) irs: u32,
    pub(crate) ts_recent: u32,
    pub(crate) ts_offset: u32,
    pub(crate) deadline: Time,
    /// 最初の SYN-ACK を作った時刻です。Go と同じく 0 は「測っていない」で、時刻 0 に作った SYN-ACK も
    /// RTT の標本にしません (bit の一致のため)。
    pub(crate) sent_at: Time,
    pub(crate) prev: u32,
    pub(crate) next: u32,
    pub(crate) peer_mss: u16,
    /// SYN-ACK で広告した窓 (scale しない値) です。
    pub(crate) rcv_wnd: u16,
    pub(crate) snd_wscale: u8,
    pub(crate) retries: u8,
    pub(crate) ws_ok: bool,
    pub(crate) sack_ok: bool,
    pub(crate) ts_ok: bool,
    /// SYN-ACK を再送しました。
    pub(crate) rtx: bool,
    /// 接続の枠へ移している途中です。
    pub(crate) promoting: bool,
    pub(crate) used: bool,
    pub(crate) pending: RowSend,
}

#[derive(Clone, Copy, Debug)]
struct List {
    head: u32,
    tail: u32,
}

/// 握手の途中の表です。
#[derive(Debug)]
pub(crate) struct SynTable {
    rows: FixedVec<SynRow>,
    idx: Index,
    free: FixedVec<u32>,
    lists: [List; SYNACK_RETRIES + 1],
    n: usize,
}

impl SynTable {
    pub(crate) fn new(n: usize, key: SipKey) -> Result<Self, AllocError> {
        let last = u32::try_from(n).map_err(|_| AllocError)?;
        Ok(Self {
            rows: FixedVec::try_filled(n, |_| SynRow {
                prev: NIL,
                next: NIL,
                ..SynRow::default()
            })?,
            idx: Index::new(n, key, false)?,
            free: FixedVec::try_filled(n, |i| last - 1 - u32::try_from(i).unwrap_or(0))?,
            lists: [List {
                head: NIL,
                tail: NIL,
            }; SYNACK_RETRIES + 1],
            n: 0,
        })
    }

    pub(crate) fn heap_bytes(&self) -> usize {
        self.rows.heap_bytes() + self.idx.heap_bytes() + self.free.heap_bytes()
    }

    /// 使っている行の数です。
    pub(crate) fn len(&self) -> usize {
        self.n
    }

    pub(crate) fn capacity(&self) -> usize {
        self.rows.len()
    }

    pub(crate) fn has_free(&self) -> bool {
        !self.free.is_empty()
    }

    pub(crate) fn find(&self, tup: Tuple) -> Option<u32> {
        self.idx.find(tup).map(|(id, _)| id)
    }

    pub(crate) fn row(&self, id: u32) -> &SynRow {
        &self.rows[id as usize]
    }

    pub(crate) fn row_mut(&mut self, id: u32) -> &mut SynRow {
        &mut self.rows[id as usize]
    }

    /// 空きの行に `row` を入れ、表と再送の回数の list に足して番号を返します。満杯なら `None` です。
    pub(crate) fn insert(&mut self, row: SynRow) -> Option<u32> {
        let id = self.free.pop()?;
        self.rows[id as usize] = SynRow {
            used: true,
            prev: NIL,
            next: NIL,
            ..row
        };
        self.idx.insert(row.tup, id, 0); // 世代は持ちません
        self.list_push(id);
        self.n += 1;
        Some(id)
    }

    /// 行を外して空きに返します。
    pub(crate) fn remove(&mut self, id: u32) {
        if !self.rows[id as usize].used {
            return;
        }
        let tup = self.rows[id as usize].tup;
        self.idx.remove(tup);
        self.list_remove(id);
        self.rows[id as usize].used = false;
        let pushed = self.free.try_push(id);
        debug_assert!(pushed.is_ok(), "the free list holds every row");
        self.n -= 1;
    }

    /// 行を今の再送の回数の list の末尾に入れます。
    pub(crate) fn list_push(&mut self, id: u32) {
        let retries = usize::from(self.rows[id as usize].retries);
        let tail = self.lists[retries].tail;
        let r = &mut self.rows[id as usize];
        (r.prev, r.next) = (tail, NIL);
        if tail == NIL {
            self.lists[retries].head = id;
        } else {
            self.rows[tail as usize].next = id;
        }
        self.lists[retries].tail = id;
    }

    /// 行を今の再送の回数の list から外します。
    pub(crate) fn list_remove(&mut self, id: u32) {
        let r = self.rows[id as usize];
        let l = &mut self.lists[usize::from(r.retries)];
        if r.prev == NIL {
            l.head = r.next;
        } else {
            self.rows[r.prev as usize].next = r.next;
        }
        if r.next == NIL {
            l.tail = r.prev;
        } else {
            self.rows[r.next as usize].prev = r.prev;
        }
        let r = &mut self.rows[id as usize];
        (r.prev, r.next) = (NIL, NIL);
    }

    /// 再送の回数 `retries` の list の先頭の行です。
    pub(crate) fn list_head(&self, retries: usize) -> Option<u32> {
        let h = self.lists[retries].head;
        (h != NIL).then_some(h)
    }

    /// 各 list の先頭の期限のうち最も早いものです。
    pub(crate) fn next_deadline(&self) -> Option<Time> {
        self.lists
            .iter()
            .filter(|l| l.head != NIL)
            .map(|l| self.rows[l.head as usize].deadline)
            .min()
    }

    /// すべての行を外します。
    pub(crate) fn clear(&mut self) {
        for id in 0..self.rows.len() {
            if let Ok(id) = u32::try_from(id) {
                self.remove(id);
            }
        }
    }

    /// 表、list、空きの list、使っている印、数が一致することを確かめます。
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        self.idx.check()?;
        let used = self.rows.iter().filter(|r| r.used).count();
        if used != self.n || used + self.free.len() != self.rows.len() || self.idx.len() != used {
            return Err("the half-open table counts disagree");
        }
        let mut listed = 0;
        for (retries, l) in self.lists.iter().enumerate() {
            let mut prev = NIL;
            let mut id = l.head;
            while id != NIL {
                let r = &self.rows[id as usize];
                if !r.used || usize::from(r.retries) != retries || r.prev != prev {
                    return Err("a half-open row is in the wrong list");
                }
                if self.find(r.tup) != Some(id) {
                    return Err("a half-open row is missing from its index");
                }
                listed += 1;
                if listed > self.n {
                    return Err("a half-open list loops");
                }
                prev = id;
                id = r.next;
            }
            if prev != l.tail {
                return Err("a half-open list tail is wrong");
            }
        }
        if listed != self.n {
            return Err("a half-open row is in no list");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(rport: u16, deadline: u64) -> SynRow {
        SynRow {
            tup: Tuple {
                laddr: 1,
                raddr: 2,
                lport: 80,
                rport,
            },
            deadline: Time::from_nanos(deadline),
            ..SynRow::default()
        }
    }

    #[test]
    fn rows_move_between_lists() {
        let mut t = SynTable::new(3, SipKey { k0: 5, k1: 6 }).unwrap();
        assert_eq!(t.insert(row(1, 30)), Some(0));
        assert_eq!(t.insert(row(2, 20)), Some(1));
        assert_eq!(t.insert(row(3, 10)), Some(2));
        assert_eq!(t.insert(row(4, 5)), None);
        // 期限は各 list の先頭だけを見ます。
        assert_eq!(t.next_deadline(), Some(Time::from_nanos(30)));
        // 再送で次の回数の list へ移します。
        t.list_remove(0);
        t.row_mut(0).retries = 1;
        t.row_mut(0).deadline = Time::from_nanos(5);
        t.list_push(0);
        t.check().unwrap();
        assert_eq!((t.list_head(0), t.list_head(1)), (Some(1), Some(0)));
        assert_eq!(t.next_deadline(), Some(Time::from_nanos(5)));
        t.remove(1);
        assert_eq!(t.find(row(2, 0).tup), None);
        assert_eq!(t.insert(row(9, 1)), Some(1), "a returned row is used first");
        t.check().unwrap();
        assert_eq!((t.len(), t.capacity(), t.has_free()), (3, 3, false));
        t.clear();
        t.check().unwrap();
        assert_eq!(
            (t.len(), t.next_deadline(), t.row(0).used),
            (0, None, false)
        );
        assert!(t.heap_bytes() > 3 * size_of::<SynRow>());
    }
}
