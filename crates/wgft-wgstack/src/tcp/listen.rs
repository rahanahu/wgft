//! 待ち受けの表とポートごとの行 (wgstack-rs.md の「上界の式の写し方」の待ち受けと UDP の endpoint の上限)。
//!
//! Go は待ち受けを map で持ちましたが、Rust は受け付けるアドレスのポートの数の固定の行で持ちます。行は世代を
//! 持ち、閉じた後の handle を誤りにします。UDP の endpoint の表も同じ [`PortTable`] を使い、行の型は UDP の段
//! (PR 6) が足します。
//!
//! accept の待ち行列は Device 全体で Q 本、待ち受け 1 つで Q の半分までで、待ち行列の節は接続の枠に持ちます。

use super::conn::ConnSlots;
use crate::fixed_vec::{AllocError, FixedVec};
use crate::output::NIL;

/// ポートの数です。行はポートごとに 1 つです。
pub(crate) const PORTS: usize = 1 << 16;

/// ポートごとの行と、その世代です。
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PortRow<R> {
    /// 開くたびに進める世代です。閉じた後の handle を見分けます。
    pub(crate) generation: u32,
    pub(crate) open: bool,
    pub(crate) row: R,
}

/// ポートの番号で引く固定の行の表です。
#[derive(Debug)]
pub(crate) struct PortTable<R> {
    rows: FixedVec<PortRow<R>>,
    open: usize,
}

/// 開く時の誤りです。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpenError {
    InUse,
}

impl<R: Default + Copy> PortTable<R> {
    pub(crate) fn new() -> Result<Self, AllocError> {
        Ok(Self {
            rows: FixedVec::try_filled(PORTS, |_| PortRow::default())?,
            open: 0,
        })
    }

    pub(crate) fn heap_bytes(&self) -> usize {
        self.rows.heap_bytes()
    }

    /// 開いている行の数です。
    pub(crate) fn open_count(&self) -> usize {
        self.open
    }

    /// ポート `port` の行を開き、世代を返します。開いていれば誤りです。
    pub(crate) fn open(&mut self, port: u16) -> Result<u32, OpenError> {
        let r = &mut self.rows[usize::from(port)];
        if r.open {
            return Err(OpenError::InUse);
        }
        r.generation = r.generation.wrapping_add(1);
        r.open = true;
        r.row = R::default();
        self.open += 1;
        Ok(r.generation)
    }

    /// handle (ポートと世代) が開いている行を指していれば、その行を返します。
    pub(crate) fn get(&mut self, port: u16, generation: u32) -> Option<&mut R> {
        let r = &mut self.rows[usize::from(port)];
        (r.open && r.generation == generation).then_some(&mut r.row)
    }

    /// 開いているポート `port` の行です。
    pub(crate) fn by_port(&self, port: u16) -> Option<&R> {
        let r = &self.rows[usize::from(port)];
        r.open.then_some(&r.row)
    }

    pub(crate) fn by_port_mut(&mut self, port: u16) -> Option<&mut R> {
        let r = &mut self.rows[usize::from(port)];
        r.open.then_some(&mut r.row)
    }

    /// handle の行を閉じ、閉じる前の行を返します。古い handle なら `None` です。
    pub(crate) fn close(&mut self, port: u16, generation: u32) -> Option<R> {
        let r = &mut self.rows[usize::from(port)];
        if !r.open || r.generation != generation {
            return None;
        }
        r.open = false;
        self.open -= 1;
        Some(core::mem::take(&mut r.row))
    }

    /// 開いている行をポートの順に渡します。
    pub(crate) fn for_each_open(&self, mut f: impl FnMut(u16, &R)) {
        for (port, r) in self.rows.iter().enumerate() {
            if r.open
                && let Ok(port) = u16::try_from(port)
            {
                f(port, &r.row);
            }
        }
    }
}

/// 待ち受けの行です。
#[derive(Clone, Copy, Debug)]
pub(crate) struct Listener {
    pub(crate) qhead: u32,
    pub(crate) qtail: u32,
    /// 待ち行列の接続と、接続の枠へ移している途中の行の数です。
    pub(crate) qlen: u16,
    /// 握手の途中の表でこの待ち受けが使う行の数です。
    pub(crate) syn_count: u16,
}

impl Default for Listener {
    fn default() -> Self {
        Self {
            qhead: NIL,
            qtail: NIL,
            qlen: 0,
            syn_count: 0,
        }
    }
}

/// 確立した接続 `slot` を、ポート `port` の待ち受けの待ち行列の末尾に入れます。`qlen` は呼び手が先に予約します。
pub(crate) fn enqueue(l: &mut Listener, port: u16, conns: &mut ConnSlots, slot: u32) {
    let tail = l.qtail;
    let c = conns.slot_mut(slot);
    c.listener = port;
    c.queued = true;
    (c.qprev, c.qnext) = (tail, NIL);
    if tail == NIL {
        l.qhead = slot;
    } else {
        conns.slot_mut(tail).qnext = slot;
    }
    l.qtail = slot;
}

/// 接続 `slot` を待ち行列から外し、予約を返します。外したかを返します。
pub(crate) fn dequeue(l: &mut Listener, conns: &mut ConnSlots, slot: u32) -> bool {
    let c = conns.slot(slot);
    if !c.queued {
        return false;
    }
    let (p, x) = (c.qprev, c.qnext);
    if p == NIL {
        l.qhead = x;
    } else {
        conns.slot_mut(p).qnext = x;
    }
    if x == NIL {
        l.qtail = p;
    } else {
        conns.slot_mut(x).qprev = p;
    }
    let c = conns.slot_mut(slot);
    (c.qprev, c.qnext) = (NIL, NIL);
    c.queued = false;
    l.qlen -= 1;
    true
}

/// 待ち行列の長さ (移している途中の行を除く) と、節の向きと印を確かめます。
pub(crate) fn check_queue(
    l: &Listener,
    port: u16,
    conns: &ConnSlots,
) -> Result<usize, &'static str> {
    let mut n = 0;
    let mut prev = NIL;
    let mut i = l.qhead;
    while i != NIL {
        let c = conns.slot(i);
        if !c.queued || !c.in_use || c.listener != port || c.qprev != prev {
            return Err("an accept queue node is linked wrongly");
        }
        n += 1;
        if n > conns.len() {
            return Err("an accept queue loops");
        }
        prev = i;
        i = c.qnext;
    }
    if prev != l.qtail || n > usize::from(l.qlen) {
        return Err("an accept queue disagrees with its length");
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_open_close_and_reject_stale_handles() {
        let mut t: PortTable<Listener> = PortTable::new().unwrap();
        let g = t.open(80).unwrap();
        assert_eq!(t.open(80), Err(OpenError::InUse));
        assert!(t.get(80, g).is_some() && t.by_port(80).is_some() && t.by_port(81).is_none());
        assert!(t.close(80, g).is_some());
        assert!(t.close(80, g).is_none(), "a closed handle is stale");
        let g2 = t.open(80).unwrap();
        assert_ne!(g, g2);
        assert!(t.get(80, g).is_none());
        let mut seen = 0;
        t.for_each_open(|p, _| {
            assert_eq!(p, 80);
            seen += 1;
        });
        assert_eq!((seen, t.open_count()), (1, 1));
        assert_eq!(t.heap_bytes(), PORTS * size_of::<PortRow<Listener>>());
        assert!(t.by_port_mut(80).is_some());
    }

    #[test]
    fn accept_queue_keeps_order() {
        let mut conns = ConnSlots::new(4).unwrap();
        let mut l = Listener::default();
        for _ in 0..3 {
            let s = conns.alloc().unwrap().unwrap();
            l.qlen += 1;
            enqueue(&mut l, 80, &mut conns, s);
        }
        assert_eq!(check_queue(&l, 80, &conns), Ok(3));
        assert!(dequeue(&mut l, &mut conns, 1));
        assert!(!dequeue(&mut l, &mut conns, 1));
        assert_eq!(check_queue(&l, 80, &conns), Ok(2));
        assert_eq!((l.qhead, l.qtail, l.qlen), (0, 2, 2));
        assert!(dequeue(&mut l, &mut conns, 0) && dequeue(&mut l, &mut conns, 2));
        assert_eq!((l.qhead, l.qtail, l.qlen), (NIL, NIL, 0));
    }

    #[test]
    fn listener_row_stays_small() {
        assert!(
            size_of::<PortRow<Listener>>() <= 20,
            "a listener row is {} bytes",
            size_of::<PortRow<Listener>>()
        );
    }
}
