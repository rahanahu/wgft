//! 待ち受けの表とポートごとの行 (wgstack-rs.md の「上界の式の写し方」の待ち受けと UDP の endpoint の上限)。
//!
//! Go は待ち受けを map で持ちましたが、Rust は受け付けるアドレスのポートの数の固定の行で持ちます。行は世代を
//! 持ち、閉じた後の handle を誤りにします。UDP の endpoint の表も同じ [`PortTable`] を使い、行の型
//! (`UdpEp`) は [`crate::udp`] が持ちます。
//!
//! accept の待ち行列は Device 全体で Q 本、待ち受け 1 つで Q の半分までです。待ち行列の節は接続の番号で引く
//! 別の配列 ([`QLink`]) に持ちます。

use super::conn::QLink;
use crate::bitset::BitSet;
use crate::fixed_vec::{AllocError, FixedVec};
use crate::output::NIL;

/// ポートの数です。行はポートごとに 1 つです。
pub(crate) const PORTS: usize = 1 << 16;

/// ポートごとの行と、その世代です。
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(any(test, feature = "harness"), derive(PartialEq, Eq))]
pub(crate) struct PortRow<R> {
    /// 開くたびに進める世代です。閉じた後の handle を見分けます。
    pub(crate) generation: u32,
    pub(crate) row: R,
}

/// ポートの番号で引く固定の行の表です。行が開いているかは行に持たず、ポートごとに 1 bit の集合 `open` だけに
/// 持ちます。開いている行をたどるときと検査は、表の行でなく bit の集合の語 (ポート 64 個で 1 語) をたどります。
#[derive(Debug)]
pub(crate) struct PortTable<R> {
    rows: FixedVec<PortRow<R>>,
    open: BitSet,
    count: usize,
    /// 作ってから開いたことのあるポートの印です。試験と fuzz の build だけにあり、核を使い回す試験が開いた行だけを
    /// 戻すのに使います ([`crate::stack::Spare`])。
    #[cfg(any(test, feature = "harness"))]
    opened: BitSet,
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
            open: BitSet::new(PORTS)?,
            count: 0,
            #[cfg(any(test, feature = "harness"))]
            opened: BitSet::new(PORTS)?,
        })
    }

    /// 表の配列の byte です。上界の式が使います。
    pub(crate) const fn bytes() -> usize {
        PORTS * size_of::<PortRow<R>>() + BitSet::bytes_for(PORTS)
    }

    #[cfg(test)]
    pub(crate) fn heap_bytes(&self) -> usize {
        self.rows.heap_bytes() + self.open.heap_bytes()
    }

    /// 開いている行の数です。
    #[cfg(test)]
    pub(crate) fn open_count(&self) -> usize {
        self.count
    }

    /// ポート `port` の行が開いているかです。
    #[inline]
    fn is_open(&self, port: u16) -> bool {
        self.open.get(u32::from(port))
    }

    /// ポート `port` の行を開き、世代を返します。開いていれば誤りです。
    pub(crate) fn open(&mut self, port: u16) -> Result<u32, OpenError> {
        if self.is_open(port) {
            return Err(OpenError::InUse);
        }
        self.open.set(u32::from(port));
        #[cfg(any(test, feature = "harness"))]
        self.opened.set(u32::from(port));
        self.count += 1;
        let r = &mut self.rows[usize::from(port)];
        r.generation = r.generation.wrapping_add(1);
        r.row = R::default();
        Ok(r.generation)
    }

    /// handle (ポートと世代) が開いている行を指していれば、その行を返します。
    pub(crate) fn get(&mut self, port: u16, generation: u32) -> Option<&mut R> {
        let open = self.is_open(port);
        let r = &mut self.rows[usize::from(port)];
        (open && r.generation == generation).then_some(&mut r.row)
    }

    /// ポート `port` の行の今の世代です。閉じた行は最後に開いた時の世代です。
    pub(crate) fn generation(&self, port: u16) -> u32 {
        self.rows[usize::from(port)].generation
    }

    /// 開いているポート `port` の行です。
    pub(crate) fn by_port(&self, port: u16) -> Option<&R> {
        self.is_open(port)
            .then(|| &self.rows[usize::from(port)].row)
    }

    pub(crate) fn by_port_mut(&mut self, port: u16) -> Option<&mut R> {
        self.is_open(port)
            .then(|| &mut self.rows[usize::from(port)].row)
    }

    /// handle の行を閉じ、閉じる前の行を返します。古い handle なら `None` です。
    pub(crate) fn close(&mut self, port: u16, generation: u32) -> Option<R> {
        if !self.is_open(port) || self.rows[usize::from(port)].generation != generation {
            return None;
        }
        self.open.unset(u32::from(port));
        self.count -= 1;
        Some(core::mem::take(&mut self.rows[usize::from(port)].row))
    }

    /// 開いている行をポートの順に渡します。手間は開いている行の数と、bit の集合の語の数に比例します。
    pub(crate) fn for_each_open(&self, mut f: impl FnMut(u16, &R)) {
        self.open.for_each(|i| {
            if let Ok(port) = u16::try_from(i) {
                f(port, &self.rows[usize::from(port)].row);
            }
        });
    }

    /// 開いたことのある行を作成の時の値に戻し、開いている印と開いたことのある印を外します。核を閉じた後に呼びます。
    /// 行の世代を変えるのは [`PortTable::open`] だけで、開いたことのある印もそこで付けます。閉じた行は世代のほかは
    /// 作成の時の値なので、表は作成の時の表と同じになります。手間は開いたことのある行の数と bit の集合の語の数に
    /// 比例します。試験と fuzz の build だけにあります。
    #[cfg(any(test, feature = "harness"))]
    pub(crate) fn restore(&mut self) {
        let (rows, open) = (&mut self.rows, &mut self.open);
        self.opened.for_each(|p| {
            open.unset(p);
            rows[p as usize] = PortRow::default();
        });
        self.opened.clear();
        self.count = 0;
    }

    /// すべての行と印が作成の時の値かを返します。手間は表の大きさに比例し、試験が使います。
    #[cfg(any(test, feature = "harness"))]
    pub(crate) fn is_fresh(&self) -> bool
    where
        R: PartialEq,
    {
        self.count == 0
            && self.open.count() == 0
            && self.opened.count() == 0
            && self.rows.iter().all(|r| *r == PortRow::default())
    }

    /// 開いている行の数が bit の集合と合うことを確かめます。
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        if self.open.count() != self.count {
            return Err("the open port count disagrees with the open ports");
        }
        Ok(())
    }
}

/// 待ち受けの行です。
#[derive(Clone, Copy, Debug)]
#[cfg_attr(any(test, feature = "harness"), derive(PartialEq, Eq))]
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

/// 確立した接続 `slot` を待ち受け `l` (ポート `port`) の待ち行列の末尾に入れます。待ち行列の長さは呼び手が
/// 予約済みです。
pub(crate) fn enqueue(l: &mut Listener, port: u16, links: &mut [QLink], slot: u32) {
    let tail = l.qtail;
    links[slot as usize] = QLink {
        queued: true,
        listener: port,
        prev: tail,
        next: NIL,
    };
    if tail == NIL {
        l.qhead = slot;
    } else {
        links[tail as usize].next = slot;
    }
    l.qtail = slot;
}

/// 接続 `slot` を待ち行列から外し、待ち受けの長さを 1 つ減らします。外したかを返します。呼び手は核の全体の
/// 数も減らします。
pub(crate) fn dequeue(l: &mut Listener, links: &mut [QLink], slot: u32) -> bool {
    let c = links[slot as usize];
    if !c.queued {
        return false;
    }
    if c.prev == NIL {
        l.qhead = c.next;
    } else {
        links[c.prev as usize].next = c.next;
    }
    if c.next == NIL {
        l.qtail = c.prev;
    } else {
        links[c.next as usize].prev = c.prev;
    }
    links[slot as usize] = QLink::default();
    l.qlen -= 1;
    true
}

/// 待ち受け `l` の待ち行列の節が使っている枠を正しく結び、数が長さ以下であることを確かめ、待ち行列の接続の
/// 数を返します。
pub(crate) fn check_queue(
    l: &Listener,
    port: u16,
    links: &[QLink],
    in_use: impl Fn(u32) -> bool,
) -> Result<usize, &'static str> {
    let mut n = 0;
    let mut prev = NIL;
    let mut i = l.qhead;
    while i != NIL {
        let c = links
            .get(i as usize)
            .ok_or("an accept queue node is out of range")?;
        if !c.queued || !in_use(i) || c.listener != port || c.prev != prev {
            return Err("an accept queue node is linked wrongly");
        }
        n += 1;
        if n > links.len() {
            return Err("an accept queue loops");
        }
        prev = i;
        i = c.next;
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
        assert_eq!(t.heap_bytes(), PortTable::<Listener>::bytes());
        assert!(t.by_port_mut(80).is_some());
        t.check().unwrap();
        t.count += 1;
        assert_eq!(
            t.check(),
            Err("the open port count disagrees with the open ports")
        );
    }

    #[test]
    fn accept_queue_keeps_order() {
        let mut links = [QLink::default(); 4];
        let mut l = Listener::default();
        for s in 0..3 {
            l.qlen += 1;
            enqueue(&mut l, 80, &mut links, s);
        }
        let used = |i: u32| i < 3;
        assert_eq!(check_queue(&l, 80, &links, used), Ok(3));
        assert!(dequeue(&mut l, &mut links, 1));
        assert!(!dequeue(&mut l, &mut links, 1));
        assert_eq!(check_queue(&l, 80, &links, used), Ok(2));
        assert_eq!((l.qhead, l.qtail, l.qlen), (0, 2, 2));
        assert_eq!(
            check_queue(&l, 81, &links, used),
            Err("an accept queue node is linked wrongly")
        );
        assert!(dequeue(&mut l, &mut links, 0) && dequeue(&mut l, &mut links, 2));
        assert_eq!((l.qhead, l.qtail, l.qlen), (NIL, NIL, 0));
    }

    #[test]
    fn listener_row_stays_small() {
        assert!(
            size_of::<PortRow<Listener>>() <= 16,
            "a listener row is {} bytes",
            size_of::<PortRow<Listener>>()
        );
    }
}
