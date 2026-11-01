//! TIME_WAIT の表 (Go の `timewait.go` の表の部分)。
//!
//! 行に移る条件を満たした TIME_WAIT と FIN_WAIT_2 の接続を、バッファを持たない小さな行に移します。行は固定の
//! 配列の上の両方向の list に入れた順で並べ、先頭から期限を過ぎた行を外します。満杯のときは最も古い行を外して
//! 数えます。接続の枠で TIME_WAIT に入った後に行に移る接続は残りの期限を持って list の末尾に入るので、list は
//! 期限の順にならないことがあります。先頭からの掃除は先頭が期限を過ぎるまで後ろの行を外さないので、
//! 引くときにも期限を確かめ、過ぎた行はその場で外します。

use super::TW_TIMEOUT;
use crate::fixed_vec::{AllocError, FixedVec};
use crate::index::Index;
use crate::output::NIL;
use crate::seq;
use crate::siphash::SipKey;
use crate::stack::shared::LogKind;
use crate::stack::{Shared, ns, time};
use crate::time::Time;
use crate::wire::{FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN, Segment, TcpHeader, Tuple};

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
    /// 行ごとの、同じ元の接続の枠から移した行の list の節 (前、次) です。
    olinks: FixedVec<[u32; 2]>,
    /// 接続の枠ごとの、その枠から移した行の list の先頭です。古い handle の abort が元の枠と世代で行を引きます。
    oheads: FixedVec<u32>,
}

impl TwTable {
    /// `n` 行の表を作ります。`conns` は接続の枠の数で、元の枠ごとの list の先頭の数です。
    pub(crate) fn new(n: usize, key: SipKey, conns: usize) -> Result<Self, AllocError> {
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
            olinks: FixedVec::try_filled(n, |_| [NIL; 2])?,
            oheads: FixedVec::try_filled(conns, |_| NIL)?,
        })
    }

    #[cfg(test)]
    pub(crate) fn heap_bytes(&self) -> usize {
        self.rows.heap_bytes()
            + self.idx.heap_bytes()
            + self.free.heap_bytes()
            + self.olinks.heap_bytes()
            + self.oheads.heap_bytes()
    }

    pub(crate) fn capacity(&self) -> usize {
        self.rows.len()
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
        self.origin_unlink(id);
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
        if let Some(h) = self.oheads.get_mut(row.origin as usize) {
            let old = *h;
            *h = id;
            self.olinks[id as usize] = [NIL, old];
            if old != NIL {
                self.olinks[old as usize][0] = id;
            }
        }
        self.n += 1;
        (id, evicted)
    }

    /// 行 `id` を元の枠の list から外します。
    fn origin_unlink(&mut self, id: u32) {
        let [p, x] = self.olinks[id as usize];
        let origin = self.rows[id as usize].origin as usize;
        if p == NIL {
            if let Some(h) = self.oheads.get_mut(origin)
                && *h == id
            {
                *h = x;
            }
        } else {
            self.olinks[p as usize][1] = x;
        }
        if x != NIL {
            self.olinks[x as usize][0] = p;
        }
        self.olinks[id as usize] = [NIL; 2];
    }

    /// 接続の枠 `origin` の世代 `generation` から移した行を探します。元の枠ごとの list をたどるので、手間はその枠
    /// から移して表に残る行のうち `generation` より新しい行の数です。
    ///
    /// 枠の世代は使うたびに進み、1 つの世代は高々 1 度だけ行に移り、行は list の先頭に入るので、list は世代の
    /// 新しい順です (`check` が確かめます)。`generation` より古い行に着いたら、その先にも無いので止めます。
    /// 表に無い世代の古い handle の abort (行が期限で消えた接続や、行に移らずに閉じた接続) は、その後に同じ枠
    /// から行に移った接続の数だけたどり、枠の最新の行より新しい世代なら先頭の 1 行で終わります。
    pub(crate) fn find_origin(&self, origin: u32, generation: u64) -> Option<u32> {
        let mut id = *self.oheads.get(origin as usize)?;
        let mut steps = 0;
        while id != NIL && steps <= self.rows.len() {
            let r = &self.rows[id as usize];
            if r.generation == generation {
                return Some(id);
            }
            if r.generation < generation {
                return None;
            }
            id = self.olinks[id as usize][1];
            steps += 1;
        }
        None
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
        super::check_free_list(&self.free, self.rows.len(), |i| self.rows[i].used)?;
        let used = self.rows.iter().filter(|r| r.used).count();
        if used != self.n || used + self.free.len() != self.rows.len() || self.idx.len() != used {
            return Err("the TIME_WAIT table counts disagree");
        }
        let mut listed = 0;
        let mut prev = NIL;
        let mut id = self.head;
        while id != NIL {
            let r = self
                .rows
                .get(id as usize)
                .ok_or("a TIME_WAIT list link is out of range")?;
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
        // 元の枠ごとの list は、使っている行をそれぞれ 1 度だけ、その行の元の枠の list に持ちます。
        // list は世代の新しい順で、同じ世代を 2 度持ちません (`find_origin` が途中で止まる根拠)。
        let mut chained = 0;
        for (origin, &h) in self.oheads.iter().enumerate() {
            let mut prev = NIL;
            let mut id = h;
            while id != NIL {
                let r = self
                    .rows
                    .get(id as usize)
                    .ok_or("an origin list link is out of range")?;
                if !r.used || r.origin as usize != origin || self.olinks[id as usize][0] != prev {
                    return Err("an origin list holds a wrong row");
                }
                if prev != NIL && self.rows[prev as usize].generation <= r.generation {
                    return Err("an origin list is not newest first");
                }
                chained += 1;
                if chained > self.n {
                    return Err("an origin list loops");
                }
                prev = id;
                id = self.olinks[id as usize][1];
            }
        }
        let orphans = self
            .rows
            .iter()
            .filter(|r| r.used && r.origin as usize >= self.oheads.len())
            .count();
        if chained + orphans != self.n {
            return Err("the origin lists disagree with the count");
        }
        Ok(())
    }
}

/// 行への segment が RFC 9293 3.10.7.4 の受け入れの範囲にあるかを返します。窓は行に移した時に広告した窓です。
fn acceptable(r: &TwRow, seg: &Segment<'_>) -> bool {
    let wnd = u32::from(r.wnd) << r.wscale;
    let n = seg.seq_len();
    let in_wnd = |x: u32| seq::ge(x, r.rcv_nxt) && seq::lt(x, r.rcv_nxt.wrapping_add(wnd));
    match (n, wnd) {
        (0, 0) => seg.seq == r.rcv_nxt,
        (0, _) => in_wnd(seg.seq),
        (_, 0) => false,
        _ => in_wnd(seg.seq) || in_wnd(seg.seq.wrapping_add(n - 1)),
    }
}

/// TIME_WAIT の 4 つ組への新しい SYN を受け入れてよいかを返します (RFC 6191 2 節)。前の接続が timestamp を
/// 使っていれば、SYN が timestamp を持つときはその値が前の接続の最後の値より大きいこと、持たないときは
/// シーケンス番号が前の接続の最後の番号より大きいことを求めます。
pub(crate) fn rfc6191(seg: &Segment<'_>, ts_ok: bool, ts_recent: u32, rcv_nxt: u32) -> bool {
    if ts_ok && let Some((ts_val, _)) = seg.opt.ts {
        return seq::gt(ts_val, ts_recent);
    }
    seq::gt(seg.seq, rcv_nxt)
}

/// TIME_WAIT の 4 つ組を使い直す SYN を待ち受けに渡せるかの判定です。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reuse {
    /// 行を作れます。
    Ok,
    /// 開いた待ち受けがありません。TIME_WAIT の ACK を返します (Linux と同じ)。
    NoListener,
    /// 握手の途中の行を作れません。SYN を捨てて TIME_WAIT を残します。
    Full,
}

impl Shared {
    /// 出力の list での TIME_WAIT の行の番号です。
    pub(crate) fn tw_row_id(&self, id: u32) -> u32 {
        u32::try_from(self.syn.capacity()).unwrap_or(0) + id
    }

    pub(crate) fn remove_tw_row(&mut self, id: u32) {
        let out = self.tw_row_id(id);
        self.unqueue_row(out);
        self.tw.remove(id);
    }

    /// 接続の枠の状態 `row` を行に移します。満杯なら最も古い行を外して数えます。枠が送るはずだった ACK は行が
    /// 送ります。
    pub(crate) fn add_tw_row(&mut self, row: TwRow, ack_now: bool, now: i64) {
        let (id, evicted) = self.tw.insert(row);
        if let Some(e) = evicted {
            let out = self.tw_row_id(e);
            self.unqueue_row(out);
            self.refused(LogKind::TwEvicted, now);
        }
        if ack_now {
            self.tw_ack(id, now, false);
        }
    }

    /// 先頭から期限を過ぎた行を外します。
    pub(crate) fn expire_tw_rows(&mut self, now: i64) {
        while let Some(h) = self.tw.head() {
            if ns(self.tw.row(h).deadline) > now {
                break;
            }
            self.remove_tw_row(h);
        }
    }

    fn tw_ack(&mut self, id: u32, now: i64, limited: bool) {
        if limited && !self.challenge_allowed(now) {
            return;
        }
        self.tw.row_mut(id).pending = true;
        let out = self.tw_row_id(id);
        self.queue_row(out);
    }

    /// 新しい SYN が待ち受けに渡せるかを返します。
    pub(crate) fn reuse_verdict(&self, seg: &Segment<'_>) -> Reuse {
        match self.listeners.by_port(seg.tup.lport) {
            None => Reuse::NoListener,
            Some(l) if !self.syn_room(l) => Reuse::Full,
            Some(_) => Reuse::Ok,
        }
    }

    /// 行 `id` への segment を処理し、処理し終えたかを返します。偽を返すのは、TIME_WAIT の行が RFC 6191 の
    /// 条件を満たす SYN を受けて行を外したか、期限を過ぎた行を外したときで、呼び手はその segment をどの行にも
    /// 当たらない segment として扱います。SYN で行を外したときは `reuse` に前の接続の SND.NXT を書きます。
    pub(crate) fn tw_input(
        &mut self,
        id: u32,
        seg: &Segment<'_>,
        now: i64,
        reuse: &mut Option<u32>,
    ) -> bool {
        let r = *self.tw.row(id);
        if ns(r.deadline) <= now {
            self.remove_tw_row(id);
            return false;
        }
        if seg.has(FLAG_RST) {
            // Linux の既定 (tcp_rfc1337=0) と同じく、番号の合う RST で行を外します。
            if seg.seq == r.rcv_nxt {
                self.remove_tw_row(id);
            }
            return true;
        }
        let payload = u32::try_from(seg.payload.len()).unwrap_or(0);
        let ts_val = seg.opt.ts.map(|(v, _)| v);
        if seg.has(FLAG_SYN) {
            // SYN と FIN の組は待ち受けが捨てるので、行を外しません。
            if !seg.has(FLAG_ACK)
                && !seg.has(FLAG_FIN)
                && r.state == TwState::TimeWait
                && rfc6191(seg, r.ts_ok, r.ts_recent, r.rcv_nxt)
            {
                // 行を外す前に、新しい行を作れるかを確かめます。作れないまま外すと、相手が再送した SYN は
                // 前の接続の番号を知らない時計だけの ISN を受けます。
                match self.reuse_verdict(seg) {
                    Reuse::NoListener => {
                        self.tw_ack(id, now, true);
                        return true;
                    }
                    Reuse::Full => {
                        self.refused(LogKind::SynFull, now);
                        return true;
                    }
                    Reuse::Ok => {}
                }
                *reuse = Some(r.snd_nxt);
                self.remove_tw_row(id);
                return false;
            }
            self.tw_ack(id, now, true);
            return true;
        }
        if r.state == TwState::FinWait2 {
            // 確立した接続と同じく、PAWS と窓の外の segment には速さを抑えた ACK を返すだけにします
            // (RFC 7323 5.3、RFC 9293 3.10.7.4)。窓の外の古いデータで行を外させません。
            if (r.ts_ok && ts_val.is_some_and(|v| seq::lt(v, r.ts_recent))) || !acceptable(&r, seg)
            {
                self.tw_ack(id, now, true);
                return true;
            }
            let end = seg.seq.wrapping_add(payload);
            if payload > 0 && seq::gt(end, r.rcv_nxt) {
                // 閉じた後に届いたデータ。Linux と同じく RST を返して行を外します。
                self.reply_rst(seg);
                self.remove_tw_row(id);
                return true;
            }
            if seg.has(FLAG_FIN) && end == r.rcv_nxt {
                let row = self.tw.row_mut(id);
                if row.ts_ok
                    && let Some(v) = ts_val
                    && seq::ge(v, row.ts_recent)
                {
                    row.ts_recent = v;
                }
                row.rcv_nxt = row.rcv_nxt.wrapping_add(1);
                row.state = TwState::TimeWait;
                row.deadline = time(now + TW_TIMEOUT);
                self.tw.unlink(id);
                self.tw.push_back(id);
                self.tw_ack(id, now, false);
            }
            return true;
        }
        // TIME_WAIT
        if seg.has(FLAG_FIN) && seg.seq.wrapping_add(payload).wrapping_add(1) == r.rcv_nxt {
            // 再送された FIN。ACK を返し、Linux と同じく期限を数え直します。ACK はこの FIN の TSval を返します。
            let row = self.tw.row_mut(id);
            if row.ts_ok
                && let Some(v) = ts_val
                && seq::ge(v, row.ts_recent)
            {
                row.ts_recent = v;
            }
            row.deadline = time(now + TW_TIMEOUT);
            self.tw.unlink(id);
            self.tw.push_back(id);
            self.tw_ack(id, now, false);
            return true;
        }
        if seg.seq_len() > 0 || seg.seq != r.rcv_nxt {
            self.tw_ack(id, now, true);
        }
        true
    }

    /// TIME_WAIT の行の ACK を作ります。
    pub(crate) fn poll_tw_row(&mut self, id: u32, b: &mut [u8], now: i64) -> usize {
        let r = *self.tw.row(id);
        if !r.used || !r.pending {
            return 0;
        }
        self.tw.row_mut(id).pending = false;
        let h = TcpHeader {
            tup: r.tup,
            seq: r.snd_nxt,
            ack: r.rcv_nxt,
            flags: FLAG_ACK,
            wnd: r.wnd,
        };
        self.build_row_ack(b, &h, r.ts_ok, r.ts_offset, r.ts_recent, now)
    }

    /// 元の接続の古い handle の abort で、その接続の行が表に残っていれば RST を送って外します。
    pub(crate) fn abort_tw_row(&mut self, origin: u32, generation: u64) {
        let Some(id) = self.tw.find_origin(origin, generation) else {
            return;
        };
        let r = *self.tw.row(id);
        let tup = r.tup;
        self.send_ctl(TcpHeader {
            tup,
            seq: r.snd_nxt,
            ack: r.rcv_nxt,
            flags: FLAG_RST | FLAG_ACK,
            wnd: 0,
        });
        self.remove_tw_row(id);
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
            // 元の枠の list は世代の新しい順なので、後に入れる行ほど新しい世代にします。
            generation: u64::from(rport),
            ..TwRow::default()
        }
    }

    #[test]
    fn origin_lookup_stops_at_an_older_generation() {
        // 1 つの枠が TIME_WAIT の期限の間に多くの接続を閉じた表。
        const N: u32 = 60_000;
        let mut t = TwTable::new(N as usize, SipKey { k0: 3, k1: 4 }, 2).unwrap();
        for g in 1..=N {
            let r = TwRow {
                tup: Tuple {
                    laddr: 1,
                    raddr: 2 + g / 60_000,
                    lport: 80,
                    rport: u16::try_from(g % 60_000).unwrap(),
                },
                generation: u64::from(g),
                ..TwRow::default()
            };
            t.insert(r);
        }
        t.check().unwrap();
        assert_eq!(t.find_origin(0, u64::from(N)), Some(N - 1));
        assert_eq!(t.find_origin(0, 1), Some(0));
        assert_eq!(t.find_origin(0, 0), None);
        assert_eq!(t.find_origin(1, 1), None);
        // 先頭の次の節を範囲の外にしても、先頭より新しい世代の探索は先頭で止まり、節をたどりません。
        let head = t.oheads[0];
        let second = t.olinks[head as usize][1];
        t.olinks[head as usize][1] = u32::MAX - 1;
        assert_eq!(t.find_origin(0, u64::from(N) + 1), None);
        assert_eq!(t.find_origin(0, u64::MAX), None);
        t.olinks[head as usize][1] = second;
        // 世代の順が崩れた list を検査が捉えます。
        t.rows[head as usize].generation = 1;
        assert_eq!(t.check(), Err("an origin list is not newest first"));
    }

    #[test]
    fn full_table_evicts_the_oldest() {
        let mut t = TwTable::new(2, SipKey { k0: 1, k1: 1 }, 4).unwrap();
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
        let (id, _) = t.insert(row(5));
        let _ = t.free.try_push(id);
        assert_eq!(t.check(), Err("a free list holds a used row"));
        t.free.pop();
        t.rows[id as usize].next = 9;
        assert_eq!(t.check(), Err("a TIME_WAIT list link is out of range"));
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
