//! 握手の途中の表 (Go の `syn.go` の表の部分)。
//!
//! SYN-RCVD の接続を、接続の枠とは別の、バッファを持たない固定の数 N_syn の行に置きます。SYN-ACK の再送の
//! 間隔は回数ごとに一定なので、回数ごとに 1 つの順序つきの list を持ち、各 list の先頭から期限を見ます。
//! 空きの行は小さい番号から使い、返した行を先に使います。握手の最後の ACK で接続の枠と accept の
//! 待ち行列の枠を予約できたら、行を接続の枠に移します (`Stack::promote`)。

use super::listen::Listener;
use super::{SYNACK_RETRIES, SYNACK_RTO, TS_OPTION_LEN, ts_clock};
use crate::fixed_vec::{AllocError, FixedVec};
use crate::index::Index;
use crate::output::NIL;
use crate::siphash::SipKey;
use crate::stack::shared::LogKind;
use crate::stack::{Shared, ns, time};
use crate::time::Time;
use crate::wire::Tuple;
use crate::wire::{
    self, FLAG_ACK, FLAG_RST, FLAG_SYN, IP_HEADER_LEN, MAX_OPTION_LEN, OptWriter, Segment,
    TCP_HEADER_LEN, TcpHeader,
};
use crate::{seq, tcp};

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

    #[cfg(test)]
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
        super::check_free_list(&self.free, self.rows.len(), |i| self.rows[i].used)?;
        let used = self.rows.iter().filter(|r| r.used).count();
        if used != self.n || used + self.free.len() != self.rows.len() || self.idx.len() != used {
            return Err("the half-open table counts disagree");
        }
        let mut listed = 0;
        for (retries, l) in self.lists.iter().enumerate() {
            let mut prev = NIL;
            let mut id = l.head;
            while id != NIL {
                let r = self
                    .rows
                    .get(id as usize)
                    .ok_or("a half-open list link is out of range")?;
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

impl Shared {
    /// 待ち受け `l` への新しい SYN に握手の途中の行を作れるかを返します。
    pub(crate) fn syn_room(&self, l: &Listener) -> bool {
        self.syn.has_free() && usize::from(l.syn_count) < self.config.limits.syn_rows / 2
    }

    /// 待ち受けへの SYN から行を作り、SYN-ACK を送ります。表が満杯か、待ち受けが N_syn の半分を使っていれば、
    /// 状態を作らずに捨てます。`reuse` は TIME_WAIT の 4 つ組を使い直す時の前の接続の SND.NXT です。
    pub(crate) fn new_syn_row(&mut self, seg: &Segment<'_>, now: i64, reuse: Option<u32>) {
        let port = seg.tup.lport;
        if !self
            .listeners
            .by_port(port)
            .is_some_and(|l| self.syn_room(l))
        {
            self.refused(LogKind::SynFull, now);
            return;
        }
        let ts = seg.opt.ts;
        let ts_ok = ts.is_some();
        let row = SynRow {
            tup: seg.tup,
            listener: port,
            iss: self.isn(seg.tup, now, reuse),
            irs: seg.seq,
            deadline: time(now + SYNACK_RTO),
            peer_mss: seg.opt.mss.filter(|&m| m != 0).unwrap_or(536),
            ws_ok: seg.opt.wscale.is_some(),
            snd_wscale: seg.opt.wscale.unwrap_or(0),
            sack_ok: seg.opt.sack_ok,
            ts_ok,
            ts_recent: ts.map_or(0, |(v, _)| v),
            ts_offset: if ts_ok { self.ts_offset(seg.tup) } else { 0 },
            rcv_wnd: u16::try_from(self.initial_window(ts_ok)).unwrap_or(u16::MAX),
            pending: RowSend::SynAck,
            ..SynRow::default()
        };
        let Some(id) = self.syn.insert(row) else {
            return;
        };
        if let Some(l) = self.listeners.by_port_mut(port) {
            l.syn_count += 1;
        }
        self.queue_row(id);
    }

    /// 行を外して空きに返します。
    pub(crate) fn remove_syn_row(&mut self, id: u32) {
        let r = *self.syn.row(id);
        if !r.used {
            return;
        }
        self.syn.remove(id);
        self.unqueue_row(id);
        if let Some(l) = self.listeners.by_port_mut(r.listener) {
            l.syn_count -= 1;
        }
    }

    /// 握手の途中の行への segment を処理します。握手の最後の ACK で accept の待ち行列の枠を予約できたら真を返し、
    /// 呼び手は接続の枠を取って行を移します。予約できなければ ACK を捨て、行は残ります (Linux の
    /// tcp_abort_on_overflow=0 と同じ)。
    pub(crate) fn syn_input(&mut self, id: u32, seg: &Segment<'_>, now: i64) -> bool {
        let r = *self.syn.row(id);
        let rcv_nxt = r.irs.wrapping_add(1);
        let in_window = || {
            let end = seg.seq.wrapping_add(seg.seq_len());
            seq::ge(end, rcv_nxt) && seq::le(seg.seq, rcv_nxt.wrapping_add(u32::from(r.rcv_wnd)))
        };
        if seg.has(FLAG_RST) {
            if in_window() {
                self.remove_syn_row(id);
            }
            return false;
        }
        if seg.has(FLAG_SYN) {
            if !seg.has(FLAG_ACK) && seg.seq == r.irs {
                // 相手が SYN を再送しました。SYN-ACK を送り直します。
                let row = self.syn.row_mut(id);
                (row.pending, row.rtx) = (RowSend::SynAck, true);
                self.queue_row(id);
                return false;
            }
            if in_window() {
                self.reply_rst(seg);
                self.remove_syn_row(id);
                return false;
            }
            self.row_ack(id, now);
            return false;
        }
        if !seg.has(FLAG_ACK) {
            return false;
        }
        if seg.ack != r.iss.wrapping_add(1) {
            self.reply_rst(seg);
            return false;
        }
        if r.ts_ok
            && let Some((ts_val, _)) = seg.opt.ts
            && seq::lt(ts_val, r.ts_recent)
        {
            self.row_ack(id, now);
            return false;
        }
        if !in_window() {
            self.row_ack(id, now);
            return false;
        }
        let q = self.config.limits.accept_queue;
        let full = self
            .listeners
            .by_port(r.listener)
            .is_none_or(|l| usize::from(l.qlen) >= q / 2);
        if full || self.queued >= q || self.conn_free.is_empty() {
            self.refused(LogKind::AcceptOverflow, now);
            return false;
        }
        self.queued += 1;
        if let Some(l) = self.listeners.by_port_mut(r.listener) {
            l.qlen += 1;
        }
        true
    }

    /// 予約した accept の待ち行列の枠を返します。接続の枠を取れなかったときに使います。
    pub(crate) fn unreserve_accept(&mut self, port: u16, now: i64) {
        self.queued -= 1;
        if let Some(l) = self.listeners.by_port_mut(port) {
            l.qlen -= 1;
        }
        self.refused(LogKind::AcceptOverflow, now);
    }

    /// 行から ACK を送ります。challenge ACK と同じ速さの制限を受けます。
    fn row_ack(&mut self, id: u32, now: i64) {
        if !self.challenge_allowed(now) {
            return;
        }
        let row = self.syn.row_mut(id);
        if row.pending == RowSend::None {
            row.pending = RowSend::Ack;
        }
        self.queue_row(id);
    }

    /// SYN-ACK の再送の期限が来た行を処理します。再送の回数を使い切った行は消します。
    pub(crate) fn expire_syn_rows(&mut self, now: i64) {
        for k in 0..=SYNACK_RETRIES {
            while let Some(id) = self.syn.list_head(k) {
                let r = *self.syn.row(id);
                if ns(r.deadline) > now {
                    break;
                }
                if usize::from(r.retries) >= SYNACK_RETRIES {
                    self.remove_syn_row(id);
                    continue;
                }
                self.syn.list_remove(id);
                let row = self.syn.row_mut(id);
                row.retries += 1;
                row.deadline = time(now + (SYNACK_RTO << row.retries));
                (row.pending, row.rtx) = (RowSend::SynAck, true);
                self.syn.list_push(id);
                self.queue_row(id);
            }
        }
    }

    /// 行の組の項目 `id` の packet を作ります。
    pub(crate) fn poll_row(&mut self, id: u32, b: &mut [u8], now: i64) -> usize {
        let cap = u32::try_from(self.syn.capacity()).unwrap_or(0);
        if id >= cap {
            return self.poll_tw_row(id - cap, b, now);
        }
        let r = *self.syn.row(id);
        if !r.used || r.pending == RowSend::None {
            return 0;
        }
        let row = self.syn.row_mut(id);
        row.pending = RowSend::None;
        if r.pending == RowSend::SynAck {
            if row.sent_at.as_nanos() == 0 {
                row.sent_at = time(now);
            }
            return self.build_syn_ack(&r, b, now);
        }
        let h = TcpHeader {
            tup: r.tup,
            seq: r.iss.wrapping_add(1),
            ack: r.irs.wrapping_add(1),
            flags: FLAG_ACK,
            wnd: r.rcv_wnd,
        };
        self.build_row_ack(b, &h, r.ts_ok, r.ts_offset, r.ts_recent, now)
    }

    /// 行の SYN-ACK を作ります。option は Linux と同じ並び (MSS、SACK-perm と TS、窓の scale) です。
    fn build_syn_ack(&mut self, r: &SynRow, b: &mut [u8], now: i64) -> usize {
        let mut o = OptWriter::default();
        o.mss(u16::try_from(self.our_mss()).unwrap_or(u16::MAX));
        let ts_val = ts_clock(now).wrapping_add(r.ts_offset);
        match (r.sack_ok, r.ts_ok) {
            (true, true) => o.sack_perm_with_ts(ts_val, r.ts_recent),
            (false, true) => o.ts(ts_val, r.ts_recent),
            (true, false) => o.sack_perm(),
            (false, false) => {}
        }
        if r.ws_ok {
            o.wscale(tcp::RCV_WINDOW_SHIFT);
        }
        let h = TcpHeader {
            tup: r.tup,
            seq: r.iss,
            ack: r.irs.wrapping_add(1),
            flags: FLAG_SYN | FLAG_ACK,
            wnd: r.rcv_wnd,
        };
        if b.len() < IP_HEADER_LEN + TCP_HEADER_LEN + MAX_OPTION_LEN {
            return 0;
        }
        let id = self.next_id();
        wire::write_tcp(b, id, &h, Some(&mut o), 0);
        wire::finish_tcp(b)
    }

    /// 行から送る ACK を作ります。
    pub(crate) fn build_row_ack(
        &mut self,
        b: &mut [u8],
        h: &TcpHeader,
        ts: bool,
        ts_offset: u32,
        ts_recent: u32,
        now: i64,
    ) -> usize {
        if b.len() < IP_HEADER_LEN + TCP_HEADER_LEN + TS_OPTION_LEN as usize {
            return 0;
        }
        let mut o = OptWriter::default();
        if ts {
            o.ts(ts_clock(now).wrapping_add(ts_offset), ts_recent);
        }
        let id = self.next_id();
        wire::write_tcp(b, id, h, Some(&mut o), 0);
        wire::finish_tcp(b)
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
        // 空きの list の重なり、範囲の外の番号、壊れた list の検出。
        let orig = t.free[0];
        t.free[0] = t.free[1];
        assert_eq!(t.check(), Err("a row is twice in a free list"));
        t.free[0] = 7;
        assert_eq!(t.check(), Err("a free list number is out of range"));
        t.free[0] = orig;
        t.check().unwrap();
        let id = t.insert(row(1, 1)).unwrap();
        t.rows[id as usize].next = 77;
        assert_eq!(t.check(), Err("a half-open list link is out of range"));
    }
}
