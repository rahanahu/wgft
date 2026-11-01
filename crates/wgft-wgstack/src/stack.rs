//! 核の値 (wgstack-rs.md の「sans-IO の API」)。
//!
//! この段の核は表をすべて作成の時に確保し、上界と保持の量と不変条件を出し、閉じる時にすべてを返します。
//! packet の入出力とアプリケーションの操作は核の段 (PR 4a 以降) が足します。

use crate::bound::{Bound, Held};
use crate::budget::Budget;
use crate::buf::chunk::ChunkPool;
use crate::buf::{BOOST_SIZE, RECV_FLOOR, SEND_FLOOR};
use crate::config::{Config, ConfigError};
use crate::event::EventList;
use crate::fixed_vec::{AllocError, FixedVec};
use crate::frag;
use crate::index::Index;
use crate::output::{CtlRing, Dlist};
use crate::rng::{ChaCha8, Seeds};
use crate::siphash::SipKey;
use crate::tcp::NUM_TIMERS;
use crate::tcp::conn::{ConnId, ConnSlots};
use crate::tcp::listen::{self, Listener, PORTS, PortTable};
use crate::tcp::syn::SynTable;
use crate::tcp::timewait::TwTable;
use crate::time::Time;
use crate::wheel::Wheel;
use core::fmt;

/// 核が呼び手に伝える boost の変化と問い合わせです (wgstack-rs.md の「boost の hook」)。
///
/// hook は核への参照を受け取らないので、核を呼び返せません。製品の hook は中継の層が渡し、試験は決まった
/// 答えを返す hook を渡します。種類は後の段で足すことがあり、足す方法は既定の実装を持つメソッドです。
pub trait Hook {
    /// 接続が boost を得た時に呼びます。
    fn boost_granted(&mut self, _conn: ConnId) {}

    /// 需要の無い保有者を floor に戻す前に呼びます。偽を返すと戻りを取り消します。
    fn may_return(&mut self, _conn: ConnId) -> bool {
        true
    }

    /// 接続を floor に戻した後に呼びます。
    fn boost_returned(&mut self, _conn: ConnId) {}
}

/// 何もしない hook です。boost の戻りを常に許します。
#[derive(Clone, Copy, Debug, Default)]
pub struct NoHook;

impl Hook for NoHook {}

/// 核を作れなかった理由と、渡した `Budget` です。
#[derive(Debug)]
pub struct NewError {
    kind: NewErrorKind,
    budget: Budget,
}

/// 核を作れなかった理由です。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewErrorKind {
    /// 設定の誤りです。
    Config(ConfigError),
    /// 表の確保に失敗しました。
    Alloc,
}

impl NewError {
    pub fn kind(&self) -> NewErrorKind {
        self.kind
    }

    /// 渡した `Budget` を取り戻します。
    pub fn into_budget(self) -> Budget {
        self.budget
    }
}

impl fmt::Display for NewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            NewErrorKind::Config(e) => write!(f, "invalid wgstack configuration: {e}"),
            NewErrorKind::Alloc => f.write_str("cannot allocate the wgstack tables"),
        }
    }
}

impl core::error::Error for NewError {}

/// 不変条件の違反です。[`Stack::check_invariants`] が返します。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvariantError {
    what: &'static str,
}

impl InvariantError {
    /// 違反の英語の説明です。
    pub fn what(&self) -> &'static str {
        self.what
    }
}

impl fmt::Display for InvariantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wgstack invariant violated: {}", self.what)
    }
}

impl core::error::Error for InvariantError {}

impl From<&'static str> for InvariantError {
    fn from(what: &'static str) -> Self {
        Self { what }
    }
}

/// [`Stack::close`] が返す、取り戻した `Budget` と最後の会計です。
#[derive(Debug)]
pub struct Closed {
    pub budget: Budget,
    pub held: Held,
}

/// 知らせの対象の番号の始まりです。接続の枠、待ち受けのポートの順に並べます。
pub(crate) struct EventTargets;

impl EventTargets {
    pub(crate) fn count(conns: usize) -> usize {
        conns + PORTS
    }
}

/// wgstack の核です。1 つの所有者が `&mut` で呼ぶ値で、錠を持ちません。
pub struct Stack<H: Hook = NoHook> {
    pub(crate) config: Config,
    pub(crate) now: Time,
    pub(crate) isn_key: SipKey,
    pub(crate) ts_key: SipKey,
    pub(crate) ip_id: u32,
    pub(crate) rng: ChaCha8,
    pub(crate) conns: ConnSlots,
    pub(crate) conn_idx: Index,
    pub(crate) syn: SynTable,
    pub(crate) tw: TwTable,
    pub(crate) listeners: PortTable<Listener>,
    /// accept の待ち行列の全体の数です。
    pub(crate) queued: usize,
    pub(crate) out_conns: Dlist,
    pub(crate) out_rows: Dlist,
    pub(crate) ctl: CtlRing,
    pub(crate) events: EventList,
    pub(crate) wheel: Wheel,
    pub(crate) fired: FixedVec<u32>,
    pub(crate) chunks: ChunkPool,
    pub(crate) frag: frag::Table,
    pub(crate) budget: Budget,
    pub(crate) hook: H,
}

impl<H: Hook> fmt::Debug for Stack<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stack")
            .field("config", &self.config)
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

impl<H: Hook> Stack<H> {
    /// 核を作り、表をすべて確保します。`seed` は 64 byte の乱数の種で、製品は OS の乱数から作り、試験は固定の
    /// 種を渡します。失敗したら渡した `Budget` を誤りに入れて返します。
    pub fn new(config: Config, budget: Budget, seed: &[u8; 64], hook: H) -> Result<Self, NewError> {
        if let Err(e) = config.validate() {
            return Err(NewError {
                kind: NewErrorKind::Config(e),
                budget,
            });
        }
        match Tables::new(&config, seed) {
            Ok(t) => Ok(Self {
                config,
                now: Time::ZERO,
                isn_key: t.seeds.isn_key,
                ts_key: t.seeds.ts_key,
                ip_id: t.seeds.ip_id,
                rng: t.seeds.rng,
                conns: t.conns,
                conn_idx: t.conn_idx,
                syn: t.syn,
                tw: t.tw,
                listeners: t.listeners,
                queued: 0,
                out_conns: t.out_conns,
                out_rows: t.out_rows,
                ctl: t.ctl,
                events: t.events,
                wheel: t.wheel,
                fired: t.fired,
                chunks: t.chunks,
                frag: t.frag,
                budget,
                hook,
            }),
            Err(_) => Err(NewError {
                kind: NewErrorKind::Alloc,
                budget,
            }),
        }
    }

    /// 作成の時の設定です。
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// この核の上界の式の値です。作成の時の設定と型の大きさだけから決まります。
    pub fn bound(&self) -> Bound {
        Bound::with_stack_size(&self.config.limits, self.config.mtu, size_of::<Self>())
    }

    /// 核が今持つ可変の保持の量です。
    pub fn held(&self) -> Held {
        let mut h = Held::default();
        for (_, s) in self.conns.iter() {
            let (recs, ivs) = s.array_bytes();
            h.record_bytes += recs;
            h.interval_bytes += ivs;
            if s.in_use {
                h.conns += 1;
                h.chunk_bytes += s.held_chunks() * crate::buf::chunk::CHUNK_SIZE;
                h.reserved += s.snd.cap() + s.rcv.r.cap();
                if s.boost.is_some() {
                    h.boosted += 1;
                }
            }
        }
        h.syn_rows = self.syn.len();
        h.tw_rows = self.tw.len();
        h.accept_queued = self.queued;
        h.ctl_queued = self.ctl.len();
        h.frag_bytes = self.frag.usage().0 - self.frag.base_cost();
        h.events = self.events.len();
        h.pool_chunks = self.chunks.kept();
        h
    }

    /// 不変条件を確かめます。予約の和が上界以下であること、表の数と予約が一致すること、chunk と配列の持ち主が
    /// 1 つであることを確かめます。呼んだ時だけ手間がかかり、製品は呼びません。試験と fuzz が各段の後に呼びます。
    pub fn check_invariants(&self) -> Result<(), InvariantError> {
        self.conns.check()?;
        self.conn_idx.check()?;
        self.syn.check()?;
        self.tw.check()?;
        self.out_conns.check()?;
        self.out_rows.check()?;
        self.events.check()?;
        self.wheel.check()?;
        self.budget.check()?;
        // 接続の表の項目は、使っている枠を同じ 4 つ組と世代で指します。
        let mut bad = None;
        self.conn_idx.for_each(|tup, slot| {
            let s = self.conns.slot(slot);
            if !s.in_use
                || !s.in_index
                || s.tup != tup
                || self
                    .conn_idx
                    .find(tup)
                    .is_none_or(|(_, g)| g != s.generation)
            {
                bad = Some("a connection index entry points to the wrong slot");
            }
        });
        if let Some(e) = bad {
            return Err(e.into());
        }
        let mut chunks = 0;
        let mut reserved = 0;
        let mut boosted = 0;
        for (i, s) in self.conns.iter() {
            if s.in_index != self.conn_idx.find(s.tup).is_some_and(|(id, _)| id == i) && s.in_use {
                return Err("a slot's index mark disagrees with the index".into());
            }
            if let Some(b) = s.boost {
                if self.budget.holder(b) != Some(self.conns.id(i)) {
                    return Err("a boosted slot is not the holder of its boost slot".into());
                }
                boosted += 1;
            }
            chunks += s.held_chunks();
            if s.in_use {
                reserved += s.snd.cap() + s.rcv.r.cap();
            }
        }
        if chunks != self.chunks.held() {
            return Err("the chunk pool count disagrees with the rings".into());
        }
        if boosted != self.budget.lent() {
            return Err("the lent boost slots disagree with the boosted connections".into());
        }
        let floors = self.conns.len() as u64 * (SEND_FLOOR + RECV_FLOOR);
        let boosts = self.budget.slots() as u64 * (2 * BOOST_SIZE - SEND_FLOOR - RECV_FLOOR);
        if reserved > floors + boosts {
            return Err("the reservations exceed the bound".into());
        }
        let mut queued = 0;
        let mut bad = None;
        self.listeners
            .for_each_open(|port, l| match listen::check_queue(l, port, &self.conns) {
                Ok(_) => queued += usize::from(l.qlen),
                Err(e) => bad = Some(e),
            });
        if let Some(e) = bad {
            return Err(e.into());
        }
        if queued != self.queued || self.queued > self.config.limits.accept_queue {
            return Err("the accept queue lengths disagree with the total".into());
        }
        Ok(())
    }

    /// 待ち受けと接続とソケットをすべて閉じ、`Budget` と最後の会計を返します。最後の会計はすべて 0 です。
    pub fn close(mut self, now: Time) -> Closed {
        self.now = self.now.max(now);
        // 借りている boost の配列を枠に返します。
        for i in 0..self.budget.slots() {
            if self.budget.holder(i).is_some() {
                let s = self
                    .conns
                    .iter()
                    .find(|(_, s)| s.boost == Some(i))
                    .map(|(n, _)| n);
                if let Some(n) = s {
                    let (recs, iv) = self.conns.slot_mut(n).take_boost_arrays();
                    self.budget.release(i, recs, iv);
                }
            }
        }
        self.syn.clear();
        self.tw.clear();
        self.conns.free_all(&mut self.chunks);
        self.chunks.drain();
        self.frag.clear();
        self.ctl.clear();
        self.events.clear();
        while self.out_conns.pop_front().is_some() {}
        while self.out_rows.pop_front().is_some() {}
        self.queued = 0;
        let held = self.held();
        debug_assert!(held.is_zero(), "close left {held:?}");
        Closed {
            budget: self.budget,
            held,
        }
    }
}

/// 核の表です。作成の途中で確保に失敗したら、確保した分を解放して誤りを返します。
struct Tables {
    seeds: Seeds,
    conns: ConnSlots,
    conn_idx: Index,
    syn: SynTable,
    tw: TwTable,
    listeners: PortTable<Listener>,
    out_conns: Dlist,
    out_rows: Dlist,
    ctl: CtlRing,
    events: EventList,
    wheel: Wheel,
    fired: FixedVec<u32>,
    chunks: ChunkPool,
    frag: frag::Table,
}

impl Tables {
    fn new(config: &Config, seed: &[u8; 64]) -> Result<Self, AllocError> {
        let l = &config.limits;
        let n = l.conns();
        let seeds = Seeds::new(seed);
        let frag_limits = frag::Limits {
            entries: l.frag_entries,
            fragments: l.frag_pieces,
            ..frag::LIMITS
        };
        Ok(Self {
            conns: ConnSlots::new(n)?,
            conn_idx: Index::new(n, seeds.table_key, true)?,
            syn: SynTable::new(l.syn_rows, seeds.table_key)?,
            tw: TwTable::new(l.tw_rows, seeds.table_key)?,
            listeners: PortTable::new()?,
            out_conns: Dlist::new(n)?,
            out_rows: Dlist::new(l.syn_rows + l.tw_rows)?,
            ctl: CtlRing::new(l.ctl_slots, config.mtu)?,
            events: EventList::new(EventTargets::count(n))?,
            wheel: Wheel::new(n * NUM_TIMERS)?,
            fired: FixedVec::try_with_capacity(n * NUM_TIMERS)?,
            chunks: ChunkPool::new()?,
            frag: frag::Table::new(frag_limits).map_err(|_| AllocError)?,
            seeds,
        })
    }
}

#[cfg(test)]
mod tests;
