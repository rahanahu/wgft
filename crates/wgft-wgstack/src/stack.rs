//! 核の値 (wgstack-rs.md の「sans-IO の API」、Go の `stack.go` と `device.go`)。
//!
//! 核は表をすべて作成の時に確保し、packet と時刻とアプリケーションの操作を受けて状態を変え、送る packet、
//! 次に起こす時刻、知らせを出します。閉じる時にすべてを返します。
//! アプリケーションの操作は [`api`] にあり、接続の枠の外の共有の状態は [`shared`] にあります。

pub(crate) mod api;
mod boost;
pub(crate) mod shared;

use crate::bound::{Bound, Held};
use crate::budget::Budget;
use crate::buf::chunk::{CHUNK_SIZE, ChunkPool};
use crate::buf::{BOOST_SIZE, RECV_FLOOR, SEND_FLOOR};
use crate::config::{Config, ConfigError};
use crate::event::EventList;
use crate::fixed_vec::{AllocError, FixedVec};
use crate::frag;
use crate::icmp::{PING_ENDPOINTS, PingId, Pings};
use crate::index::Index;
use crate::output::{CtlRing, Dlist};
use crate::rng::Seeds;
use crate::tcp::conn::{ConnBufs, ConnId, ConnSlots, QLink, State, Tcb, new_free_list};
use crate::tcp::ctx::Conn;
use crate::tcp::listen::{self, Listener, PORTS, PortTable};
use crate::tcp::syn::{RowVerdict, SynTable};
use crate::tcp::timewait::TwTable;
use crate::tcp::{NUM_TIMERS, NUM_TIMERS32};
use crate::time::Time;
use crate::udp::{Udp, UdpId};
use crate::wheel::{NO_TICK, TICK_NS, Wheel};
use crate::wire::{self, FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN, Ipv4Drop, PayloadDrop};
pub use api::{Error, Event, ListenerId};
use core::fmt;
pub use shared::{LogKind, LogLine, Stats};
pub(crate) use shared::{Output, Shared};

/// 核が呼び手に伝える boost の変化と問い合わせです (wgstack-rs.md の「boost の hook」)。
///
/// hook は核への参照を受け取らないので、核を呼び返せません。製品の hook は中継の層が渡し、試験は決まった
/// 答えを返す hook を渡します。種類を足すときは、既定の実装を持つメソッドで足します。
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

/// 知らせの対象の番号の始まりです。接続の枠、ポート (TCP の待ち受けと UDP の endpoint が分け合います)、ping の
/// endpoint の順に並べます。
pub(crate) struct EventTargets;

impl EventTargets {
    pub(crate) fn count(conns: usize) -> usize {
        conns + PORTS + PING_ENDPOINTS
    }
}

/// 接続の枠 1 つの数えです。不変条件の確かめが、表の数と比べる和を作ります。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SlotTally {
    /// 送受信の輪が持つ chunk の数です。
    chunks: usize,
    /// 使っている枠の送受信の輪の容量 (予約) の byte です。
    reserved: u64,
    /// boost の枠を借りていれば 1 です。
    boosted: usize,
}

impl SlotTally {
    fn add(&mut self, t: Self) {
        self.chunks += t.chunks;
        self.reserved += t.reserved;
        self.boosted += t.boosted;
    }

    #[cfg(any(test, feature = "harness"))]
    fn sub(&mut self, t: Self) {
        self.chunks -= t.chunks;
        self.reserved -= t.reserved;
        self.boosted -= t.boosted;
    }
}

/// [`Stack::check_invariants_touched`] が呼び出しの間に持つ、接続の枠ごとの数えとその和です。
///
/// 核の外の値で、核の型は持ちません。1 つの核に属します。別の核に渡すと、印の無い枠の数えが前の核の値のまま残り、
/// 答えが変わります。核を作り直したら [`TouchedCheck::new`] で作り直します。
/// 試験と fuzz の build (`cfg(test)` か feature `harness`) だけにあります。
#[cfg(any(test, feature = "harness"))]
#[derive(Debug, Default)]
pub struct TouchedCheck {
    tally: FixedVec<SlotTally>,
    sum: SlotTally,
    /// 書き換えた枠の番号を取り出す場所です。
    pending: FixedVec<u32>,
    /// 数えが前の呼び出しの状態と合っています。偽なら次の呼び出しがすべての枠を数え直します。
    primed: bool,
}

#[cfg(any(test, feature = "harness"))]
impl TouchedCheck {
    /// 空の控えです。最初の呼び出しがすべての枠を確かめます。
    pub fn new() -> Self {
        Self::default()
    }
}

fn slot_u32(i: usize) -> u32 {
    u32::try_from(i).unwrap_or(u32::MAX)
}

/// 試験と fuzz の build (`cfg(test)` か feature `harness`) だけにある核の欄の byte です。接続の枠の表の書き換えの印
/// (`ConnSlots::touched`)、印を持つ知らせの対象の数 (`EventList::marked`)、待ち受けの表と UDP の endpoint の表の
/// 開いたことのある印 (`PortTable::opened`)、配列を返された boost の枠の印 (`Budget::dirty`) です。
#[cfg(any(test, feature = "harness"))]
pub(crate) const HARNESS_BYTES: usize =
    3 * size_of::<crate::bitset::BitSet>() + size_of::<usize>() + size_of::<u64>();

/// 上界の式が使う核の値の大きさです。製品の核の大きさで数え、試験と fuzz の build だけにある欄を入れません。
pub(crate) const fn stack_size<H: Hook>() -> usize {
    let size = size_of::<Stack<H>>();
    #[cfg(any(test, feature = "harness"))]
    let size = size - HARNESS_BYTES;
    size
}

/// wgstack の核です。1 つの所有者が `&mut` で呼ぶ値で、錠を持ちません。
pub struct Stack<H: Hook = NoHook> {
    pub(crate) conns: ConnSlots,
    pub(crate) s: Shared,
    pub(crate) hook: H,
}

impl<H: Hook> fmt::Debug for Stack<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stack")
            .field("config", &self.s.config)
            .field("now", &self.s.now)
            .finish_non_exhaustive()
    }
}

/// 核が使う時刻の上限 (ns) です。約 73 年で、核が時刻に足す最も長い期限 (PAWS の 24 日、再送の打ち切りの
/// 約 15 分) を足しても `i64` に収まります。
pub(crate) const MAX_NOW: i64 = i64::MAX / 4;

/// 核の時刻を Go と同じ符号つきの ns にします。`i64` を超える時刻は上限で止めます。
pub(crate) fn ns(t: Time) -> i64 {
    i64::try_from(t.as_nanos()).unwrap_or(i64::MAX)
}

/// 符号つきの ns を核の時刻にします。負の値は 0 にします。
pub(crate) fn time(ns: i64) -> Time {
    Time::from_nanos(u64::try_from(ns).unwrap_or(0))
}

impl<H: Hook> Stack<H> {
    /// 核を作り、表をすべて確保します。`seed` は 64 byte の乱数の種で、製品は OS の乱数から作り、試験は固定の
    /// 種を渡します。失敗したら渡した `Budget` を誤りに入れて返します。
    pub fn new(config: Config, budget: Budget, seed: &[u8; 64], hook: H) -> Result<Self, NewError> {
        Self::create(config, budget, hook, |c| Tables::new(c, seed))
    }

    /// [`Stack::new`] と同じく核を作り、`spare` の表 ([`Stack::close_keeping`] が返した表) を新しく作る代わりに
    /// 使います。大きさが合わない表と `spare` に無い表は新しく作ります。ほかの表は [`Stack::new`] と同じ口で
    /// 作るので、作った核は [`Stack::new`] が作る核と同じ状態です。試験と fuzz の build だけにあります。
    #[cfg(any(test, feature = "harness"))]
    pub fn new_reusing(
        config: Config,
        budget: Budget,
        spare: Spare,
        seed: &[u8; 64],
        hook: H,
    ) -> Result<Self, NewError> {
        Self::create(config, budget, hook, |c| {
            let n = c.limits.conns();
            Tables::with_ports(
                c,
                seed,
                match spare.listeners {
                    Some(t) => t,
                    None => PortTable::new()?,
                },
                match spare.eps {
                    Some(t) => t,
                    None => PortTable::new()?,
                },
                match spare.events {
                    Some(e) if e.targets() == EventTargets::count(n) => e,
                    _ => EventList::new(EventTargets::count(n))?,
                },
            )
        })
    }

    /// 設定を確かめ、`tables` で表を作り、核を組み立てます。
    fn create(
        config: Config,
        budget: Budget,
        hook: H,
        tables: impl FnOnce(&Config) -> Result<Tables, AllocError>,
    ) -> Result<Self, NewError> {
        if let Err(e) = config.validate() {
            return Err(NewError {
                kind: NewErrorKind::Config(e),
                budget,
            });
        }
        match tables(&config) {
            Ok(t) => Ok(Self {
                conns: t.conns,
                s: Shared {
                    config,
                    addr: config.addr.to_bits(),
                    now: 0,
                    isn_key: t.seeds.isn_key,
                    ts_key: t.seeds.ts_key,
                    cookie_key: t.seeds.cookie_key,
                    cookie_sent: None,
                    ip_id: t.seeds.ip_id,
                    rng: t.seeds.rng,
                    conn_free: t.conn_free,
                    qlinks: t.qlinks,
                    conn_idx: t.conn_idx,
                    syn: t.syn,
                    tw: t.tw,
                    listeners: t.listeners,
                    queued: 0,
                    out: Output {
                        conns: t.out_conns,
                        rows: t.out_rows,
                        ctl: t.ctl,
                        udp_queued: 0,
                        cur: 0,
                        deficit: [0; shared::NUM_CLASSES],
                    },
                    events: t.events,
                    wheel: t.wheel,
                    fired: t.fired,
                    chunks: t.chunks,
                    frag: t.frag,
                    frag_next_sweep: 0,
                    udp: t.udp,
                    pings: t.pings,
                    icmp_sec: -1,
                    icmp_count: 0,
                    budget,
                    ch_sec: -1,
                    ch_count: 0,
                    stats: Stats::default(),
                    gates: shared::Gates::default(),
                },
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
        &self.s.config
    }

    /// 作成の時に渡した hook です。中継の層が hook と分け合う表を引くのに使います。
    pub fn hook(&self) -> &H {
        &self.hook
    }

    /// この核の上界の式の値です。作成の時の設定と型の大きさだけから決まります。
    pub fn bound(&self) -> Bound {
        Bound::with_stack_size(&self.s.config.limits, self.s.config.mtu, stack_size::<H>())
    }

    /// 枠 `i` の接続の view です。
    pub(crate) fn conn(&mut self, i: u32) -> Conn<'_> {
        let (t, k, b) = self.conns.parts_mut(i);
        Conn {
            id: i,
            t,
            k,
            b,
            s: &mut self.s,
        }
    }

    /// 呼び手の時刻を核の時刻にします。前の値より戻った時刻は前の値にします。
    ///
    /// 時刻は [`MAX_NOW`] で止めます。核は時刻に期限の長さを足すので、止めないと上限の近くの時刻で足し算が
    /// 溢れます。
    pub(crate) fn clock(&mut self, now: Time) -> i64 {
        self.s.now = self.s.now.max(ns(now).min(MAX_NOW));
        self.s.now
    }

    /// 事象の数です。
    pub fn stats(&self) -> Stats {
        self.s.stats
    }

    /// 核が今持つ可変の保持の量です。
    pub fn held(&self) -> Held {
        let mut h = Held::default();
        for (_, t, b) in self.conns.iter_bufs() {
            let (recs, ivs) = b.array_bytes();
            h.record_bytes += recs;
            h.interval_bytes += ivs;
            h.slot_arrays += usize::from(b.has_floor_arrays());
            if t.state != State::Free {
                h.conns += 1;
                h.chunk_bytes += b.held_chunks() * CHUNK_SIZE;
                h.reserved += b.snd.cap() + b.rcv.r.cap();
                if b.boost.is_some() {
                    h.boosted += 1;
                    h.lent_array_bytes += b.lent_array_bytes();
                }
            }
        }
        h.syn_rows = self.s.syn.len();
        h.tw_rows = self.s.tw.len();
        h.accept_queued = self.s.queued;
        h.ctl_queued = self.s.out.ctl.len();
        h.frag_bytes = self.s.frag.usage().0 - self.s.frag.base_cost();
        (h.udp_rx_bytes, h.udp_rx_datagrams) = self.s.udp.held(crate::udp::RX);
        (h.udp_tx_bytes, h.udp_tx_datagrams) = self.s.udp.held(crate::udp::TX);
        h.ping_endpoints = self.s.pings.used();
        h.events = self.s.events.len();
        h.pool_chunks = self.s.chunks.kept();
        h.pool_bytes = h.pool_chunks * CHUNK_SIZE;
        h
    }

    /// 核を作ってから使ったことのある接続の枠の数です。枠は初めて使う時に floor の送信の記録の輪と区間の表を確保し、
    /// 持ち続けるので、この数の枠がその配列を持ちます。数えは枠を初めて使う時だけ増えるので、読むのは定数の手間です。
    pub fn slots_used(&self) -> usize {
        self.conns.with_arrays()
    }

    /// 不変条件を確かめます。予約の和が上界以下であること、表の数と予約が一致すること、chunk と配列の持ち主が
    /// 1 つであることを確かめます。呼んだ時だけ手間がかかり、製品は呼びません。試験と fuzz が各段の後に呼びます。
    ///
    /// すべての接続の枠を確かめ、表の数と和をすべて数え直します。各段の後に書き換えた枠だけを確かめる形は
    /// [`Stack::check_invariants_touched`] で、同じ状態に同じ答えを返します。
    pub fn check_invariants(&self) -> Result<(), InvariantError> {
        let s = &self.s;
        self.conns.check_free(&s.conn_free, &s.qlinks)?;
        let mut sum = SlotTally::default();
        for i in 0..self.conns.len() {
            sum.add(self.check_slot(slot_u32(i))?);
        }
        self.check_shared(&sum, EventList::check, u64::MAX)
    }

    /// [`Stack::check_invariants`] と同じ不変条件を、前の呼び出しから書き換えた接続の枠だけを確かめて確かめます
    /// (wgstack-rs.md の「書き換えた所だけの確かめ」)。試験と fuzz が各段の後に呼びます。試験と fuzz の build
    /// (`cfg(test)` か feature `harness`) だけにあります。
    ///
    /// 接続の枠の表は、試験と fuzz の build で、配列を書き換える口を通った枠に印を付けます。この関数は印のある枠
    /// だけを確かめ直して印を外します。`c` は前の呼び出しまでの枠ごとの数え (chunk、予約、boost) とその和を持ち、
    /// 書き換えた枠の分だけを入れ替えます。初めての呼び出しと、前の呼び出しが誤りを返した後は、すべての枠を
    /// 確かめて数え直します。
    ///
    /// 枠の配列は表の型の外から見えないので、印の無い枠の欄と輪は前の呼び出しが確かめた時のままです。枠だけを
    /// 読む確かめ (輪、区間の表、段、送り手と scoreboard) はその時と同じ答えを返し、数えも同じ値なので、この関数は
    /// 同じ状態に [`Stack::check_invariants`] と同じ答えを返します。枠と共有の表の間の確かめと共有の表の確かめは、
    /// 毎回すべてを確かめます。知らせの印は数え直さず、印を書く口が増減で保つ数で確かめます。誤りの文も同じです。
    #[cfg(any(test, feature = "harness"))]
    pub fn check_invariants_touched(&mut self, c: &mut TouchedCheck) -> Result<(), InvariantError> {
        let slots = self.conns.len();
        let ready = c.primed && c.tally.len() == slots;
        c.primed = false;
        if c.pending.capacity() < slots {
            c.pending = FixedVec::try_with_capacity(slots)
                .map_err(|_| "allocation failed while checking")?;
        }
        c.pending.clear();
        let pending = &mut c.pending;
        self.conns.take_touched(|i| {
            let _ = pending.try_push(i);
        });
        // 空きの boost の枠の chunk の表は、配列を返された枠だけを確かめ直します。最初の呼び出しはすべてを確かめます。
        let dirty = self.s.budget.take_dirty();
        let budget_scan = if ready { dirty } else { u64::MAX };
        let s = &self.s;
        self.conns.check_free(&s.conn_free, &s.qlinks)?;
        if ready {
            for k in 0..c.pending.len() {
                let i = c.pending[k] as usize;
                let t = self.check_slot(slot_u32(i))?;
                c.sum.sub(c.tally[i]);
                c.sum.add(t);
                c.tally[i] = t;
            }
        } else {
            if c.tally.len() != slots {
                c.tally = FixedVec::try_filled(slots, |_| SlotTally::default())
                    .map_err(|_| "allocation failed while checking")?;
            }
            c.sum = SlotTally::default();
            for i in 0..slots {
                let t = self.check_slot(slot_u32(i))?;
                c.sum.add(t);
                c.tally[i] = t;
            }
        }
        self.check_shared(&c.sum, EventList::check_counted, budget_scan)?;
        c.primed = true;
        Ok(())
    }

    /// 枠 `i` の配列の要素と、それが持つ配列だけを読む確かめをし、枠の数えを返します。
    fn check_slot(&self, i: u32) -> Result<SlotTally, InvariantError> {
        self.conns.check_slot(i)?;
        let (t, b) = (self.conns.tcb(i), self.conns.bufs(i));
        let used = t.state != State::Free;
        if used {
            check_conn(t, b)?;
            crate::tcp::sack::check_sender(t, &b.recs)?;
        }
        Ok(SlotTally {
            chunks: b.held_chunks(),
            reserved: if used { b.snd.cap() + b.rcv.r.cap() } else { 0 },
            boosted: usize::from(b.boost.is_some()),
        })
    }

    /// 共有の表と、枠と共有の表の間の不変条件を確かめ、枠の数えの和 `sum` を表の数と比べます。知らせの list は
    /// `events` で確かめ、空きの boost の枠の chunk の表は `budget_scan` の bit の立った枠だけで確かめます。
    fn check_shared(
        &self,
        sum: &SlotTally,
        events: fn(&EventList) -> Result<(), &'static str>,
        budget_scan: u64,
    ) -> Result<(), InvariantError> {
        let s = &self.s;
        s.conn_idx.check()?;
        s.syn.check()?;
        s.tw.check()?;
        s.out.conns.check()?;
        s.out.rows.check()?;
        events(&s.events)?;
        s.wheel.check()?;
        s.budget.check_scanning(budget_scan)?;
        s.udp.check()?;
        s.pings.check()?;
        s.listeners.check()?;
        if s.udp.held(crate::udp::TX).1 != s.out.udp_queued {
            return Err("the UDP output count disagrees with the send FIFO".into());
        }
        // 接続の表の項目は、使っている枠を同じ 4 つ組と世代で指します。
        let mut bad = None;
        s.conn_idx.for_each(|tup, slot| {
            let t = self.conns.tcb(slot);
            if t.state == State::Free
                || !t.in_index
                || t.tup != tup
                || s.conn_idx.find(tup).is_none_or(|(_, g)| g != t.generation)
            {
                bad = Some("a connection index entry points to the wrong slot");
            }
        });
        if let Some(e) = bad {
            return Err(e.into());
        }
        for (i, t, b) in self.conns.iter_bufs() {
            let used = t.state != State::Free;
            if used && t.in_index != s.conn_idx.find(t.tup).is_some_and(|(id, _)| id == i) {
                return Err("a slot's index mark disagrees with the index".into());
            }
            if let Some(n) = b.boost
                && s.budget.holder(n) != Some(self.conns.id(i))
            {
                return Err("a boosted slot is not the holder of its boost slot".into());
            }
            for (k, &d) in t.tdl.iter().enumerate() {
                let node = i * NUM_TIMERS32 + u32::try_from(k).unwrap_or(0);
                if (d != 0) != s.wheel.deadline(node).is_some() {
                    return Err("a connection timer disagrees with the wheel".into());
                }
            }
            if !used && s.out.conns.contains(i) {
                return Err("a free slot is in the output list".into());
            }
        }
        let (rx, _) = s.udp.held(crate::udp::RX);
        let (tx, _) = s.udp.held(crate::udp::TX);
        if sum.chunks + (rx + tx) / CHUNK_SIZE != s.chunks.held() {
            return Err("the chunk pool count disagrees with the rings".into());
        }
        if sum.boosted != s.budget.lent() {
            return Err("the lent boost slots disagree with the boosted connections".into());
        }
        let floors = self.conns.len() as u64 * (SEND_FLOOR + RECV_FLOOR);
        let boosts = s.budget.slots() as u64 * (2 * BOOST_SIZE - SEND_FLOOR - RECV_FLOOR);
        if sum.reserved > floors + boosts {
            return Err("the reservations exceed the bound".into());
        }
        let mut queued = 0;
        let mut syn_rows = 0;
        let mut bad = None;
        s.listeners.for_each_open(|port, l| {
            syn_rows += usize::from(l.syn_count);
            match listen::check_queue(l, port, &s.qlinks, |i| {
                self.conns.tcb(i).state != State::Free
            }) {
                Ok(_) => queued += usize::from(l.qlen),
                Err(e) => bad = Some(e),
            }
        });
        if let Some(e) = bad {
            return Err(e.into());
        }
        if syn_rows != s.syn.len() {
            return Err("the listeners' half-open counts disagree with the table".into());
        }
        if queued != s.queued || s.queued > s.config.limits.accept_queue {
            return Err("the accept queue lengths disagree with the total".into());
        }
        Ok(())
    }

    /// 待ち受けと接続とソケットをすべて閉じ、`Budget` と最後の会計を返します。最後の会計はすべて 0 です。
    pub fn close(mut self, now: Time) -> Closed {
        let held = self.close_tables(now);
        Closed {
            budget: self.s.budget,
            held,
        }
    }

    /// [`Stack::close`] と同じく核を閉じ、加えてポートの数の行を持つ表を作成の時の値に戻して返します
    /// (wgstack-rs.md の「核の使い回し」)。試験と fuzz が、次の核を [`Stack::new_reusing`] で作るために使います。
    ///
    /// ポートの行は開いた時にだけ世代が進み、閉じた行は世代のほかは作成の時の値です。ポートの表は開いたことのある
    /// 行に印を持つので (試験と fuzz の build だけ)、その行を戻せば表は作成の時と同じになります。印の残る知らせの
    /// list は返さず、次の核はそれを新しく作ります。試験と fuzz の build だけにあります。
    #[cfg(any(test, feature = "harness"))]
    pub fn close_keeping(mut self, now: Time) -> (Closed, Spare) {
        let held = self.close_tables(now);
        let Self { s, .. } = self;
        let mut spare = Spare::default();
        let mut listeners = s.listeners;
        listeners.restore();
        spare.listeners = Some(listeners);
        let mut eps = s.udp.eps;
        eps.restore();
        spare.eps = Some(eps);
        if s.events.is_empty() {
            spare.events = Some(s.events);
        }
        (
            Closed {
                budget: s.budget,
                held,
            },
            spare,
        )
    }

    /// 核の表を空にし、最後の会計を返します。会計はすべて 0 です。
    fn close_tables(&mut self, now: Time) -> Held {
        self.clock(now);
        let s = &mut self.s;
        // 借りている boost の配列を枠に返します。
        for i in 0..s.budget.slots() {
            if let Some(id) = s.budget.holder(i) {
                let arrays = self
                    .conns
                    .bufs_mut(id.slot)
                    .take_boost_arrays(&mut s.chunks);
                s.budget.release(i, arrays);
            }
        }
        s.syn.clear();
        s.tw.clear();
        s.udp.clear(&mut s.chunks);
        s.out.udp_queued = 0;
        s.pings.clear();
        self.conns.free_all(&mut s.chunks);
        s.chunks.drain();
        s.frag.clear();
        s.out.ctl.clear();
        s.events.clear();
        while s.out.conns.pop_front().is_some() {}
        while s.out.rows.pop_front().is_some() {}
        for l in s.qlinks.iter_mut() {
            *l = QLink::default();
        }
        s.queued = 0;
        let held = self.held();
        debug_assert!(held.is_zero(), "close left {held:?}");
        held
    }

    /// トンネルから届いた IPv4 の packet を 1 つ処理します。packet は呼び出しの間だけ読み、保持するものは自分の
    /// 予約に写します。捨てた packet は理由ごとに数えます。
    pub fn handle_packet(&mut self, now: Time, pkt: &[u8]) {
        let now = self.clock(now);
        self.input(pkt, now);
    }

    /// 1 つの IPv4 の packet を処理します (Go の `stack.input`)。再組み立ての表が完成させた datagram もここに
    /// 戻ります。
    pub(crate) fn input(&mut self, pkt: &[u8], now: i64) {
        let ip = match wire::parse_ipv4(pkt) {
            Ok(ip) => ip,
            Err(Ipv4Drop::Malformed) => {
                self.s.stats.malformed += 1;
                return;
            }
            Err(Ipv4Drop::BadChecksum) => {
                self.s.stats.bad_checksum += 1;
                return;
            }
        };
        if ip.dst != self.s.addr || ip.src == ip.dst {
            self.s.stats.not_local += 1;
            return;
        }
        if ip.fragment {
            self.input_fragment(&ip, now);
            return;
        }
        match ip.proto {
            wire::PROTO_TCP => match wire::parse_tcp(&ip) {
                Ok(seg) => self.input_tcp(&seg, now),
                Err(PayloadDrop::Malformed) => self.s.stats.malformed += 1,
                Err(PayloadDrop::BadChecksum) => self.s.stats.bad_checksum += 1,
            },
            wire::PROTO_UDP => self.s.input_udp(&ip, now),
            wire::PROTO_ICMP => self.input_icmp(&ip, now),
            _ => self.s.stats.malformed += 1,
        }
    }

    /// TCP の segment を、接続の枠、TIME_WAIT の行、握手の途中の行、待ち受けの順に渡します。
    fn input_tcp(&mut self, seg: &wire::Segment<'_>, now: i64) {
        if seg.has(FLAG_SYN)
            && seg
                .opt
                .mss
                .is_some_and(|m| m != 0 && u32::from(m) < crate::tcp::MIN_MSS)
        {
            self.s.drop_mss(now);
            return;
        }
        let mut reuse = None;
        for _ in 0..3 {
            if let Some((id, generation)) = self.s.conn_idx.find(seg.tup) {
                let t = self.conns.tcb(id);
                if t.generation != generation || !t.in_index {
                    continue;
                }
                if self.conn(id).input(seg, now, &mut reuse) {
                    continue; // TIME_WAIT の接続が新しい SYN を受けた (RFC 6191)
                }
                return;
            }
            if let Some(r) = self.s.tw.find(seg.tup)
                && self.s.tw_input(r, seg, now, &mut reuse)
            {
                return;
            }
            // 行を外したら、SYN を待ち受けに渡します。
            if let Some(r) = self.s.syn.find(seg.tup) {
                match self.s.syn_input(r, seg, now) {
                    RowVerdict::Done => {}
                    RowVerdict::Promote => self.promote(r, seg, now),
                    RowVerdict::Cookie => {
                        if !self.establish_cookie(seg, now, Some(r)) {
                            self.s.reply_rst(seg);
                        }
                    }
                }
                return;
            }
            let listening = self.s.listeners.by_port(seg.tup.lport).is_some();
            if listening && seg.flags & (FLAG_SYN | FLAG_ACK | FLAG_RST | FLAG_FIN) == FLAG_SYN {
                self.s.new_syn_row(seg, now, reuse);
                return;
            }
            if listening && seg.has(FLAG_SYN) && !seg.has(FLAG_ACK) {
                // SYN と RST、SYN と FIN の組を持つ segment は捨てます。SYN と FIN の組は凍結した Go の
                // wgstack と違います (wgstack-rs.md の「待ち受けへの SYN と FIN の組」)。
                return;
            }
            if listening
                && seg.flags & (FLAG_SYN | FLAG_ACK | FLAG_RST) == FLAG_ACK
                && self.s.cookie_window(now)
            {
                if self.establish_cookie(seg, now, None) {
                    return;
                }
                if seg.seq_len() > 0 {
                    // 中身か FIN を持つ ACK は RST を返さずに捨てます。最後の ACK と最初の中身を失った相手の
                    // 次の segment は cookie が通らないので、RST で切らずに、最初の中身の再送を待ちます。
                    return;
                }
            }
            self.s.reply_rst(seg);
            return;
        }
    }

    /// 待ち受けへの ACK を cookie として確かめ、通れば接続を作って accept の待ち行列に入れます。cookie が
    /// 通ったかを返します。偽なら呼び手が捨てるか RST を返します。`row` は同じ 4 つ組の握手の途中の行で、
    /// cookie が通れば外します。
    ///
    /// 相手はこの ACK で握手を終えたので、cookie が通った接続を黙って捨てません。accept の待ち行列か接続の
    /// 枠が満杯なら、cookie の値で握手の途中の行を作り、行の SYN-ACK の再送が相手の ACK を引き出した時に
    /// 接続を作ります。行も作れなければ、中身の無い ACK には RST を返し、中身か FIN を持つ ACK は相手の再送を
    /// 待って捨てます (wgstack-rs.md の「確かめ」)。
    fn establish_cookie(&mut self, seg: &wire::Segment<'_>, now: i64, row: Option<u32>) -> bool {
        let Some(r) = self.s.check_cookie(seg, now) else {
            return false;
        };
        if self.s.reserve_accept(r.listener, now) && self.open_from_row(&r, row, seg, now) {
            self.s.stats.syn_cookies_accepted += 1;
            return true;
        }
        // 同じ 4 つ組の行は相手の知らない ISN を持つので、cookie の値の行に替えます。
        if let Some(row) = row {
            self.s.remove_syn_row(row);
        }
        if self.s.defer_cookie(&r, now) {
            self.s.stats.syn_cookies_deferred += 1;
        } else if seg.seq_len() == 0 {
            self.s.stats.syn_cookies_reset += 1;
            self.s.reply_rst(seg);
        }
        // 中身か FIN を持つ ACK は捨てます。相手はそれを送り直すので、その時にもう一度 cookie を確かめます。
        true
    }

    /// 握手の途中の行 `row` を空きの接続の枠に移し、accept の待ち行列に入れ、最後の ACK が運んだ
    /// データと FIN を処理します (Go の `promote`)。
    fn promote(&mut self, row: u32, seg: &wire::Segment<'_>, now: i64) {
        let r = *self.s.syn.row(row);
        if self.open_from_row(&r, Some(row), seg, now) && r.cookie {
            self.s.stats.syn_cookies_accepted += 1;
        }
    }

    /// 握手の途中の行の値 `r` から接続を作り、作れたかを返します。accept の待ち行列の枠は呼び手が予約済み
    /// です。`row` は表の行の番号で、cookie から取り戻した値は `None` です。
    fn open_from_row(
        &mut self,
        r: &crate::tcp::syn::SynRow,
        row: Option<u32>,
        seg: &wire::Segment<'_>,
        now: i64,
    ) -> bool {
        // floor の配列を確保できなければ、accept の待ち行列が満杯の時と同じく ACK を捨てて行を残します。
        let Ok(Some(slot)) = self.conns.alloc(&mut self.s.conn_free) else {
            self.s.unreserve_accept(r.listener, now);
            return false;
        };
        let mut c = self.conn(slot);
        c.establish(r, seg, now);
        if let Some(row) = row {
            c.s.remove_syn_row(row);
        }
        let generation = c.t.generation;
        c.s.conn_idx.insert(c.t.tup, slot, generation);
        c.t.in_index = true;
        let port = r.listener;
        if let Some(l) = c.s.listeners.by_port_mut(port) {
            listen::enqueue(l, port, &mut c.s.qlinks, slot);
        }
        c.s.signal_listener(port);
        c.input_data(seg, now);
        c.after_input(now);
        true
    }

    /// 期限の来たタイマーと行の期限を、新しい `now` の時刻で 1 回ずつ処理します (Go の `advance`)。
    pub fn handle_timeout(&mut self, now: Time) {
        let now = self.clock(now);
        let mut fired = core::mem::take(&mut self.s.fired);
        fired.clear();
        self.s
            .wheel
            .advance(u64::try_from(now).unwrap_or(0), &mut fired);
        for &n in fired.iter() {
            let i = n / NUM_TIMERS32;
            let kind = (n % NUM_TIMERS32) as usize;
            let t = self.conns.tcb_mut(i);
            if t.state != State::Free && t.tdl[kind] != 0 && t.tdl[kind] <= now {
                t.tdl[kind] = 0;
                self.conn(i).on_timer(kind, now);
            }
        }
        fired.clear();
        self.s.fired = fired;
        self.s.expire_syn_rows(now);
        self.s.expire_tw_rows(now);
        self.s.sweep_frag(now);
    }

    /// 次に [`Stack::handle_timeout`] を呼ぶ時刻です。
    pub fn poll_timeout(&self) -> Option<Time> {
        let mut next: Option<i64> = None;
        let tick = self.s.wheel.next_tick();
        if tick != NO_TICK {
            next = Some(i64::try_from(tick * TICK_NS).unwrap_or(i64::MAX));
        }
        // 0 は「無し」で、行の期限と同じに扱います (Go の `nextDeadline`)。
        if let Some(d) = self.s.frag_deadline()
            && d != 0
            && next.is_none_or(|n| d < n)
        {
            next = Some(d);
        }
        for d in [self.s.syn.next_deadline(), self.s.tw.next_deadline()]
            .into_iter()
            .flatten()
        {
            let d = ns(d);
            if d != 0 && next.is_none_or(|n| d < n) {
                next = Some(d);
            }
        }
        next.map(time)
    }

    /// 次に送る IPv4 の packet を 1 つ `buf` に作り、長さを返します。`buf` は MTU 以上の長さを持ちます。組は
    /// deficit round robin で選びます (Go の `stack.poll`)。
    pub fn poll_transmit(&mut self, now: Time, buf: &mut [u8]) -> Option<usize> {
        let now = self.clock(now);
        let quantum = i64::try_from(self.s.config.mtu).unwrap_or(i64::MAX);
        // 取り出した項目が何も作らなければ次を見ます。何も作らない項目は入れ直さないので、この繰り返しは有限です。
        // 守りを重ねるため、list に入りうる項目の数を超えて何も作らなければ諦めます。Go の `len(rows)` は作成の時に
        // 確保した行の数なので、表の容量と同じ値です。
        let limit =
            self.conns.len() + self.s.syn.capacity() + self.s.tw.capacity() + shared::NUM_CLASSES;
        for _ in 0..=limit {
            let cls = self.s.out.pick(quantum)?;
            let n = match cls {
                shared::CLASS_CTL => self.s.out.ctl.pop(buf).unwrap_or(0),
                shared::CLASS_CONN => match self.s.out.conns.pop_front() {
                    Some(id) => self.conn(id).poll(buf, now),
                    None => 0,
                },
                shared::CLASS_ROW => match self.s.out.rows.pop_front() {
                    Some(id) => self.s.poll_row(id, buf, now),
                    None => 0,
                },
                shared::CLASS_UDP => self.s.poll_udp(buf),
                _ => 0,
            };
            if n == 0 {
                continue;
            }
            self.s.out.spent(cls, n);
            return Some(n);
        }
        None
    }

    /// 次の知らせを取り出します。同じ対象の同じ種類の知らせは、取り出すまで 1 つにまとまります。
    pub fn poll_event(&mut self) -> Option<Event> {
        let (target, bit) = self.s.events.pop()?;
        let n = self.conns.len();
        if (target as usize) < n {
            let t = self.conns.tcb(target);
            // 枠を返した後の知らせは、枠を最後に使った接続の handle で出します。
            let generation = if t.state == State::Free {
                t.generation.saturating_sub(1)
            } else {
                t.generation
            };
            let id = ConnId {
                slot: target,
                generation,
            };
            return Some(match bit {
                shared::EV_READ => Event::Readable(id),
                shared::EV_WRITE => Event::Writable(id),
                _ => Event::Closed(id),
            });
        }
        let t = target as usize - n;
        if t >= PORTS {
            let slot = t - PORTS;
            return Some(Event::PingReply(PingId {
                slot: u8::try_from(slot).unwrap_or(u8::MAX),
                generation: self.s.pings.generation(slot),
            }));
        }
        let port = u16::try_from(t).unwrap_or(0);
        Some(match bit {
            shared::EV_UDP_READ | shared::EV_UDP_WRITE => {
                let id = UdpId {
                    port,
                    generation: self.s.udp.eps.generation(port),
                };
                if bit == shared::EV_UDP_READ {
                    Event::UdpReadable(id)
                } else {
                    Event::UdpWritable(id)
                }
            }
            _ => Event::Acceptable(ListenerId {
                port,
                generation: self.s.listeners.generation(port),
            }),
        })
    }

    /// 1 分に 1 回までの門を通った拒否の数を 1 つ取り出します。駆動の層が英語の 1 行にしてログに出します。
    pub fn poll_log(&mut self) -> Option<LogLine> {
        if self.s.udp.take_fault_log() {
            return Some(LogLine {
                kind: LogKind::UdpFault,
                count: 1,
            });
        }
        self.s.gates.pop()
    }
}

/// 使っている接続の欄が会計と合うことを確かめます。
fn check_conn(t: &Tcb, b: &ConnBufs) -> Result<(), InvariantError> {
    if t.tail_off < t.una_off || t.tail_off - t.una_off > b.snd.cap() {
        return Err("the send ring holds more than its capacity".into());
    }
    if b.snd.holds_outside(t.una_off, t.tail_off) {
        return Err("the send ring holds a chunk outside its unacknowledged data".into());
    }
    if b.recs.len() > b.recs.capacity() {
        return Err("a record ring holds more than its capacity".into());
    }
    if b.rcv.read_off > b.rcv.nxt_off {
        return Err("the receive buffer reads past what arrived".into());
    }
    if t.snd_cap != b.snd.cap() || t.rcv_cap != b.rcv.r.cap() {
        return Err("a connection's reservation disagrees with its rings".into());
    }
    if b.boost.is_none() && t.rcv_cap != crate::buf::RECV_FLOOR {
        return Err("a connection without boost has a boost reservation".into());
    }
    Ok(())
}

/// 閉じた核から次の核へ渡す、ポートの数の行を持つ表です (wgstack-rs.md の「核の使い回し」)。
///
/// 待ち受けの表、UDP の endpoint の表、知らせの list はポートの数 (65,536) の行を持ち、小さな表の核の作成の手間の
/// 大部分を占めます。[`Stack::close_keeping`] が閉じた核から取り出して作成の時の値に戻し、
/// [`Stack::new_reusing`] が新しく作る代わりに使います。試験と fuzz の build だけにあります。
#[cfg(any(test, feature = "harness"))]
#[derive(Debug, Default)]
pub struct Spare {
    listeners: Option<PortTable<Listener>>,
    eps: Option<PortTable<crate::udp::UdpEp>>,
    events: Option<EventList>,
}

#[cfg(any(test, feature = "harness"))]
impl Spare {
    /// 表を持たない値です。[`Stack::new_reusing`] はすべての表を新しく作ります。
    pub fn new() -> Self {
        Self::default()
    }

    /// 持っている表の数です。3 なら次の核はポートの数の行を持つ表を作りません。
    pub fn kept(&self) -> usize {
        usize::from(self.listeners.is_some())
            + usize::from(self.eps.is_some())
            + usize::from(self.events.is_some())
    }

    /// 持っている表が、新しく作った表とすべての行で同じ値かを返します。試験が使い、手間は表を作るのと同じほどです。
    pub fn is_fresh(&self) -> bool {
        self.listeners.as_ref().is_none_or(PortTable::is_fresh)
            && self.eps.as_ref().is_none_or(PortTable::is_fresh)
            && self.events.as_ref().is_none_or(EventList::is_fresh)
    }
}

/// 核の表です。作成の途中で確保に失敗したら、確保した分を解放して誤りを返します。
struct Tables {
    seeds: Seeds,
    conns: ConnSlots,
    conn_free: FixedVec<u32>,
    qlinks: FixedVec<QLink>,
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
    udp: Udp,
    pings: Pings,
}

impl Tables {
    fn new(config: &Config, seed: &[u8; 64]) -> Result<Self, AllocError> {
        let n = config.limits.conns();
        Self::with_ports(
            config,
            seed,
            PortTable::new()?,
            PortTable::new()?,
            EventList::new(EventTargets::count(n))?,
        )
    }

    /// ポートの数の行を持つ表 (待ち受けの表 `listeners`、UDP の endpoint の表 `eps`、知らせの list `events`) を
    /// 使い、ほかの表を作ります。
    fn with_ports(
        config: &Config,
        seed: &[u8; 64],
        listeners: PortTable<Listener>,
        eps: PortTable<crate::udp::UdpEp>,
        events: EventList,
    ) -> Result<Self, AllocError> {
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
            conn_free: new_free_list(n)?,
            qlinks: FixedVec::try_filled(n, |_| QLink::default())?,
            conn_idx: Index::new(n, seeds.table_key, true)?,
            syn: SynTable::new(l.syn_rows, seeds.table_key)?,
            tw: TwTable::new(l.tw_rows, seeds.table_key, n)?,
            listeners,
            out_conns: Dlist::new(n)?,
            out_rows: Dlist::new(l.syn_rows + l.tw_rows)?,
            ctl: CtlRing::new(l.ctl_slots, config.mtu)?,
            events,
            wheel: Wheel::new(n * NUM_TIMERS)?,
            fired: FixedVec::try_with_capacity(n * NUM_TIMERS)?,
            chunks: ChunkPool::new()?,
            frag: frag::Table::new(frag_limits).map_err(|_| AllocError)?,
            udp: Udp::with_eps(l, eps)?,
            pings: Pings::new(config.mtu)?,
            seeds,
        })
    }
}

#[cfg(test)]
mod tests;
