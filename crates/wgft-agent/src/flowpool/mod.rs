//! フロー数の予算 (Resource Guard)。Go の `internal/resource` の `Pool` を移したもの。
//!
//! 規則は `docs/design/userspace/flow-limits.md` と `docs/design/resource/admission.md` の 7a.10 節が
//! 正本である。プロセス全体の予算 T を、ルールの登録ごとの最低分 m と予備 P と、ルール 1 本の上限 C の
//! 中の先着順の共有に分ける。判定は 1 つの排他の中で行い、ルールごと、理由ごとの拒否の数を、この
//! `Pool` を作ってからの累計として持つ。agent は中継をトンネルごとに作り直すので、数もそのたびに 0 に
//! 戻る。
//!
//! 記号は設計に合わせる。登録 g はルール ID が受け付けている待ち受けを持ち続ける 1 期間で、A は受け付けて
//! いる登録の集合、N はその大きさである。a_g は g に数えるフローの数 (受け付けたときの登録に数え、退役
//! した登録のフローの帰属の規則でだけ移る)、c_g は g に今属する受け付けている待ち受けが運ぶフローの数、
//! x_g = max(a_g, c_g) である。u はプロセス全体のフロー数、m = max(f, q)、
//! q = floor(floor((T - f) / 2) / (N - 1)) (N ≥ 2)、S = Σ max(0, m - a_g)、S_f = Σ max(0, f - a_g)
//! (和は A)、P = f である。
//!
//! I/O を持たない型で、TUN の試作の中継と wgstack の上の中継が同じものを使う。登録、待ち受け、cell は
//! 添字で引く表に置き、ポインタを辿らない。フロー 1 本の枠は [`Lease`] で、落とすと返る。Go の
//! `Release` の二重の呼び出しは型で起こらないので、その数は持たない。

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

#[cfg(test)]
mod tests;

/// 登録ごとの下限 f。予備 P も同じ値である。
pub const FLOW_FLOOR: usize = 4;

/// プロセス全体の UDP の上限の既定。
pub const UDP_TOTAL: usize = 8192;
/// プロセス全体の TCP の上限の既定。
pub const TCP_TOTAL: usize = 2048;
/// プロセス全体の上限に設定できる範囲の下限。
pub const TOTAL_MIN: usize = 16;
/// プロセス全体の上限に設定できる範囲の上限。
pub const TOTAL_MAX: usize = 65535;

/// プロセス全体のフロー数の上限 (`WGFT_MAX_UDP_FLOWS` と `WGFT_MAX_TCP_FLOWS`)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// UDP のセッションの上限。
    pub udp: usize,
    /// TCP の接続の上限。
    pub tcp: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            udp: UDP_TOTAL,
            tcp: TCP_TOTAL,
        }
    }
}

/// 拒否の理由。理由の語は Go と同じで、`agent doctor` の `refusals` の鍵になる。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reason {
    /// プロセス全体の予算が埋まっている (u < T を満たさない)。
    Budget,
    /// ルール 1 本の上限 C に達している (ルールが 2 本以上あるときだけ効く)。c_g で判定する。
    RuleCap,
    /// x_g が自分の最低分に届いていて、残りの空きが満たされていない最低分で埋まっている (u + 1 + S > T)。
    Reserve,
    /// x_g が自分の最低分に届いていない予約の部分の取得が、他の登録の満たされていない下限と予備を残せない。
    Floor,
    /// x_g が自分の最低分に届いていて、満たされていない最低分を残しても空きはあるが、予備を残すと空きが無い。
    Spare,
}

impl Reason {
    /// すべての理由。表の添字の順である。
    pub const ALL: [Reason; 5] = [
        Reason::Budget,
        Reason::RuleCap,
        Reason::Reserve,
        Reason::Floor,
        Reason::Spare,
    ];

    /// Go と同じ理由の語。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::Budget => "budget",
            Reason::RuleCap => "rule_cap",
            Reason::Reserve => "reserve",
            Reason::Floor => "floor",
            Reason::Spare => "spare",
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 拒んだ 1 回の判定の内訳。中継はこれをログの文にする。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Refusal {
    /// 理由。
    pub reason: Option<Reason>,
    /// ルールの ID。
    pub rule_id: String,
    /// u。
    pub in_use: usize,
    /// T。
    pub total: usize,
    /// 判定に使ったそのルールの数。`rule_cap` では c_g、`floor`、`spare`、`reserve` では x_g。
    pub rule_flows: usize,
    /// C。
    pub rule_cap: usize,
    /// m。
    pub minimum: usize,
    /// P。
    pub spare: usize,
    /// S。
    pub unfilled: usize,
    /// S の項が正の登録の数。
    pub unfilled_rules: usize,
    /// S の項が正の登録に自分が入るか。
    pub unfilled_self: bool,
    /// S_f。
    pub floor_short: usize,
    /// S_f の項が正の登録の数 (`floor` では自分は入らない)。
    pub floor_short_rules: usize,
    /// 受け付けている他のルールの数。
    pub other_rules: usize,
}

impl fmt::Display for Refusal {
    /// 理由を説明する 1 文。Go の `Refusal.String` と同じ文である。中継は待ち受けの名前と処置を前後に
    /// 付けてログに出す。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let free = self.total.saturating_sub(self.in_use);
        let Refusal {
            rule_id: id,
            rule_flows: n,
            total,
            minimum,
            unfilled,
            spare,
            ..
        } = self;
        match self.reason {
            Some(Reason::Budget) => write!(
                f,
                "flow budget full: {} of {total} in use in this process",
                self.in_use
            ),
            Some(Reason::RuleCap) => write!(
                f,
                "rule {id} holds {n} flows and the rest of the budget is reserved for {}",
                other_rules(self.other_rules)
            ),
            Some(Reason::Reserve) => write!(
                f,
                "rule {id} holds {n} flows, at or above its minimum of {minimum}, and the free part of the budget, {free} of {total}, is held for the unfilled minimums of {}, {unfilled} flows",
                self.unfilled_owners()
            ),
            Some(Reason::Spare) if *unfilled == 0 => write!(
                f,
                "rule {id} holds {n} flows and the free part of the budget, {free} of {total}, is kept spare for a rule added later"
            ),
            Some(Reason::Spare) => write!(
                f,
                "rule {id} holds {n} flows, at or above its minimum of {minimum}, and the free part of the budget, {free} of {total}, is held for the unfilled minimums of {}, {unfilled} flows, and {spare} spare flows for a rule added later",
                self.unfilled_owners()
            ),
            Some(Reason::Floor) if self.floor_short == 0 => write!(
                f,
                "rule {id} holds {n} flows, below its minimum of {minimum}, and the free part of the budget, {free} of {total}, is kept spare for a rule added later"
            ),
            Some(Reason::Floor) => write!(
                f,
                "rule {id} holds {n} flows, below its minimum of {minimum}, and the free part of the budget, {free} of {total}, is held for the first flows of {} and {spare} spare flows for a rule added later",
                other_rules(self.floor_short_rules)
            ),
            None => f.write_str("refused by the flow budget"),
        }
    }
}

impl Refusal {
    /// 満たされていない最低分を持つ登録の言い方。自分の不足が S に入るのは、予約の部分の入口が閉じて
    /// 共有分に回った登録だけである。
    fn unfilled_owners(&self) -> String {
        if !self.unfilled_self {
            return other_rules(self.unfilled_rules);
        }
        if self.unfilled_rules <= 1 {
            return "this rule".to_owned();
        }
        format!("this rule and {}", other_rules(self.unfilled_rules - 1))
    }
}

/// "1 other rule" か "3 other rules"。
fn other_rules(n: usize) -> String {
    if n == 1 {
        "1 other rule".to_owned()
    } else {
        format!("{n} other rules")
    }
}

/// [`Listener::take`] が枠を渡さなかったこと。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Denied {
    /// 受け付けていない待ち受け (保留、受け付けの停止、閉鎖済み)。予算の拒否ではないので、拒否の数にも
    /// ログにも入れない。
    NotAccepting,
    /// 予算が拒んだ。理由ごとの数に 1 を足してある。
    Refused(Refusal),
}

/// ルールごとの拒否の数。添字は [`Reason::ALL`] の順。
pub type RefusalCounts = [u64; 5];

/// 帳簿の読み出し。試験が帳簿を照合し、`agent doctor` が予算を示すのに使う。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    /// u。
    pub in_use: usize,
    /// T。
    pub total: usize,
    /// C。
    pub rule_cap: usize,
    /// m。
    pub minimum: usize,
    /// N。
    pub rules: usize,
    /// S。
    pub unfilled: usize,
    /// S_f。
    pub floor_short: usize,
    /// 請求の合計 E = u + S + P。
    pub claim: usize,
    /// ルールの今の登録の a_g。
    pub reg_flows: BTreeMap<String, usize>,
    /// ルールの今の登録の c_g。
    pub reg_carried: BTreeMap<String, usize>,
    /// 退役した登録に残るフロー。
    pub retired_flows: usize,
    /// まだフローを持つ退役した登録の数。
    pub retired_regs: usize,
    /// 退役した登録にあり、受け付けている待ち受けが運ぶフロー (0 のはず)。
    pub orphans: usize,
    /// 受け付けていない待ち受けへの取得の数。
    pub not_accepting: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct RegId(u32);
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CellId(u32);
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct LisId(u32);

/// 添字で引く表。空いた枠を使い回す。
#[derive(Debug)]
struct Slab<T> {
    items: Vec<Option<T>>,
    free: Vec<u32>,
}

impl<T> Default for Slab<T> {
    fn default() -> Self {
        Slab {
            items: Vec::new(),
            free: Vec::new(),
        }
    }
}

impl<T> Slab<T> {
    fn insert(&mut self, v: T) -> u32 {
        if let Some(i) = self.free.pop() {
            self.items[i as usize] = Some(v);
            return i;
        }
        let i = u32::try_from(self.items.len()).expect("fewer than 2^32 entries");
        self.items.push(Some(v));
        i
    }

    fn remove(&mut self, i: u32) {
        if self.items[i as usize].take().is_some() {
            self.free.push(i);
        }
    }

    fn get(&self, i: u32) -> &T {
        self.items[i as usize].as_ref().expect("live slab entry")
    }

    fn get_mut(&mut self, i: u32) -> &mut T {
        self.items[i as usize].as_mut().expect("live slab entry")
    }

    fn contains(&self, i: u32) -> bool {
        self.items.get(i as usize).is_some_and(Option::is_some)
    }

    #[cfg(test)]
    fn iter(&self) -> impl Iterator<Item = (u32, &T)> {
        self.items
            .iter()
            .enumerate()
            .filter_map(|(i, v)| Some((u32::try_from(i).ok()?, v.as_ref()?)))
    }
}

/// ルールの登録。ルール ID が受け付けている待ち受けを 1 つ以上持ち続ける期間で、受け付けている待ち受けが
/// 0 個になった時点で退役し、以後 A に戻らない。
#[derive(Debug)]
struct Registration {
    rule: String,
    /// 受け付けている待ち受けの数。
    members: usize,
    retired: bool,
    /// a_g。
    count: usize,
    /// c_g。
    carried: usize,
    cells: Vec<CellId>,
}

/// 待ち受けと登録の組ごとのフローの数。[`Lease`] は cell を指す。待ち受けが運ぶフローは、取得の後は
/// 変わらずその待ち受けが運ぶ。帰属の規則で移るのは cell の登録だけである。
#[derive(Debug)]
struct Cell {
    lis: LisId,
    reg: RegId,
    n: usize,
}

#[derive(Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the flags mirror the Go pool's listener states one to one"
)]
struct ListenerState {
    rule: String,
    accepting: bool,
    open: bool,
    /// 登録に加わっているか (open かつ accepting)。
    counted: bool,
    /// handle が生きているか。handle が落ち、フローが 0 になったら表から消す。
    handle: bool,
    flows: usize,
    reg: Option<RegId>,
    cells: Vec<CellId>,
    cur: Option<CellId>,
}

#[derive(Debug, Default)]
struct Inner {
    /// T。0 なら予算の判定を行わない。
    total: usize,
    /// C。
    rule_cap: usize,
    /// u。
    in_use: usize,
    /// A。ルール ID から今の登録への表。
    regs: BTreeMap<String, RegId>,
    /// 退役した登録のうち、まだ数えるフローを持つもの。
    retired: BTreeSet<RegId>,
    /// m。N が変わるたびに求め直す。
    minimum: usize,
    unfilled: usize,
    floor_short: usize,
    unfilled_regs: usize,
    floor_short_regs: usize,
    refusals: BTreeMap<String, RefusalCounts>,
    not_accepting: u64,
    reg: Slab<Registration>,
    cell: Slab<Cell>,
    lis: Slab<ListenerState>,
}

/// 1 つのプロトコルのフロー予算。複製は同じ予算を指す。
#[derive(Clone, Debug)]
pub struct Pool {
    inner: Arc<Mutex<Inner>>,
}

/// C = ceil(T/2)。
fn rule_cap_for(total: usize) -> usize {
    total.div_ceil(2)
}

/// 登録ごとの最低分 m = max(f, q)。q は予備を除いた T - f から求める。
fn minimum_for(total: usize, rules: usize) -> usize {
    if rules < 2 {
        return FLOW_FLOOR;
    }
    FLOW_FLOOR.max(total.saturating_sub(FLOW_FLOOR) / 2 / (rules - 1))
}

impl Pool {
    /// 予算 `total` の pool を作る。ルール 1 本の上限と最低分は `total` から導く。0 なら予算の判定を
    /// 行わない。
    #[must_use]
    pub fn new(total: usize) -> Pool {
        let inner = Inner {
            total,
            rule_cap: rule_cap_for(total),
            minimum: minimum_for(total, 0),
            ..Inner::default()
        };
        Pool {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // 排他の中で panic しても、帳簿は 1 つの操作の途中で止まるだけで、読み続けるほうが止めるより安全
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// 予算 T。
    #[must_use]
    pub fn total(&self) -> usize {
        self.lock().total
    }

    /// ルールが 2 本以上あるときのルール 1 本の上限 C。
    #[must_use]
    pub fn rule_cap(&self) -> usize {
        self.lock().rule_cap
    }

    /// 今受け付けているルールの数 N。
    #[must_use]
    pub fn rules(&self) -> usize {
        self.lock().regs.len()
    }

    /// 登録ごとの最低分 m。
    #[must_use]
    pub fn reserve(&self) -> usize {
        self.lock().minimum
    }

    /// 今保持しているフローの数 u。受け付けをやめた待ち受けと、閉じた待ち受けの残りのフローも含む。
    #[must_use]
    pub fn in_use(&self) -> usize {
        self.lock().in_use
    }

    /// そのルールの登録の待ち受けが運ぶフローの数 c_g。
    #[must_use]
    pub fn rule_flows(&self, rule: &str) -> usize {
        let g = self.lock();
        g.regs.get(rule).map_or(0, |r| g.reg.get(r.0).carried)
    }

    /// ルール ID から理由ごとの拒否の数への表の複製。
    #[must_use]
    pub fn refusals(&self) -> BTreeMap<String, RefusalCounts> {
        self.lock().refusals.clone()
    }

    /// 待ち受け 1 つ分の枠を登録する。登録した時点で新しいフローを受け付けている。
    #[must_use]
    pub fn listener(&self, rule: &str) -> Listener {
        self.make_listener(rule, true)
    }

    /// まだ新しいフローを受け付けない待ち受けの枠を登録する。bind の後に [`Listener::accept`] を呼ぶ。
    /// A は開けた待ち受けを持つルールの集合なので、bind の最中と失敗した待ち受けのルールを N に数えない。
    #[must_use]
    pub fn pending_listener(&self, rule: &str) -> Listener {
        self.make_listener(rule, false)
    }

    fn make_listener(&self, rule: &str, accepting: bool) -> Listener {
        let mut g = self.lock();
        let id = LisId(g.lis.insert(ListenerState {
            rule: rule.to_owned(),
            accepting,
            open: true,
            counted: false,
            handle: true,
            flows: 0,
            reg: None,
            cells: Vec::new(),
            cur: None,
        }));
        g.attach(id);
        Listener {
            pool: self.clone(),
            id,
        }
    }

    /// 帳簿の複製。
    #[must_use]
    pub fn ledger(&self) -> Ledger {
        let g = self.lock();
        let mut lg = Ledger {
            in_use: g.in_use,
            total: g.total,
            rule_cap: g.rule_cap,
            minimum: g.minimum,
            rules: g.regs.len(),
            unfilled: g.unfilled,
            floor_short: g.floor_short,
            claim: g.in_use + g.unfilled + FLOW_FLOOR,
            retired_regs: g.retired.len(),
            not_accepting: g.not_accepting,
            ..Ledger::default()
        };
        for (rule, r) in &g.regs {
            let r = g.reg.get(r.0);
            lg.reg_flows.insert(rule.clone(), r.count);
            lg.reg_carried.insert(rule.clone(), r.carried);
        }
        for r in &g.retired {
            let r = g.reg.get(r.0);
            lg.retired_flows += r.count;
            for c in &r.cells {
                let c = g.cell.get(c.0);
                if g.lis.get(c.lis.0).counted {
                    lg.orphans += c.n;
                }
            }
        }
        lg
    }
}

impl Inner {
    fn reg(&self, id: RegId) -> &Registration {
        self.reg.get(id.0)
    }

    fn reg_mut(&mut self, id: RegId) -> &mut Registration {
        self.reg.get_mut(id.0)
    }

    fn lis(&self, id: LisId) -> &ListenerState {
        self.lis.get(id.0)
    }

    fn lis_mut(&mut self, id: LisId) -> &mut ListenerState {
        self.lis.get_mut(id.0)
    }

    /// 受け付けている登録 g の取得の判定。通すなら `None` を返す。2 つ目の値は拒否の文が示すそのルールの
    /// フローの数 (`rule_cap` では c_g、`floor`、`spare`、`reserve` では x_g)。
    #[expect(
        clippy::many_single_char_names,
        reason = "the names are the design's symbols u, T, g and x"
    )]
    fn judge(&self, g: RegId) -> Option<(Reason, usize)> {
        let (u, t) = (self.in_use, self.total);
        if u >= t {
            return Some((Reason::Budget, 0));
        }
        let r = self.reg(g);
        if self.regs.len() >= 2 && r.carried >= self.rule_cap {
            return Some((Reason::RuleCap, r.carried));
        }
        if r.count < FLOW_FLOOR {
            return None;
        }
        let x = r.count.max(r.carried);
        if x < self.minimum {
            if u + 1 + self.floor_short + FLOW_FLOOR <= t {
                return None;
            }
            return Some((Reason::Floor, x));
        }
        if u + 1 + self.unfilled + FLOW_FLOOR <= t {
            return None;
        }
        if u + 1 + self.unfilled > t {
            return Some((Reason::Reserve, x));
        }
        Some((Reason::Spare, x))
    }

    fn take(&mut self, l: LisId) -> Result<CellId, Denied> {
        let Some(g) = self.lis(l).reg.filter(|_| self.lis(l).counted) else {
            self.not_accepting += 1;
            return Err(Denied::NotAccepting);
        };
        if self.total > 0
            && let Some((reason, flows)) = self.judge(g)
        {
            return Err(Denied::Refused(self.refuse(reason, l, flows)));
        }
        self.in_use += 1;
        self.lis_mut(l).flows += 1;
        self.reg_mut(g).carried += 1;
        let c = self.cell_for(l, g);
        self.cell.get_mut(c.0).n += 1;
        self.add_count(g, 1);
        Ok(c)
    }

    fn refuse(&mut self, reason: Reason, l: LisId, flows: usize) -> Refusal {
        let rule = self.lis(l).rule.clone();
        self.refusals.entry(rule.clone()).or_default()[reason.index()] += 1;
        let own = self.lis(l).reg.map_or(0, |g| self.reg(g).count);
        Refusal {
            reason: Some(reason),
            rule_id: rule,
            in_use: self.in_use,
            total: self.total,
            rule_flows: flows,
            rule_cap: self.rule_cap,
            minimum: self.minimum,
            spare: FLOW_FLOOR,
            unfilled: self.unfilled,
            unfilled_rules: self.unfilled_regs,
            unfilled_self: own < self.minimum,
            floor_short: self.floor_short,
            floor_short_rules: self.floor_short_regs,
            other_rules: self.regs.len().saturating_sub(1),
        }
    }

    fn release(&mut self, c: CellId) {
        self.in_use -= 1;
        let (l, g) = {
            let cell = self.cell.get(c.0);
            (cell.lis, cell.reg)
        };
        let lis = self.lis_mut(l);
        lis.flows -= 1;
        if let Some(cur) = lis.reg.filter(|_| lis.counted) {
            self.reg_mut(cur).carried -= 1;
        }
        let cell = self.cell.get_mut(c.0);
        cell.n -= 1;
        if cell.n == 0 {
            remove_id(&mut self.reg_mut(g).cells, &c);
            let lis = self.lis_mut(l);
            remove_id(&mut lis.cells, &c);
            if lis.cur == Some(c) {
                lis.cur = None;
            }
            self.cell.remove(c.0);
        }
        self.add_count(g, -1);
        self.maybe_free_listener(l);
    }

    /// 待ち受けの今の登録の cell。無ければ作る。
    fn cell_for(&mut self, l: LisId, g: RegId) -> CellId {
        if let Some(c) = self.lis(l).cur
            && self.cell.get(c.0).reg == g
        {
            return c;
        }
        let c = CellId(self.cell.insert(Cell {
            lis: l,
            reg: g,
            n: 0,
        }));
        let lis = self.lis_mut(l);
        lis.cells.push(c);
        lis.cur = Some(c);
        self.reg_mut(g).cells.push(c);
        c
    }

    /// 今の N から m を求め、S と S_f を A の全登録について作り直す。N が変わったときだけ呼ぶ。
    fn refresh(&mut self) {
        self.minimum = minimum_for(self.total, self.regs.len());
        self.unfilled = 0;
        self.floor_short = 0;
        self.unfilled_regs = 0;
        self.floor_short_regs = 0;
        let ids: Vec<RegId> = self.regs.values().copied().collect();
        for g in ids {
            self.terms(g, true);
        }
    }

    /// 受け付けている登録 g の S と S_f の項を足すか引く。退役した登録は項を持たない。
    fn terms(&mut self, g: RegId, add: bool) {
        let r = self.reg(g);
        if r.retired {
            return;
        }
        let count = r.count;
        let apply = |v: &mut usize, d: usize| {
            if add {
                *v += d;
            } else {
                *v -= d;
            }
        };
        if let Some(d) = self.minimum.checked_sub(count).filter(|d| *d > 0) {
            apply(&mut self.unfilled, d);
            apply(&mut self.unfilled_regs, 1);
        }
        if let Some(d) = FLOW_FLOOR.checked_sub(count).filter(|d| *d > 0) {
            apply(&mut self.floor_short, d);
            apply(&mut self.floor_short_regs, 1);
        }
    }

    /// a_g を delta だけ動かし、S と S_f を合わせる。退役した登録の数が 0 になれば表から消す。
    fn add_count(&mut self, g: RegId, delta: isize) {
        self.terms(g, false);
        let r = self.reg_mut(g);
        r.count = r
            .count
            .checked_add_signed(delta)
            .expect("a_g stays non-negative");
        self.terms(g, true);
        self.maybe_free_reg(g);
    }

    fn maybe_free_reg(&mut self, g: RegId) {
        if !self.reg.contains(g.0) {
            return;
        }
        let r = self.reg(g);
        if r.retired && r.count == 0 {
            debug_assert!(r.cells.is_empty() && r.members == 0);
            self.retired.remove(&g);
            self.reg.remove(g.0);
        }
    }

    fn maybe_free_listener(&mut self, l: LisId) {
        let lis = self.lis(l);
        if !lis.handle && lis.flows == 0 {
            debug_assert!(lis.cells.is_empty() && !lis.counted);
            self.lis.remove(l.0);
        }
    }

    /// cell の登録を移す (退役した登録のフローの帰属の規則)。u と c_g は変わらない。
    fn move_cell(&mut self, c: CellId, to: RegId) {
        let (from, n) = {
            let cell = self.cell.get(c.0);
            (cell.reg, cell.n)
        };
        remove_id(&mut self.reg_mut(from).cells, &c);
        let n = isize::try_from(n).expect("flow count fits isize");
        self.add_count(from, -n);
        self.cell.get_mut(c.0).reg = to;
        self.reg_mut(to).cells.push(c);
        self.add_count(to, n);
    }

    /// 開いていて受け付けている待ち受けを今のルールの登録に加える (登録、受け付けの開始と再開、付け替えの
    /// 後)。登録が無ければ新しい登録を作り、N が変わるので S を作り直す。加わった後、この待ち受けが運ぶ
    /// フローのうち退役した登録にあるものを、加わった登録へ移す (加入の発火)。
    fn attach(&mut self, l: LisId) {
        let lis = self.lis(l);
        if lis.counted || !lis.open || !lis.accepting {
            return;
        }
        let rule = lis.rule.clone();
        let g = if let Some(g) = self.regs.get(&rule) {
            *g
        } else {
            let g = RegId(self.reg.insert(Registration {
                rule: rule.clone(),
                members: 0,
                retired: false,
                count: 0,
                carried: 0,
                cells: Vec::new(),
            }));
            self.regs.insert(rule, g);
            self.refresh();
            g
        };
        let flows = self.lis(l).flows;
        let r = self.reg_mut(g);
        r.members += 1;
        r.carried += flows;
        let lis = self.lis_mut(l);
        lis.reg = Some(g);
        lis.counted = true;
        let cells = lis.cells.clone();
        for c in cells {
            if self.reg(self.cell.get(c.0).reg).retired {
                self.move_cell(c, g);
            }
        }
    }

    /// 待ち受けを登録から外す (閉鎖、受け付けの停止、付け替えの前)。登録の受け付けている待ち受けが 0 個に
    /// なれば、登録は退役し、N が変わるので S を作り直す。退役した登録のフローのうち、受け付けている
    /// 待ち受けが運ぶものを、その待ち受けの今の登録へ移す (退役の発火)。
    fn detach(&mut self, l: LisId) {
        let lis = self.lis_mut(l);
        if !lis.counted {
            return;
        }
        let g = lis
            .reg
            .take()
            .expect("a counted listener has a registration");
        lis.counted = false;
        let flows = lis.flows;
        let r = self.reg_mut(g);
        r.members -= 1;
        r.carried -= flows;
        if r.members > 0 {
            return;
        }
        r.retired = true;
        let (rule, count) = (r.rule.clone(), r.count);
        self.regs.remove(&rule);
        self.refresh();
        if count > 0 {
            self.retired.insert(g);
        }
        let cells = self.reg(g).cells.clone();
        for c in cells {
            let owner = self.lis(self.cell.get(c.0).lis);
            if owner.counted
                && let Some(to) = owner.reg
            {
                self.move_cell(c, to);
            }
        }
        self.maybe_free_reg(g);
    }
}

fn remove_id<T: PartialEq>(v: &mut Vec<T>, x: &T) {
    if let Some(i) = v.iter().position(|y| y == x) {
        v.swap_remove(i);
    }
}

/// pool に登録した待ち受け 1 つ。フローの枠はこの型を通して取る。落とすと閉じる。
#[derive(Debug)]
pub struct Listener {
    pool: Pool,
    id: LisId,
}

impl Listener {
    /// フロー 1 つ分の枠を取る。
    ///
    /// 判定の順は、受け付けていない、予算 (u < T)、ルール 1 本の上限 (N ≥ 2 なら c_g < C)、下限の部分
    /// (a_g < f なら通す)、予約の部分 (x_g < m なら u + 1 + S_f + P ≤ T で通し、満たさなければ `floor`)、
    /// 共有分 (u + 1 + S + P ≤ T で通し、満たさなければ u + 1 + S > T なら `reserve`、そうでなければ
    /// `spare`) である。T が 0 の pool は受け付けていない待ち受けだけを拒む。
    ///
    /// # Errors
    ///
    /// 枠を渡さなかった理由を返す。
    pub fn take(&self) -> Result<Lease, Denied> {
        let cell = self.pool.lock().take(self.id)?;
        Ok(Lease {
            pool: self.pool.clone(),
            cell,
        })
    }

    /// 所属ルールを付け替える (分割と統合)。既存のフローは受け付けたときの登録に数えたままで、この
    /// 待ち受けが運ぶ数 c_g だけが付け替え先の登録へ移る。
    pub fn set_rule(&self, rule: &str) {
        let mut g = self.pool.lock();
        if g.lis(self.id).rule == rule {
            return;
        }
        g.detach(self.id);
        rule.clone_into(&mut g.lis_mut(self.id).rule);
        g.attach(self.id);
    }

    /// 新しいフローを受け付けない状態にする。残っているフローは u と登録の数に残る。
    pub fn stop_accepting(&self) {
        let mut g = self.pool.lock();
        g.lis_mut(self.id).accepting = false;
        g.detach(self.id);
    }

    /// 保留の待ち受けの受け付けを始めるか、止めた受け付けを再開する。
    pub fn accept(&self) {
        let mut g = self.pool.lock();
        g.lis_mut(self.id).accepting = true;
        g.attach(self.id);
    }

    /// 待ち受けを pool から外す。まだ返していないフローは、[`Lease`] を落とすまで u と登録の数に残る。
    pub fn close(&self) {
        let mut g = self.pool.lock();
        let lis = g.lis_mut(self.id);
        if !lis.open {
            return;
        }
        lis.open = false;
        g.detach(self.id);
    }

    /// この待ち受けが保持しているフローの数。
    #[must_use]
    pub fn flows(&self) -> usize {
        self.pool.lock().lis(self.id).flows
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let mut g = self.pool.lock();
        let lis = g.lis_mut(self.id);
        lis.handle = false;
        if lis.open {
            lis.open = false;
            g.detach(self.id);
        }
        g.maybe_free_listener(self.id);
    }
}

/// フロー 1 つ分の枠。落とすと返る。
#[derive(Debug)]
pub struct Lease {
    pool: Pool,
    cell: CellId,
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.pool.lock().release(self.cell);
    }
}

#[cfg(test)]
impl Pool {
    /// 足し引きで保った帳簿を、登録と cell の値から作り直した値と照合する。
    fn check_ledger(&self) -> Result<(), String> {
        let g = self.lock();
        if g.total > 0 && g.in_use > g.total {
            return Err(format!("u {} > T {}", g.in_use, g.total));
        }
        let mut all = Vec::new();
        for (rule, id) in &g.regs {
            let r = g.reg(*id);
            if r.retired || &r.rule != rule || r.members == 0 {
                return Err(format!(
                    "registration {} in A: retired {}, members {}",
                    r.rule, r.retired, r.members
                ));
            }
            all.push(*id);
        }
        for id in &g.retired {
            let r = g.reg(*id);
            if !r.retired || r.count == 0 || r.members != 0 {
                return Err(format!(
                    "retired registration {}: retired {}, count {}, members {}",
                    r.rule, r.retired, r.count, r.members
                ));
            }
            all.push(*id);
        }
        // 表に残る登録は A か退役の一覧のどちらかにある
        if g.reg.iter().count() != all.len() {
            return Err(format!(
                "{} registrations in the table, {} in A or retired",
                g.reg.iter().count(),
                all.len()
            ));
        }
        let mut sum = 0;
        let mut carried: BTreeMap<RegId, usize> = BTreeMap::new();
        let mut flows: BTreeMap<LisId, usize> = BTreeMap::new();
        for id in &all {
            let r = g.reg(*id);
            let mut cs = 0;
            for c in &r.cells {
                let cell = g.cell.get(c.0);
                if cell.reg != *id || cell.n == 0 {
                    return Err(format!("cell of {} points elsewhere or is empty", r.rule));
                }
                let lis = g.lis(cell.lis);
                if !lis.cells.contains(c) {
                    return Err(format!("cell of {} is missing from its listener", r.rule));
                }
                cs += cell.n;
                *flows.entry(cell.lis).or_default() += cell.n;
                if lis.counted {
                    if r.retired {
                        return Err(format!(
                            "retired registration {} holds {} flows carried by an accepting listener",
                            r.rule, cell.n
                        ));
                    }
                    *carried
                        .entry(lis.reg.expect("counted listener has a registration"))
                        .or_default() += cell.n;
                }
            }
            if cs != r.count {
                return Err(format!(
                    "registration {}: cells {cs}, a_g {}",
                    r.rule, r.count
                ));
            }
            sum += r.count;
        }
        if sum != g.in_use {
            return Err(format!("registrations hold {sum}, u = {}", g.in_use));
        }
        for (id, lis) in g.lis.iter() {
            let n = flows.get(&LisId(id)).copied().unwrap_or(0);
            if lis.flows != n {
                return Err(format!(
                    "listener {}: cells {n}, flows {}",
                    lis.rule, lis.flows
                ));
            }
            if !lis.handle && lis.flows == 0 {
                return Err(format!("listener {} lingers without a handle", lis.rule));
            }
        }
        let m = minimum_for(g.total, g.regs.len());
        let (mut s, mut sf, mut ks, mut kf) = (0, 0, 0, 0);
        for id in g.regs.values() {
            let r = g.reg(*id);
            if carried.get(id).copied().unwrap_or(0) != r.carried {
                return Err(format!(
                    "registration {}: c_g {}, rebuilt {}",
                    r.rule,
                    r.carried,
                    carried.get(id).copied().unwrap_or(0)
                ));
            }
            if m > r.count {
                s += m - r.count;
                ks += 1;
            }
            if FLOW_FLOOR > r.count {
                sf += FLOW_FLOOR - r.count;
                kf += 1;
            }
        }
        if (m, s, sf, ks, kf)
            != (
                g.minimum,
                g.unfilled,
                g.floor_short,
                g.unfilled_regs,
                g.floor_short_regs,
            )
        {
            return Err(format!(
                "kept m {} S {} Sf {} kS {} kf {}, rebuilt m {m} S {s} Sf {sf} kS {ks} kf {kf}",
                g.minimum, g.unfilled, g.floor_short, g.unfilled_regs, g.floor_short_regs
            ));
        }
        Ok(())
    }

    /// 表に残っている待ち受けの数。handle を落とし、フローを返した待ち受けは残らない。
    fn listener_slots(&self) -> usize {
        self.lock().lis.iter().count()
    }
}
