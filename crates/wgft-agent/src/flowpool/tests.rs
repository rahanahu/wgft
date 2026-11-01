//! Go の `internal/resource` の pool の試験を移したもの。
//!
//! 参照の pool (`RefPool`) は判定と帳簿を、足し引きを使わず毎回その場で数え直して書いたもの。設計の
//! 7a.10 節の判定の順と帰属の規則をそのまま書き下してある。製品の pool と同じ操作列を流し、判定と帳簿が
//! 毎手一致することを確かめる。

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefState {
    Pending,
    Accepting,
    Retiring,
    Closed,
}

#[derive(Debug)]
struct RefListener {
    rule: String,
    st: RefState,
    reg: Option<usize>,
    flows: usize,
}

#[derive(Debug, Default)]
struct RefReg {
    members: usize,
    live: usize,
    carried: usize,
}

#[derive(Debug)]
struct RefLease {
    l: usize,
    reg: usize,
    live: bool,
}

#[derive(Debug)]
enum RefOutcome {
    Granted(usize),
    Refused(Reason, usize),
    NotAccepting,
}

#[derive(Debug)]
struct RefPool {
    t: usize,
    c: usize,
    u: usize,
    ls: Vec<RefListener>,
    regs: Vec<RefReg>,
    cur: BTreeMap<String, usize>,
    leases: Vec<RefLease>,
}

const F: usize = FLOW_FLOOR;

impl RefPool {
    fn new(t: usize) -> Self {
        RefPool {
            t,
            c: t.div_ceil(2),
            u: 0,
            ls: Vec::new(),
            regs: Vec::new(),
            cur: BTreeMap::new(),
            leases: Vec::new(),
        }
    }

    fn n(&self) -> usize {
        self.cur.len()
    }

    fn min(&self) -> usize {
        let n = self.n();
        if n < 2 {
            return F;
        }
        F.max((self.t - F) / 2 / (n - 1))
    }

    fn s(&self) -> usize {
        let m = self.min();
        self.cur
            .values()
            .map(|g| m.saturating_sub(self.regs[*g].live))
            .sum()
    }

    fn sf(&self) -> usize {
        self.cur
            .values()
            .map(|g| F.saturating_sub(self.regs[*g].live))
            .sum()
    }

    fn join(&mut self, l: usize) {
        self.ls[l].st = RefState::Accepting;
        let rule = self.ls[l].rule.clone();
        let g = *self.cur.entry(rule).or_insert_with(|| {
            self.regs.push(RefReg::default());
            self.regs.len() - 1
        });
        self.regs[g].members += 1;
        self.regs[g].carried += self.ls[l].flows;
        self.ls[l].reg = Some(g);
        // 加入の発火
        for le in &mut self.leases {
            if le.live && le.l == l && le.reg != g && self.regs[le.reg].members == 0 {
                self.regs[le.reg].live -= 1;
                self.regs[g].live += 1;
                le.reg = g;
            }
        }
    }

    fn leave(&mut self, l: usize, st: RefState) {
        if self.ls[l].st != RefState::Accepting {
            self.ls[l].st = st;
            return;
        }
        let g = self.ls[l].reg.take().unwrap();
        self.regs[g].members -= 1;
        self.regs[g].carried -= self.ls[l].flows;
        self.ls[l].st = st;
        if self.regs[g].members == 0 {
            let rule = self.ls[l].rule.clone();
            self.cur.remove(&rule);
            // 退役の発火
            for le in &mut self.leases {
                if le.live && le.reg == g && self.ls[le.l].st == RefState::Accepting {
                    let to = self.ls[le.l].reg.unwrap();
                    self.regs[g].live -= 1;
                    self.regs[to].live += 1;
                    le.reg = to;
                }
            }
        }
    }

    fn new_listener(&mut self, rule: &str, accepting: bool) -> usize {
        self.ls.push(RefListener {
            rule: rule.into(),
            st: RefState::Pending,
            reg: None,
            flows: 0,
        });
        let id = self.ls.len() - 1;
        if accepting {
            self.join(id);
        }
        id
    }

    fn accept(&mut self, l: usize) {
        if matches!(self.ls[l].st, RefState::Pending | RefState::Retiring) {
            self.join(l);
        }
    }

    fn stop(&mut self, l: usize) {
        if self.ls[l].st != RefState::Closed {
            self.leave(l, RefState::Retiring);
        }
    }

    fn close(&mut self, l: usize) {
        if self.ls[l].st != RefState::Closed {
            self.leave(l, RefState::Closed);
        }
    }

    fn set_rule(&mut self, l: usize, rule: &str) {
        if self.ls[l].rule == rule {
            return;
        }
        if self.ls[l].st == RefState::Accepting {
            self.leave(l, RefState::Retiring);
            rule.clone_into(&mut self.ls[l].rule);
            self.join(l);
            return;
        }
        rule.clone_into(&mut self.ls[l].rule);
    }

    /// 7a.10 節の判定の順。
    #[expect(
        clippy::many_single_char_names,
        reason = "the names are the design's symbols"
    )]
    fn decide(&self, l: usize) -> RefOutcome {
        let lis = &self.ls[l];
        if lis.st != RefState::Accepting {
            return RefOutcome::NotAccepting;
        }
        let g = lis.reg.unwrap();
        if self.u >= self.t {
            return RefOutcome::Refused(Reason::Budget, 0);
        }
        let (a, c, m) = (self.regs[g].live, self.regs[g].carried, self.min());
        if self.n() >= 2 && c >= self.c {
            return RefOutcome::Refused(Reason::RuleCap, c);
        }
        if a < F {
            return RefOutcome::Granted(g);
        }
        let x = a.max(c);
        if x < m {
            if self.u + 1 + self.sf() + F <= self.t {
                return RefOutcome::Granted(g);
            }
            return RefOutcome::Refused(Reason::Floor, x);
        }
        let s = self.s();
        if self.u + 1 + s + F <= self.t {
            return RefOutcome::Granted(g);
        }
        if self.u + 1 + s > self.t {
            return RefOutcome::Refused(Reason::Reserve, x);
        }
        RefOutcome::Refused(Reason::Spare, x)
    }

    fn take(&mut self, l: usize) -> RefOutcome {
        let o = self.decide(l);
        let RefOutcome::Granted(g) = o else { return o };
        self.leases.push(RefLease {
            l,
            reg: g,
            live: true,
        });
        self.u += 1;
        self.ls[l].flows += 1;
        self.regs[g].carried += 1;
        self.regs[g].live += 1;
        RefOutcome::Granted(self.leases.len() - 1)
    }

    fn release(&mut self, id: usize) {
        let le = &mut self.leases[id];
        if !le.live {
            return;
        }
        le.live = false;
        let (l, reg) = (le.l, le.reg);
        self.u -= 1;
        self.ls[l].flows -= 1;
        if self.ls[l].st == RefState::Accepting {
            let cur = self.ls[l].reg.unwrap();
            self.regs[cur].carried -= 1;
        }
        self.regs[reg].live -= 1;
    }

    /// 退役した登録に残る lease の数と、そのうち受け付けている待ち受けが運ぶもの。
    fn retired_live(&self) -> (usize, usize) {
        let (mut retired, mut orphans) = (0, 0);
        for le in self.leases.iter().filter(|le| le.live) {
            if self.regs[le.reg].members == 0 {
                retired += 1;
                if self.ls[le.l].st == RefState::Accepting {
                    orphans += 1;
                }
            }
        }
        (retired, orphans)
    }
}

/// 製品の pool と参照の pool に同じ操作を当てる。
struct Twin {
    p: Pool,
    r: RefPool,
    ls: Vec<Listener>,
    leases: Vec<Option<Lease>>,
}

impl Twin {
    fn new(t: usize) -> Self {
        Twin {
            p: Pool::new(t),
            r: RefPool::new(t),
            ls: Vec::new(),
            leases: Vec::new(),
        }
    }

    fn listener(&mut self, rule: &str, accepting: bool) -> usize {
        self.ls.push(if accepting {
            self.p.listener(rule)
        } else {
            self.p.pending_listener(rule)
        });
        let id = self.r.new_listener(rule, accepting);
        self.check("listener");
        id
    }

    fn accept(&mut self, l: usize) {
        self.ls[l].accept();
        self.r.accept(l);
        self.check("accept");
    }

    fn stop(&mut self, l: usize) {
        self.ls[l].stop_accepting();
        self.r.stop(l);
        self.check("stop");
    }

    fn close(&mut self, l: usize) {
        self.ls[l].close();
        self.r.close(l);
        self.check("close");
    }

    fn set_rule(&mut self, l: usize, rule: &str) {
        self.ls[l].set_rule(rule);
        self.r.set_rule(l, rule);
        self.check("setrule");
    }

    /// 1 回の取得。製品と参照の結果が違えば失敗にする。
    fn take(&mut self, l: usize) -> Result<(), Option<Reason>> {
        let got = self.ls[l].take();
        let want = self.r.take(l);
        let state = self.state();
        let out = match (got, want) {
            (Ok(lease), RefOutcome::Granted(id)) => {
                if self.leases.len() <= id {
                    self.leases.resize_with(id + 1, || None);
                }
                self.leases[id] = Some(lease);
                Ok(())
            }
            (Err(Denied::NotAccepting), RefOutcome::NotAccepting) => Err(None),
            (Err(Denied::Refused(r)), RefOutcome::Refused(reason, n))
                if r.reason == Some(reason) && r.rule_flows == n =>
            {
                if !matches!(reason, Reason::Budget | Reason::RuleCap) {
                    // 拒否の文は判定に使った x_g を示す
                    assert!(
                        r.to_string().contains(&format!("holds {n} flows")),
                        "refusal text {r} does not show x_g {n}"
                    );
                }
                Err(Some(reason))
            }
            (got, want) => panic!(
                "take l{l} ({}): product {got:?}, formula {want:?}; {state}",
                self.r.ls[l].rule
            ),
        };
        self.check("take");
        out
    }

    fn take_n(&mut self, l: usize, n: usize) -> (usize, Option<Reason>) {
        for i in 0..n {
            if let Err(r) = self.take(l) {
                return (i, r);
            }
        }
        (n, None)
    }

    fn release(&mut self, id: usize) {
        drop(self.leases[id].take());
        self.r.release(id);
        self.check("release");
    }

    fn live_leases(&self) -> Vec<usize> {
        self.r
            .leases
            .iter()
            .enumerate()
            .filter(|(_, le)| le.live)
            .map(|(i, _)| i)
            .collect()
    }

    fn state(&self) -> String {
        let lg = self.p.ledger();
        format!(
            "u={} N={} m={} S={} Sf={} E={} a={:?} c={:?} retired={}",
            lg.in_use,
            lg.rules,
            lg.minimum,
            lg.unfilled,
            lg.floor_short,
            lg.claim,
            lg.reg_flows,
            lg.reg_carried,
            lg.retired_flows
        )
    }

    /// 各操作の後の不変条件。製品の帳簿を登録と cell から作り直した値と照合し、参照の pool の値と
    /// 一致させる。
    fn check(&self, op: &str) {
        if let Err(e) = self.p.check_ledger() {
            panic!("after {op}: {e}");
        }
        let lg = self.p.ledger();
        let r = &self.r;
        let (ret, orph) = r.retired_live();
        assert!(
            lg.in_use == r.u
                && lg.rules == r.n()
                && lg.minimum == r.min()
                && lg.unfilled == r.s()
                && lg.floor_short == r.sf()
                && lg.retired_flows == ret
                && lg.orphans == 0
                && orph == 0,
            "after {op}: product {} orphans {}; formula u={} N={} m={} S={} Sf={} retired={ret} orphans {orph}",
            self.state(),
            lg.orphans,
            r.u,
            r.n(),
            r.min(),
            r.s(),
            r.sf()
        );
        for (rule, g) in &r.cur {
            assert_eq!(
                (lg.reg_flows[rule], lg.reg_carried[rule]),
                (r.regs[*g].live, r.regs[*g].carried),
                "after {op}: rule {rule}"
            );
        }
        // c_g は登録の待ち受けの flows の和
        let mut sum: BTreeMap<&str, usize> = BTreeMap::new();
        for (i, l) in r.ls.iter().enumerate() {
            if l.st == RefState::Accepting {
                *sum.entry(&l.rule).or_default() += l.flows;
                assert_eq!(self.ls[i].flows(), l.flows, "after {op}: listener {i}");
            }
        }
        for (rule, n) in sum {
            assert_eq!(lg.reg_carried[rule], n, "after {op}: rule {rule} c_g");
        }
    }
}

// ---- 場面 (7a.10 節の例) ----

/// 例 1:ルールが 2 本で 1 本がフラッド。A は 1022 で spare、B は 1022 まで。
#[test]
fn two_rules_one_flooded() {
    let mut w = Twin::new(2048);
    let a = w.listener("a", true);
    let b = w.listener("b", true);
    assert_eq!(w.take_n(a, 5000), (1022, Some(Reason::Spare)));
    assert_eq!(w.take_n(b, 5000), (1022, Some(Reason::Spare)));
}

/// 例 2:3 本のうち 2 本がフラッド。A 1022、B 511、D は 511 まで。
#[test]
fn three_rules_two_flooded() {
    let mut w = Twin::new(2048);
    let a = w.listener("a", true);
    assert_eq!(w.take_n(a, 5000), (2044, Some(Reason::Spare)));
    for id in w.live_leases().split_off(1022) {
        w.release(id);
    }
    let b = w.listener("b", true);
    let d = w.listener("d", true);
    assert_eq!(w.take_n(b, 5000), (511, Some(Reason::Spare)));
    assert_eq!(w.take_n(d, 5000), (511, Some(Reason::Spare)));
}

/// 例 3:1 本が持ち切った後に新しいルール。B は予備の 4 枠を取り、その後 budget。A が 10 本を閉じると
/// B は予約の部分で 6 本を取った後 floor。
#[test]
fn new_rule_after_a_full_rule() {
    let mut w = Twin::new(2048);
    let a = w.listener("a", true);
    w.take_n(a, 5000);
    let b = w.listener("b", true);
    assert_eq!(w.take(a), Err(Some(Reason::RuleCap)));
    assert_eq!(w.take_n(b, 100), (4, Some(Reason::Budget)));
    for id in w.live_leases().into_iter().take(10) {
        w.release(id);
    }
    assert_eq!(w.take_n(b, 100), (6, Some(Reason::Floor)));
}

/// 例 4 (T=16):削除したルールの旧い 8 本が残り、A が 4 本を持ち、B が加わる。A の 5 本目は floor、
/// B は 4 本を取った後 budget。
#[test]
fn small_budget() {
    let mut w = Twin::new(16);
    let old = w.listener("old", true);
    assert_eq!(w.take_n(old, 8).0, 8);
    let a = w.listener("a", true);
    assert_eq!(w.take_n(a, 4).0, 4);
    w.close(old);
    let b = w.listener("b", true);
    assert_eq!(w.take(a), Err(Some(Reason::Floor)));
    assert_eq!(w.take_n(b, 100), (4, Some(Reason::Budget)));
}

/// 例 5 (統合):A、B、X で X 256 本、B 1022 本。B を A へ統合すると B の 1022 本は A の登録へ移り、
/// 統合したポートへのフラッドは spare、X は 1022 本まで。
#[test]
fn merge_moves_flows() {
    let mut w = Twin::new(2048);
    let _a = w.listener("a", true);
    let b = w.listener("b", true);
    let x = w.listener("x", true);
    w.take_n(x, 256);
    assert_eq!(w.take_n(b, 5000).0, 1022);
    w.set_rule(b, "a");
    let lg = w.p.ledger();
    assert_eq!(
        (lg.reg_flows["a"], lg.reg_carried["a"], lg.retired_flows),
        (1022, 1022, 0)
    );
    assert_eq!(w.take(b), Err(Some(Reason::Spare)));
    assert_eq!(w.take_n(x, 5000), (1022 - 256, Some(Reason::Spare)));
}

/// 例 6 (UDP の再開):A の受け付けの停止で A の登録が退役し、再開で旧い 1022 本が新しい登録へ移る。
#[test]
fn resume_moves_flows() {
    let mut w = Twin::new(2048);
    let a = w.listener("a", true);
    let b = w.listener("b", true);
    w.take_n(a, 5000);
    w.take_n(b, 5000);
    w.stop(a);
    assert_eq!(w.p.ledger().retired_flows, 1022);
    w.accept(a);
    let lg = w.p.ledger();
    assert_eq!(
        (lg.retired_flows, lg.reg_flows["a"], lg.claim),
        (0, 1022, 2048)
    );
    assert_eq!(w.take(a), Err(Some(Reason::Spare)));
}

/// 例 7、8、11 の形:B がポート b1 と b2 を持ち、無関係の X がいる。b2 へのフラッドで B は 1022 本
/// (N=2)。b2 を D へ分割する。
fn split_rig() -> (Twin, usize, usize, usize) {
    let mut w = Twin::new(2048);
    let b1 = w.listener("b", true);
    let b2 = w.listener("b", true);
    assert_eq!(w.take_n(b2, 5000), (2044, Some(Reason::Spare)));
    let x = w.listener("x", true);
    for id in w.live_leases().split_off(1022) {
        w.release(id);
    }
    w.set_rule(b2, "d");
    (w, b1, b2, x)
}

/// 例 7 (分割の直後の分割元の削除):b2 が運ぶ 1022 本は D へ移り、X は 1022 本まで。
#[test]
fn split_then_delete_head() {
    let (mut w, b1, _b2, x) = split_rig();
    w.close(b1);
    let lg = w.p.ledger();
    assert_eq!(
        (lg.reg_flows["d"], lg.reg_carried["d"], lg.retired_flows),
        (1022, 1022, 0)
    );
    assert_eq!(w.take_n(x, 5000), (1022, Some(Reason::Spare)));
}

/// 例 8 と例 13:分割元が続く間のフラッド。D は a_D=0、c_D=1022 で下限の部分で 2 本を取ると
/// c_D=1024=C で rule_cap。X は 511 本まで。B を削除すると 1022 本が D へ移り、X は 1020 本まで。
#[test]
fn split_flood_while_head_lives() {
    let (mut w, b1, b2, x) = split_rig();
    assert_eq!(w.take_n(b2, 5000), (2, Some(Reason::RuleCap)));
    let Err(Denied::Refused(r)) = w.ls[b2].take() else {
        panic!("not refused")
    };
    assert_eq!(r.rule_flows, 1024);
    assert!(r.to_string().contains("rule d holds 1024 flows"), "{r}");
    // 参照の側も同じ拒否を数える
    let _ = w.r.take(b2);
    assert_eq!(w.take_n(x, 5000), (511, Some(Reason::Spare)));
    let live = w.live_leases();
    for &id in &live[live.len() - 511..] {
        w.release(id);
    }
    w.close(b1);
    assert_eq!(w.take_n(x, 5000), (1020, Some(Reason::Floor)));
}

/// 例 11 と回避の手順:分割元に残ったポート b1 は 0 本で spare。B を別の ID に名前を変えると、B の
/// 登録が退役して b2 の旧い接続が D へ移り、新しい ID の b1 は最低分を得る。
#[test]
fn split_remainder_and_rename() {
    let (mut w, b1, b2, x) = split_rig();
    assert_eq!(w.take(b1), Err(Some(Reason::Spare)));
    w.take_n(b2, 5000);
    assert_eq!(w.take(b1), Err(Some(Reason::Spare)));
    // 名前の変更:1 回の適用の中で、分割元の最後の待ち受けを閉じて同じポートを新しい ID で開く
    w.close(b1);
    let b1n = w.listener("b2name", true);
    let lg = w.p.ledger();
    assert_eq!((lg.reg_flows["d"], lg.retired_flows), (1024, 0));
    let (nb, _) = w.take_n(b1n, 5000);
    let (nx, _) = w.take_n(x, 5000);
    assert!(nb >= 500 && nx >= 500, "new b1 {nb}, x {nx}");
}

/// 1 本だけにフラッドを掛け、他のルールは空きのとき、フラッドを受けたルールが止まる数と理由。
#[test]
fn steady_stop_table() {
    let cases = [
        (2048, 1, 2044, Reason::Spare),
        (2048, 2, 1022, Reason::Spare),
        (2048, 3, 1022, Reason::Spare),
        (2048, 4, 1024, Reason::RuleCap),
        (2048, 8, 1022, Reason::Spare),
        (2048, 15, 1022, Reason::Spare),
        (1024, 1, 1020, Reason::Spare),
        (1024, 2, 510, Reason::Spare),
        (1024, 4, 510, Reason::Spare),
        (1024, 5, 512, Reason::RuleCap),
        (1024, 11, 510, Reason::Spare),
    ];
    for (t, n, want, reason) in cases {
        let mut w = Twin::new(t);
        let f = w.listener("r0", true);
        for i in 1..n {
            w.listener(&format!("r{i}"), true);
        }
        assert_eq!(w.take_n(f, 2 * t), (want, Some(reason)), "T={t} N={n}");
    }
}

/// 例 9 と例 10 (T=1024):各理由が実際に出る。
#[test]
fn reasons_under_claim_excess() {
    let mut w = Twin::new(1024);
    let a = w.listener("a", true);
    assert_eq!(w.take_n(a, 5000), (1020, Some(Reason::Spare)));
    let b = w.listener("b", true);
    assert_eq!(w.take(a), Err(Some(Reason::RuleCap)));
    assert_eq!(w.take_n(b, 100), (4, Some(Reason::Budget)));
    for id in w.live_leases().into_iter().take(10) {
        w.release(id);
    }
    assert_eq!(w.take_n(b, 100), (6, Some(Reason::Floor)));

    let mut v = Twin::new(1024);
    let va = v.listener("a", true);
    let vb = v.listener("b", true);
    v.take_n(va, 5000);
    v.take_n(vb, 5000);
    let vx = v.listener("x", true);
    assert_eq!(v.take(va), Err(Some(Reason::Reserve)));
    assert_eq!(v.take_n(vx, 100), (4, Some(Reason::Budget)));
}

/// T が 0 の pool:受け付けていない待ち受けは拒み、予算の判定は行わない。帳簿は同じに保つ。
#[test]
fn no_budget() {
    let p = Pool::new(0);
    let l = p.listener("a");
    let held: Vec<Lease> = (0..100).map(|_| l.take().unwrap()).collect();
    l.stop_accepting();
    assert_eq!(l.take().unwrap_err(), Denied::NotAccepting);
    p.check_ledger().unwrap();
    drop(held);
    assert_eq!(p.in_use(), 0);
}

/// 拒否の文 (7a.10 節の例)。Go の `TestFloorRefusalMessages` の期待値をそのまま写したもの。
#[test]
fn refusal_messages() {
    let r = |reason, f: fn(&mut Refusal)| {
        let mut r = Refusal {
            reason: Some(reason),
            rule_id: "r1".into(),
            ..Refusal::default()
        };
        f(&mut r);
        r
    };
    let cases = [
        (
            r(Reason::Spare, |r| {
                (
                    r.in_use,
                    r.total,
                    r.rule_flows,
                    r.minimum,
                    r.spare,
                    r.unfilled,
                    r.unfilled_rules,
                ) = (6141, 8192, 4094, 2047, 4, 2047, 1);
            }),
            "rule r1 holds 4094 flows, at or above its minimum of 2047, and the free part of the budget, 2051 of 8192, is held for the unfilled minimums of 1 other rule, 2047 flows, and 4 spare flows for a rule added later",
        ),
        (
            r(Reason::Spare, |r| {
                (r.in_use, r.total, r.rule_flows, r.minimum, r.spare) = (8188, 8192, 8188, 4, 4);
            }),
            "rule r1 holds 8188 flows and the free part of the budget, 4 of 8192, is kept spare for a rule added later",
        ),
        (
            r(Reason::Floor, |r| {
                (
                    r.in_use,
                    r.total,
                    r.rule_flows,
                    r.minimum,
                    r.spare,
                    r.floor_short,
                    r.floor_short_rules,
                ) = (8184, 8192, 300, 4094, 4, 4, 1);
            }),
            "rule r1 holds 300 flows, below its minimum of 4094, and the free part of the budget, 8 of 8192, is held for the first flows of 1 other rule and 4 spare flows for a rule added later",
        ),
        (
            r(Reason::Floor, |r| {
                (r.in_use, r.total, r.rule_flows, r.minimum, r.spare) = (2044, 2048, 10, 1022, 4);
            }),
            "rule r1 holds 10 flows, below its minimum of 1022, and the free part of the budget, 4 of 2048, is kept spare for a rule added later",
        ),
        (
            r(Reason::Reserve, |r| {
                (
                    r.in_use,
                    r.total,
                    r.rule_flows,
                    r.minimum,
                    r.unfilled,
                    r.unfilled_rules,
                    r.unfilled_self,
                ) = (1800, 2048, 600, 511, 300, 2, true);
            }),
            "rule r1 holds 600 flows, at or above its minimum of 511, and the free part of the budget, 248 of 2048, is held for the unfilled minimums of this rule and 1 other rule, 300 flows",
        ),
        (
            r(Reason::RuleCap, |r| {
                (r.rule_flows, r.other_rules) = (4096, 1);
            }),
            "rule r1 holds 4096 flows and the rest of the budget is reserved for 1 other rule",
        ),
        (
            r(Reason::Budget, |r| {
                r.rule_id = String::new();
                (r.in_use, r.total) = (8192, 8192);
            }),
            "flow budget full: 8192 of 8192 in use in this process",
        ),
    ];
    for (r, want) in cases {
        let got = r.to_string();
        assert_eq!(got, want, "{:?}", r.reason);
        assert!(!got.contains(['(', ')']), "parentheses in {got}");
    }
    // 理由の語と、他のルールの数の言い方
    assert_eq!(
        Reason::ALL.map(Reason::as_str),
        ["budget", "rule_cap", "reserve", "floor", "spare"]
    );
    let many = r(Reason::RuleCap, |r| r.other_rules = 3);
    assert!(many.to_string().ends_with("reserved for 3 other rules"));
    let own = r(Reason::Reserve, |r| {
        (r.unfilled_rules, r.unfilled_self) = (1, true);
    });
    assert!(own.to_string().contains("unfilled minimums of this rule,"));
}

#[test]
fn refusals_are_counted_per_rule_and_reason() {
    let p = Pool::new(16);
    let a = p.listener("a");
    let _held: Vec<Lease> = (0..12).map(|_| a.take().unwrap()).collect();
    for _ in 0..3 {
        assert!(matches!(a.take(), Err(Denied::Refused(_))));
    }
    a.stop_accepting();
    assert_eq!(a.take().unwrap_err(), Denied::NotAccepting);
    let r = p.refusals();
    assert_eq!(r.len(), 1);
    assert_eq!(r["a"][Reason::Spare as usize], 3);
    assert_eq!(p.ledger().not_accepting, 1);
}

// ---- 無作為の列 ----

/// 小さな擬似乱数 (xorshift64*)。試験の再現のために種から決まる。
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).unwrap()
    }
}

/// 無作為の操作列を製品と参照に当て、毎手の判定と帳簿を照合する。あわせて 7a.10 節の保証のうち、
/// 帳簿の外から見えるものを確かめる。
#[expect(
    clippy::many_single_char_names,
    reason = "the names follow the Go test"
)]
fn random_run(t: usize, seed: u64, steps: usize) {
    let mut rng = Rng::new(seed);
    let rules = &["a", "b", "c", "d", "e", "f"][..2 + usize::try_from(seed % 5).unwrap()];
    let mut w = Twin::new(t);
    let first = 1 + rng.below(3);
    for _ in 0..first {
        let rule = rules[rng.below(rules.len())];
        w.listener(rule, true);
    }
    let burst = (t / 8).max(1);
    for s in 0..steps {
        let lg = w.p.ledger();
        let reserve_held = t - lg.in_use >= lg.floor_short + FLOW_FLOOR;
        let mut creates_reg = false;
        match rng.below(100) {
            k if k < 6 => {
                let rule = rules[rng.below(rules.len())];
                let exists = w.r.cur.contains_key(rule);
                let acc = rng.below(5) != 0;
                creates_reg = acc && !exists;
                w.listener(rule, acc);
            }
            k if k < 12 => {
                let l = rng.below(w.ls.len());
                let exists = w.r.cur.contains_key(&w.r.ls[l].rule);
                let st = w.r.ls[l].st;
                creates_reg = !exists && matches!(st, RefState::Pending | RefState::Retiring);
                w.accept(l);
            }
            k if k < 17 => {
                let l = rng.below(w.ls.len());
                w.stop(l);
            }
            k if k < 21 => {
                let l = rng.below(w.ls.len());
                w.close(l);
            }
            k if k < 30 => {
                let l = rng.below(w.ls.len());
                let rule = rules[rng.below(rules.len())];
                let exists = w.r.cur.contains_key(rule);
                creates_reg = w.r.ls[l].st == RefState::Accepting && !exists;
                w.set_rule(l, rule);
            }
            k if k < 70 => {
                let l = rng.below(w.ls.len());
                let n = 1 + rng.below(burst);
                for _ in 0..n {
                    let before = w.p.ledger();
                    let o = w.take(l);
                    if let Err(Some(r)) = o
                        && matches!(r, Reason::Budget | Reason::Reserve | Reason::Floor)
                    {
                        assert!(
                            before.claim > t,
                            "seed {seed}: {r} while E={} <= T",
                            before.claim
                        );
                    }
                    if o.is_ok() {
                        let after = w.p.ledger();
                        let rule = &w.r.ls[l].rule;
                        assert!(
                            after.rules < 2 || after.reg_carried[rule] <= w.p.rule_cap(),
                            "seed {seed}: c_g above C after a take"
                        );
                        assert!(
                            after.claim <= t || after.claim <= before.claim,
                            "seed {seed}: take raised E above T: {} -> {}",
                            before.claim,
                            after.claim
                        );
                    } else {
                        break;
                    }
                }
            }
            _ => {
                let mut live = w.live_leases();
                let n = 1 + rng.below(burst);
                for _ in 0..n {
                    if live.is_empty() {
                        break;
                    }
                    let j = rng.below(live.len());
                    let id = live.swap_remove(j);
                    w.release(id);
                }
            }
        }
        let after = w.p.ledger();
        assert!(
            !reserve_held || creates_reg || t - after.in_use >= after.floor_short + FLOW_FLOOR,
            "seed {seed} step {s}: T-u >= Sf+P broken without a new registration: {}",
            w.state()
        );
    }
    for id in w.live_leases() {
        w.release(id);
    }
    let lg = w.p.ledger();
    assert_eq!((lg.in_use, lg.retired_flows), (0, 0), "seed {seed}");
    // handle を落とすと表から待ち受けが消える
    let p = w.p.clone();
    drop(w);
    assert_eq!(p.listener_slots(), 0, "seed {seed}");
    p.check_ledger().unwrap();
}

#[test]
fn matches_the_formula_on_random_runs() {
    let seeds: u64 = if cfg!(miri) { 2 } else { 300 };
    for t in [16, 64, 2048] {
        let n = if t == 2048 { seeds / 10 } else { seeds };
        for seed in 1..=n {
            random_run(t, seed, 300);
        }
    }
}

// ---- 並行 ----

/// 取得と返却と設定の変更を並行に流し、最後に帳簿が整合し u が 0 に戻ることを確かめる。
#[test]
fn concurrent_takes_releases_and_changes() {
    let p = Pool::new(64);
    let rules = ["a", "b", "c", "d"];
    let ls: Vec<Arc<Listener>> = (0..6).map(|i| Arc::new(p.listener(rules[i % 3]))).collect();
    let stop = Arc::new(AtomicBool::new(false));
    let workers: Vec<_> = ls
        .iter()
        .enumerate()
        .map(|(i, l)| {
            let l = Arc::clone(l);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut rng = Rng::new(i as u64 + 1);
                let mut held = Vec::new();
                while !stop.load(Ordering::Relaxed) {
                    if rng.below(2) == 0 {
                        if let Ok(x) = l.take() {
                            held.push(x);
                        }
                    } else if !held.is_empty() {
                        let j = rng.below(held.len());
                        held.swap_remove(j);
                    }
                }
            })
        })
        .collect();
    let mut rng = Rng::new(99);
    for _ in 0..3000 {
        let l = &ls[rng.below(ls.len())];
        match rng.below(4) {
            0 => l.set_rule(rules[rng.below(4)]),
            1 => l.stop_accepting(),
            2 => l.accept(),
            _ => p.check_ledger().unwrap(),
        }
    }
    stop.store(true, Ordering::Relaxed);
    for w in workers {
        w.join().unwrap();
    }
    p.check_ledger().unwrap();
    assert_eq!(p.in_use(), 0);
    drop(ls);
    assert_eq!(p.listener_slots(), 0);
}

/// 閉じた待ち受けの残りのフローは、返すまで数え続け、返した後に表から消える。
#[test]
fn a_closed_listener_keeps_its_flows_until_they_are_released() {
    let p = Pool::new(16);
    let l = p.listener("a");
    let x = l.take().unwrap();
    drop(l);
    assert_eq!(p.in_use(), 1);
    assert_eq!(p.rules(), 0);
    assert_eq!(p.listener_slots(), 1);
    p.check_ledger().unwrap();
    drop(x);
    assert_eq!(p.in_use(), 0);
    assert_eq!(p.listener_slots(), 0);
    p.check_ledger().unwrap();
}

// ---- 式の性質 ----

/// TOTAL_MIN から TOTAL_MAX までのすべての T で、C = ceil(T/2)、f ≤ C、3f ≤ T が成り立ち、q ≥ f と
/// なるすべての N で N × m + P ≤ T が成り立つ。
#[test]
fn formula_across_budgets() {
    for t in TOTAL_MIN..=TOTAL_MAX {
        let c = rule_cap_for(t);
        assert!(
            c == t.div_ceil(2) && FLOW_FLOOR <= c && 3 * FLOW_FLOOR <= t,
            "T={t}"
        );
        for n in 2.. {
            let q = (t - FLOW_FLOOR) / 2 / (n - 1);
            if q < FLOW_FLOOR {
                break;
            }
            let m = minimum_for(t, n);
            assert!(m == q && n * m + FLOW_FLOOR <= t, "T={t} N={n}");
        }
    }
}

/// 1 本のルールに受け付けを続けたとき (他のルールはフローを持たない) の最大は、N = 1 で T - P、
/// N ≥ 2 で min(C, max(m, T - P - (N - 1) × m))。
#[test]
fn single_flood_maximum() {
    let mut cases = Vec::new();
    for t in TOTAL_MIN..=200 {
        for n in 1..=20 {
            cases.push((t, n));
        }
    }
    for t in [1024, 1500, 2048, 4097, 8192] {
        for n in [1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 74, 147, 257, 300] {
            cases.push((t, n));
        }
    }
    for (t, n) in cases {
        let p = Pool::new(t);
        let l = p.listener("r0");
        let _others: Vec<Listener> = (1..n).map(|i| p.listener(&format!("r{i}"))).collect();
        let mut held = Vec::new();
        while let Ok(x) = l.take() {
            held.push(x);
        }
        let want = if n >= 2 {
            let m = minimum_for(t, n);
            rule_cap_for(t).min(m.max((t - FLOW_FLOOR).saturating_sub((n - 1) * m)))
        } else {
            t - FLOW_FLOOR
        };
        assert_eq!(held.len(), want, "T={t} N={n}");
    }
}

/// `agent doctor` の読みは、0 でない拒否だけを、ルール ID と理由の語の順 (Go の `doctorBudget`) に並べる。
/// 語の順 (budget、floor、reserve、rule_cap、spare) は表の添字の順と違うので、並べ替えを外すか添字の順で
/// 並べると、`r_b` の並びが変わる。
#[test]
fn reading_orders_refusals_by_rule_and_reason_word() {
    let pool = Pool::new(16);
    {
        let mut g = pool.lock();
        // 添字は Reason::ALL の順 (budget、rule_cap、reserve、floor、spare)
        g.refusals.insert("r_b".into(), [1, 2, 3, 4, 5]);
        g.refusals.insert("r_a".into(), [0, 7, 0, 0, 6]);
        g.refusals.insert("r_c".into(), [0; 5]);
    }
    let r = pool.reading();
    let got: Vec<(&str, &str, u64)> = r
        .refusals
        .iter()
        .map(|(rule, reason, n)| (rule.as_str(), reason.as_str(), *n))
        .collect();
    assert_eq!(
        got,
        [
            ("r_a", "rule_cap", 7),
            ("r_a", "spare", 6),
            ("r_b", "budget", 1),
            ("r_b", "floor", 4),
            ("r_b", "reserve", 3),
            ("r_b", "rule_cap", 2),
            ("r_b", "spare", 5),
        ]
    );
}

/// 待ち受けごとのフローの数は、1 回の排他でも待ち受けごとの読みと同じ値になる。
#[test]
fn flows_of_matches_each_listener() {
    let pool = Pool::new(64);
    let a = pool.listener("r_a");
    let b = pool.listener("r_b");
    let _held: Vec<Lease> = (0..3)
        .map(|_| a.take().unwrap())
        .chain(std::iter::once(b.take().unwrap()))
        .collect();
    assert_eq!(pool.flows_of([&a, &b, &a]), [3, 1, 3]);
    assert_eq!(pool.flows_of([&b]), [b.flows()]);
}
