package resource

import (
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"
)

// ---- 式から作り直す参照の Pool ----
//
// refPool は判定と帳簿を、足し引きを使わず毎回その場で数え直して書いたもの。設計文書 7a.10 節の判定の
// 順と帰属の規則をそのまま書き下してある。製品の Pool と同じ操作列を流し、判定と帳簿が毎手一致する
// ことを確かめる。

type refState int

const (
	refPending refState = iota
	refAccepting
	refRetiring
	refClosed
)

type refListener struct {
	rule  string
	st    refState
	reg   int
	flows int
}

type refReg struct {
	rule    string
	members int
	live    int // a_g
	carried int // c_g
}

type refLease struct {
	l, reg int
	live   bool
}

type refPool struct {
	T, F, C int
	u       int
	ls      []refListener
	regs    []refReg
	cur     map[string]int
	leases  []refLease
}

func newRefPool(T int) *refPool {
	return &refPool{T: T, F: FlowFloor, C: (T + 1) / 2, cur: map[string]int{}}
}

func (p *refPool) N() int { return len(p.cur) }

func (p *refPool) min() int {
	N := p.N()
	if N < 2 {
		return p.F
	}
	return max(p.F, (p.T-p.F)/2/(N-1))
}

func (p *refPool) S() int {
	m, s := p.min(), 0
	for _, g := range p.cur {
		s += max(0, m-p.regs[g].live)
	}
	return s
}

func (p *refPool) Sf() int {
	s := 0
	for _, g := range p.cur {
		s += max(0, p.F-p.regs[g].live)
	}
	return s
}

func (p *refPool) E() int { return p.u + p.S() + p.F }

func (p *refPool) join(l int) {
	L := &p.ls[l]
	L.st = refAccepting
	g, ok := p.cur[L.rule]
	if !ok {
		p.regs = append(p.regs, refReg{rule: L.rule})
		g = len(p.regs) - 1
		p.cur[L.rule] = g
	}
	p.regs[g].members++
	p.regs[g].carried += L.flows
	L.reg = g
	// 加入の発火
	for i := range p.leases {
		le := &p.leases[i]
		if le.live && le.l == l && le.reg != g && p.regs[le.reg].members == 0 {
			p.regs[le.reg].live--
			p.regs[g].live++
			le.reg = g
		}
	}
}

func (p *refPool) leave(l int, st refState) {
	L := &p.ls[l]
	if L.st != refAccepting {
		L.st = st
		return
	}
	g := L.reg
	p.regs[g].members--
	p.regs[g].carried -= L.flows
	L.reg = -1
	L.st = st
	if p.regs[g].members == 0 {
		delete(p.cur, L.rule)
		// 退役の発火
		for i := range p.leases {
			le := &p.leases[i]
			if le.live && le.reg == g && p.ls[le.l].st == refAccepting {
				p.regs[g].live--
				p.regs[p.ls[le.l].reg].live++
				le.reg = p.ls[le.l].reg
			}
		}
	}
}

func (p *refPool) newListener(rule string, accepting bool) int {
	p.ls = append(p.ls, refListener{rule: rule, st: refPending, reg: -1})
	id := len(p.ls) - 1
	if accepting {
		p.join(id)
	}
	return id
}

func (p *refPool) accept(l int) {
	if st := p.ls[l].st; st == refPending || st == refRetiring {
		p.join(l)
	}
}

func (p *refPool) stop(l int) {
	if p.ls[l].st != refClosed {
		p.leave(l, refRetiring)
	}
}

func (p *refPool) close(l int) {
	if p.ls[l].st != refClosed {
		p.leave(l, refClosed)
	}
}

func (p *refPool) setRule(l int, rule string) {
	L := &p.ls[l]
	if L.rule == rule {
		return
	}
	if L.st == refAccepting {
		p.leave(l, refRetiring)
		p.ls[l].rule = rule
		p.join(l)
		return
	}
	L.rule = rule
}

// decide は設計文書 7a.10 節の判定の順。
func (p *refPool) decide(l int) (int, Outcome, Reason, int) {
	L := p.ls[l]
	if L.st != refAccepting {
		return -1, NotAccepting, "", 0
	}
	g := L.reg
	if p.u >= p.T {
		return -1, Refused, ReasonBudget, 0
	}
	a, c, m := p.regs[g].live, p.regs[g].carried, p.min()
	if p.N() >= 2 && c >= p.C {
		return -1, Refused, ReasonRuleCap, c
	}
	if a < p.F {
		return g, Granted, "", 0
	}
	x := max(a, c)
	if x < m {
		if p.u+1+p.Sf()+p.F <= p.T {
			return g, Granted, "", 0
		}
		return -1, Refused, ReasonFloor, x
	}
	S := p.S()
	if p.u+1+S+p.F <= p.T {
		return g, Granted, "", 0
	}
	if p.u+1+S > p.T {
		return -1, Refused, ReasonReserve, x
	}
	return -1, Refused, ReasonSpare, x
}

func (p *refPool) take(l int) (int, Outcome, Reason, int) {
	g, o, r, n := p.decide(l)
	if o != Granted {
		return -1, o, r, n
	}
	p.leases = append(p.leases, refLease{l: l, reg: g, live: true})
	p.u++
	p.ls[l].flows++
	p.regs[g].carried++
	p.regs[g].live++
	return len(p.leases) - 1, Granted, "", 0
}

func (p *refPool) release(id int) {
	le := &p.leases[id]
	if !le.live {
		return
	}
	le.live = false
	p.u--
	L := &p.ls[le.l]
	L.flows--
	if L.st == refAccepting {
		p.regs[L.reg].carried--
	}
	p.regs[le.reg].live--
}

// retiredLive は退役した登録に残る lease の数。orphans はそのうち受け付けている listener が運ぶもの。
func (p *refPool) retiredLive() (retired, orphans int) {
	for _, le := range p.leases {
		if le.live && p.regs[le.reg].members == 0 {
			retired++
			if p.ls[le.l].st == refAccepting {
				orphans++
			}
		}
	}
	return
}

// ---- 製品と参照の組 ----

// twin は製品の Pool と参照の Pool に同じ操作を当てる。
type twin struct {
	t      testing.TB
	p      *Pool
	r      *refPool
	ls     []*Listener
	leases []*Lease
}

func newTwin(t testing.TB, T int) *twin {
	return &twin{t: t, p: NewPool(T), r: newRefPool(T)}
}

func (w *twin) listener(rule string, accepting bool) int {
	var l *Listener
	if accepting {
		l = w.p.Listener(rule)
	} else {
		l = w.p.PendingListener(rule)
	}
	w.ls = append(w.ls, l)
	id := w.r.newListener(rule, accepting)
	w.check("listener")
	return id
}

func (w *twin) accept(l int) {
	w.ls[l].Accept()
	w.r.accept(l)
	w.check("accept")
}

func (w *twin) stop(l int) {
	w.ls[l].StopAccepting()
	w.r.stop(l)
	w.check("stop")
}

func (w *twin) close(l int) {
	w.ls[l].Close()
	w.r.close(l)
	w.check("close")
}

func (w *twin) setRule(l int, rule string) {
	w.ls[l].SetRule(rule)
	w.r.setRule(l, rule)
	w.check("setrule")
}

// take は 1 回の取得。製品と参照の結果が違えば失敗にする。
func (w *twin) take(l int) (Outcome, Reason) {
	w.t.Helper()
	x, ref, o := w.ls[l].Take()
	id, ro, rr, rn := w.r.take(l)
	if o != ro || ref.Reason != rr || (o == Refused && ref.RuleFlows != rn) {
		w.t.Fatalf("take l%d (%s): product %v %q %d, formula %v %q %d; %s", l, w.ls[l].rule, o, ref.Reason, ref.RuleFlows, ro, rr, rn, w.state())
	}
	if o == Refused && ref.Reason != ReasonBudget && ref.Reason != ReasonRuleCap {
		// 拒否の文言は判定に使った x_g を示す
		if !strings.Contains(ref.String(), fmt.Sprintf("holds %d flows", rn)) {
			w.t.Fatalf("refusal text %q does not show x_g %d", ref.String(), rn)
		}
	}
	if o == Granted {
		for len(w.leases) <= id {
			w.leases = append(w.leases, nil)
		}
		w.leases[id] = x
	}
	w.check("take")
	return o, ref.Reason
}

func (w *twin) takeN(l, n int) (granted int, last Reason) {
	for i := 0; i < n; i++ {
		o, r := w.take(l)
		if o != Granted {
			return granted, r
		}
		granted++
	}
	return granted, ""
}

func (w *twin) release(id int) {
	x := w.leases[id]
	first := !w.r.leases[id].live
	got := x.Release()
	w.r.release(id)
	if got == first {
		w.t.Fatalf("release %d: product %v, first %v", id, got, !first)
	}
	w.check("release")
}

func (w *twin) liveLeases() []int {
	var out []int
	for i, le := range w.r.leases {
		if le.live {
			out = append(out, i)
		}
	}
	return out
}

func (w *twin) state() string {
	lg := w.p.Ledger()
	return fmt.Sprintf("u=%d N=%d m=%d S=%d Sf=%d E=%d a=%v c=%v retired=%d", lg.InUse, lg.Rules, lg.Minimum, lg.Unfilled, lg.FloorShort, lg.Claim, lg.RegFlows, lg.RegCarried, lg.RetiredFlows)
}

// check は各操作の後の不変条件。製品の帳簿を登録と cell から作り直した値と照合し(CheckLedger)、
// 参照の Pool の値と一致させる。
func (w *twin) check(op string) {
	w.t.Helper()
	if err := w.p.CheckLedger(); err != nil {
		w.t.Fatalf("after %s: %v", op, err)
	}
	lg := w.p.Ledger()
	r := w.r
	ret, orph := r.retiredLive()
	if lg.InUse != r.u || lg.Rules != r.N() || lg.Minimum != r.min() || lg.Unfilled != r.S() || lg.FloorShort != r.Sf() || lg.RetiredFlows != ret || lg.Orphans != 0 || orph != 0 {
		w.t.Fatalf("after %s: product %s orphans %d; formula u=%d N=%d m=%d S=%d Sf=%d retired=%d orphans %d", op, w.state(), lg.Orphans, r.u, r.N(), r.min(), r.S(), r.Sf(), ret, orph)
	}
	for rule, g := range r.cur {
		if lg.RegFlows[rule] != r.regs[g].live || lg.RegCarried[rule] != r.regs[g].carried {
			w.t.Fatalf("after %s: rule %s product a=%d c=%d, formula a=%d c=%d", op, rule, lg.RegFlows[rule], lg.RegCarried[rule], r.regs[g].live, r.regs[g].carried)
		}
	}
	// c_g は登録の listener の flows の和
	sum := map[string]int{}
	for i, L := range r.ls {
		if L.st == refAccepting {
			sum[L.rule] += L.flows
			if w.ls[i].Flows() != L.flows {
				w.t.Fatalf("after %s: listener %d flows %d, formula %d", op, i, w.ls[i].Flows(), L.flows)
			}
		}
	}
	for rule, n := range sum {
		if lg.RegCarried[rule] != n {
			w.t.Fatalf("after %s: rule %s c_g %d, listener flows %d", op, rule, lg.RegCarried[rule], n)
		}
	}
}

// ---- 場面 (設計文書 7a.10 節の例) ----

// 例 1: ルールが 2 本で 1 本がフラッド。A は ceil((T-f)/2) = 1022 で spare、B は 1022 まで。
func TestFloorTwoRulesOneFlooded(t *testing.T) {
	w := newTwin(t, 2048)
	a := w.listener("a", true)
	b := w.listener("b", true)
	if n, r := w.takeN(a, 5000); n != 1022 || r != ReasonSpare {
		t.Fatalf("a: %d %s", n, r)
	}
	if n, r := w.takeN(b, 5000); n != 1022 || r != ReasonSpare {
		t.Fatalf("b: %d %s", n, r)
	}
}

// 例 2: 3 本のうち 2 本がフラッド。A 1022、B 511、D は 511 まで。
func TestFloorThreeRulesTwoFlooded(t *testing.T) {
	w := newTwin(t, 2048)
	a := w.listener("a", true)
	if n, r := w.takeN(a, 5000); n != 2044 || r != ReasonSpare {
		t.Fatalf("a alone: %d %s", n, r)
	}
	for _, id := range w.liveLeases()[1022:] {
		w.release(id)
	}
	b := w.listener("b", true)
	d := w.listener("d", true)
	if n, r := w.takeN(b, 5000); n != 511 || r != ReasonSpare {
		t.Fatalf("b: %d %s %s", n, r, w.state())
	}
	if n, r := w.takeN(d, 5000); n != 511 || r != ReasonSpare {
		t.Fatalf("d: %d %s %s", n, r, w.state())
	}
}

// 例 3: 1 本が持ち切った後に新しいルール。B は予備の 4 枠を取り、その後 budget。A が 10 本を閉じると
// B は予約の部分で 6 本を取った後 floor。
func TestFloorNewRuleAfterFullRule(t *testing.T) {
	w := newTwin(t, 2048)
	a := w.listener("a", true)
	w.takeN(a, 5000)
	b := w.listener("b", true)
	if o, r := w.take(a); o != Refused || r != ReasonRuleCap {
		t.Fatalf("a after b: %v %s", o, r)
	}
	if n, r := w.takeN(b, 100); n != 4 || r != ReasonBudget {
		t.Fatalf("b: %d %s", n, r)
	}
	for _, id := range w.liveLeases()[:10] {
		w.release(id)
	}
	if n, r := w.takeN(b, 100); n != 6 || r != ReasonFloor {
		t.Fatalf("b after 10 closed: %d %s %s", n, r, w.state())
	}
}

// 例 4 (T=16): 削除したルールの旧い 8 本が残り、A が 4 本を持ち、B が加わる。A の 5 本目は floor、
// B は 4 本を取った後 budget。
func TestFloorSmallBudget(t *testing.T) {
	w := newTwin(t, 16)
	old := w.listener("old", true)
	if n, _ := w.takeN(old, 8); n != 8 {
		t.Fatalf("old: %d", n)
	}
	a := w.listener("a", true)
	if n, _ := w.takeN(a, 4); n != 4 {
		t.Fatalf("a: %d", n)
	}
	w.close(old)
	b := w.listener("b", true)
	if o, r := w.take(a); o != Refused || r != ReasonFloor {
		t.Fatalf("a: %v %s %s", o, r, w.state())
	}
	if n, r := w.takeN(b, 100); n != 4 || r != ReasonBudget {
		t.Fatalf("b: %d %s", n, r)
	}
}

// 例 5 (統合): A、B、X で X 256 本、B 1022 本。B を A へ統合すると B の 1022 本は A の登録へ移り、
// 統合したポートへのフラッドは spare、X は 1022 本まで。
func TestFloorMergeMovesFlows(t *testing.T) {
	w := newTwin(t, 2048)
	a := w.listener("a", true)
	b := w.listener("b", true)
	x := w.listener("x", true)
	w.takeN(x, 256)
	if n, _ := w.takeN(b, 5000); n != 1022 {
		t.Fatalf("b: %d", n)
	}
	w.setRule(b, "a")
	lg := w.p.Ledger()
	if lg.RegFlows["a"] != 1022 || lg.RegCarried["a"] != 1022 || lg.RetiredFlows != 0 {
		t.Fatalf("after merge %s", w.state())
	}
	if o, r := w.take(b); o != Refused || r != ReasonSpare {
		t.Fatalf("merged port: %v %s", o, r)
	}
	if n, r := w.takeN(x, 5000); n != 1022-256 || r != ReasonSpare {
		t.Fatalf("x: %d %s %s", n, r, w.state())
	}
	_ = a
}

// 例 6 (UDP の再開): A の fail-closed で A の登録が退役し、再開で旧い 1022 本が新しい登録へ移る。
func TestFloorResumeMovesFlows(t *testing.T) {
	w := newTwin(t, 2048)
	a := w.listener("a", true)
	b := w.listener("b", true)
	w.takeN(a, 5000)
	w.takeN(b, 5000)
	w.stop(a)
	if lg := w.p.Ledger(); lg.RetiredFlows != 1022 {
		t.Fatalf("retiring %s", w.state())
	}
	w.accept(a)
	if lg := w.p.Ledger(); lg.RetiredFlows != 0 || lg.RegFlows["a"] != 1022 || lg.Claim != 2048 {
		t.Fatalf("resumed %s", w.state())
	}
	if o, r := w.take(a); o != Refused || r != ReasonSpare {
		t.Fatalf("a: %v %s", o, r)
	}
}

// splitRig は例 7、8、11 の形: B がポート b1 と b2 を持ち、無関係の X がいる。b2 へのフラッドで B は
// 1022 本(N=2)。b2 を D へ分割する。
func splitRig(t *testing.T) (w *twin, b1, b2, x int) {
	w = newTwin(t, 2048)
	b1 = w.listener("b", true)
	b2 = w.listener("b", true)
	if n, r := w.takeN(b2, 5000); n != 2044 || r != ReasonSpare {
		t.Fatalf("b alone: %d %s", n, r)
	}
	x = w.listener("x", true)
	for _, id := range w.liveLeases()[1022:] {
		w.release(id)
	}
	w.setRule(b2, "d")
	return
}

// 例 7 (分割の直後の分割元の削除): b2 が運ぶ 1022 本は D へ移り、X は 1022 本まで。
func TestFloorSplitThenDeleteHead(t *testing.T) {
	w, b1, b2, x := splitRig(t)
	w.close(b1)
	lg := w.p.Ledger()
	if lg.RegFlows["d"] != 1022 || lg.RegCarried["d"] != 1022 || lg.RetiredFlows != 0 {
		t.Fatalf("after delete %s", w.state())
	}
	if n, r := w.takeN(x, 5000); n != 1022 || r != ReasonSpare {
		t.Fatalf("x: %d %s %s", n, r, w.state())
	}
	_ = b2
}

// 例 8 と例 13: 分割元が続く間のフラッド。D は a_D=0、c_D=1022 で下限の部分で 2 本を取ると
// c_D=1024=C で rule_cap。X は 511 本まで。B を削除すると 1022 本が D へ移り、X は 1020 本まで。
func TestFloorSplitFloodWhileHeadLives(t *testing.T) {
	w, b1, b2, x := splitRig(t)
	if n, r := w.takeN(b2, 5000); n != 2 || r != ReasonRuleCap {
		t.Fatalf("d: %d %s %s", n, r, w.state())
	}
	_, ref, _ := w.ls[b2].Take()
	if ref.RuleFlows != 1024 || !strings.Contains(ref.String(), "rule d holds 1024 flows") {
		t.Fatalf("rule_cap text %q", ref.String())
	}
	w.r.take(b2) // 参照側も同じ拒否を数える
	if n, r := w.takeN(x, 5000); n != 511 || r != ReasonSpare {
		t.Fatalf("x while head lives: %d %s %s", n, r, w.state())
	}
	for _, id := range w.liveLeases()[len(w.liveLeases())-511:] {
		w.release(id)
	}
	w.close(b1)
	if n, r := w.takeN(x, 5000); n != 1020 || r != ReasonFloor {
		t.Fatalf("x after delete: %d %s %s", n, r, w.state())
	}
}

// 例 11 と回避の手順: 分割元に残ったポート b1 は 0 本で spare。B を別の ID に名前を変える(同じ
// ポートの削除と追加を 1 回の適用で行う)と、B の登録が退役して b2 の旧い接続が D へ移り、新しい ID
// の b1 は最低分を得る。
func TestFloorSplitRemainderAndRename(t *testing.T) {
	w, b1, b2, x := splitRig(t)
	if o, r := w.take(b1); o != Refused || r != ReasonSpare {
		t.Fatalf("b1 after split: %v %s %s", o, r, w.state())
	}
	// D が 2 本を取った後も同じ
	w.takeN(b2, 5000)
	if o, r := w.take(b1); o != Refused || r != ReasonSpare {
		t.Fatalf("b1 after d: %v %s", o, r)
	}
	_, ref, _ := w.ls[b1].Take()
	w.r.take(b1)
	t.Logf("b1 refusal: %s", ref)
	// 名前の変更: 1 回の適用の中で、分割元の最後の待ち受けを閉じて同じポートを新しい ID で開く
	w.close(b1)
	b1n := w.listener("b2name", true)
	lg := w.p.Ledger()
	if lg.RegFlows["d"] != 1024 || lg.RetiredFlows != 0 {
		t.Fatalf("after rename %s", w.state())
	}
	nb, rb := w.takeN(b1n, 5000)
	nx, rx := w.takeN(x, 5000)
	t.Logf("after rename: new b1 %d %s, x %d %s; %s", nb, rb, nx, rx, w.state())
	if nb < 500 || nx < 500 {
		t.Fatalf("rename workaround: new b1 %d, x %d", nb, nx)
	}
}

// 3.3 節の表: 1 本だけにフラッドを掛け、他のルールは空きのとき、フラッドを受けたルールが止まる数と理由。
func TestFloorSteadyStopTable(t *testing.T) {
	cases := []struct {
		T, N, want int
		reason     Reason
	}{
		{2048, 1, 2044, ReasonSpare}, {2048, 2, 1022, ReasonSpare}, {2048, 3, 1022, ReasonSpare},
		{2048, 4, 1024, ReasonRuleCap}, {2048, 8, 1022, ReasonSpare}, {2048, 15, 1022, ReasonSpare},
		{1024, 1, 1020, ReasonSpare}, {1024, 2, 510, ReasonSpare}, {1024, 4, 510, ReasonSpare},
		{1024, 5, 512, ReasonRuleCap}, {1024, 11, 510, ReasonSpare},
	}
	for _, c := range cases {
		w := newTwin(t, c.T)
		f := w.listener("r0", true)
		for i := 1; i < c.N; i++ {
			w.listener(fmt.Sprintf("r%d", i), true)
		}
		if n, r := w.takeN(f, 2*c.T); n != c.want || r != c.reason {
			t.Errorf("T=%d N=%d: %d %s, want %d %s", c.T, c.N, n, r, c.want, c.reason)
		}
	}
}

// 例 9 と例 10 (ラボの場面 R と V、T=1024): 各理由が実際に出る。
func TestFloorReasonsUnderClaimExcess(t *testing.T) {
	w := newTwin(t, 1024)
	a := w.listener("a", true)
	if n, r := w.takeN(a, 5000); n != 1020 || r != ReasonSpare {
		t.Fatalf("a: %d %s", n, r)
	}
	b := w.listener("b", true)
	if o, r := w.take(a); r != ReasonRuleCap {
		t.Fatalf("a with b: %v %s", o, r)
	}
	if n, r := w.takeN(b, 100); n != 4 || r != ReasonBudget {
		t.Fatalf("b: %d %s", n, r)
	}
	for _, id := range w.liveLeases()[:10] {
		w.release(id)
	}
	if n, r := w.takeN(b, 100); n != 6 || r != ReasonFloor {
		t.Fatalf("b floor: %d %s", n, r)
	}

	v := newTwin(t, 1024)
	va := v.listener("a", true)
	vb := v.listener("b", true)
	v.takeN(va, 5000)
	v.takeN(vb, 5000)
	vx := v.listener("x", true)
	if o, r := v.take(va); r != ReasonReserve {
		t.Fatalf("v a: %v %s %s", o, r, v.state())
	}
	if n, r := v.takeN(vx, 100); n != 4 || r != ReasonBudget {
		t.Fatalf("v x: %d %s", n, r)
	}
}

// T ≤ 0 の Pool: 受け付けていない handle は拒み、予算の判定は行わない。帳簿は同じに保つ。
func TestFloorNoBudget(t *testing.T) {
	p := NewPool(0)
	l := p.Listener("a")
	for i := 0; i < 100; i++ {
		if _, _, o := l.Take(); o != Granted {
			t.Fatal(o)
		}
	}
	l.StopAccepting()
	if _, _, o := l.Take(); o != NotAccepting {
		t.Fatal(o)
	}
	if err := p.CheckLedger(); err != nil {
		t.Fatal(err)
	}
}

// 拒否の文言(設計文書 7a.10 節の例)。
func TestFloorRefusalMessages(t *testing.T) {
	cases := []struct {
		r    Refusal
		want string
	}{
		{Refusal{Reason: ReasonSpare, RuleID: "r1", InUse: 6141, Total: 8192, RuleFlows: 4094, Minimum: 2047, Spare: 4, Unfilled: 2047, UnfilledRules: 1},
			"rule r1 holds 4094 flows, at or above its minimum of 2047, and the free part of the budget, 2051 of 8192, is held for the unfilled minimums of 1 other rule, 2047 flows, and 4 spare flows for a rule added later"},
		{Refusal{Reason: ReasonSpare, RuleID: "r1", InUse: 8188, Total: 8192, RuleFlows: 8188, Minimum: 4, Spare: 4},
			"rule r1 holds 8188 flows and the free part of the budget, 4 of 8192, is kept spare for a rule added later"},
		{Refusal{Reason: ReasonFloor, RuleID: "r1", InUse: 8184, Total: 8192, RuleFlows: 300, Minimum: 4094, Spare: 4, FloorShort: 4, FloorShortRules: 1},
			"rule r1 holds 300 flows, below its minimum of 4094, and the free part of the budget, 8 of 8192, is held for the first flows of 1 other rule and 4 spare flows for a rule added later"},
		{Refusal{Reason: ReasonFloor, RuleID: "r1", InUse: 2044, Total: 2048, RuleFlows: 10, Minimum: 1022, Spare: 4},
			"rule r1 holds 10 flows, below its minimum of 1022, and the free part of the budget, 4 of 2048, is kept spare for a rule added later"},
		{Refusal{Reason: ReasonReserve, RuleID: "r1", InUse: 1800, Total: 2048, RuleFlows: 600, Minimum: 511, Unfilled: 300, UnfilledRules: 2, UnfilledSelf: true},
			"rule r1 holds 600 flows, at or above its minimum of 511, and the free part of the budget, 248 of 2048, is held for the unfilled minimums of this rule and 1 other rule, 300 flows"},
		{Refusal{Reason: ReasonRuleCap, RuleID: "r1", RuleFlows: 4096, OtherRules: 1},
			"rule r1 holds 4096 flows and the rest of the budget is reserved for 1 other rule"},
		{Refusal{Reason: ReasonBudget, InUse: 8192, Total: 8192},
			"flow budget full: 8192 of 8192 in use in this process"},
	}
	for _, c := range cases {
		if got := c.r.String(); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.r.Reason, got, c.want)
		}
		if strings.ContainsAny(c.r.String(), "()") {
			t.Errorf("parentheses in %q", c.r.String())
		}
	}
}

// ---- 無作為の列 ----

// randomRun は無作為の操作列を製品と参照に当て、毎手の判定と帳簿を照合する。あわせて設計文書 7a.10 節の
// 保証のうち、帳簿の外から見えるものを確かめる。
func randomRun(t *testing.T, T int, seed int64, steps int) {
	rng := rand.New(rand.NewSource(seed))
	w := newTwin(t, T)
	rules := []string{"a", "b", "c", "d", "e", "f"}[:2+int(seed%5)]
	pick := func() string { return rules[rng.Intn(len(rules))] }
	for i := 0; i < 1+rng.Intn(3); i++ {
		w.listener(pick(), true)
	}
	burst := max(1, T/8)
	for s := 0; s < steps; s++ {
		lg := w.p.Ledger()
		reserveHeld := T-lg.InUse >= lg.FloorShort+FlowFloor
		createsReg := false
		switch k := rng.Intn(100); {
		case k < 6:
			rule := pick()
			_, exists := w.r.cur[rule]
			acc := rng.Intn(5) != 0
			createsReg = acc && !exists
			w.listener(rule, acc)
		case k < 12:
			l := rng.Intn(len(w.ls))
			_, exists := w.r.cur[w.r.ls[l].rule]
			st := w.r.ls[l].st
			createsReg = !exists && (st == refPending || st == refRetiring)
			w.accept(l)
		case k < 17:
			w.stop(rng.Intn(len(w.ls)))
		case k < 21:
			w.close(rng.Intn(len(w.ls)))
		case k < 30:
			l := rng.Intn(len(w.ls))
			rule := pick()
			_, exists := w.r.cur[rule]
			createsReg = w.r.ls[l].st == refAccepting && !exists
			w.setRule(l, rule)
		case k < 70:
			l := rng.Intn(len(w.ls))
			n := 1 + rng.Intn(burst)
			for i := 0; i < n; i++ {
				before := w.p.Ledger()
				o, r := w.take(l)
				if o == Refused && (r == ReasonBudget || r == ReasonReserve || r == ReasonFloor) && before.Claim <= T {
					t.Fatalf("seed %d: %s while E=%d <= T", seed, r, before.Claim)
				}
				if o == Granted {
					after := w.p.Ledger()
					if after.Rules >= 2 && after.RegCarried[w.r.ls[l].rule] > w.p.RuleCap() {
						t.Fatalf("seed %d: c_g above C after a take", seed)
					}
					if after.Claim > T && after.Claim > before.Claim {
						t.Fatalf("seed %d: take raised E above T: %d -> %d", seed, before.Claim, after.Claim)
					}
				}
				if o != Granted {
					break
				}
			}
		default:
			live := w.liveLeases()
			n := 1 + rng.Intn(burst)
			for i := 0; i < n && len(live) > 0; i++ {
				j := rng.Intn(len(live))
				w.release(live[j])
				live = append(live[:j], live[j+1:]...)
			}
			if rng.Intn(20) == 0 && len(w.r.leases) > 0 {
				w.release(rng.Intn(len(w.r.leases))) // 2 度目の返却を混ぜる
			}
		}
		after := w.p.Ledger()
		if reserveHeld && !createsReg && T-after.InUse < after.FloorShort+FlowFloor {
			t.Fatalf("seed %d step %d: T-u >= Sf+P broken without a new registration: %s", seed, s, w.state())
		}
	}
	for _, id := range w.liveLeases() {
		w.release(id)
	}
	if lg := w.p.Ledger(); lg.InUse != 0 || lg.RetiredFlows != 0 {
		t.Fatalf("seed %d: leftover %s", seed, w.state())
	}
}

func TestFloorMatchesFormulaRandom(t *testing.T) {
	seeds := 300
	if testing.Short() {
		seeds = 30
	}
	for _, T := range []int{16, 64, 2048} {
		n := seeds
		if T == 2048 {
			n = seeds / 10
		}
		for seed := int64(1); seed <= int64(n); seed++ {
			randomRun(t, T, seed, 300)
		}
	}
}

// ---- 並行 ----

// 取得と返却と設定の変更を並行に流し、-race の報告が無いことと、最後に帳簿が整合し u が 0 に戻る
// ことを確かめる。
func TestFloorConcurrent(t *testing.T) {
	p := NewPool(64)
	var ls []*Listener
	for i := 0; i < 6; i++ {
		ls = append(ls, p.Listener([]string{"a", "b", "c"}[i%3]))
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := range ls {
		wg.Add(1)
		go func(l *Listener, seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed))
			var held []*Lease
			for {
				select {
				case <-stop:
					for _, x := range held {
						x.Release()
					}
					return
				default:
				}
				if rng.Intn(2) == 0 {
					if x, _, o := l.Take(); o == Granted {
						held = append(held, x)
					}
				} else if len(held) > 0 {
					j := rng.Intn(len(held))
					held[j].Release()
					held = append(held[:j], held[j+1:]...)
				}
			}
		}(ls[i], int64(i))
	}
	rng := rand.New(rand.NewSource(99))
	for i := 0; i < 3000; i++ {
		l := ls[rng.Intn(len(ls))]
		switch rng.Intn(4) {
		case 0:
			l.SetRule([]string{"a", "b", "c", "d"}[rng.Intn(4)])
		case 1:
			l.StopAccepting()
		case 2:
			l.Accept()
		default:
			if err := p.CheckLedger(); err != nil {
				t.Fatal(err)
			}
		}
	}
	close(stop)
	wg.Wait()
	if err := p.CheckLedger(); err != nil {
		t.Fatal(err)
	}
	if lg := p.Ledger(); lg.InUse != 0 {
		t.Fatalf("u = %d", lg.InUse)
	}
}

func BenchmarkTakeRelease(b *testing.B) {
	p := NewPool(1 << 20)
	l := p.Listener("a")
	p.Listener("b")
	for i := 0; i < b.N; i++ {
		x, _, _ := l.Take()
		x.Release()
	}
}

// ---- 式の性質 (設計文書 7a.10 節の「ホストで確かめること」) ----

// TotalMin から TotalMax までのすべての T で、C = ceil(T/2)、f ≤ C、3f ≤ T が成り立ち、q ≥ f と
// なるすべての N で N × m + P ≤ T が成り立つ。
func TestFloorFormulaAcrossBudgets(t *testing.T) {
	for T := TotalMin; T <= TotalMax; T++ {
		C := ruleCapFor(T)
		if C != (T+1)/2 || FlowFloor > C || 3*FlowFloor > T {
			t.Fatalf("T=%d: C=%d", T, C)
		}
		for N := 2; ; N++ {
			q := (T - FlowFloor) / 2 / (N - 1)
			if q < FlowFloor {
				break
			}
			if m := minimumFor(T, N); m != q || N*m+FlowFloor > T {
				t.Fatalf("T=%d N=%d: m=%d, N*m+P=%d", T, N, m, N*m+FlowFloor)
			}
		}
	}
}

// 1 本のルールに受け付けを続けたとき (他のルールはフローを持たない) の最大は、N = 1 で T - P、
// N ≥ 2 で min(C, max(m, T - P - (N - 1) × m))。
func TestFloorSingleFloodMaximum(t *testing.T) {
	type tc struct{ T, N int }
	var cases []tc
	for T := TotalMin; T <= 200; T++ {
		for N := 1; N <= 20; N++ {
			cases = append(cases, tc{T, N})
		}
	}
	for _, T := range []int{1024, 1500, 2048, 4097, 8192} {
		for _, N := range []int{1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 74, 147, 257, 300} {
			cases = append(cases, tc{T, N})
		}
	}
	for _, c := range cases {
		p := NewPool(c.T)
		l := p.Listener("r0")
		for i := 1; i < c.N; i++ {
			p.Listener(fmt.Sprintf("r%d", i))
		}
		n := 0
		for {
			if _, _, o := l.Take(); o != Granted {
				break
			}
			n++
		}
		want := c.T - FlowFloor
		if c.N >= 2 {
			m := minimumFor(c.T, c.N)
			want = min(ruleCapFor(c.T), max(m, c.T-FlowFloor-(c.N-1)*m))
		}
		if n != want {
			t.Errorf("T=%d N=%d: held %d, want %d", c.T, c.N, n, want)
		}
	}
}
