package resource

import (
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
)

// trackedPool is a test-only wrapper around Pool that records every Listener and PendingListener
// it creates, so checkInvariants can recompute Pool's running totals (u, u_r, q, the unused-reserve
// sum) from scratch without pool.go itself carrying a registry of live listeners; that bookkeeping
// existed in production only so tests could recompute it (design.md 7a.10 節), and now lives here
// instead. Tests create trackedPool the same way they used to create *Pool (newTrackedPool in place
// of NewPool); every other Pool method is promoted unchanged through the embedded *Pool.
type trackedPool struct {
	*Pool
	mu sync.Mutex
	ls []*Listener
}

func newTrackedPool(total int) *trackedPool {
	return &trackedPool{Pool: NewPool(total)}
}

func (tp *trackedPool) track(l *Listener) *Listener {
	tp.mu.Lock()
	tp.ls = append(tp.ls, l)
	tp.mu.Unlock()
	return l
}

func (tp *trackedPool) Listener(ruleID string) *Listener {
	return tp.track(tp.Pool.Listener(ruleID))
}

func (tp *trackedPool) PendingListener(ruleID string) *Listener {
	return tp.track(tp.Pool.PendingListener(ruleID))
}

func (tp *trackedPool) checkInvariants() error {
	tp.mu.Lock()
	ls := append([]*Listener(nil), tp.ls...)
	tp.mu.Unlock()
	return checkInvariants(tp.Pool, ls)
}

// checkInvariants recomputes the numbers Pool keeps by addition and subtraction (u, u_r, q, the
// unused-reserve sum) from the listeners a test created, and compares them against what Pool
// reports. It plays the role pool.go's own checkInvariants used to play before that bookkeeping
// moved to the test side: the hot path (Acquire,
// Release) no longer maintains a registry of listeners, so this function is handed one instead.
//
// A tracked listener that is closed and has released every flow is never removed from the slice
// (unlike the old production registry, which forgot it): that removal was a memory-bound
// implementation detail of the registry itself, not a behaviour Pool promises, so recomputing from
// a list that keeps every listener ever created is equivalent for every check below (a fully
// drained, closed listener contributes 0 flows and is never counted, so it cannot skew any sum).
func checkInvariants(p *Pool, listeners []*Listener) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	inUse := 0
	want := map[string]*ruleFlows{}
	for _, l := range listeners {
		if l.flows < 0 {
			return fmt.Errorf("a listener of rule %s holds %d flows", l.rule, l.flows)
		}
		if l.counted != (l.open && l.accepting) {
			return fmt.Errorf("a listener of rule %s: counted=%v, open=%v, accepting=%v", l.rule, l.counted, l.open, l.accepting)
		}
		inUse += l.flows
		if !l.counted {
			continue
		}
		st := want[l.rule]
		if st == nil {
			st = &ruleFlows{}
			want[l.rule] = st
		}
		st.flows += l.flows
		st.listeners++
	}
	if inUse != p.inUse {
		return fmt.Errorf("InUse = %d, the listeners hold %d flows", p.inUse, inUse)
	}
	if p.total > 0 && p.inUse > p.total {
		return fmt.Errorf("InUse = %d, over the budget of %d", p.inUse, p.total)
	}
	if len(want) != len(p.accepting) {
		return fmt.Errorf("%d accepting rules, the listeners belong to %d", len(p.accepting), len(want))
	}
	for rule, st := range want {
		got := p.accepting[rule]
		if got == nil {
			return fmt.Errorf("rule %s is missing from the accepting rules", rule)
		}
		if got.flows != st.flows || got.listeners != st.listeners {
			return fmt.Errorf("rule %s holds %d flows in %d listeners, the listeners say %d in %d",
				rule, got.flows, got.listeners, st.flows, st.listeners)
		}
	}
	reserve := reserveFor(p.total, len(want))
	if got := reserveFor(p.total, len(p.accepting)); got != reserve {
		return fmt.Errorf("reserve = %d, want %d for %d rules of a budget of %d", got, reserve, len(want), p.total)
	}
	short := 0
	for _, st := range want {
		short += shortfallOf(reserve, st.flows)
	}
	if short != p.shortfall {
		return fmt.Errorf("the unused reserve sums to %d, recomputed %d", p.shortfall, short)
	}
	if p.total > 0 && len(want)*reserve > p.total {
		return fmt.Errorf("%d rules of a reserve of %d each do not fit in the budget of %d", len(want), reserve, p.total)
	}
	return nil
}

// acquireN は n 回続けて枠を取り、通った数と最後の拒否を返す。
func acquireN(l *Listener, n int) (int, Refusal) {
	passed := 0
	var last Refusal
	for range n {
		ref, ok := l.Acquire()
		if !ok {
			last = ref
			continue
		}
		passed++
	}
	return passed, last
}

// fillUp は拒まれるまで枠を取り、通った数と拒否を返す。
func fillUp(t *testing.T, l *Listener, limit int) (int, Refusal) {
	t.Helper()
	for i := range limit {
		if ref, ok := l.Acquire(); !ok {
			return i, ref
		}
	}
	t.Fatalf("%d flows passed without a refusal", limit)
	return 0, Refusal{}
}

// ok は不変条件の検算。running total が待ち受けの一覧と合っていることを確かめる。
func ok(t *testing.T, p *trackedPool) {
	t.Helper()
	if err := p.checkInvariants(); err != nil {
		t.Fatalf("pool invariants: %v", err)
	}
}

// ルールが 1 本なら、そのルールは予算 T のすべてを使える(設計文書 7a.10 節)。
func TestPoolOneRuleUsesTheWholeBudget(t *testing.T) {
	for _, total := range []int{1, 2, 3, 15, 16, 17, 100, 101, 2048, 8192} {
		p := newTrackedPool(total)
		l := p.Listener("r1")
		passed, ref := fillUp(t, l, total+1)
		if passed != total {
			t.Errorf("budget %d: one rule held %d flows, want %d", total, passed, total)
		}
		if ref.Reason != ReasonBudget {
			t.Errorf("budget %d: refusal reason = %q, want %q", total, ref.Reason, ReasonBudget)
		}
		if p.Rules() != 1 || p.Reserve() != 0 {
			t.Errorf("budget %d: rules = %d, reserve = %d, want 1 and 0", total, p.Rules(), p.Reserve())
		}
		ok(t, p)
	}
}

// プロセス全体の予算の拒否は budget で、返した枠は使い直せる。
func TestPoolBudget(t *testing.T) {
	p := newTrackedPool(3)
	l := p.Listener("r1")
	passed, ref := acquireN(l, 5)
	if passed != 3 {
		t.Errorf("admitted %d flows, want 3 (the budget)", passed)
	}
	if ref.Reason != ReasonBudget {
		t.Errorf("refusal reason = %q, want %q", ref.Reason, ReasonBudget)
	}
	if ref.InUse != 3 || ref.Total != 3 {
		t.Errorf("refusal = %+v, want 3 of 3 in use", ref)
	}
	if p.InUse() != 3 {
		t.Errorf("InUse = %d, want 3 (refused flows are not counted)", p.InUse())
	}
	l.Release()
	if p.InUse() != 2 {
		t.Errorf("InUse after a release = %d, want 2", p.InUse())
	}
	if _, admitted := l.Acquire(); !admitted {
		t.Error("a released slot must be reusable")
	}
	ok(t, p)
}

// ルール 1 本の上限 C は、そのルールの待ち受けの合計で見る。他のルールは自分の予約を使える。
func TestPoolRuleCapSumsTheRuleListeners(t *testing.T) {
	p := newTrackedPool(10) // C = 5、ルールが 2 本なら q = 5
	a1 := p.Listener("r1")
	a2 := p.Listener("r1")
	b := p.Listener("r2")
	if p.RuleCap() != 5 || p.Reserve() != 5 {
		t.Fatalf("cap = %d, reserve = %d, want 5 and 5", p.RuleCap(), p.Reserve())
	}
	if n, _ := acquireN(a1, 3); n != 3 {
		t.Fatalf("r1's first listener admitted %d flows, want 3", n)
	}
	passed, ref := acquireN(a2, 4)
	if passed != 2 {
		t.Errorf("r1's second listener admitted %d flows, want 2 (3 of the cap of 5 are held by the first)", passed)
	}
	if ref.Reason != ReasonRuleCap {
		t.Errorf("refusal reason = %q, want %q", ref.Reason, ReasonRuleCap)
	}
	if ref.RuleID != "r1" || ref.RuleFlows != 5 || ref.RuleCap != 5 {
		t.Errorf("refusal = %+v, want rule r1 holding 5 of a cap of 5", ref)
	}
	if got := p.RuleFlows("r1"); got != 5 {
		t.Errorf("RuleFlows(r1) = %d, want 5", got)
	}
	if n, _ := acquireN(b, 5); n != 5 {
		t.Errorf("r2 admitted %d flows, want 5 (its own reserve, out of the shared budget)", n)
	}
	if p.InUse() != 10 {
		t.Errorf("InUse = %d, want 10", p.InUse())
	}
	ok(t, p)
}

// 判定の順序は、予算、ルール 1 本の上限、隔離予約である(設計文書 7a.10 節の条件の並び)。
func TestPoolReasonPrecedence(t *testing.T) {
	// 予算が尽きているときは、ルール 1 本の上限に達していても budget
	p := newTrackedPool(2) // C = 1
	a, b := p.Listener("r1"), p.Listener("r2")
	if _, admitted := a.Acquire(); !admitted {
		t.Fatal("r1's first flow must pass")
	}
	if _, admitted := b.Acquire(); !admitted {
		t.Fatal("r2's first flow must pass")
	}
	if ref, admitted := a.Acquire(); admitted || ref.Reason != ReasonBudget {
		t.Errorf("refusal = %+v, admitted = %v, want %q (the budget is judged first)", ref, admitted, ReasonBudget)
	}
	ok(t, p)

	// 上限に達しているルールは、空きがあり、他のルールの予約が余っていても rule_cap
	p2 := newTrackedPool(10) // C = 5、N = 3 で q = 2
	c := p2.Listener("r1")
	p2.Listener("r2")
	p2.Listener("r3")
	if n, _ := acquireN(c, 5); n != 5 {
		t.Fatalf("r1 admitted %d flows, want 5 (its cap)", n)
	}
	ref, admitted := c.Acquire()
	if admitted || ref.Reason != ReasonRuleCap {
		t.Errorf("refusal = %+v, admitted = %v, want %q", ref, admitted, ReasonRuleCap)
	}
	if p2.InUse() != 5 {
		t.Errorf("InUse = %d, want 5 (the budget still has room)", p2.InUse())
	}
	ok(t, p2)
}

// 自分の予約を超えたルールは、残りの空きが他のルールの予約で埋まっていれば reserve で拒まれる。
// 予約の内側にいるルールは、そのあいだも予約まで通せる。
func TestPoolReserveKeepsRoomForTheOtherRules(t *testing.T) {
	p := newTrackedPool(10) // C = 5、N = 3 で q = 2
	a, b, c := p.Listener("r1"), p.Listener("r2"), p.Listener("r3")
	if p.Reserve() != 2 {
		t.Fatalf("reserve = %d, want 2", p.Reserve())
	}
	if n, _ := acquireN(a, 4); n != 4 {
		t.Fatalf("r1 admitted %d flows, want 4", n)
	}
	if n, _ := acquireN(b, 4); n != 4 {
		t.Fatalf("r2 admitted %d flows, want 4", n)
	}
	// 空きは 2 つあるが、どちらも r3 の予約の分なので、予約を超えた 2 本は通せない
	for _, l := range []*Listener{a, b} {
		ref, admitted := l.Acquire()
		if admitted || ref.Reason != ReasonReserve {
			t.Errorf("rule %s: refusal = %+v, admitted = %v, want %q", ref.RuleID, ref, admitted, ReasonReserve)
		}
	}
	if p.InUse() != 8 {
		t.Errorf("InUse = %d, want 8", p.InUse())
	}
	// 予約の内側の r3 は、他のルールがフラッドを受けている最中も予約まで通せる
	if n, _ := acquireN(c, 2); n != 2 {
		t.Errorf("r3 admitted %d flows, want 2 (its reserve)", n)
	}
	if ref, admitted := c.Acquire(); admitted || ref.Reason != ReasonBudget {
		t.Errorf("refusal = %+v, admitted = %v, want %q (the budget is full now)", ref, admitted, ReasonBudget)
	}
	ok(t, p)
}

// ルールが 2 本以上あるとき、他のルールがフローを持たなくても、1 本のルールが持てる最大はちょうど C。
func TestPoolFloodedRuleStopsAtTheCap(t *testing.T) {
	totals := []int{1, 2, 3, 4, 5, 7, 16, 17, 63, 100, 101, 255, 256, 1024, 2048, 8192, TotalMax}
	for _, total := range totals {
		for _, rules := range []int{2, 3, 4, 7, 16, 100, 300} {
			p := newTrackedPool(total)
			flooded := p.Listener("r1")
			for i := 1; i < rules; i++ {
				p.Listener(fmt.Sprintf("r%d", i+1))
			}
			if p.Rules() != rules {
				t.Fatalf("budget %d, %d rules: Rules() = %d", total, rules, p.Rules())
			}
			want := (total + 1) / 2
			if p.RuleCap() != want {
				t.Fatalf("budget %d: cap = %d, want ceil(T/2) = %d", total, p.RuleCap(), want)
			}
			passed, ref := fillUp(t, flooded, total+1)
			if passed != want {
				t.Errorf("budget %d, %d rules: one rule held %d flows, want the cap %d (refused with %q)",
					total, rules, passed, want, ref.Reason)
			}
			ok(t, p)
		}
	}
}

// ルール 1 本の上限は、どの予算でも ceil(T/2) である。既定以上の予算では、置き換えた式の値を下回らない。
func TestRuleCapIsHalfTheBudgetRoundedUp(t *testing.T) {
	// replaced は Phase 6 の移行の手順 4 が置き換えた式 max(floor(T/2), min(F, T))。
	// F は設定項目にする前の固定値(UDP 4096、TCP 1024)である。
	replaced := func(total, floor int) int { return max(total/2, min(floor, total), 1) }
	for total := TotalMin; total <= TotalMax; total++ {
		got := ruleCapFor(total)
		want := (total + 1) / 2
		if got != want {
			t.Fatalf("ruleCapFor(%d) = %d, want %d", total, got, want)
		}
		if total >= UDPTotal && got < replaced(total, 4096) {
			t.Fatalf("budget %d: cap %d is below the replaced UDP cap %d", total, got, replaced(total, 4096))
		}
		if total >= TCPTotal && got < replaced(total, 1024) {
			t.Fatalf("budget %d: cap %d is below the replaced TCP cap %d", total, got, replaced(total, 1024))
		}
	}
	// 既定の予算は従来の固定値のちょうど 2 倍なので、C は従来の上限と同じ値になる
	if got := ruleCapFor(UDPTotal); got != 4096 {
		t.Errorf("cap at the default UDP budget = %d, want 4096", got)
	}
	if got := ruleCapFor(TCPTotal); got != 1024 {
		t.Errorf("cap at the default TCP budget = %d, want 1024", got)
	}
}

// 予約の合計は予算に収まる(N × q <= T)。どの予算とルールの本数でも成り立つ。
func TestReserveTimesRulesFitsTheBudget(t *testing.T) {
	for total := TotalMin; total <= TotalMax; total++ {
		if q := reserveFor(total, 1); q != 0 {
			t.Fatalf("reserveFor(%d, 1) = %d, want 0", total, q)
		}
		for rules := 2; rules <= 300; rules++ {
			q := reserveFor(total, rules)
			if want := (total - (total+1)/2) / (rules - 1); q != want {
				t.Fatalf("reserveFor(%d, %d) = %d, want %d", total, rules, q, want)
			}
			if rules*q > total {
				t.Fatalf("budget %d, %d rules: %d x %d does not fit", total, rules, rules, q)
			}
			if q > ruleCapFor(total) {
				t.Fatalf("budget %d, %d rules: reserve %d is over the cap %d", total, rules, q, ruleCapFor(total))
			}
		}
	}
}

// 1 本のルールへのフラッドの最中も、他のどのルールも自分の予約まで新しいフローを通せる。
func TestPoolReserveIsReachableUnderAFlood(t *testing.T) {
	for _, total := range []int{16, 17, 100, 101, 1024, 2048} {
		for _, rules := range []int{2, 3, 5, 8, 33} {
			p := newTrackedPool(total)
			ls := make([]*Listener, rules)
			for i := range ls {
				ls[i] = p.Listener(fmt.Sprintf("r%d", i+1))
			}
			q := p.Reserve()
			fillUp(t, ls[0], total+1) // 1 本目を拒まれるまで埋める
			for i := 1; i < rules; i++ {
				if n, ref := acquireN(ls[i], q); n != q {
					t.Fatalf("budget %d, %d rules: rule %d admitted %d of its reserve of %d (refused with %q)",
						total, rules, i+1, n, q, ref.Reason)
				}
			}
			ok(t, p)
		}
	}
}

// 分割と統合で所属ルールが変わった待ち受けの既存のフローは、移動先のルールで数える(仕様 7 節)。
// 統合で移動先のルールが上限を超えても既存のフローは追い出さず、新しいフローだけを拒む。
func TestPoolSetRuleMovesExistingFlows(t *testing.T) {
	p := newTrackedPool(10) // N = 3 で C = 5、q = 2
	a, b, c := p.Listener("r1"), p.Listener("r2"), p.Listener("r3")
	if n, _ := acquireN(a, 4); n != 4 {
		t.Fatalf("r1 admitted %d flows, want 4", n)
	}
	if n, _ := acquireN(b, 3); n != 3 {
		t.Fatalf("r2 admitted %d flows, want 3", n)
	}
	a.SetRule("r2") // r1 と r2 の統合。r2 は 7 本を持ち、上限 5 を超える
	if got := p.RuleFlows("r1"); got != 0 {
		t.Errorf("RuleFlows(r1) after the merge = %d, want 0", got)
	}
	if got := p.RuleFlows("r2"); got != 7 {
		t.Errorf("RuleFlows(r2) after the merge = %d, want 7", got)
	}
	if p.InUse() != 7 {
		t.Errorf("InUse after the merge = %d, want 7 (no flow is evicted)", p.InUse())
	}
	for _, l := range []*Listener{a, b} {
		if ref, admitted := l.Acquire(); admitted || ref.Reason != ReasonRuleCap {
			t.Errorf("a rule over its cap must be refused with %q, got %+v (admitted=%v)", ReasonRuleCap, ref, admitted)
		}
	}
	// 予約の内側の r3 は、統合の後も空きのあいだ先着順に通せる
	if n, _ := acquireN(c, 4); n != 3 {
		t.Errorf("r3 admitted %d flows, want 3 (the rest of the budget)", n)
	}
	ok(t, p)
	// 元のルールに新しい待ち受けを開けば、そのルールは空の状態から数え直す
	fresh := p.Listener("r1")
	if got := p.RuleFlows("r1"); got != 0 {
		t.Errorf("RuleFlows(r1) with a fresh listener = %d, want 0", got)
	}
	if ref, admitted := fresh.Acquire(); admitted || ref.Reason != ReasonBudget {
		t.Errorf("refusal = %+v, admitted = %v, want %q (the budget is full)", ref, admitted, ReasonBudget)
	}
	ok(t, p)
}

// 受け付けをやめた待ち受け(Retiring)のフローは、プロセス全体の数に残り、ルールごとの数から外れる。
// そのルールは受け付けているルールの集合から外れるので、残りのルールの予約は増える。
func TestPoolStopAcceptingKeepsTheFlowsInTheBudget(t *testing.T) {
	p := newTrackedPool(10)
	retiring := p.Listener("r1")
	other := p.Listener("r2")
	if p.Reserve() != 5 {
		t.Fatalf("reserve with 2 rules = %d, want 5", p.Reserve())
	}
	if n, _ := acquireN(retiring, 2); n != 2 {
		t.Fatal("the first two flows must pass")
	}
	retiring.StopAccepting()
	if p.InUse() != 2 {
		t.Errorf("InUse = %d, want 2 (a retiring listener still holds its flows)", p.InUse())
	}
	if got := p.RuleFlows("r1"); got != 0 {
		t.Errorf("RuleFlows(r1) = %d, want 0 (a retiring listener is out of the rule's count)", got)
	}
	if p.Rules() != 1 || p.Reserve() != 0 {
		t.Errorf("rules = %d, reserve = %d, want 1 and 0 (only r2 accepts now)", p.Rules(), p.Reserve())
	}
	ok(t, p)
	// 残った 1 本のルールは、Retiring のフローを除いた予算の残りを全部使える
	if n, _ := acquireN(other, 9); n != 8 {
		t.Errorf("r2 admitted %d flows, want 8 (the rest of the budget)", n)
	}
	// 宣言に戻った待ち受けは、また数に入る
	retiring.Accept()
	if got := p.RuleFlows("r1"); got != 2 {
		t.Errorf("RuleFlows(r1) after Accept = %d, want 2", got)
	}
	if p.Rules() != 2 {
		t.Errorf("rules after Accept = %d, want 2", p.Rules())
	}
	ok(t, p)
}

// 閉じた待ち受けの残りのフローは、Release を呼ぶまでプロセス全体の数に残る。
func TestPoolCloseKeepsFlowsUntilRelease(t *testing.T) {
	p := newTrackedPool(4)
	l := p.Listener("r1")
	if n, _ := acquireN(l, 2); n != 2 {
		t.Fatal("the first two flows must pass")
	}
	l.Close()
	if p.InUse() != 2 {
		t.Errorf("InUse after Close = %d, want 2", p.InUse())
	}
	if got := p.RuleFlows("r1"); got != 0 {
		t.Errorf("RuleFlows(r1) after Close = %d, want 0", got)
	}
	if p.Rules() != 0 {
		t.Errorf("rules after Close = %d, want 0", p.Rules())
	}
	ok(t, p)
	l.Release()
	l.Release()
	if p.InUse() != 0 {
		t.Errorf("InUse after the releases = %d, want 0", p.InUse())
	}
	l.Close() // 2 回目は何もしない
	if p.InUse() != 0 {
		t.Errorf("InUse after a second Close = %d, want 0", p.InUse())
	}
	ok(t, p)
}

// 枠を取っていない Release は数を負にしない。負にすると、以後の判定が予算を過大に空いていると見る。
func TestPoolReleaseNeverGoesNegative(t *testing.T) {
	p := newTrackedPool(2)
	l := p.Listener("r1")
	l.Release()
	l.Release()
	if p.InUse() != 0 || l.Flows() != 0 {
		t.Fatalf("InUse = %d, listener flows = %d, want 0 and 0", p.InUse(), l.Flows())
	}
	if n, _ := acquireN(l, 3); n != 2 {
		t.Errorf("admitted %d flows after the stray releases, want 2 (the budget is intact)", n)
	}
	ok(t, p)
}

// 拒否の数は、ルールごと、理由ごとに数える。3 つの理由を混ぜても取り違えない。
func TestPoolRefusalCounters(t *testing.T) {
	p := newTrackedPool(10) // C = 5、N = 3 で q = 2
	a, b, c := p.Listener("r1"), p.Listener("r2"), p.Listener("r3")
	acquireN(a, 4) // 4 本通る
	acquireN(b, 6) // 4 本通り、2 本は reserve(r3 の予約の分だけ空きが残る)
	acquireN(a, 1) // reserve
	acquireN(c, 4) // 2 本通り(予約)、2 本は budget
	fresh := p.Listener("r1")
	acquireN(fresh, 1) // budget(予算が先に判定される)
	got := p.Refusals()
	want := map[string]map[Reason]uint64{
		"r1": {ReasonReserve: 1, ReasonBudget: 1},
		"r2": {ReasonReserve: 2},
		"r3": {ReasonBudget: 2},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("Refusals = %+v, want %+v", got, want)
	}
	// 返す表は複製で、書き換えても Pool の数は変わらない
	got["r1"][ReasonReserve] = 99
	if p.Refusals()["r1"][ReasonReserve] != 1 {
		t.Error("Refusals must return a copy")
	}
	ok(t, p)

	// ルール 1 本の上限の拒否も、同じ表に理由ごとに積む
	p2 := newTrackedPool(10)
	d := p2.Listener("r1")
	p2.Listener("r2")
	acquireN(d, 7) // 5 本通り(上限)、2 本は rule_cap
	if n := p2.Refusals()["r1"][ReasonRuleCap]; n != 2 {
		t.Errorf("rule_cap refusals = %d, want 2 (all: %+v)", n, p2.Refusals())
	}
	ok(t, p2)
}

// ログの文言は理由で分かれる(設計文書 7a.10 節の「拒否の報告」)。
func TestRefusalMessages(t *testing.T) {
	p := newTrackedPool(1)
	l := p.Listener("r1")
	if _, admitted := l.Acquire(); !admitted {
		t.Fatal("the first flow must pass")
	}
	ref, _ := l.Acquire()
	if got, want := ref.String(), "flow budget full: 1 of 1 in use in this process"; got != want {
		t.Errorf("budget message = %q, want %q", got, want)
	}

	// 既定の UDP の予算でルールが 2 本、1 本が上限まで持ったときの行(設計文書 7a.10 節の例)
	p2 := newTrackedPool(UDPTotal)
	l2 := p2.Listener("r1")
	p2.Listener("r2")
	acquireN(l2, UDPTotal/2+1)
	ref2, _ := l2.Acquire()
	want2 := "rule r1 holds 4096 flows and the rest of the budget is reserved for 1 other rule"
	if got := ref2.String(); got != want2 {
		t.Errorf("rule cap message = %q, want %q", got, want2)
	}

	// 予約による拒否の行
	p3 := newTrackedPool(10)
	a, b, c := p3.Listener("r1"), p3.Listener("r2"), p3.Listener("r3")
	acquireN(a, 4)
	acquireN(b, 4)
	_ = c
	ref3, _ := a.Acquire()
	want3 := "rule r1 holds 4 flows, above its reserve of 2, and the free part of the budget, 2 of 10, is reserved for 2 other rules"
	if got := ref3.String(); got != want3 {
		t.Errorf("reserve message = %q, want %q", got, want3)
	}
}

// model は隔離予約の式(設計文書 7a.10 節)を Pool とは別に素直に書き下したもの。待ち受けごとの
// フロー数から毎回すべてを数え直し、Pool が足し引きで保つ値のずれと式の取り違えを見つける。
type model struct {
	total     int
	flows     []int
	rules     []string
	accepting []bool
	open      []bool
}

func (m *model) add(rule string) int {
	m.flows = append(m.flows, 0)
	m.rules = append(m.rules, rule)
	m.accepting = append(m.accepting, true)
	m.open = append(m.open, true)
	return len(m.flows) - 1
}

// inUse は u。閉じた待ち受けの返していないフローも数える。
func (m *model) inUse() int {
	n := 0
	for _, f := range m.flows {
		n += f
	}
	return n
}

// acceptingRules は A と、そのルールごとの u_r。
func (m *model) acceptingRules() map[string]int {
	out := map[string]int{}
	for i := range m.flows {
		if m.open[i] && m.accepting[i] {
			out[m.rules[i]] += m.flows[i]
		}
	}
	return out
}

func (m *model) cap() int {
	if m.total <= 0 {
		return 0
	}
	return (m.total + 1) / 2
}

func (m *model) reserve() int {
	a := m.acceptingRules()
	if m.total <= 0 || len(a) < 2 {
		return 0
	}
	return (m.total - m.cap()) / (len(a) - 1)
}

// judge は待ち受け i の新しいフローを通すかを判定する(数は動かさない)。
func (m *model) judge(i int) (Reason, bool) {
	if m.total <= 0 {
		return "", true
	}
	u := m.inUse()
	if u >= m.total {
		return ReasonBudget, false
	}
	a := m.acceptingRules()
	rule := m.rules[i]
	ruleFlows := a[rule]
	if !(m.open[i] && m.accepting[i]) {
		ruleFlows += m.flows[i]
	}
	if len(a) >= 2 && ruleFlows >= m.cap() {
		return ReasonRuleCap, false
	}
	q := m.reserve()
	if ruleFlows < q {
		return "", true
	}
	others := 0
	for s, f := range a {
		if s != rule && f < q {
			others += q - f
		}
	}
	if m.total-u-others >= 1 {
		return "", true
	}
	return ReasonReserve, false
}

func (m *model) acquire(i int) (Reason, bool) {
	reason, admitted := m.judge(i)
	if admitted {
		m.flows[i]++
	}
	return reason, admitted
}

func (m *model) release(i int) {
	if m.flows[i] == 0 {
		return
	}
	m.flows[i]--
}

// 取得、返却、所属ルールの付け替え、Retiring、閉鎖、待ち受けの追加を混ぜた列に対して、Pool と
// 式を素直に書き下した模型が同じフローを通し、同じ理由で拒む。数の不変条件も毎手で確かめる。
func TestPoolMatchesTheFormula(t *testing.T) {
	for _, total := range []int{20, 8, 30, 12, 1, 16, 47} {
		rnd := rand.New(rand.NewPCG(1, uint64(total)))
		pool := newTrackedPool(total)
		m := &model{total: total}
		var ls []*Listener
		var held []int
		add := func(rule string) {
			ls = append(ls, pool.Listener(rule))
			m.add(rule)
			held = append(held, 0)
		}
		add("r1")
		add("r1")
		add("r2")
		rules := []string{"r1", "r2", "r3", "r4"}
		for step := range 6000 {
			i := rnd.IntN(len(ls))
			switch rnd.IntN(10) {
			case 0, 1, 2, 3, 4, 5: // 枠を取る
				gotRef, gotOK := ls[i].Acquire()
				wantReason, wantOK := m.acquire(i)
				if gotOK != wantOK || (!gotOK && gotRef.Reason != wantReason) {
					t.Fatalf("budget %d step %d listener %d (rule %s): Pool admitted=%v reason=%q, the formula says admitted=%v reason=%q (in use %d, rules %v, reserve %d)",
						total, step, i, m.rules[i], gotOK, gotRef.Reason, wantOK, wantReason, pool.InUse(), m.acceptingRules(), m.reserve())
				}
				if gotOK {
					held[i]++
				}
				// 予約の内側にいるルールは、予算に空きがあるかぎり reserve で拒まれない
				if !gotOK && gotRef.Reason == ReasonReserve && gotRef.RuleFlows < gotRef.Reserve {
					t.Fatalf("budget %d step %d: rule %s holds %d flows, below its reserve of %d, and was refused with %q",
						total, step, gotRef.RuleID, gotRef.RuleFlows, gotRef.Reserve, gotRef.Reason)
				}
			case 6, 7: // 枠を返す
				if held[i] == 0 {
					continue
				}
				ls[i].Release()
				m.release(i)
				held[i]--
			case 8: // 所属ルールを付け替える、または受け付けを止める・再開する
				switch rnd.IntN(3) {
				case 0:
					r := rules[rnd.IntN(len(rules))]
					ls[i].SetRule(r)
					m.rules[i] = r
				case 1:
					ls[i].StopAccepting()
					m.accepting[i] = false
				default:
					ls[i].Accept()
					m.accepting[i] = true
				}
			default: // 待ち受けを閉じる、または開く
				if len(ls) < 7 && rnd.IntN(2) == 0 {
					add(rules[rnd.IntN(len(rules))])
					continue
				}
				if !m.open[i] {
					continue
				}
				ls[i].Close()
				m.open[i] = false
			}
			if pool.InUse() != m.inUse() {
				t.Fatalf("budget %d step %d: InUse = %d, the formula counts %d", total, step, pool.InUse(), m.inUse())
			}
			if total > 0 && pool.InUse() > total {
				t.Fatalf("budget %d step %d: InUse = %d, over the budget", total, step, pool.InUse())
			}
			if err := pool.checkInvariants(); err != nil {
				t.Fatalf("budget %d step %d: %v", total, step, err)
			}
			if got, want := pool.Reserve(), m.reserve(); got != want {
				t.Fatalf("budget %d step %d: reserve = %d, the formula says %d", total, step, got, want)
			}
			for rule, flows := range m.acceptingRules() {
				if got := pool.RuleFlows(rule); got != flows {
					t.Fatalf("budget %d step %d: RuleFlows(%s) = %d, the formula counts %d", total, step, rule, got, flows)
				}
			}
		}
	}
}

// Acquire と Release を並行に呼んでも、数は壊れず、予算を超えない(-race で流す)。
func TestPoolConcurrentAcquireRelease(t *testing.T) {
	const total, workers, rounds = 40, 16, 500
	p := newTrackedPool(total)
	ls := []*Listener{p.Listener("r1"), p.Listener("r1"), p.Listener("r2"), p.Listener("r3")}
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			l := ls[w%len(ls)]
			for range rounds {
				if _, admitted := l.Acquire(); admitted {
					l.Release()
				}
				switch w % 4 {
				case 0:
					l.SetRule("r1")
					l.SetRule("r2")
				case 1:
					l.StopAccepting()
					l.Accept()
				}
			}
		}(w)
	}
	wg.Wait()
	if p.InUse() != 0 {
		t.Errorf("InUse after every flow was released = %d, want 0", p.InUse())
	}
	ok(t, p)
	// 予算はそのまま残っている。1 本のルールだけを使い、予算のすべてを取り直せることを確かめる
	p2 := newTrackedPool(total)
	l := p2.Listener("solo")
	if n, _ := acquireN(l, total+1); n != total {
		t.Errorf("only %d of the %d flows fit after the concurrent run", n, total)
	}
	ok(t, p2)
}

// 並行した取得と返却の最中に待ち受けの集合が変わっても、数はずれない(-race で流す)。
func TestPoolConcurrentRuleSetChanges(t *testing.T) {
	p := newTrackedPool(64)
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for round := range 200 {
				l := p.Listener(fmt.Sprintf("r%d", w%3))
				held := 0
				for range 4 {
					if _, admitted := l.Acquire(); admitted {
						held++
					}
				}
				if round%2 == 0 {
					l.SetRule(fmt.Sprintf("s%d", w))
				}
				l.StopAccepting()
				l.Close()
				for range held {
					l.Release()
				}
			}
		}(w)
	}
	wg.Wait()
	if p.InUse() != 0 {
		t.Errorf("InUse after every listener closed = %d, want 0", p.InUse())
	}
	if p.Rules() != 0 {
		t.Errorf("accepting rules after every listener closed = %d, want 0", p.Rules())
	}
	ok(t, p)
}

// bind の済んでいない待ち受けの枠(PendingListener)は、Accept を呼ぶまで受け付けているルールの
// 集合 A に入らない。枠を取れば予算は使うが、ルールごとの数には入らない(設計文書 7a.10 節)。
func TestPoolPendingListenerStaysOutOfTheAcceptingRules(t *testing.T) {
	p := newTrackedPool(10)
	held := p.Listener("r1")
	if n, _ := acquireN(held, 3); n != 3 {
		t.Fatalf("r1 admitted %d flows, want 3", n)
	}
	if p.Rules() != 1 || p.Reserve() != 0 {
		t.Fatalf("rules = %d, reserve = %d, want 1 and 0", p.Rules(), p.Reserve())
	}
	pending := p.PendingListener("r2")
	if p.Rules() != 1 || p.Reserve() != 0 {
		t.Errorf("rules = %d, reserve = %d after a pending listener, want 1 and 0", p.Rules(), p.Reserve())
	}
	if got := p.RuleFlows("r2"); got != 0 {
		t.Errorf("RuleFlows(r2) = %d, want 0", got)
	}
	// r1 は A に 1 本だけのルールなので、予算のすべてを使える
	if n, ref := acquireN(held, 7); n != 7 {
		t.Errorf("r1 admitted %d of the remaining budget, want 7 (refused with %q)", n, ref.Reason)
	}
	held.Release()
	// 受け付けていない枠でも判定は数の帳簿だけを見るので、枠は取れる。取ったフローは予算に入り、
	// ルールごとの数には入らず、ルールを A にも入れない
	if _, admitted := pending.Acquire(); !admitted {
		t.Error("a pending listener must still be able to take a slot (a flow accepted just before the socket was ready)")
	}
	if p.InUse() != 10 {
		t.Errorf("InUse = %d, want 10", p.InUse())
	}
	if got := p.RuleFlows("r2"); got != 0 {
		t.Errorf("RuleFlows(r2) = %d, want 0 (a pending listener is out of the rule's count)", got)
	}
	if p.Rules() != 1 {
		t.Errorf("rules = %d, want 1 (a pending listener does not join A by taking a slot)", p.Rules())
	}
	ok(t, p)
	// Accept で A に入り、そのフローがルールごとの数に入る
	pending.Accept()
	if p.Rules() != 2 || p.Reserve() != 5 {
		t.Errorf("rules = %d, reserve = %d after Accept, want 2 and 5", p.Rules(), p.Reserve())
	}
	if got := p.RuleFlows("r2"); got != 1 {
		t.Errorf("RuleFlows(r2) after Accept = %d, want 1", got)
	}
	ok(t, p)
}

// BenchmarkAcquireRelease measures the cost of the hot path (Acquire used to do a per-flow map
// write kept only for an invariant check, which has since moved to pool_test.go). It uses the plain Pool, not trackedPool, since the tracking
// wrapper exists only to help tests and would skew the measurement. The rule count varies because
// ruleFlowsForLocked, the rule_cap check and the reserve check all read len(p.accepting).
func BenchmarkAcquireRelease(b *testing.B) {
	for _, rules := range []int{1, 32, 1024} {
		b.Run(fmt.Sprintf("rules=%d", rules), func(b *testing.B) {
			p := NewPool(TotalMax)
			var l *Listener
			for i := range rules {
				ln := p.Listener(fmt.Sprintf("r%d", i))
				if i == 0 {
					l = ln
				}
			}
			b.ResetTimer()
			for range b.N {
				if _, ok := l.Acquire(); ok {
					l.Release()
				}
			}
		})
	}
}
