package resource

import (
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
)

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

// プロセス全体の予算は、ルールごとの上限を持たないプールでも効く。拒否の理由は budget。
func TestPoolBudget(t *testing.T) {
	p := NewPool(3, 0)
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
	if _, ok := l.Acquire(); !ok {
		t.Error("a released slot must be reusable")
	}
}

// ルールごとの上限は、同じルールの待ち受けの合計で見る。他のルールは残りの予算を使える。
func TestPoolRuleCapSumsTheRuleListeners(t *testing.T) {
	p := NewPool(10, 3)
	a1 := p.Listener("r1")
	a2 := p.Listener("r1")
	b := p.Listener("r2")
	if n, _ := acquireN(a1, 2); n != 2 {
		t.Fatalf("r1's first listener admitted %d flows, want 2", n)
	}
	passed, ref := acquireN(a2, 3)
	if passed != 1 {
		t.Errorf("r1's second listener admitted %d flows, want 1 (2 of the cap of 3 are held by the first)", passed)
	}
	if ref.Reason != ReasonRuleCap {
		t.Errorf("refusal reason = %q, want %q", ref.Reason, ReasonRuleCap)
	}
	if ref.RuleID != "r1" || ref.RuleFlows != 3 || ref.RuleCap != 3 {
		t.Errorf("refusal = %+v, want rule r1 holding 3 of a cap of 3", ref)
	}
	if got := p.RuleFlows("r1"); got != 3 {
		t.Errorf("RuleFlows(r1) = %d, want 3", got)
	}
	if n, _ := acquireN(b, 3); n != 3 {
		t.Errorf("r2 admitted %d flows, want 3 (its own cap, out of the shared budget)", n)
	}
	if p.InUse() != 6 {
		t.Errorf("InUse = %d, want 6", p.InUse())
	}
}

// 予算が先に尽きたときの理由は budget、ルールごとの上限が先なら rule_cap。
func TestPoolBudgetBeatsRuleCap(t *testing.T) {
	p := NewPool(2, 5)
	l := p.Listener("r1")
	if n, _ := acquireN(l, 2); n != 2 {
		t.Fatal("the first two flows must pass")
	}
	ref, ok := l.Acquire()
	if ok {
		t.Fatal("a flow over the budget must be refused")
	}
	if ref.Reason != ReasonBudget {
		t.Errorf("reason = %q, want %q (the budget is tighter than the rule cap here)", ref.Reason, ReasonBudget)
	}
}

// 分割と統合で所属ルールが変わった待ち受けの既存のフローは、移動先のルールで数える(仕様 7 節)。
func TestPoolSetRuleMovesExistingFlows(t *testing.T) {
	p := NewPool(10, 2)
	l := p.Listener("r1")
	if n, _ := acquireN(l, 2); n != 2 {
		t.Fatal("the first two flows must pass")
	}
	l.SetRule("r2")
	if got := p.RuleFlows("r1"); got != 0 {
		t.Errorf("RuleFlows(r1) after the relabel = %d, want 0", got)
	}
	if got := p.RuleFlows("r2"); got != 2 {
		t.Errorf("RuleFlows(r2) after the relabel = %d, want 2", got)
	}
	// 移動先のルールで上限に達しているので、この待ち受けは新しいフローを通さない
	if _, ok := l.Acquire(); ok {
		t.Error("the relabelled listener must be at its new rule's cap")
	}
	// 元のルールに別の待ち受けがあれば、そちらは空の枠を使える
	other := p.Listener("r1")
	if n, _ := acquireN(other, 2); n != 2 {
		t.Error("the old rule must be empty again")
	}
}

// 受け付けをやめた待ち受け(Retiring)のフローは、プロセス全体の数に残り、ルールごとの数から外れる。
func TestPoolStopAcceptingKeepsTheFlowsInTheBudget(t *testing.T) {
	p := NewPool(10, 2)
	retiring := p.Listener("r1")
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
	fresh := p.Listener("r1")
	if n, _ := acquireN(fresh, 2); n != 2 {
		t.Error("a new listener of the same rule must get the whole rule cap")
	}
	// 宣言に戻った待ち受けは、また数に入る
	retiring.Accept()
	if got := p.RuleFlows("r1"); got != 4 {
		t.Errorf("RuleFlows(r1) after Accept = %d, want 4", got)
	}
}

// 閉じた待ち受けの残りのフローは、Release を呼ぶまでプロセス全体の数に残る。
func TestPoolCloseKeepsFlowsUntilRelease(t *testing.T) {
	p := NewPool(4, 0)
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
	l.Release()
	l.Release()
	if p.InUse() != 0 {
		t.Errorf("InUse after the releases = %d, want 0", p.InUse())
	}
	l.Close() // 2 回目は何もしない
	if p.InUse() != 0 {
		t.Errorf("InUse after a second Close = %d, want 0", p.InUse())
	}
}

// 枠を取っていない Release は数を負にしない。負にすると、以後の判定が予算を過大に空いていると見る。
func TestPoolReleaseNeverGoesNegative(t *testing.T) {
	p := NewPool(2, 0)
	l := p.Listener("r1")
	l.Release()
	l.Release()
	if p.InUse() != 0 || l.Flows() != 0 {
		t.Fatalf("InUse = %d, listener flows = %d, want 0 and 0", p.InUse(), l.Flows())
	}
	if n, _ := acquireN(l, 3); n != 2 {
		t.Errorf("admitted %d flows after the stray releases, want 2 (the budget is intact)", n)
	}
}

// 拒否の数は、ルールごと、理由ごとに数える。通ったフローは数えない。
func TestPoolRefusalCounters(t *testing.T) {
	p := NewPool(3, 2)
	a := p.Listener("r1")
	b := p.Listener("r2")
	acquireN(a, 4) // 2 は通り、2 は rule_cap で拒む
	acquireN(b, 3) // 1 は通り(予算の残りは 1)、2 は budget で拒む
	got := p.Refusals()
	want := map[string]map[Reason]uint64{
		"r1": {ReasonRuleCap: 2},
		"r2": {ReasonBudget: 2},
	}
	if len(got) != len(want) {
		t.Fatalf("Refusals = %+v, want %+v", got, want)
	}
	for rule, byReason := range want {
		for reason, n := range byReason {
			if got[rule][reason] != n {
				t.Errorf("Refusals[%s][%s] = %d, want %d (all: %+v)", rule, reason, got[rule][reason], n, got)
			}
		}
		if len(got[rule]) != len(byReason) {
			t.Errorf("Refusals[%s] = %+v, want %+v", rule, got[rule], byReason)
		}
	}
	// 返す表は複製で、書き換えても Pool の数は変わらない
	got["r1"][ReasonRuleCap] = 99
	if p.Refusals()["r1"][ReasonRuleCap] != 2 {
		t.Error("Refusals must return a copy")
	}
}

// ログの文言は理由で分かれる(設計文書 7a.10 節の「拒否の報告」)。
func TestRefusalMessages(t *testing.T) {
	p := NewPool(1, 1)
	l := p.Listener("r1")
	if _, ok := l.Acquire(); !ok {
		t.Fatal("the first flow must pass")
	}
	ref, _ := l.Acquire()
	if got, want := ref.String(), "flow budget full (1 of 1 in use in this process)"; got != want {
		t.Errorf("budget message = %q, want %q", got, want)
	}
	p2 := NewPool(10, 1)
	l2 := p2.Listener("r1")
	if _, ok := l2.Acquire(); !ok {
		t.Fatal("the first flow must pass")
	}
	ref2, _ := l2.Acquire()
	if got, want := ref2.String(), "rule r1 holds 1 of the 1 flows one rule may hold"; got != want {
		t.Errorf("rule cap message = %q, want %q", got, want)
	}
}

// oldGuard は Pool を置く前の判定(設計文書 7a.10 節の移行の手順 2 が置き換えたもの)。
// relay.Manager はルールごとの数を待ち受けの合計から読み、そのあとにプロセス全体の Counter で
// 枠を取っていた。移行の手順 2 の完了条件は、同じ入力の列に対して通す・拒むが一致することである。
type oldGuard struct {
	total, ruleCap int
	inUse          int
	flows          []int // 待ち受けごとのフロー数
	rules          []string
	accepting      []bool
	open           []bool
}

func (g *oldGuard) add(rule string) int {
	g.flows = append(g.flows, 0)
	g.rules = append(g.rules, rule)
	g.accepting = append(g.accepting, true)
	g.open = append(g.open, true)
	return len(g.flows) - 1
}

func (g *oldGuard) ruleFlows(rule string) int {
	n := 0
	for i := range g.flows {
		if g.open[i] && g.accepting[i] && g.rules[i] == rule {
			n += g.flows[i]
		}
	}
	return n
}

func (g *oldGuard) acquire(i int) bool {
	if g.ruleCap > 0 && g.ruleFlows(g.rules[i]) >= g.ruleCap {
		return false
	}
	if g.total > 0 && g.inUse >= g.total {
		return false
	}
	g.inUse++
	g.flows[i]++
	return true
}

func (g *oldGuard) release(i int) {
	if g.flows[i] == 0 {
		return
	}
	g.flows[i]--
	g.inUse--
}

// 移行の手順 2 の完了条件:待ち受けの追加、所属ルールの付け替え、Retiring、閉鎖、取得と返却を
// 混ぜた列に対して、Pool と置き換え前の判定が同じフローを通し、同じフローを拒む。
func TestPoolMatchesTheJudgementItReplaces(t *testing.T) {
	for _, c := range []struct{ total, ruleCap int }{{20, 8}, {8, 8}, {30, 3}, {12, 0}, {0, 4}} {
		rnd := rand.New(rand.NewPCG(1, uint64(c.total*100+c.ruleCap)))
		pool := NewPool(c.total, c.ruleCap)
		old := &oldGuard{total: c.total, ruleCap: c.ruleCap}
		var ls []*Listener
		var held [][]int // 待ち受けごとに、取れている枠の数を両者で数える
		add := func(rule string) {
			ls = append(ls, pool.Listener(rule))
			old.add(rule)
			held = append(held, []int{0, 0})
		}
		add("r1")
		add("r1")
		add("r2")
		rules := []string{"r1", "r2", "r3"}
		for step := range 4000 {
			i := rnd.IntN(len(ls))
			switch rnd.IntN(10) {
			case 0, 1, 2, 3, 4, 5: // 枠を取る
				if !old.open[i] || !old.accepting[i] {
					continue
				}
				_, newOK := ls[i].Acquire()
				oldOK := old.acquire(i)
				if newOK != oldOK {
					t.Fatalf("case %+v step %d listener %d: Pool admitted=%v, the replaced judgement admitted=%v (in use %d, rule %s holds %d)",
						c, step, i, newOK, oldOK, pool.InUse(), old.rules[i], old.ruleFlows(old.rules[i]))
				}
				if newOK {
					held[i][0]++
					held[i][1]++
				}
			case 6, 7: // 枠を返す
				if held[i][0] == 0 {
					continue
				}
				ls[i].Release()
				old.release(i)
				held[i][0]--
				held[i][1]--
			case 8: // 所属ルールを付け替える、または受け付けを止める・再開する
				switch rnd.IntN(3) {
				case 0:
					r := rules[rnd.IntN(len(rules))]
					ls[i].SetRule(r)
					old.rules[i] = r
				case 1:
					ls[i].StopAccepting()
					old.accepting[i] = false
				default:
					ls[i].Accept()
					old.accepting[i] = true
				}
			default: // 待ち受けを閉じる、または開く
				if len(ls) < 6 && rnd.IntN(2) == 0 {
					add(rules[rnd.IntN(len(rules))])
					continue
				}
				if !old.open[i] {
					continue
				}
				ls[i].Close()
				old.open[i] = false
			}
			if pool.InUse() != old.inUse {
				t.Fatalf("case %+v step %d: InUse = %d, the replaced judgement counts %d", c, step, pool.InUse(), old.inUse)
			}
		}
	}
}

// Acquire と Release を並行に呼んでも、数は壊れず、予算を超えない(-race で流す)。
func TestPoolConcurrentAcquireRelease(t *testing.T) {
	const total, ruleCap, workers, rounds = 40, 10, 16, 500
	p := NewPool(total, ruleCap)
	ls := []*Listener{p.Listener("r1"), p.Listener("r1"), p.Listener("r2"), p.Listener("r3")}
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			l := ls[w%len(ls)]
			for range rounds {
				if _, ok := l.Acquire(); ok {
					l.Release()
				}
				if w%4 == 0 {
					l.SetRule("r1")
					l.SetRule("r2")
				}
			}
		}(w)
	}
	wg.Wait()
	if p.InUse() != 0 {
		t.Errorf("InUse after every flow was released = %d, want 0", p.InUse())
	}
	// 予算はそのまま残っている。ルールごとの上限に当たらないよう、1 フローずつ別のルールで埋める
	for i := range total {
		if _, ok := p.Listener(fmt.Sprintf("fill%d", i)).Acquire(); !ok {
			t.Fatalf("only %d of the %d flows fit after the concurrent run", i, total)
		}
	}
	if _, ok := p.Listener("fill_over").Acquire(); ok {
		t.Error("a flow over the budget passed after the concurrent run")
	}
}
