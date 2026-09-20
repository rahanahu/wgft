package resource

import (
	"fmt"
	"sync"
)

// Reason は Pool が新しいフローを拒んだ理由(設計文書 7a.10 節の「拒否の報告」)。
// Admission Policy の drop の種類とは別で、SQLite にも drop カウンタにも混ぜない。
// 隔離予約の理由(reserve)は、判定を予約の式に切り替える移行の手順 4 で加わる。
type Reason string

const (
	// ReasonBudget はプロセス全体の予算が埋まっていること。
	ReasonBudget Reason = "budget"
	// ReasonRuleCap はルール 1 本の上限に達していること。
	ReasonRuleCap Reason = "rule_cap"
)

// Pool は 1 つのプロトコルのフロー予算(設計文書 7a.5、7a.10 節の Resource Guard)。
// プロセス全体の予算とルールごとの上限を 1 つの排他の中で判定し、ルールごと、理由ごとの拒否の数を
// プロセスが起動してからの累計として持つ。SQLite には保存しない。
//
// フローは待ち受け(Listener)に付けて数え、待ち受けから所属ルールへの対応は Pool が持つ。
// ルールのフロー数は、そのルールの待ち受けのフロー数の合計である。分割と統合で待ち受けの所属ルールが
// 変わると、その待ち受けの既存のフローは移動先のルールで数える(仕様 7 節の規則のまま)。
type Pool struct {
	total   int // プロセス全体の予算。0 以下なら予算を持たない
	ruleCap int // ルール 1 本の上限。0 以下ならルールごとの上限を持たない

	mu        sync.Mutex
	inUse     int
	listeners map[*Listener]struct{}
	refusals  map[string]map[Reason]uint64
}

// NewPool は予算 total、ルール 1 本の上限 ruleCap のプールを作る。
func NewPool(total, ruleCap int) *Pool {
	return &Pool{total: total, ruleCap: ruleCap, listeners: map[*Listener]struct{}{}, refusals: map[string]map[Reason]uint64{}}
}

// Total はプロセス全体の予算。
func (p *Pool) Total() int { return p.total }

// RuleCap はルール 1 本の上限。
func (p *Pool) RuleCap() int { return p.ruleCap }

// InUse は今保持しているフローの数。受け付けをやめた待ち受けと、閉じた待ち受けの残りのフローも含む。
func (p *Pool) InUse() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.inUse
}

// RuleFlows はそのルールのフロー数(受け付けている待ち受けの合計)。
func (p *Pool) RuleFlows(ruleID string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for s := range p.listeners {
		if s.accepting && s.rule == ruleID {
			n += s.flows
		}
	}
	return n
}

// Refusals はルール ID から理由ごとの拒否の数への表を複製して返す。
func (p *Pool) Refusals() map[string]map[Reason]uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]map[Reason]uint64, len(p.refusals))
	for rule, byReason := range p.refusals {
		m := make(map[Reason]uint64, len(byReason))
		for reason, n := range byReason {
			m[reason] = n
		}
		out[rule] = m
	}
	return out
}

// Listener は待ち受け 1 つ分の枠を Pool に登録する。呼び出し側は待ち受けを閉じるときに Close を呼ぶ。
func (p *Pool) Listener(ruleID string) *Listener {
	l := &Listener{p: p, rule: ruleID, accepting: true, open: true}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.listeners[l] = struct{}{}
	return l
}

// Listener は Pool に登録した待ち受け 1 つ。フローの枠はこの型を通して取る。
// どの項目も Pool の排他が守るので、複数の goroutine から呼べる。
type Listener struct {
	p         *Pool
	rule      string
	accepting bool
	flows     int
	open      bool
}

// Acquire はフロー 1 つ分の枠を取る。取れたら真を返し、呼び出し側はフローの終わりに Release を
// 1 回呼ぶ。取れなければ理由を返し、何も数えない。拒否は理由ごとの数に 1 を足す。
func (l *Listener) Acquire() (Refusal, bool) {
	p := l.p
	p.mu.Lock()
	defer p.mu.Unlock()
	ruleFlows := l.flows + p.otherRuleFlowsLocked(l)
	if p.total > 0 && p.inUse >= p.total {
		return p.refuseLocked(ReasonBudget, l, ruleFlows), false
	}
	if p.ruleCap > 0 && ruleFlows >= p.ruleCap {
		return p.refuseLocked(ReasonRuleCap, l, ruleFlows), false
	}
	p.inUse++
	l.flows++
	return Refusal{}, true
}

// Release は Acquire で取った枠を返す。Acquire が真を返した回数より多く呼ばれたときは何もしない。
// 数を負にすると、以後の判定が予算を過大に空いていると見て守りが外れるためである。
func (l *Listener) Release() {
	p := l.p
	p.mu.Lock()
	defer p.mu.Unlock()
	if l.flows == 0 {
		return
	}
	l.flows--
	p.inUse--
}

// Flows はこの待ち受けが保持しているフローの数。
func (l *Listener) Flows() int {
	p := l.p
	p.mu.Lock()
	defer p.mu.Unlock()
	return l.flows
}

// SetRule は所属ルールを付け替える(分割と統合の relabel)。既存のフローは移動先のルールで数える。
func (l *Listener) SetRule(ruleID string) {
	p := l.p
	p.mu.Lock()
	defer p.mu.Unlock()
	l.rule = ruleID
}

// StopAccepting は、この待ち受けを新しいフローを受け付けない状態にする(設計文書 7a.3 節の
// Retiring)。残っているフローはプロセス全体の数に入り続けるが、ルールごとの数には入らない。
// ルール単位の fail-closed はそのルールの待ち受けをすべて Retiring にするので、ルールごとの上限の
// 判定は Retiring の待ち受けを見ない。
func (l *Listener) StopAccepting() {
	p := l.p
	p.mu.Lock()
	defer p.mu.Unlock()
	l.accepting = false
}

// Accept は StopAccepting でやめた受け付けを再開する(宣言に戻った UDP の待ち受け)。
func (l *Listener) Accept() {
	p := l.p
	p.mu.Lock()
	defer p.mu.Unlock()
	l.accepting = true
}

// Close は待ち受けを Pool から外す。まだ返していないフローは、Release を呼ぶまでプロセス全体の数に
// 残る(閉じた待ち受けのフローは、中継が閉じ終えるまで資源を使っているため)。
func (l *Listener) Close() {
	p := l.p
	p.mu.Lock()
	defer p.mu.Unlock()
	if !l.open {
		return
	}
	l.open = false
	delete(p.listeners, l)
}

// otherRuleFlowsLocked は、l と同じルールに属する他の待ち受けのフロー数の合計。
// 受け付けをやめた待ち受けの分は数えない。
func (p *Pool) otherRuleFlowsLocked(l *Listener) int {
	n := 0
	for s := range p.listeners {
		if s != l && s.accepting && s.rule == l.rule {
			n += s.flows
		}
	}
	return n
}

func (p *Pool) refuseLocked(reason Reason, l *Listener, ruleFlows int) Refusal {
	byReason := p.refusals[l.rule]
	if byReason == nil {
		byReason = map[Reason]uint64{}
		p.refusals[l.rule] = byReason
	}
	byReason[reason]++
	return Refusal{
		Reason: reason, RuleID: l.rule,
		InUse: p.inUse, Total: p.total,
		RuleFlows: ruleFlows, RuleCap: p.ruleCap,
	}
}

// Refusal は拒んだ 1 回の判定の内訳。中継はこれをログの文言にする(設計文書 7a.10 節)。
type Refusal struct {
	Reason    Reason
	RuleID    string
	InUse     int // 判定したときのプロセス全体のフロー数
	Total     int // プロセス全体の予算
	RuleFlows int // 判定したときのそのルールのフロー数
	RuleCap   int // ルール 1 本の上限
}

// String は理由を説明する 1 文。中継は待ち受けの名前と処置を前後に付けてログに出す。
func (r Refusal) String() string {
	switch r.Reason {
	case ReasonBudget:
		return fmt.Sprintf("flow budget full (%d of %d in use in this process)", r.InUse, r.Total)
	case ReasonRuleCap:
		return fmt.Sprintf("rule %s holds %d of the %d flows one rule may hold", r.RuleID, r.RuleFlows, r.RuleCap)
	default:
		return fmt.Sprintf("refused by the flow budget (%s)", r.Reason)
	}
}
