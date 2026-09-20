package resource

import (
	"fmt"
	"sync"
)

// Reason は Pool が新しいフローを拒んだ理由(設計文書 7a.10 節の「拒否の報告」)。
// Admission Policy の drop の種類とは別で、SQLite にも drop カウンタにも混ぜない。
type Reason string

const (
	// ReasonBudget はプロセス全体の予算が埋まっていること(u < T を満たさない)。
	ReasonBudget Reason = "budget"
	// ReasonRuleCap はルール 1 本の上限 C に達していること(ルールが 2 本以上あるときだけ効く)。
	ReasonRuleCap Reason = "rule_cap"
	// ReasonReserve は、自分の隔離予約を超えていて、残りの空きが他のルールの予約で埋まっていること。
	ReasonReserve Reason = "reserve"
)

// Pool は 1 つのプロトコルのフロー予算(設計文書 7a.5、7a.10 節の Resource Guard)。プロセス全体の
// 予算 T を共有プールとし、受け付けているルールごとの隔離予約で 1 つのルールへのフラッドが他の
// ルールの新しいフローを止めることを防ぐ。判定は 1 つの排他の中で行い、ルールごと、理由ごとの
// 拒否の数をプロセスが起動してからの累計として持つ。SQLite には保存しない。
//
// フローは待ち受け(Listener)に付けて数え、待ち受けから所属ルールへの対応は Pool が持つ。
// ルールのフロー数は、そのルールの受け付けている待ち受けのフロー数の合計である。分割と統合で
// 待ち受けの所属ルールが変わると、その待ち受けの既存のフローは移動先のルールで数える
// (仕様 7 節の規則のまま)。
//
// 記号は設計文書 7a.10 節に合わせる。T は予算、C はルールが 2 本以上あるときのルール 1 本の上限
// (ceil(T/2))、A は受け付けているルールの集合、N は A の大きさ、q は N が 2 以上のときの
// floor((T - C) / (N - 1))、u はプロセス全体のフロー数、u_r はルール r のフロー数である。
// ルール r の新しいフローは、u < T であり、N が 2 以上なら u_r < C であり、かつ u_r < q または
// T - u - Σ max(0, q - u_s) >= 1(和は A のうち r 以外)のときに通す。
//
// 判定を 1 回あたり一定の手間で済ませるため、u_r と Σ max(0, q - u_s) は足し引きで保つ。
// q は N が変わったときだけ変わるので、待ち受けの登録、閉鎖、受け付けの開始と停止、所属ルールの
// 付け替えのときに作り直す(設計文書 7a.10 節が A と q を Commit で更新すると定めているとおり、
// この 5 つの操作はどれも収束の Commit から呼ばれる)。
type Pool struct {
	total   int // T。0 以下なら予算を持たない(判定を行わない)
	ruleCap int // C。T から導く

	mu    sync.Mutex
	inUse int // u
	// listeners は登録している待ち受けと、閉じた後もまだフローを返し終えていない待ち受け。
	// 不変条件の検算(checkInvariants)のために持つ。
	listeners map[*Listener]struct{}
	// accepting は集合 A。受け付けているルールから、その待ち受けの数とフロー数への表。
	accepting map[string]*ruleFlows
	reserve   int // q
	// shortfall は Σ max(0, q - u_s)。和は A のすべてのルールを取る(判定では r の分を引く)。
	shortfall int
	refusals  map[string]map[Reason]uint64
}

// ruleFlows は受け付けているルール 1 本の内訳。
type ruleFlows struct {
	listeners int // そのルールの受け付けている待ち受けの数。0 になったらルールは A から外れる
	flows     int // u_r
}

// NewPool は予算 total のプールを作る。ルール 1 本の上限と隔離予約は total から導く。
func NewPool(total int) *Pool {
	return &Pool{
		total:     total,
		ruleCap:   ruleCapFor(total),
		listeners: map[*Listener]struct{}{},
		accepting: map[string]*ruleFlows{},
		refusals:  map[string]map[Reason]uint64{},
	}
}

// ruleCapFor は C。どの T でも ceil(T/2) で、残りの floor(T/2) は他のルールの予約に回る。
func ruleCapFor(total int) int {
	if total <= 0 {
		return 0
	}
	return (total + 1) / 2
}

// reserveFor は q。ルールが 1 本以下なら 0 で、そのルールは予算のすべてを使える。
func reserveFor(total, rules int) int {
	if total <= 0 || rules < 2 {
		return 0
	}
	return (total - ruleCapFor(total)) / (rules - 1)
}

// Total は予算 T。
func (p *Pool) Total() int { return p.total }

// RuleCap はルールが 2 本以上あるときのルール 1 本の上限 C。ルールが 1 本のときは効かない。
func (p *Pool) RuleCap() int { return p.ruleCap }

// Rules は今受け付けているルールの数 N。
func (p *Pool) Rules() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.accepting)
}

// Reserve はルール 1 本あたりの隔離予約 q。
func (p *Pool) Reserve() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.reserve
}

// InUse は今保持しているフローの数 u。受け付けをやめた待ち受けと、閉じた待ち受けの残りのフローも含む。
func (p *Pool) InUse() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.inUse
}

// RuleFlows はそのルールのフロー数 u_r(受け付けている待ち受けの合計)。
func (p *Pool) RuleFlows(ruleID string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if st := p.accepting[ruleID]; st != nil {
		return st.flows
	}
	return 0
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
// この handle は登録した時点で新しいフローを受け付けている状態になり、そのルールは A に入る。
// ソケットを bind する前に handle が要る呼び出し側は、代わりに PendingListener を使う。
func (p *Pool) Listener(ruleID string) *Listener { return p.listener(ruleID, true) }

// PendingListener は、まだ新しいフローを受け付けられない待ち受けの枠を登録する。ソケットの bind が
// 済む前に handle が要る呼び出し側が使い、bind が成功してから、中継を始める前に Accept を呼ぶ。
// そのルールは Accept を呼ぶまで A に入らない。A は開けた待ち受けを持つルールの集合なので
// (設計文書 7a.10 節)、bind の最中の待ち受けと bind に失敗した待ち受けが、その間だけ N を増やして
// 他のルールの予約を減らすことを防ぐ。
func (p *Pool) PendingListener(ruleID string) *Listener { return p.listener(ruleID, false) }

func (p *Pool) listener(ruleID string, accepting bool) *Listener {
	l := &Listener{p: p, rule: ruleID, accepting: accepting, open: true}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.listeners[l] = struct{}{}
	p.attachLocked(l)
	return l
}

// Listener は Pool に登録した待ち受け 1 つ。フローの枠はこの型を通して取る。
// どの項目も Pool の排他が守るので、複数の goroutine から呼べる。
type Listener struct {
	p         *Pool
	rule      string
	accepting bool
	open      bool
	// counted は、この待ち受けのフローを Pool の accepting の表に足しているか(open かつ accepting)。
	counted bool
	flows   int
}

// Acquire はフロー 1 つ分の枠を取る。取れたら真を返し、呼び出し側はフローの終わりに Release を
// 1 回呼ぶ。取れなければ理由を返し、何も数えない。拒否は理由ごとの数に 1 を足す。
//
// 判定は数の帳簿だけを見るので、受け付けていない handle(Retiring と、bind の済んでいない
// PendingListener)でも枠は取れる。取った枠はプロセス全体の数 u に入り、ルールごとの数 u_r には
// 入らず、そのルールを A にも入れない。中継は、待ち受けを Retiring にするときにソケットを閉じ、
// bind が済んで Accept を呼んでから中継を始めるので、この状態で Acquire を呼ぶのは、閉じる直前に
// accept してしまったフローだけである。
func (l *Listener) Acquire() (Refusal, bool) {
	p := l.p
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.total > 0 {
		if p.inUse >= p.total {
			return p.refuseLocked(ReasonBudget, l, 0), false
		}
		ruleFlows := p.ruleFlowsForLocked(l)
		if len(p.accepting) >= 2 && ruleFlows >= p.ruleCap {
			return p.refuseLocked(ReasonRuleCap, l, ruleFlows), false
		}
		// 自分の予約の内側にいないときは、他のルールの予約の未使用分を残しても空きが要る
		if ruleFlows >= p.reserve && p.total-p.inUse-p.otherReserveLocked(l) < 1 {
			return p.refuseLocked(ReasonReserve, l, ruleFlows), false
		}
	}
	p.inUse++
	l.flows++
	// 閉じた待ち受けは、フローを返し終えた時点で一覧から外れている。中継が閉じ終える前に取った枠も
	// プロセス全体の数に入るので、その待ち受けを一覧に戻して数え直せる状態を保つ
	p.listeners[l] = struct{}{}
	if l.counted {
		p.addRuleFlowsLocked(l.rule, 1)
	}
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
	if l.counted {
		p.addRuleFlowsLocked(l.rule, -1)
	}
	if !l.open && l.flows == 0 {
		delete(p.listeners, l)
	}
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
	if l.rule == ruleID {
		return
	}
	p.detachLocked(l)
	l.rule = ruleID
	p.attachLocked(l)
}

// StopAccepting は、この待ち受けを新しいフローを受け付けない状態にする(設計文書 7a.3 節の
// Retiring)。残っているフローはプロセス全体の数 u に入り続けるが、ルールごとの数 u_r からは
// 外れ、そのルールは待ち受けが他に無ければ A から外れる。ルール単位の fail-closed はそのルールの
// 待ち受けをすべて Retiring にするので、そのルールは新しいフローを受け付けているルールではなくなる。
func (l *Listener) StopAccepting() {
	p := l.p
	p.mu.Lock()
	defer p.mu.Unlock()
	l.accepting = false
	p.detachLocked(l)
}

// Accept は StopAccepting でやめた受け付けを再開する(宣言に戻った UDP の待ち受け)。
func (l *Listener) Accept() {
	p := l.p
	p.mu.Lock()
	defer p.mu.Unlock()
	l.accepting = true
	p.attachLocked(l)
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
	p.detachLocked(l)
	if l.flows == 0 {
		delete(p.listeners, l)
	}
}

// ruleFlowsForLocked は判定に使う u_r。受け付けている待ち受けの合計で、判定する待ち受け自身が
// 受け付けから外れている(Retiring、閉鎖済み)ときは、その待ち受けのフローも足す。
func (p *Pool) ruleFlowsForLocked(l *Listener) int {
	n := 0
	if st := p.accepting[l.rule]; st != nil {
		n = st.flows
	}
	if !l.counted {
		n += l.flows
	}
	return n
}

// otherReserveLocked は Σ max(0, q - u_s)(和は A のうち l のルール以外)。
func (p *Pool) otherReserveLocked(l *Listener) int {
	n := p.shortfall
	if st := p.accepting[l.rule]; st != nil {
		n -= shortfallOf(p.reserve, st.flows)
	}
	return n
}

// addRuleFlowsLocked はルールのフロー数を delta だけ動かし、予約の未使用分の合計を合わせる。
func (p *Pool) addRuleFlowsLocked(rule string, delta int) {
	st := p.accepting[rule]
	p.shortfall -= shortfallOf(p.reserve, st.flows)
	st.flows += delta
	p.shortfall += shortfallOf(p.reserve, st.flows)
}

// detachLocked は待ち受けのフローをルールごとの数から外す(閉鎖、受け付けの停止、付け替えの前)。
func (p *Pool) detachLocked(l *Listener) {
	if !l.counted {
		return
	}
	st := p.accepting[l.rule]
	p.shortfall -= shortfallOf(p.reserve, st.flows)
	st.flows -= l.flows
	st.listeners--
	if st.listeners == 0 {
		delete(p.accepting, l.rule)
	} else {
		p.shortfall += shortfallOf(p.reserve, st.flows)
	}
	l.counted = false
	p.refreshReserveLocked()
}

// attachLocked は待ち受けのフローをルールごとの数に入れる(登録、受け付けの再開、付け替えの後)。
func (p *Pool) attachLocked(l *Listener) {
	if l.counted || !l.open || !l.accepting {
		return
	}
	st := p.accepting[l.rule]
	if st == nil {
		st = &ruleFlows{}
		p.accepting[l.rule] = st
	} else {
		p.shortfall -= shortfallOf(p.reserve, st.flows)
	}
	st.flows += l.flows
	st.listeners++
	p.shortfall += shortfallOf(p.reserve, st.flows)
	l.counted = true
	p.refreshReserveLocked()
}

// refreshReserveLocked は N から q を計算し直し、変わっていれば予約の未使用分の合計を作り直す。
func (p *Pool) refreshReserveLocked() {
	q := reserveFor(p.total, len(p.accepting))
	if q == p.reserve {
		return
	}
	p.reserve = q
	p.shortfall = 0
	for _, st := range p.accepting {
		p.shortfall += shortfallOf(q, st.flows)
	}
}

// shortfallOf は 1 つのルールの予約の未使用分 max(0, q - u_s)。
func shortfallOf(reserve, flows int) int {
	if flows >= reserve {
		return 0
	}
	return reserve - flows
}

// checkInvariants は、足し引きで保っている数(u、u_r、q、予約の未使用分の合計)を待ち受けの一覧から
// 作り直して突き合わせる。単体テストが操作の列のあいだに呼び、running total のずれを見つける。
func (p *Pool) checkInvariants() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	inUse := 0
	want := map[string]*ruleFlows{}
	for l := range p.listeners {
		if l.flows < 0 {
			return fmt.Errorf("a listener of rule %s holds %d flows", l.rule, l.flows)
		}
		if !l.open && l.flows == 0 {
			return fmt.Errorf("a closed listener of rule %s with no flows left is still registered", l.rule)
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
	if q := reserveFor(p.total, len(want)); q != p.reserve {
		return fmt.Errorf("reserve = %d, want %d for %d rules of a budget of %d", p.reserve, q, len(want), p.total)
	}
	short := 0
	for _, st := range want {
		short += shortfallOf(p.reserve, st.flows)
	}
	if short != p.shortfall {
		return fmt.Errorf("the unused reserve sums to %d, recomputed %d", p.shortfall, short)
	}
	if p.total > 0 && len(want)*p.reserve > p.total {
		return fmt.Errorf("%d rules of a reserve of %d each do not fit in the budget of %d", len(want), p.reserve, p.total)
	}
	return nil
}

func (p *Pool) refuseLocked(reason Reason, l *Listener, ruleFlows int) Refusal {
	byReason := p.refusals[l.rule]
	if byReason == nil {
		byReason = map[Reason]uint64{}
		p.refusals[l.rule] = byReason
	}
	byReason[reason]++
	// 他のルールの数は、予約を持つルールのうち自分を除いた数。Retiring の待ち受けからの判定では
	// そのルールが A に無いので、A のすべてが「他のルール」になる
	others := len(p.accepting)
	if _, ok := p.accepting[l.rule]; ok {
		others--
	}
	return Refusal{
		Reason: reason, RuleID: l.rule,
		InUse: p.inUse, Total: p.total,
		RuleFlows: ruleFlows, RuleCap: p.ruleCap,
		Reserve: p.reserve, OtherRules: others,
	}
}

// Refusal は拒んだ 1 回の判定の内訳。中継はこれをログの文言にする(設計文書 7a.10 節)。
type Refusal struct {
	Reason     Reason
	RuleID     string
	InUse      int // 判定したときのプロセス全体のフロー数 u
	Total      int // プロセス全体の予算 T
	RuleFlows  int // 判定したときのそのルールのフロー数 u_r。予算で拒んだときは数えないので 0
	RuleCap    int // ルールが 2 本以上あるときのルール 1 本の上限 C
	Reserve    int // ルール 1 本あたりの隔離予約 q
	OtherRules int // 予約を持つ他のルールの数(新しいフローを受け付けているルールのうち自分以外)
}

// String は理由を説明する 1 文。中継は待ち受けの名前と処置を前後に付けてログに出す。
func (r Refusal) String() string {
	switch r.Reason {
	case ReasonBudget:
		return fmt.Sprintf("flow budget full (%d of %d in use in this process)", r.InUse, r.Total)
	case ReasonRuleCap:
		return fmt.Sprintf("rule %s holds %d flows and the rest of the budget is reserved for %s",
			r.RuleID, r.RuleFlows, otherRules(r.OtherRules))
	case ReasonReserve:
		return fmt.Sprintf("rule %s holds %d flows, above its reserve of %d, and the free part of the budget (%d of %d) is reserved for %s",
			r.RuleID, r.RuleFlows, r.Reserve, r.Total-r.InUse, r.Total, otherRules(r.OtherRules))
	default:
		return fmt.Sprintf("refused by the flow budget (%s)", r.Reason)
	}
}

// otherRules は "1 other rule" か "3 other rules"。拒否の文言に埋める。
func otherRules(n int) string {
	if n == 1 {
		return "1 other rule"
	}
	return fmt.Sprintf("%d other rules", n)
}
