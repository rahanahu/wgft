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
	// 登録の listener が運ぶ数 c_g で判定する。
	ReasonRuleCap Reason = "rule_cap"
	// ReasonReserve は、x_g で見て自分の最低分に届いていて、残りの空きが満たされていない最低分で
	// 埋まっていること(u + 1 + S > T)。
	ReasonReserve Reason = "reserve"
	// ReasonFloor は、x_g で見て自分の最低分に届いていない予約の部分の取得が、他の登録の満たされて
	// いない下限と予備を残せないこと。
	ReasonFloor Reason = "floor"
	// ReasonSpare は、x_g で見て自分の最低分に届いていて、満たされていない最低分を残しても空きは
	// あるが、予備を残すと空きが無いこと。
	ReasonSpare Reason = "spare"
)

// FlowFloor は登録ごとの下限 f。予備 P も同じ値である(設計文書 7a.10 節)。
const FlowFloor = 4

// Outcome は Take の結果。
type Outcome int

const (
	Granted Outcome = iota
	Refused
	NotAccepting
)

func (o Outcome) String() string {
	switch o {
	case Granted:
		return "granted"
	case Refused:
		return "refused"
	case NotAccepting:
		return "not accepting"
	}
	return fmt.Sprintf("outcome(%d)", int(o))
}

// Pool は 1 つのプロトコルのフロー予算(設計文書 7a.5、7a.10 節の Resource Guard)。プロセス全体の
// 予算 T を、ルールの登録ごとの最低分 m と予備 P と、固定の上限の中の先着順の共有に分ける。判定は
// 1 つの排他の中で行い、ルールごと、理由ごとの拒否の数を、この Pool を作ってからの累計として持つ。
// SQLite には保存しない。累計の起点は呼び出し側の作り方で決まる。vpsd はプロセスの起動時に 1 つ作る
// のでプロセスが起動してからの累計になり、エージェントはトンネルを立て直すたびに中継ごと作り直すので、
// そのたびに 0 に戻る(設計文書 10.2c 節の relay.refusals)。
//
// 記号は設計文書 7a.10 節に合わせる。登録 g はルール ID が受け付けている listener を持ち続ける 1 期間で、
// A は受け付けている登録の集合、N はその大きさである。a_g は g に数えるフローの数(受け付けたときの
// 登録に数え、退役した登録のフローの帰属の規則でだけ移る)、c_g は g に今属する受け付けている listener
// が運ぶフローの数、x_g = max(a_g, c_g) である。u はプロセス全体のフロー数、m = max(f, q)、
// q = floor(floor((T - f) / 2) / (N - 1))(N ≥ 2)、S = Σ max(0, m - a_g)、S_f = Σ max(0, f - a_g)
// (和は A)、P = f である。判定の順は Take の注釈にある。
//
// a_g、c_g、u、S、S_f は足し引きで保つ。m は N が変わるときだけ変わるので、S は登録の始まりと退役の
// ときだけ A の全登録について作り直す(refreshLocked)。どちらも収束の Commit(エージェントでは Apply)
// から呼ばれる。
type Pool struct {
	total   int // T。0 以下なら予算の判定を行わない
	ruleCap int // C

	mu    sync.Mutex
	inUse int // u
	// regs は A。ルール ID から今の登録への表。
	regs map[string]*registration
	// retired は退役した登録のうち、まだ数えるフローを持つもの。
	retired map[*registration]struct{}
	minimum int // m。N が変わるたびに求め直す
	// unfilled は S、floorShort は S_f。unfilledRegs と floorShortRegs はそれぞれの項が正の登録の数で、
	// 拒否の文言にだけ使う。
	unfilled, floorShort         int
	unfilledRegs, floorShortRegs int
	refusals                     map[string]map[Reason]uint64
	notAccepting                 uint64
	doubleReleases               uint64
	regSerial                    int
}

// NewPool は予算 total のプールを作る。ルール 1 本の上限と最低分は total から導く。
func NewPool(total int) *Pool {
	p := &Pool{
		total:    total,
		ruleCap:  ruleCapFor(total),
		regs:     map[string]*registration{},
		retired:  map[*registration]struct{}{},
		refusals: map[string]map[Reason]uint64{},
	}
	p.minimum = minimumFor(total, 0)
	return p
}

// ruleCapFor は C = ceil(T/2)。
func ruleCapFor(total int) int {
	if total <= 0 {
		return 0
	}
	return (total + 1) / 2
}

// minimumFor は登録ごとの最低分 m = max(f, q)。q は予備を除いた T - f から求める。
func minimumFor(total, rules int) int {
	if rules < 2 {
		return FlowFloor
	}
	return max(FlowFloor, (total-FlowFloor)/2/(rules-1))
}

// Total は予算 T。
func (p *Pool) Total() int { return p.total }

// RuleCap はルールが 2 本以上あるときのルール 1 本の上限 C。ルールが 1 本のときは効かない。
func (p *Pool) RuleCap() int { return p.ruleCap }

// Rules は今受け付けているルールの数 N。
func (p *Pool) Rules() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.regs)
}

// Reserve は登録ごとの最低分 m。
func (p *Pool) Reserve() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.minimum
}

// InUse は今保持しているフローの数 u。受け付けをやめた待ち受けと、閉じた待ち受けの残りのフローも含む。
func (p *Pool) InUse() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.inUse
}

// RuleFlows はそのルールの登録の listener が運ぶフローの数 c_g(改訂の前のルールのフロー数と同じ数)。
func (p *Pool) RuleFlows(ruleID string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if g := p.regs[ruleID]; g != nil {
		return g.carried
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
// この handle は登録した時点で新しいフローを受け付けている状態になる。bind の成否に関わらず handle を
// 保ちたい呼び出し側は、代わりに PendingListener を使い、bind の後に Accept を呼ぶ。A は開けた待ち受け
// を持つルールの集合なので(設計文書 7a.10 節)、bind の最中と失敗した待ち受けのルールを N に数えない。
func (p *Pool) Listener(ruleID string) *Listener { return p.listener(ruleID, true) }

// PendingListener は、まだ新しいフローを受け付けられない待ち受けの枠を登録する。
func (p *Pool) PendingListener(ruleID string) *Listener { return p.listener(ruleID, false) }

func (p *Pool) listener(ruleID string, accepting bool) *Listener {
	l := &Listener{p: p, rule: ruleID, accepting: accepting, open: true}
	p.mu.Lock()
	defer p.mu.Unlock()
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
	// counted は、この待ち受けが登録に加わっているか(open かつ accepting)。
	counted bool
	flows   int
	// reg は counted のときの今の登録。cells はこの待ち受けが運ぶフローの、登録ごとの cell。
	reg   *registration
	cells map[*cell]struct{}
	cur   *cell
}

// Take はフロー 1 つ分の枠を取る。受け付けていない handle(保留、Retiring、閉鎖済み)では
// NotAccepting を返し、拒否の数にもログにも入れない。予算で拒んだときは Refused と理由を返し、
// 理由ごとの数に 1 を足す。取れたら Lease を返し、呼び出し側はフローの終わりにその Release を
// 1 度呼ぶ。
//
// 判定の順は、受け付けていない、予算(u < T)、ルール 1 本の上限(N ≥ 2 なら c_g < C)、下限の部分
// (a_g < f なら通す)、予約の部分(x_g < m なら u + 1 + S_f + P ≤ T で通し、満たさなければ floor)、
// 共有分(u + 1 + S + P ≤ T で通し、満たさなければ u + 1 + S > T なら reserve、そうでなければ spare)
// である。T ≤ 0 の Pool は受け付けていない handle だけを拒み、予算の判定を行わない。
func (l *Listener) Take() (*Lease, Refusal, Outcome) {
	p := l.p
	p.mu.Lock()
	defer p.mu.Unlock()
	if !l.counted {
		p.notAccepting++
		return nil, Refusal{}, NotAccepting
	}
	g := l.reg
	if p.total > 0 {
		if reason, flows := p.judgeLocked(g); reason != "" {
			return nil, p.refuseLocked(reason, l, flows), Refused
		}
	}
	p.inUse++
	l.flows++
	g.carried++
	c := p.cellFor(l)
	c.n++
	p.addCountLocked(g, 1)
	return &Lease{l: l, c: c}, Refusal{}, Granted
}

// judgeLocked は受け付けている登録 g の取得の判定。通すなら空の理由を返す。2 つ目の値は拒否の文言が
// 示すそのルールのフローの数(rule_cap では c_g、floor、spare、reserve では x_g)。
func (p *Pool) judgeLocked(g *registration) (Reason, int) {
	u, T := p.inUse, p.total
	if u >= T {
		return ReasonBudget, 0
	}
	if len(p.regs) >= 2 && g.carried >= p.ruleCap {
		return ReasonRuleCap, g.carried
	}
	if g.count < FlowFloor {
		return "", 0
	}
	x := max(g.count, g.carried)
	if x < p.minimum {
		if u+1+p.floorShort+FlowFloor <= T {
			return "", 0
		}
		return ReasonFloor, x
	}
	if u+1+p.unfilled+FlowFloor <= T {
		return "", 0
	}
	if u+1+p.unfilled > T {
		return ReasonReserve, x
	}
	return ReasonSpare, x
}

// SetRule は所属ルールを付け替える(分割と統合の relabel)。既存のフローは受け付けたときの登録に
// 数えたままで、この待ち受けが運ぶ数 c_g だけが付け替え先の登録へ移る。元の登録が退役すれば、
// 退役した登録のフローの帰属の規則が働く。
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

// StopAccepting は、この待ち受けを新しいフローを受け付けない状態にする(設計文書 7a.3 節の Retiring)。
// 残っているフローは u と登録の数に残るが、この待ち受けは登録から外れる。
func (l *Listener) StopAccepting() {
	p := l.p
	p.mu.Lock()
	defer p.mu.Unlock()
	l.accepting = false
	p.detachLocked(l)
}

// Accept は保留の待ち受けの受け付けを始めるか、StopAccepting でやめた受け付けを再開する。
func (l *Listener) Accept() {
	p := l.p
	p.mu.Lock()
	defer p.mu.Unlock()
	l.accepting = true
	p.attachLocked(l)
}

// Close は待ち受けを Pool から外す。まだ返していないフローは、Release を呼ぶまで u と登録の数に残る。
func (l *Listener) Close() {
	p := l.p
	p.mu.Lock()
	defer p.mu.Unlock()
	if !l.open {
		return
	}
	l.open = false
	p.detachLocked(l)
}

// Flows はこの待ち受けが保持しているフローの数。
func (l *Listener) Flows() int {
	p := l.p
	p.mu.Lock()
	defer p.mu.Unlock()
	return l.flows
}

// refreshLocked は今の N から m を求め、S と S_f を A の全登録について作り直す。N が変わったとき
// (登録の始まりと退役)だけ呼ぶ。
func (p *Pool) refreshLocked() {
	p.minimum = minimumFor(p.total, len(p.regs))
	p.unfilled, p.floorShort, p.unfilledRegs, p.floorShortRegs = 0, 0, 0, 0
	for _, g := range p.regs {
		p.termsLocked(g, 1)
	}
}

// termsLocked は受け付けている登録 g の S と S_f の項を sign の向きに足す。退役した登録は項を持たない。
func (p *Pool) termsLocked(g *registration, sign int) {
	if g.retired {
		return
	}
	if d := p.minimum - g.count; d > 0 {
		p.unfilled += sign * d
		p.unfilledRegs += sign
	}
	if d := FlowFloor - g.count; d > 0 {
		p.floorShort += sign * d
		p.floorShortRegs += sign
	}
}

// addCountLocked は a_g を delta だけ動かし、S と S_f を合わせる。
func (p *Pool) addCountLocked(g *registration, delta int) {
	p.termsLocked(g, -1)
	g.count += delta
	p.termsLocked(g, 1)
	if g.retired && g.count == 0 {
		delete(p.retired, g)
	}
}

func (p *Pool) refuseLocked(reason Reason, l *Listener, flows int) Refusal {
	byReason := p.refusals[l.rule]
	if byReason == nil {
		byReason = map[Reason]uint64{}
		p.refusals[l.rule] = byReason
	}
	byReason[reason]++
	return Refusal{
		Reason: reason, RuleID: l.rule,
		InUse: p.inUse, Total: p.total,
		RuleFlows: flows, RuleCap: p.ruleCap,
		Minimum: p.minimum, Spare: FlowFloor,
		Unfilled: p.unfilled, UnfilledRules: p.unfilledRegs, UnfilledSelf: l.reg.count < p.minimum,
		FloorShort: p.floorShort, FloorShortRules: p.floorShortRegs,
		OtherRules: len(p.regs) - 1,
	}
}

// Refusal は拒んだ 1 回の判定の内訳。中継はこれをログの文言にする(設計文書 7a.10 節)。
type Refusal struct {
	Reason    Reason
	RuleID    string
	InUse     int // u
	Total     int // T
	RuleFlows int // 判定に使ったそのルールの数。rule_cap では c_g、floor、spare、reserve では x_g
	RuleCap   int // C
	Minimum   int // m
	Spare     int // P
	// Unfilled は S、UnfilledRules は S の項が正の登録の数。UnfilledSelf はそのうちに自分が入るか。
	Unfilled      int
	UnfilledRules int
	UnfilledSelf  bool
	// FloorShort は S_f、FloorShortRules は S_f の項が正の登録の数(floor では自分は入らない)。
	FloorShort      int
	FloorShortRules int
	OtherRules      int // 受け付けている他のルールの数
}

// String は理由を説明する 1 文。中継は待ち受けの名前と処置を前後に付けてログに出す。
func (r Refusal) String() string {
	free := r.Total - r.InUse
	switch r.Reason {
	case ReasonBudget:
		return fmt.Sprintf("flow budget full: %d of %d in use in this process", r.InUse, r.Total)
	case ReasonRuleCap:
		return fmt.Sprintf("rule %s holds %d flows and the rest of the budget is reserved for %s",
			r.RuleID, r.RuleFlows, otherRules(r.OtherRules))
	case ReasonReserve:
		return fmt.Sprintf("rule %s holds %d flows, at or above its minimum of %d, and the free part of the budget, %d of %d, is held for the unfilled minimums of %s, %d flows",
			r.RuleID, r.RuleFlows, r.Minimum, free, r.Total, r.unfilledOwners(), r.Unfilled)
	case ReasonSpare:
		if r.Unfilled == 0 {
			return fmt.Sprintf("rule %s holds %d flows and the free part of the budget, %d of %d, is kept spare for a rule added later",
				r.RuleID, r.RuleFlows, free, r.Total)
		}
		return fmt.Sprintf("rule %s holds %d flows, at or above its minimum of %d, and the free part of the budget, %d of %d, is held for the unfilled minimums of %s, %d flows, and %d spare flows for a rule added later",
			r.RuleID, r.RuleFlows, r.Minimum, free, r.Total, r.unfilledOwners(), r.Unfilled, r.Spare)
	case ReasonFloor:
		if r.FloorShort == 0 {
			return fmt.Sprintf("rule %s holds %d flows, below its minimum of %d, and the free part of the budget, %d of %d, is kept spare for a rule added later",
				r.RuleID, r.RuleFlows, r.Minimum, free, r.Total)
		}
		return fmt.Sprintf("rule %s holds %d flows, below its minimum of %d, and the free part of the budget, %d of %d, is held for the first flows of %s and %d spare flows for a rule added later",
			r.RuleID, r.RuleFlows, r.Minimum, free, r.Total, otherRules(r.FloorShortRules), r.Spare)
	default:
		return fmt.Sprintf("refused by the flow budget: %s", r.Reason)
	}
}

// unfilledOwners は満たされていない最低分を持つ登録の言い方。自分の不足が S に入るのは、予約の部分の
// 入口が閉じて共有分に回った登録だけである。
func (r Refusal) unfilledOwners() string {
	if !r.UnfilledSelf {
		return otherRules(r.UnfilledRules)
	}
	if r.UnfilledRules <= 1 {
		return "this rule"
	}
	return "this rule and " + otherRules(r.UnfilledRules-1)
}

// otherRules は "1 other rule" か "3 other rules"。拒否の文言に埋める。
func otherRules(n int) string {
	if n == 1 {
		return "1 other rule"
	}
	return fmt.Sprintf("%d other rules", n)
}
