// Package goengine は AdmissionPolicy の IR(internal/policy)から作る Go の評価器である
// (設計文書 7a.9 節「Go の評価器へのコンパイルの約束」)。userspace モードの中継は、新しいフローと
// 成立済みの UDP セッションのデータグラムを、この評価器で判定する。
//
// 評価順は policy.Order だけが持ち、この評価器は Order を順に回す。ある段が拒んだとき、それより後の
// 段の状態(トークン、送信元ごとの同時フロー数の枠)は消費しない。拒んだ段の drop の種類は
// Decision.Kind に入り、drop カウンタも評価器が数える。呼び出し側は drop の種類を決めない。
//
// このパッケージは純粋で、internal/policy と proto だけを import する。dataplane、frontend、
// platform、vpsd、agent のどの package も import しない(設計文書 7a.7 節)。
package goengine

import (
	"container/list"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/rahanahu/wgft/internal/policy"
	"github.com/rahanahu/wgft/proto"
)

// Decision は判定 1 つの結果。Allow が偽のとき、Kind は拒んだ段の drop の種類
// (policy.Step.DropKind)で、その drop は評価器が数えている。Kind が空の拒否は drop に数えない
// 拒否で、IR に無いルール ID と IPv4 でない送信元に使う(fail-closed)。
type Decision struct {
	Allow bool
	Kind  string
}

var allow = Decision{Allow: true}

// Drop は 1 つのルールの 1 つの種類の drop の累計。Packets は拒んだフローかデータグラムの数、Bytes は
// 呼び出し側が渡した大きさの合計(UDP はデータグラムの中身の長さ、TCP は 0。設計文書 7a.9 節の
// 許容差 drop_counter_units)。
type Drop struct {
	RuleID  string
	Kind    string
	Packets uint64
	Bytes   uint64
}

// Engine は評価器。すべての状態を mu で守るので、複数の中継から同時に呼んでよい。
type Engine struct {
	mu    sync.Mutex
	now   func() time.Time
	rules map[string]*ruleState
	caps  policy.PerSourceFlowCaps
	// flows は送信元ごとの同時フロー数(プロトコルごと、全ルールの合計。設計文書 7 節)。上限が 0 でも
	// 数え続けるので、上限を Update で変えると、成立済みのフローを含めた数で次の判定から効く。
	flows map[flowKey]int
	drops map[dropKey]*Drop
}

type flowKey struct {
	proto proto.Proto
	src   netip.Addr
}

type dropKey struct {
	ruleID string
	kind   string
}

// ruleState はルール 1 つ分の評価の状態。バケットと送信元の表は、Update で同じ ID のルールが残り、
// かつそのレートが変わっていない限り引き継ぐ(設計文書 7a.4 節「テーブル差し替えによる ct count/meter
// のリセット」)。
type ruleState struct {
	rp policy.RulePolicy

	perSource *sourceTable
	newFlow   *tokenBucket
	packet    *tokenBucket
}

// New は空の評価器を作る。Update を呼ぶまで、どのルール ID のフローも拒む。now はテストで時計を
// 差し替えるため(nil なら time.Now)。
func New(now func() time.Time) *Engine {
	if now == nil {
		now = time.Now
	}
	return &Engine{
		now:   now,
		rules: map[string]*ruleState{},
		flows: map[flowKey]int{},
		drops: map[dropKey]*Drop{},
	}
}

// Update は IR から評価器を作り直す。p.Rules は転送するルール(有効で、エージェントが登録済みで、
// fail-closed にしていないもの)だけを持つ。消えたルールの状態は捨て、残ったルールのうちレートの値が
// 変わっていないものは、そのバケットと送信元の表を引き継ぐ。送信元ごとの同時フロー数は捨てずに
// 引き継ぎ、新しい上限で次の判定から数える(成立済みのフローは追い出さない)。
func (e *Engine) Update(p policy.Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	next := make(map[string]*ruleState, len(p.Rules))
	for _, rp := range p.Rules {
		next[rp.RuleID] = buildRuleState(rp, e.rules[rp.RuleID])
	}
	e.rules = next
	e.caps = p.PerSourceFlowCaps
}

func buildRuleState(rp policy.RulePolicy, old *ruleState) *ruleState {
	rs := &ruleState{rp: rp}
	if rp.PerSourceRate != nil {
		if old != nil && old.perSource != nil && *old.rp.PerSourceRate == *rp.PerSourceRate {
			rs.perSource = old.perSource
		} else {
			rs.perSource = newSourceTable(*rp.PerSourceRate)
		}
	}
	if rp.NewFlowRate != nil {
		if old != nil && old.newFlow != nil && *old.rp.NewFlowRate == *rp.NewFlowRate {
			rs.newFlow = old.newFlow
		} else {
			rs.newFlow = newTokenBucket(*rp.NewFlowRate)
		}
	}
	if rp.PacketRate != nil {
		if old != nil && old.packet != nil && *old.rp.PacketRate == *rp.PacketRate {
			rs.packet = old.packet
		} else {
			rs.packet = newTokenBucket(*rp.PacketRate)
		}
	}
	return rs
}

// Ticket は AdmitFlow が取った送信元ごとの同時フロー数の枠。フローの終わりに Release で返す。
// Release は何度呼んでも 1 回だけ返し、nil の Ticket の Release は何もしない。
type Ticket struct {
	e    *Engine
	key  flowKey
	held bool
}

// Release は枠を返す。
func (t *Ticket) Release() {
	if t == nil {
		return
	}
	t.e.mu.Lock()
	defer t.e.mu.Unlock()
	if !t.held {
		return
	}
	t.held = false
	t.e.releaseLocked(t.key)
}

func (e *Engine) releaseLocked(k flowKey) {
	if n := e.flows[k]; n <= 1 {
		delete(e.flows, k)
	} else {
		e.flows[k] = n - 1
	}
}

// AdmitFlow は新しいフロー(TCP の accept、UDP の新しいセッションの最初のデータグラム)を
// policy.Order の全段で判定する。size はそのフローの最初のパケットの大きさで、拒んだときの drop の
// バイト数になる(UDP はデータグラムの長さ、TCP は 0)。
//
// 通したときは、送信元ごとの同時フロー数の枠を持つ Ticket を返す。呼び出し側はフローの終わりに
// Release を呼ぶ。後の Resource Guard(プロセス全体の予算、ルールごとの隔離)が拒んだとき、あるいは
// フローを始められなかったときも、その場で Release を呼ぶ。拒んだときの Ticket は nil で、段の途中で
// 取った枠は評価器が既に返している。
func (e *Engine) AdmitFlow(ruleID string, src netip.Addr, size int) (Decision, *Ticket) {
	return e.admit(ruleID, src, size, policy.Order)
}

// relayOrder は AdmitSourceFlow が評価する段。
var relayOrder = []policy.Step{policy.StepPerSourceConcurrentFlows}

// AdmitSourceFlow は、userspace モードの Relay の中継(internal/vpsd/proxyrelay)の新しい接続を、
// 送信元ごとの同時フロー数の段だけで判定する。Relay の中継は、送信元の許可拒否を自分で判定し、
// レートを評価しない。kernel モードの Relay のポートに src_flow の行だけがあるのと同じ扱いで、
// 設計文書 7a.9 節の移行の手順 4 で AdmitFlow に置き換える。それまでも、Relay の接続は Transparent の
// TCP のルールと同じ送信元ごとの数に入る(設計文書 6.3 節)。IR に無いルール ID と IPv4 でない
// 送信元は、AdmitFlow と同じく drop に数えずに拒む。
func (e *Engine) AdmitSourceFlow(ruleID string, src netip.Addr) (Decision, *Ticket) {
	return e.admit(ruleID, src, 0, relayOrder)
}

func (e *Engine) admit(ruleID string, src netip.Addr, size int, order []policy.Step) (Decision, *Ticket) {
	src = src.Unmap()
	e.mu.Lock()
	defer e.mu.Unlock()
	rs, known := e.rules[ruleID]
	if !known || !src.Is4() {
		return Decision{}, nil
	}
	var t *Ticket
	var now time.Time
	clock := func() time.Time {
		if now.IsZero() {
			now = e.now()
		}
		return now
	}
	for _, step := range order {
		if e.passLocked(rs, step, src, clock, &t) {
			continue
		}
		if t != nil {
			// 後の段が拒んだフローは成立しないので、取った枠をその場で返す
			t.held = false
			e.releaseLocked(t.key)
		}
		kind := step.DropKind()
		if kind != "" {
			e.recordDropLocked(ruleID, kind, size)
		}
		return Decision{Kind: kind}, nil
	}
	if t == nil {
		// 送信元ごとの同時フロー数の段を評価しない順序は無いが、呼び出し側が常に Release を
		// 呼べるよう、空の Ticket を返す
		t = &Ticket{e: e}
	}
	return allow, t
}

// passLocked は段 1 つを評価し、通すなら真を返す。通した段の状態(トークン、同時フロー数の枠)は
// ここで消費する。
func (e *Engine) passLocked(rs *ruleState, step policy.Step, src netip.Addr, clock func() time.Time, t **Ticket) bool {
	rp := &rs.rp
	switch step {
	case policy.StepSourceDeny:
		return !matchesAny(rp.SourceDeny, src)
	case policy.StepSourceAllow:
		return len(rp.SourceAllow) == 0 || matchesAny(rp.SourceAllow, src)
	case policy.StepPerSourceRate:
		return rs.perSource == nil || rs.perSource.get(src, clock()).allow(clock())
	case policy.StepPerSourceConcurrentFlows:
		k := flowKey{rp.Proto, src}
		if limit := e.caps.ForProto(rp.Proto); limit > 0 && e.flows[k] >= limit {
			return false
		}
		e.flows[k]++
		*t = &Ticket{e: e, key: k, held: true}
		return true
	case policy.StepAggregateNewFlowRate:
		return rs.newFlow == nil || rs.newFlow.allow(clock())
	case policy.StepAggregatePacketRate:
		// packet_rate は UDP のデータグラムだけに効く(設計文書 7a.9 節「TCP の packet_rate」)
		return rp.Proto != proto.UDP || rs.packet == nil || rs.packet.allow(clock())
	default:
		// IR に知らない段が加わったら、評価器を直すまで通さない
		return false
	}
}

// AdmitPacket は成立済みの UDP セッションのデータグラム 1 つを packet_rate の段で判定する。size は
// データグラムの長さ。TCP のルールのパケットは判定しない(通す)。IR に無いルール ID は drop に
// 数えずに拒む。
func (e *Engine) AdmitPacket(ruleID string, size int) Decision {
	e.mu.Lock()
	defer e.mu.Unlock()
	rs, known := e.rules[ruleID]
	if !known {
		return Decision{}
	}
	if rs.rp.Proto != proto.UDP || rs.packet == nil || rs.packet.allow(e.now()) {
		return allow
	}
	kind := policy.StepAggregatePacketRate.DropKind()
	e.recordDropLocked(ruleID, kind, size)
	return Decision{Kind: kind}
}

// SourceAllowed は成立済みのフローを残すかを、送信元の拒否と許可だけで判定する(ルール変更の後に
// セッションを閉じる判定。設計文書 7a.3 節)。状態を持つ段は評価せず、drop にも数えない。IR に無い
// ルール ID と IPv4 でない送信元は偽を返す。
func (e *Engine) SourceAllowed(ruleID string, src netip.Addr) bool {
	src = src.Unmap()
	e.mu.Lock()
	defer e.mu.Unlock()
	rs, known := e.rules[ruleID]
	if !known || !src.Is4() {
		return false
	}
	return rs.rp.SourceAllowed(src)
}

// Drops は前回の呼び出し以降に数えた drop を、ルール ID と種類の順に返して 0 に戻す。呼び出し側が
// SQLite へ累積する(kernel モードでテーブルの差し替えの直前にカウンタを読むのと同じ経路)。
func (e *Engine) Drops() []Drop {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.drops) == 0 {
		return nil
	}
	out := make([]Drop, 0, len(e.drops))
	for _, d := range e.drops {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].Kind < out[j].Kind
	})
	e.drops = map[dropKey]*Drop{}
	return out
}

func (e *Engine) recordDropLocked(ruleID, kind string, size int) {
	k := dropKey{ruleID, kind}
	d := e.drops[k]
	if d == nil {
		d = &Drop{RuleID: ruleID, Kind: kind}
		e.drops[k] = d
	}
	d.Packets++
	d.Bytes += uint64(max(size, 0))
}

func matchesAny(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// tokenBucket は nftables の `limit rate over <count>/<unit>` と同じ振る舞いをするトークンバケット
// (容量は policy.TokenBucketBurst、満杯から始まり、count/unit の速さで補充する。設計文書 7a.4 節
// 「トークンバケットの粒度」)。ラボでカーネルモードと通過数・drop 数の累計が一致することを
// 確かめている(2026-09-17)。golang.org/x/time/rate は壁時計しか使えないため、時計を差し替えられる
// よう自前で持つ。Engine の mu の下でだけ使う。
type tokenBucket struct {
	refill float64 // 1 秒あたりに補充するトークン数
	tokens float64
	last   time.Time
}

func newTokenBucket(r proto.Rate) *tokenBucket {
	return &tokenBucket{refill: float64(r.Count) / unitSeconds(r.Unit), tokens: policy.TokenBucketBurst}
}

// allow はトークンを 1 つ消費できれば真を返す。直前の呼び出しからの経過時間ぶんを補充してから判定する。
func (b *tokenBucket) allow(now time.Time) bool {
	if b.last.IsZero() {
		b.last = now
	}
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens = min(b.tokens+elapsed.Seconds()*b.refill, policy.TokenBucketBurst)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func unitSeconds(u proto.RateUnit) float64 {
	switch u {
	case proto.PerSecond:
		return 1
	case proto.PerMinute:
		return 60
	case proto.PerHour:
		return 3600
	case proto.PerDay:
		return 24 * 3600
	case proto.PerWeek:
		return 7 * 24 * 3600
	default:
		// proto.Rate は ParseRate/UnmarshalText でしか作られず、ここに来る値は検査済みのはずである。
		// 念のため 1 秒として扱う。
		return 1
	}
}

// sourceTable はルール 1 つ分の、送信元ごとのバケットの表(nftables の meter に当たる)。最後に触れて
// から policy.PerSourceTableTTL で消し、policy.PerSourceTableSize 件で埋まったら最も長く触れていない
// 送信元を捨てる(設計文書 7a.9 節の許容差 per_source_table_expiry。許可を広げない側に倒す)。
// 全件の走査を避けるため、最近触れた順に container/list で並べる。
type sourceTable struct {
	rate    proto.Rate
	entries map[netip.Addr]*list.Element
	order   *list.List // 先頭が最近触れたもの、末尾が最も長く触れていないもの
}

type sourceEntry struct {
	key      netip.Addr
	bucket   *tokenBucket
	lastSeen time.Time
}

func newSourceTable(rate proto.Rate) *sourceTable {
	return &sourceTable{rate: rate, entries: map[netip.Addr]*list.Element{}, order: list.New()}
}

// get は key のバケットを返す。無ければ作る。期限切れのものを末尾から捨て、上限に達していれば
// さらに末尾を捨ててから加える。
func (t *sourceTable) get(key netip.Addr, now time.Time) *tokenBucket {
	for back := t.order.Back(); back != nil; back = t.order.Back() {
		if now.Sub(back.Value.(*sourceEntry).lastSeen) < policy.PerSourceTableTTL {
			break
		}
		t.remove(back)
	}
	if el, ok := t.entries[key]; ok {
		e := el.Value.(*sourceEntry)
		e.lastSeen = now
		t.order.MoveToFront(el)
		return e.bucket
	}
	for len(t.entries) >= policy.PerSourceTableSize {
		t.remove(t.order.Back())
	}
	e := &sourceEntry{key: key, bucket: newTokenBucket(t.rate), lastSeen: now}
	t.entries[key] = t.order.PushFront(e)
	return e.bucket
}

func (t *sourceTable) remove(el *list.Element) {
	delete(t.entries, el.Value.(*sourceEntry).key)
	t.order.Remove(el)
}
