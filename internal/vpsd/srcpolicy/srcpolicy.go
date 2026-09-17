// Package srcpolicy はユーザースペースモード(nftables を使わない転送)向けに、
// 接続元制限とレート制限を Go で評価する。カーネルモードで nftables が担う評価順
// (deny、allow、接続元ごとの meter、新規フローの集約上限、パケットの集約上限。
// design.md 6.1 節)を、userspace の中継の手前で同じ順に再現する。
package srcpolicy

import (
	"container/list"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/nft"
	"github.com/rahanahu/wgft/proto"
)

// 接続元ごとの meter の上限(design.md 6.1 節の set と同じ、1 分で期限切れ、上限 65535)。
const (
	perSourceCap = 65535
	perSourceTTL = time.Minute
)

// Policy はルール集合から作る評価器。AdmitFlow、AdmitPacket、SourceAllowed、Drops が
// 読み書きする状態はすべて mu で守る。
type Policy struct {
	mu    sync.Mutex
	now   func() time.Time
	rules map[string]*ruleState
	drops map[dropKey]*nft.Drop
}

type dropKey struct {
	ruleID string
	kind   string
}

// ruleState はルール 1 つ分の評価に要る状態。バケットや接続元の表は、Update で
// 同じ ID のルールが残り、かつ対応するレートが変わっていない限り使い回す。
type ruleState struct {
	allow []netip.Prefix
	deny  []netip.Prefix

	newFlow     *tokenBucket
	newFlowRate proto.Rate // newFlow != nil のときだけ意味を持つ

	packet     *tokenBucket
	packetRate proto.Rate // packet != nil のときだけ意味を持つ

	perSource     *sourceTable
	perSourceRate *proto.Rate // nil なら接続元ごとの制限なし
}

// New は方針の評価器を作る。now はテストで時計を差し替えるため(nil なら time.Now)。
func New(now func() time.Time) *Policy {
	if now == nil {
		now = time.Now
	}
	return &Policy{
		now:   now,
		rules: make(map[string]*ruleState),
		drops: make(map[dropKey]*nft.Drop),
	}
}

// Update はルール集合から方針を作り直す。消えたルールの状態(接続元の表、バケット)は
// 捨て、残ったルールのうち、レートの設定(Count と Unit)が変わっていないものは
// バケットと接続元の表をそのまま引き継ぐ。allow/deny の一覧は毎回差し替える(進行中の
// 判定に対する影響は SourceAllowed の呼び出し側が扱う)。
func (p *Policy) Update(rules []proto.Rule) {
	p.mu.Lock()
	defer p.mu.Unlock()

	next := make(map[string]*ruleState, len(rules))
	for _, r := range rules {
		next[r.ID] = buildRuleState(r, p.rules[r.ID])
	}
	p.rules = next
}

func buildRuleState(r proto.Rule, old *ruleState) *ruleState {
	rs := &ruleState{
		allow: r.SourceAllow,
		deny:  r.SourceDeny,
	}

	if r.NewFlowRate != nil {
		rs.newFlowRate = *r.NewFlowRate
		if old != nil && old.newFlow != nil && old.newFlowRate == *r.NewFlowRate {
			rs.newFlow = old.newFlow
		} else {
			rs.newFlow = newTokenBucket(*r.NewFlowRate)
		}
	}

	if r.PacketRate != nil {
		rs.packetRate = *r.PacketRate
		if old != nil && old.packet != nil && old.packetRate == *r.PacketRate {
			rs.packet = old.packet
		} else {
			rs.packet = newTokenBucket(*r.PacketRate)
		}
	}

	if r.PerSourceRate != nil {
		rate := *r.PerSourceRate
		rs.perSourceRate = &rate
		if old != nil && old.perSource != nil && old.perSourceRate != nil && *old.perSourceRate == rate {
			rs.perSource = old.perSource
		} else {
			rs.perSource = newSourceTable()
		}
	}

	return rs
}

// AdmitFlow は新しいフロー(TCP の accept、UDP の新しいセッション)を、
// deny、allow、per_source、new_flow の順に判定する。通さない場合は落とした種類を返し、
// そのルールの drop を 1 パケット size バイトとして数える。未知のルール ID は通す。
func (p *Policy) AdmitFlow(ruleID string, src netip.Addr, size int) (ok bool, kind string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	rs, known := p.rules[ruleID]
	if !known {
		return true, ""
	}

	if matchesAny(rs.deny, src) {
		p.recordDropLocked(ruleID, "deny", size)
		return false, "deny"
	}
	if len(rs.allow) > 0 && !matchesAny(rs.allow, src) {
		p.recordDropLocked(ruleID, "allow", size)
		return false, "allow"
	}

	now := p.now()

	if rs.perSourceRate != nil {
		b := rs.perSource.get(sourceKey(src), now, *rs.perSourceRate)
		if !b.allow(now) {
			p.recordDropLocked(ruleID, "per_source", size)
			return false, "per_source"
		}
	}

	if rs.newFlow != nil && !rs.newFlow.allow(now) {
		p.recordDropLocked(ruleID, "new_flow", size)
		return false, "new_flow"
	}

	return true, ""
}

// AdmitPacket は UDP のデータグラム 1 つを packet_rate で判定する(TCP には使わない)。
// 落とした場合は kind "packet" として数える。未知のルール ID、packet_rate 未設定の
// ルールは通す。
func (p *Policy) AdmitPacket(ruleID string, size int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	rs, known := p.rules[ruleID]
	if !known || rs.packet == nil {
		return true
	}

	now := p.now()
	if !rs.packet.allow(now) {
		p.recordDropLocked(ruleID, "packet", size)
		return false
	}
	return true
}

// SourceAllowed は deny と allow だけを見る。レート制限は新しいフローにだけ意味を持つ
// ので、進行中のセッションを制限の変更後に切るかどうかの判定には含めない。
// 未知のルール ID は通す。
func (p *Policy) SourceAllowed(ruleID string, src netip.Addr) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	rs, known := p.rules[ruleID]
	if !known {
		return true
	}
	if matchesAny(rs.deny, src) {
		return false
	}
	if len(rs.allow) > 0 && !matchesAny(rs.allow, src) {
		return false
	}
	return true
}

// Drops は前回の呼び出し以降に数えた drop を返して 0 に戻す。nft.ReadDrops がテーブル
// 差し替えの直前にカーネルのカウンタを読むのと同じ扱いで、呼び出し側が SQLite へ累積する。
func (p *Policy) Drops() []nft.Drop {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.drops) == 0 {
		return nil
	}
	out := make([]nft.Drop, 0, len(p.drops))
	for _, d := range p.drops {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].Kind < out[j].Kind
	})
	p.drops = make(map[dropKey]*nft.Drop)
	return out
}

func (p *Policy) recordDropLocked(ruleID, kind string, size int) {
	k := dropKey{ruleID, kind}
	d := p.drops[k]
	if d == nil {
		d = &nft.Drop{RuleID: ruleID, Kind: kind}
		p.drops[k] = d
	}
	d.Packets++
	d.Bytes += uint64(size)
}

func matchesAny(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// sourceKey は接続元ごとの meter のキー。IPv4 はアドレスそのまま、IPv6 は /64 に丸める
// (design.md 6.1 節の meter は IPv4 の set だが、userspace 側は IPv6 も中継しうるため、
// 単一ホストが /128 を変えながら 1 送信元として溢れさせるのを防ぐ)。
func sourceKey(addr netip.Addr) netip.Addr {
	addr = addr.Unmap()
	if addr.Is4() {
		return addr
	}
	return netip.PrefixFrom(addr, 64).Masked().Addr()
}

// tokenBucket は nftables の `limit rate over <count>/<unit>`(burst は nft の既定の 5。nft/build.go の
// limitOver と同じ)と同じ振る舞いをするトークンバケット。容量は 5 で、count/unit の速さで補充する。
// ラボでカーネルモードと突き合わせて揃えた(2026-09-17):瞬間的に通るのは 5 個、以後は設定した速さ。
// golang.org/x/time/rate は壁時計しか使えないため、テストで時計を差し替えられるよう
// 自前で持つ。呼び出し側の mutex の下でだけ使うので、自身はロックを持たない。
type tokenBucket struct {
	capacity float64
	refill   float64 // 1 秒あたりに補充するトークン数
	tokens   float64
	last     time.Time
}

// nftBurst は nftables の limit の既定の burst(パケット数)。
const nftBurst = 5

func newTokenBucket(r proto.Rate) *tokenBucket {
	return &tokenBucket{
		capacity: nftBurst,
		refill:   float64(r.Count) / unitSeconds(r.Unit),
		// nftables の meter/limit は最初から満杯のバケットで始まる。
		tokens: nftBurst,
	}
}

// allow はトークンを 1 つ消費できれば true を返す。呼ぶたびに、直前の呼び出しからの
// 経過時間ぶんだけ補充してから判定する。
func (b *tokenBucket) allow(now time.Time) bool {
	if b.last.IsZero() {
		b.last = now
	}
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += elapsed.Seconds() * b.refill
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
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
		// proto.Rate は ParseRate/UnmarshalText でしか作られない前提であり、
		// ここに来る値は既に検査済みのはずである。念のため 1 秒として扱う。
		return 1
	}
}

// sourceTable はルール 1 つ分の、接続元ごとのバケットを持つ表。design.md 6.1 節の
// nftables の meter(1 分で期限切れ、上限 65535)を Go 側で再現する。
//
// 全件走査を避けるため、エントリを container/list で最近使った順に並べる
// (LRU)。触れるたびに先頭へ動かすので、末尾は「最後に触れてから最も時間が
// 経ったエントリ」と一致する。挿入のたびに末尾から期限切れ分だけを剥がし
// (期限切れでなくなったところで止める)、それでも上限を超える場合は末尾を
// 1 つ捨てて枠を空ける。読み取りのたびに全件を舐める実装は避けている。
type sourceTable struct {
	entries map[netip.Addr]*list.Element
	order   *list.List // 先頭 = 最近触れた、末尾 = 最も長く触れていない
}

type sourceEntry struct {
	key      netip.Addr
	bucket   *tokenBucket
	lastSeen time.Time
}

func newSourceTable() *sourceTable {
	return &sourceTable{
		entries: make(map[netip.Addr]*list.Element),
		order:   list.New(),
	}
}

// get は key のバケットを返す。無ければ rate で新しく作る。期限切れのエントリを
// 末尾から剥がし、上限に達していればさらに 1 つ捨ててから挿入する。
func (t *sourceTable) get(key netip.Addr, now time.Time, rate proto.Rate) *tokenBucket {
	t.evictExpired(now)

	if el, ok := t.entries[key]; ok {
		e := el.Value.(*sourceEntry)
		e.lastSeen = now
		t.order.MoveToFront(el)
		return e.bucket
	}

	for len(t.entries) >= perSourceCap {
		back := t.order.Back()
		if back == nil {
			break
		}
		t.removeElement(back)
	}

	e := &sourceEntry{key: key, bucket: newTokenBucket(rate), lastSeen: now}
	el := t.order.PushFront(e)
	t.entries[key] = el
	return e.bucket
}

func (t *sourceTable) evictExpired(now time.Time) {
	for {
		back := t.order.Back()
		if back == nil {
			return
		}
		e := back.Value.(*sourceEntry)
		if now.Sub(e.lastSeen) < perSourceTTL {
			return
		}
		t.removeElement(back)
	}
}

func (t *sourceTable) removeElement(el *list.Element) {
	e := el.Value.(*sourceEntry)
	delete(t.entries, e.key)
	t.order.Remove(el)
}
