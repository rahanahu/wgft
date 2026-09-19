package goengine

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/policy"
	"github.com/rahanahu/wgft/proto"
)

// 共有 fixture(internal/policy/testdata/admission)が覆わない場面を確かめる。IPv6 の送信元は
// kernel の行に一致しないので fixture に書けず、ここで確かめる(設計文書 7a.9 節)。

type clock struct{ t time.Time }

func newClock() *clock                   { return &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)} }
func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func rate(n uint64, u proto.RateUnit) *proto.Rate { return &proto.Rate{Count: n, Unit: u} }

var (
	src1 = netip.MustParseAddr("198.51.100.1")
	src2 = netip.MustParseAddr("198.51.100.2")
)

func udpRule(id string) policy.RulePolicy { return policy.RulePolicy{RuleID: id, Proto: proto.UDP} }

// must は AdmitFlow と AdmitSourceFlow の結果が通す判定であることを確かめ、Ticket を返す。
func must(t *testing.T) func(Decision, *Ticket) *Ticket {
	t.Helper()
	return func(d Decision, tk *Ticket) *Ticket {
		t.Helper()
		if !d.Allow || tk == nil {
			t.Fatalf("decision = %+v, ticket = %v; want an admit with a ticket", d, tk)
		}
		return tk
	}
}

func TestUnknownRuleFailsClosedUncounted(t *testing.T) {
	e := New(newClock().now)
	e.Update(policy.Policy{Rules: []policy.RulePolicy{udpRule("r1")}})
	if d, tk := e.AdmitFlow("r_missing", src1, 10); d.Allow || d.Kind != "" || tk != nil {
		t.Errorf("AdmitFlow(unknown) = %+v, %v; want an uncounted reject", d, tk)
	}
	if d, _ := e.AdmitSourceFlow("r_missing", src1); d.Allow || d.Kind != "" {
		t.Errorf("AdmitSourceFlow(unknown) = %+v; want an uncounted reject", d)
	}
	if d := e.AdmitPacket("r_missing", 10); d.Allow || d.Kind != "" {
		t.Errorf("AdmitPacket(unknown) = %+v; want an uncounted reject", d)
	}
	if e.SourceAllowed("r_missing", src1) {
		t.Error("SourceAllowed(unknown) = true; want false")
	}
	if d := e.Drops(); d != nil {
		t.Errorf("Drops = %v; want none", d)
	}
}

func TestNewEngineRejectsBeforeUpdate(t *testing.T) {
	e := New(nil)
	if d, _ := e.AdmitFlow("r1", src1, 0); d.Allow {
		t.Error("an engine without a policy admitted a flow")
	}
}

func TestNonIPv4SourceFailsClosedUncounted(t *testing.T) {
	e := New(newClock().now)
	e.Update(policy.Policy{Rules: []policy.RulePolicy{udpRule("r1")}})
	for _, s := range []string{"2001:db8::1", "::1", "fe80::1"} {
		a := netip.MustParseAddr(s)
		if d, tk := e.AdmitFlow("r1", a, 10); d.Allow || d.Kind != "" || tk != nil {
			t.Errorf("AdmitFlow(%s) = %+v; want an uncounted reject", s, d)
		}
		if d, _ := e.AdmitSourceFlow("r1", a); d.Allow || d.Kind != "" {
			t.Errorf("AdmitSourceFlow(%s) = %+v; want an uncounted reject", s, d)
		}
		if e.SourceAllowed("r1", a) {
			t.Errorf("SourceAllowed(%s) = true; want false", s)
		}
	}
	if d, zero := e.AdmitFlow("r1", netip.Addr{}, 0); d.Allow || zero != nil {
		t.Error("the zero address was admitted")
	}
	// IPv4 射影は IPv4 に戻してから判定する
	mapped := netip.MustParseAddr("::ffff:198.51.100.1")
	must(t)(e.AdmitFlow("r1", mapped, 10))
	if !e.SourceAllowed("r1", mapped) {
		t.Error("SourceAllowed(IPv4-mapped) = false; want true")
	}
	if d := e.Drops(); d != nil {
		t.Errorf("Drops = %v; want none", d)
	}
}

// 後の段が拒んだフローは、送信元ごとの同時フロー数の枠をその場で返す。
func TestLaterStepReleasesSlot(t *testing.T) {
	c := newClock()
	e := New(c.now)
	r := udpRule("r1")
	r.NewFlowRate = rate(1, proto.PerHour)
	e.Update(policy.Policy{Rules: []policy.RulePolicy{r}, PerSourceFlowCaps: policy.PerSourceFlowCaps{UDP: 1}})
	for i := range policy.TokenBucketBurst {
		tk := must(t)(e.AdmitFlow("r1", netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}), 0))
		tk.Release()
	}
	for range 3 {
		if d, tk := e.AdmitFlow("r1", src1, 5); d.Allow || d.Kind != "new_flow" || tk != nil {
			t.Fatalf("AdmitFlow = %+v; want drop:new_flow", d)
		}
	}
	if n := len(e.flows); n != 0 {
		t.Fatalf("per-source counts after rejected flows = %v; want empty", e.flows)
	}
	// new_flow が拒んだ 3 つのフローが枠を持ち続けていれば、上限 1 のこの送信元は src_flow で拒まれる
	r.NewFlowRate = nil
	e.Update(policy.Policy{Rules: []policy.RulePolicy{r}, PerSourceFlowCaps: policy.PerSourceFlowCaps{UDP: 1}})
	tk := must(t)(e.AdmitFlow("r1", src1, 0))
	if d, _ := e.AdmitFlow("r1", src1, 7); d.Kind != "src_flow" {
		t.Fatalf("second flow = %+v; want drop:src_flow", d)
	}
	tk.Release()
	tk.Release() // 2 回目は何もしない
	var none *Ticket
	none.Release()
	must(t)(e.AdmitFlow("r1", src1, 0))
	drops := e.Drops()
	want := []Drop{{RuleID: "r1", Kind: "new_flow", Packets: 3, Bytes: 15}, {RuleID: "r1", Kind: "src_flow", Packets: 1, Bytes: 7}}
	if len(drops) != len(want) || drops[0] != want[0] || drops[1] != want[1] {
		t.Errorf("Drops = %+v; want %+v", drops, want)
	}
	if d := e.Drops(); d != nil {
		t.Errorf("Drops after reading = %v; want none", d)
	}
}

// 送信元ごとの同時フロー数はプロトコルごとに全ルールで合算し、Relay の接続(AdmitSourceFlow)も
// Transparent の TCP と同じ数に入る。
func TestSourceFlowSharedAcrossRulesAndRelay(t *testing.T) {
	e := New(newClock().now)
	tcp := policy.RulePolicy{RuleID: "r_tcp", Proto: proto.TCP}
	relay := policy.RulePolicy{RuleID: "r_relay", Proto: proto.TCP, NewFlowRate: rate(1, proto.PerHour), SourceDeny: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}}
	e.Update(policy.Policy{Rules: []policy.RulePolicy{tcp, relay, udpRule("r_udp")}, PerSourceFlowCaps: policy.PerSourceFlowCaps{UDP: 1, TCP: 2}})
	a := must(t)(e.AdmitFlow("r_tcp", src1, 0))
	// AdmitSourceFlow は送信元の拒否もレートも評価しない(移行の手順 4 まで)
	b := must(t)(e.AdmitSourceFlow("r_relay", src1))
	if d, _ := e.AdmitSourceFlow("r_relay", src1); d.Kind != "src_flow" {
		t.Errorf("third TCP flow = %+v; want drop:src_flow", d)
	}
	if d, _ := e.AdmitFlow("r_tcp", src1, 0); d.Kind != "src_flow" {
		t.Errorf("third TCP flow = %+v; want drop:src_flow", d)
	}
	must(t)(e.AdmitFlow("r_udp", src1, 0)) // UDP は別に数える
	must(t)(e.AdmitFlow("r_tcp", src2, 0)) // 送信元ごと
	b.Release()
	must(t)(e.AdmitFlow("r_tcp", src1, 0))
	a.Release()
}

// 上限を Update で下げても成立済みのフローは追い出さず、数は引き継ぐ。0 は上限なし。
// 宣言から消えたルールは、次の Update まで旧い方針で判定を続ける(分割と統合で待ち受けの所属ルール
// ID を付け替えるまでの間、旧い ID の新しいフローを拒まないため)。その次の Update で拒むようになり、
// 宣言に戻れば状態を新しく作る。一度も宣言に無かった ID は、最初から拒む。
func TestRemovedRuleRetiresForOneUpdate(t *testing.T) {
	e := New(newClock().now)
	old := udpRule("r_old")
	old.SourceDeny = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	old.NewFlowRate = rate(1, proto.PerHour)
	e.Update(policy.Policy{Rules: []policy.RulePolicy{old}})
	for range policy.TokenBucketBurst {
		must(t)(e.AdmitFlow("r_old", src1, 0)).Release()
	}
	// 分割:r_old が r_a と r_b に置き換わる
	split := policy.Policy{Rules: []policy.RulePolicy{udpRule("r_a"), udpRule("r_b")}}
	e.Update(split)
	if d, _ := e.AdmitFlow("r_old", src1, 0); d.Kind != "new_flow" {
		t.Errorf("r_old right after the split = %+v; want its old policy (drop:new_flow), not a refusal as unknown", d)
	}
	if d, _ := e.AdmitFlow("r_old", netip.MustParseAddr("203.0.113.9"), 0); d.Kind != "deny" {
		t.Errorf("r_old right after the split, denied source = %+v; want drop:deny", d)
	}
	if !e.SourceAllowed("r_old", src1) {
		t.Error("SourceAllowed(r_old) right after the split = false")
	}
	if d, _ := e.AdmitFlow("r_never", src1, 0); d.Allow || d.Kind != "" {
		t.Errorf("a rule ID never declared = %+v; want an uncounted refusal", d)
	}
	e.Update(split)
	if d, _ := e.AdmitFlow("r_old", src1, 0); d.Allow || d.Kind != "" {
		t.Errorf("r_old one Update later = %+v; want an uncounted refusal", d)
	}
	// 退いたルールの状態は引き継がない(使い切った new_flow のバケットは新しくなる)
	e.Update(policy.Policy{Rules: []policy.RulePolicy{old}})
	for range policy.TokenBucketBurst {
		must(t)(e.AdmitFlow("r_old", src1, 0)).Release()
	}
	e.Update(policy.Policy{Rules: []policy.RulePolicy{udpRule("r_a")}})
	e.Update(policy.Policy{Rules: []policy.RulePolicy{old}})
	must(t)(e.AdmitFlow("r_old", src1, 0))
}

func TestUpdateKeepsFlowCounts(t *testing.T) {
	e := New(newClock().now)
	rules := []policy.RulePolicy{udpRule("r1")}
	e.Update(policy.Policy{Rules: rules})
	var held []*Ticket
	for range 3 {
		held = append(held, must(t)(e.AdmitFlow("r1", src1, 0)))
	}
	e.Update(policy.Policy{Rules: rules, PerSourceFlowCaps: policy.PerSourceFlowCaps{UDP: 2}})
	if d, _ := e.AdmitFlow("r1", src1, 0); d.Kind != "src_flow" {
		t.Fatalf("flow over the lowered cap = %+v; want drop:src_flow", d)
	}
	held[0].Release()
	held[1].Release()
	must(t)(e.AdmitFlow("r1", src1, 0))
}

func TestUpdateCarriesBucketsUnlessRateChanges(t *testing.T) {
	c := newClock()
	e := New(c.now)
	r := udpRule("r1")
	r.NewFlowRate = rate(1, proto.PerHour)
	other := udpRule("r2")
	other.PerSourceRate = rate(1, proto.PerHour)
	e.Update(policy.Policy{Rules: []policy.RulePolicy{r, other}})
	for range policy.TokenBucketBurst {
		must(t)(e.AdmitFlow("r1", netip.AddrFrom4([4]byte{10, 0, 0, 1}), 0)).Release()
		must(t)(e.AdmitFlow("r2", src1, 0)).Release()
	}
	// 値の同じ宣言をもう一度入れても、バケットと送信元の表は引き継ぐ
	r2 := r
	r2.NewFlowRate = rate(1, proto.PerHour)
	e.Update(policy.Policy{Rules: []policy.RulePolicy{r2, other}})
	if d, _ := e.AdmitFlow("r1", src2, 0); d.Kind != "new_flow" {
		t.Errorf("after an unchanged Update = %+v; want drop:new_flow (bucket kept)", d)
	}
	if d, _ := e.AdmitFlow("r2", src1, 0); d.Kind != "per_source" {
		t.Errorf("after an unchanged Update = %+v; want drop:per_source (table kept)", d)
	}
	// レートの値を変えると、そのルールの状態だけを作り直す
	r2.NewFlowRate = rate(2, proto.PerHour)
	e.Update(policy.Policy{Rules: []policy.RulePolicy{r2, other}})
	must(t)(e.AdmitFlow("r1", src2, 0))
	if d, _ := e.AdmitFlow("r2", src1, 0); d.Kind != "per_source" {
		t.Errorf("r2 after r1's rate changed = %+v; want drop:per_source", d)
	}
	// 消えたルールの状態は捨て、戻ってきたら新しく作る
	e.Update(policy.Policy{Rules: []policy.RulePolicy{r2}})
	e.Update(policy.Policy{Rules: []policy.RulePolicy{r2, other}})
	must(t)(e.AdmitFlow("r2", src1, 0))
}

func TestAdmitPacket(t *testing.T) {
	c := newClock()
	e := New(c.now)
	u := udpRule("r_udp")
	u.PacketRate = rate(10, proto.PerSecond)
	tcp := policy.RulePolicy{RuleID: "r_tcp", Proto: proto.TCP, PacketRate: rate(1, proto.PerHour)}
	e.Update(policy.Policy{Rules: []policy.RulePolicy{u, tcp, udpRule("r_none")}})
	for i := range policy.TokenBucketBurst {
		if d := e.AdmitPacket("r_udp", 100); !d.Allow {
			t.Fatalf("datagram %d = %+v; want admit", i, d)
		}
	}
	if d := e.AdmitPacket("r_udp", 100); d.Kind != "packet" {
		t.Fatalf("datagram over the burst = %+v; want drop:packet", d)
	}
	c.advance(150 * time.Millisecond)
	if d := e.AdmitPacket("r_udp", 100); !d.Allow {
		t.Errorf("datagram after a refill = %+v; want admit", d)
	}
	for range 10 {
		if d := e.AdmitPacket("r_tcp", 100); !d.Allow {
			t.Fatalf("TCP packet = %+v; packet_rate must not apply to TCP", d)
		}
		if d := e.AdmitPacket("r_none", 100); !d.Allow {
			t.Fatalf("datagram without packet_rate = %+v; want admit", d)
		}
	}
	if d := e.Drops(); len(d) != 1 || d[0] != (Drop{RuleID: "r_udp", Kind: "packet", Packets: 1, Bytes: 100}) {
		t.Errorf("Drops = %+v", d)
	}
}

func TestSourceAllowed(t *testing.T) {
	e := New(newClock().now)
	r := udpRule("r1")
	r.SourceAllow = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	r.SourceDeny = []netip.Prefix{netip.MustParsePrefix("198.51.100.2/32")}
	r.NewFlowRate = rate(1, proto.PerHour)
	e.Update(policy.Policy{Rules: []policy.RulePolicy{r}})
	for range 20 {
		if !e.SourceAllowed("r1", src1) {
			t.Fatal("SourceAllowed(allowed source) = false")
		}
	}
	if e.SourceAllowed("r1", src2) || e.SourceAllowed("r1", netip.MustParseAddr("203.0.113.1")) {
		t.Error("SourceAllowed admitted a denied or not-allowed source")
	}
	// SourceAllowed はトークンを使わず、drop にも数えない
	must(t)(e.AdmitFlow("r1", src1, 0))
	if d := e.Drops(); d != nil {
		t.Errorf("Drops = %v; want none", d)
	}
}

func TestSourceTableExpiryAndOverflow(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tbl := newSourceTable(proto.Rate{Count: 1, Unit: proto.PerHour})
	spend := func(b *tokenBucket) {
		for b.allow(now) {
		}
	}
	first := netip.MustParseAddr("10.0.0.1")
	spend(tbl.get(first, now))
	if tbl.get(first, now).allow(now) {
		t.Fatal("a spent bucket admitted")
	}
	// 最後に触れてから期限まで経つと、新しいバケットになる
	later := now.Add(policy.PerSourceTableTTL)
	if !tbl.get(first, later).allow(later) {
		t.Error("the entry did not expire after the TTL")
	}
	spend(tbl.get(first, later))
	// 上限まで埋まると、最も長く触れていない送信元を捨てる
	for i := 1; i <= policy.PerSourceTableSize; i++ {
		tbl.get(netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)}), later)
	}
	if len(tbl.entries) != policy.PerSourceTableSize {
		t.Fatalf("entries = %d; want %d", len(tbl.entries), policy.PerSourceTableSize)
	}
	if !tbl.get(first, later).allow(later) {
		t.Error("the least recently used source was not evicted")
	}
}

// 複数の中継からの同時の呼び出しを、-race で確かめる。
func TestConcurrentUse(t *testing.T) {
	e := New(nil)
	r := udpRule("r1")
	r.NewFlowRate = rate(1000, proto.PerSecond)
	r.PacketRate = rate(1000, proto.PerSecond)
	pol := policy.Policy{Rules: []policy.RulePolicy{r}, PerSourceFlowCaps: policy.PerSourceFlowCaps{UDP: 4}}
	e.Update(pol)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			src := netip.AddrFrom4([4]byte{10, 0, 0, byte(g)})
			for range 500 {
				if d, tk := e.AdmitFlow("r1", src, 1); d.Allow {
					e.AdmitPacket("r1", 1)
					e.SourceAllowed("r1", src)
					tk.Release()
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 100 {
			e.Update(pol)
			e.Drops()
		}
	}()
	wg.Wait()
	if len(e.flows) != 0 {
		t.Errorf("per-source counts after every flow ended = %v; want empty", e.flows)
	}
}
