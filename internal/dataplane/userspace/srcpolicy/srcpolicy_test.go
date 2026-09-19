package srcpolicy

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/policy"
	"github.com/rahanahu/wgft/proto"
)

// fakeClock は AdmitFlow/AdmitPacket の呼び出しをテストの実時間から切り離す。
// advance で明示的に進めない限り時刻は変わらない。
type fakeClock struct {
	t time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time { return c.t }

func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func rate(count uint64, unit proto.RateUnit) *proto.Rate {
	return &proto.Rate{Count: count, Unit: unit}
}

func prefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatalf("ParsePrefix(%q): %v", c, err)
		}
		out = append(out, p)
	}
	return out
}

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

func TestAdmitFlow_UnknownRuleAdmits(t *testing.T) {
	p := New(newFakeClock().now)
	ok, kind := p.AdmitFlow("r_unknown", addr(t, "203.0.113.1"), 40)
	if !ok || kind != "" {
		t.Fatalf("AdmitFlow for an unknown rule = (%v, %q), want (true, \"\")", ok, kind)
	}
}

func TestAdmitFlow_NoListsNoRatesAdmitsEverything(t *testing.T) {
	p := New(newFakeClock().now)
	p.Update([]policy.RulePolicy{{RuleID: "r1"}})

	for i := 0; i < 100; i++ {
		ok, kind := p.AdmitFlow("r1", addr(t, "203.0.113.1"), 40)
		if !ok || kind != "" {
			t.Fatalf("call %d: AdmitFlow = (%v, %q), want (true, \"\")", i, ok, kind)
		}
	}
	if drops := p.Drops(); drops != nil {
		t.Fatalf("Drops = %v, want nil (no state, nothing dropped)", drops)
	}
}

func TestAdmitFlow_DenyList(t *testing.T) {
	clock := newFakeClock()
	p := New(clock.now)
	p.Update([]policy.RulePolicy{{
		RuleID:     "r1",
		SourceDeny: prefixes(t, "203.0.113.0/24"),
	}})

	ok, kind := p.AdmitFlow("r1", addr(t, "203.0.113.5"), 40)
	if ok || kind != "deny" {
		t.Fatalf("denied source: AdmitFlow = (%v, %q), want (false, \"deny\")", ok, kind)
	}
	ok, kind = p.AdmitFlow("r1", addr(t, "198.51.100.5"), 40)
	if !ok || kind != "" {
		t.Fatalf("other source: AdmitFlow = (%v, %q), want (true, \"\")", ok, kind)
	}
}

func TestAdmitFlow_AllowList(t *testing.T) {
	clock := newFakeClock()
	p := New(clock.now)
	p.Update([]policy.RulePolicy{{
		RuleID:      "r1",
		SourceAllow: prefixes(t, "10.0.0.0/24"),
	}})

	ok, kind := p.AdmitFlow("r1", addr(t, "10.0.0.5"), 40)
	if !ok || kind != "" {
		t.Fatalf("allowed source: AdmitFlow = (%v, %q), want (true, \"\")", ok, kind)
	}
	ok, kind = p.AdmitFlow("r1", addr(t, "10.0.1.5"), 40)
	if ok || kind != "allow" {
		t.Fatalf("outside allow: AdmitFlow = (%v, %q), want (false, \"allow\")", ok, kind)
	}
}

// TestAdmitFlow_DenyPrecedesLimits は評価順(deny、allow、per_source、new_flow)を確かめる。
// deny された送信元は、他の送信元の new_flow バケットを消費しない
// (deny が最初に効き、他の判定に進まない)ことを、別の送信元の枠が減っていないことで示す。
func TestAdmitFlow_DenyPrecedesLimits(t *testing.T) {
	clock := newFakeClock()
	p := New(clock.now)
	p.Update([]policy.RulePolicy{{
		RuleID:      "r1",
		SourceDeny:  prefixes(t, "203.0.113.0/24"),
		NewFlowRate: rate(1, proto.PerSecond),
	}})

	denied := addr(t, "203.0.113.5")
	for i := 0; i < 5; i++ {
		ok, kind := p.AdmitFlow("r1", denied, 40)
		if ok || kind != "deny" {
			t.Fatalf("call %d: AdmitFlow(denied) = (%v, %q), want (false, \"deny\")", i, ok, kind)
		}
	}

	// new_flow のバケットは容量 1。deny が新規フローの判定に進んでいれば、
	// ここまでの 5 回でどれか 1 回は消費されてしまっているはずである。
	other := addr(t, "198.51.100.5")
	ok, kind := p.AdmitFlow("r1", other, 40)
	if !ok || kind != "" {
		t.Fatalf("AdmitFlow(other) = (%v, %q), want (true, \"\"): deny consumed the shared new_flow bucket", ok, kind)
	}

	drops := p.Drops()
	if len(drops) != 1 {
		t.Fatalf("Drops = %v, want exactly one accumulated drop (kind=deny, packets=5)", drops)
	}
	d := drops[0]
	if d.RuleID != "r1" || d.Kind != "deny" || d.Packets != 5 || d.Bytes != 200 {
		t.Fatalf("Drops[0] = %+v, want {RuleID:r1 Kind:deny Packets:5 Bytes:200}", d)
	}
}

func TestAdmitFlow_PerSourceIsolatesSources(t *testing.T) {
	clock := newFakeClock()
	p := New(clock.now)
	p.Update([]policy.RulePolicy{{
		RuleID:        "r1",
		PerSourceRate: rate(2, proto.PerSecond),
	}})

	a := addr(t, "203.0.113.1")
	b := addr(t, "203.0.113.2")

	for i := 0; i < nftBurst; i++ { // burst の分だけ通る
		if ok, kind := p.AdmitFlow("r1", a, 10); !ok || kind != "" {
			t.Fatalf("src A call %d = (%v, %q), want (true, \"\")", i, ok, kind)
		}
	}
	if ok, kind := p.AdmitFlow("r1", a, 10); ok || kind != "per_source" {
		t.Fatalf("src A call after the burst = (%v, %q), want (false, \"per_source\")", ok, kind)
	}

	// src B のバケットは src A と独立していて、まだ満杯のはずである。
	if ok, kind := p.AdmitFlow("r1", b, 10); !ok || kind != "" {
		t.Fatalf("src B call = (%v, %q), want (true, \"\"): per_source bucket leaked across sources", ok, kind)
	}
}

func TestAdmitFlow_NewFlowSharedAcrossSources(t *testing.T) {
	clock := newFakeClock()
	p := New(clock.now)
	p.Update([]policy.RulePolicy{{
		RuleID:      "r1",
		NewFlowRate: rate(2, proto.PerSecond),
	}})

	// 送信元を変えても同じバケットを消費する。burst の分が尽きたら次の送信元も落ちる
	for i := 0; i < nftBurst; i++ {
		src := addr(t, fmt.Sprintf("203.0.113.%d", i+1))
		if ok, kind := p.AdmitFlow("r1", src, 10); !ok || kind != "" {
			t.Fatalf("call %d = (%v, %q), want (true, \"\")", i, ok, kind)
		}
	}
	ok, kind := p.AdmitFlow("r1", addr(t, "203.0.113.100"), 10)
	if ok || kind != "new_flow" {
		t.Fatalf("distinct source after the burst = (%v, %q), want (false, \"new_flow\")", ok, kind)
	}
}

func TestAdmitFlow_RefillsOverTime(t *testing.T) {
	clock := newFakeClock()
	p := New(clock.now)
	p.Update([]policy.RulePolicy{{
		RuleID:      "r1",
		NewFlowRate: rate(1, proto.PerSecond),
	}})

	src := addr(t, "203.0.113.1")
	for i := 0; i < nftBurst; i++ {
		if ok, _ := p.AdmitFlow("r1", src, 10); !ok {
			t.Fatalf("call %d within the burst should be admitted", i)
		}
	}
	if ok, kind := p.AdmitFlow("r1", src, 10); ok || kind != "new_flow" {
		t.Fatalf("call after the burst before refill = (%v, %q), want (false, \"new_flow\")", ok, kind)
	}

	clock.advance(time.Second)
	if ok, kind := p.AdmitFlow("r1", src, 10); !ok || kind != "" {
		t.Fatalf("call after 1s refill = (%v, %q), want (true, \"\")", ok, kind)
	}
}

func TestAdmitPacket_UsesPacketRateOnly(t *testing.T) {
	clock := newFakeClock()
	p := New(clock.now)
	p.Update([]policy.RulePolicy{{
		RuleID:     "r1",
		PacketRate: rate(2, proto.PerSecond),
	}})

	src := addr(t, "203.0.113.1")
	// AdmitFlow はこのルールに new_flow/per_source を設定していないので、
	// packet_rate の状態を消費せず何度呼んでも通る。
	for i := 0; i < 5; i++ {
		if ok, kind := p.AdmitFlow("r1", src, 10); !ok || kind != "" {
			t.Fatalf("AdmitFlow call %d = (%v, %q), want (true, \"\")", i, ok, kind)
		}
	}

	for i := 0; i < nftBurst; i++ {
		if ok := p.AdmitPacket("r1", 10); !ok {
			t.Fatalf("packet %d within the burst should be admitted", i)
		}
	}
	if ok := p.AdmitPacket("r1", 10); ok {
		t.Fatalf("packet after the burst should be dropped (packet_rate exhausted)")
	}

	drops := p.Drops()
	if len(drops) != 1 || drops[0].Kind != "packet" || drops[0].Packets != 1 {
		t.Fatalf("Drops = %v, want one packet drop", drops)
	}
}

func TestAdmitPacket_UnknownOrUnsetAdmits(t *testing.T) {
	clock := newFakeClock()
	p := New(clock.now)
	p.Update([]policy.RulePolicy{{RuleID: "r1"}})

	if ok := p.AdmitPacket("r1", 10); !ok {
		t.Fatalf("rule without packet_rate should admit")
	}
	if ok := p.AdmitPacket("r_missing", 10); !ok {
		t.Fatalf("unknown rule should admit")
	}
}

func TestDrops_AccumulatesAndResets(t *testing.T) {
	clock := newFakeClock()
	p := New(clock.now)
	p.Update([]policy.RulePolicy{{
		RuleID:     "r1",
		SourceDeny: prefixes(t, "203.0.113.0/24"),
	}})

	if drops := p.Drops(); drops != nil {
		t.Fatalf("Drops before any activity = %v, want nil", drops)
	}

	src := addr(t, "203.0.113.9")
	p.AdmitFlow("r1", src, 100)
	p.AdmitFlow("r1", src, 50)

	drops := p.Drops()
	if len(drops) != 1 {
		t.Fatalf("Drops = %v, want exactly one entry", drops)
	}
	if drops[0].RuleID != "r1" || drops[0].Kind != "deny" || drops[0].Packets != 2 || drops[0].Bytes != 150 {
		t.Fatalf("Drops[0] = %+v, want {r1 deny 2 150}", drops[0])
	}

	if drops := p.Drops(); drops != nil {
		t.Fatalf("Drops after read = %v, want nil (reset to zero)", drops)
	}
}

func TestSourceAllowed(t *testing.T) {
	clock := newFakeClock()
	p := New(clock.now)
	p.Update([]policy.RulePolicy{{
		RuleID:      "r1",
		SourceAllow: prefixes(t, "10.0.0.0/24"),
		SourceDeny:  prefixes(t, "10.0.0.128/28"),
	}})

	if !p.SourceAllowed("r1", addr(t, "10.0.0.5")) {
		t.Fatalf("10.0.0.5 should be allowed")
	}
	if p.SourceAllowed("r1", addr(t, "10.0.1.5")) {
		t.Fatalf("10.0.1.5 is outside source_allow, should not be allowed")
	}
	if p.SourceAllowed("r1", addr(t, "10.0.0.129")) {
		t.Fatalf("10.0.0.129 is inside source_deny, should not be allowed")
	}
	if !p.SourceAllowed("r_missing", addr(t, "10.0.0.5")) {
		t.Fatalf("unknown rule should be allowed")
	}
}

func TestUpdate_KeepsStateOfUnchangedRulesAndDropsRemoved(t *testing.T) {
	clock := newFakeClock()
	p := New(clock.now)
	r1 := policy.RulePolicy{RuleID: "r1", PerSourceRate: rate(1, proto.PerSecond)}
	r2 := policy.RulePolicy{RuleID: "r2", NewFlowRate: rate(1, proto.PerSecond)}
	p.Update([]policy.RulePolicy{r1, r2})

	src := addr(t, "203.0.113.1")
	// r1 のバケットを使い切った状態にする(burst の分を通した後、次の呼び出しは per_source で落ちるはず)。
	for i := 0; i < nftBurst; i++ {
		if ok, _ := p.AdmitFlow("r1", src, 10); !ok {
			t.Fatalf("r1 call %d should be admitted", i)
		}
	}
	if ok, kind := p.AdmitFlow("r1", src, 10); ok || kind != "per_source" {
		t.Fatalf("r1 call after the burst = (%v, %q), want (false, \"per_source\")", ok, kind)
	}
	p.Drops() // ここまでの drop を捨てて、後の検証をやり直しやすくする

	// r1 と同じ設定のまま Update し直す。r2 は消える。
	p.Update([]policy.RulePolicy{r1})

	// r1 は消費済みの状態が保たれ、時間が経っていないので依然として落ちる。
	if ok, kind := p.AdmitFlow("r1", src, 10); ok || kind != "per_source" {
		t.Fatalf("r1 after Update = (%v, %q), want (false, \"per_source\"); state should have been kept", ok, kind)
	}

	// r2 は集合から消えたので、未知のルールとして常に通る。
	if ok, kind := p.AdmitFlow("r2", src, 10); !ok || kind != "" {
		t.Fatalf("r2 after removal = (%v, %q), want (true, \"\"); removed rule state should be discarded", ok, kind)
	}
}

func TestUpdate_RateChangeResetsBucket(t *testing.T) {
	clock := newFakeClock()
	p := New(clock.now)
	r1 := policy.RulePolicy{RuleID: "r1", NewFlowRate: rate(1, proto.PerSecond)}
	p.Update([]policy.RulePolicy{r1})

	src := addr(t, "203.0.113.1")
	for i := 0; i < nftBurst; i++ {
		p.AdmitFlow("r1", src, 10) // バケットを使い切る
	}

	r1Changed := policy.RulePolicy{RuleID: "r1", NewFlowRate: rate(5, proto.PerSecond)}
	p.Update([]policy.RulePolicy{r1Changed})

	// レートが変わった(容量が増えた)ので、新しいバケットで満杯から始まるはずである。
	if ok, kind := p.AdmitFlow("r1", src, 10); !ok || kind != "" {
		t.Fatalf("after rate change = (%v, %q), want (true, \"\"): bucket should have been recreated", ok, kind)
	}
}

func TestSourceTable_CapEvictsLeastRecentlyUsed(t *testing.T) {
	tbl := newSourceTable()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r := proto.Rate{Count: 1, Unit: proto.PerSecond}

	first := netip.MustParseAddr("10.0.0.1")
	b := tbl.get(first, now, r)
	if !b.allow(now) {
		t.Fatalf("first token for %s should be available", first)
	}
	// first のトークンは使い切った。時間を進めないので自然には補充されない。

	// perSourceCap を超える数の別送信元を挿入し、first を追い出させる。
	for i := 0; i <= perSourceCap; i++ {
		a := netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
		if a == first {
			continue
		}
		tbl.get(a, now, r)
	}

	if len(tbl.entries) > perSourceCap {
		t.Fatalf("len(entries) = %d, want at most %d", len(tbl.entries), perSourceCap)
	}

	// first は最も長く触れられていないエントリとして押し出されているはずなので、
	// 新しいバケットが返り、使い切ったトークンは残っていない。
	b2 := tbl.get(first, now, r)
	if !b2.allow(now) {
		t.Fatalf("%s should have gotten a fresh bucket after being evicted", first)
	}
}

func TestSourceTable_ExpiresAfterTTL(t *testing.T) {
	tbl := newSourceTable()
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r := proto.Rate{Count: 1, Unit: proto.PerSecond}

	a := netip.MustParseAddr("10.0.0.1")
	b := tbl.get(a, start, r)
	b.allow(start) // トークンを使い切る

	after := start.Add(perSourceTTL + time.Second)
	b2 := tbl.get(a, after, r)
	if !b2.allow(after) {
		t.Fatalf("entry should have expired after TTL and started with a fresh bucket")
	}
	if len(tbl.entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(tbl.entries))
	}
}

func TestPerSource_IPv6Slash64Keying(t *testing.T) {
	clock := newFakeClock()
	p := New(clock.now)
	p.Update([]policy.RulePolicy{{
		RuleID:        "r1",
		PerSourceRate: rate(1, proto.PerSecond),
	}})

	a1 := addr(t, "2001:db8::1")
	a2 := addr(t, "2001:db8::2")   // 同じ /64
	b1 := addr(t, "2001:db8:1::1") // 異なる /64

	for i := 0; i < nftBurst; i++ {
		if ok, _ := p.AdmitFlow("r1", a1, 10); !ok {
			t.Fatalf("a1 call %d should be admitted", i)
		}
	}
	if ok, kind := p.AdmitFlow("r1", a2, 10); ok || kind != "per_source" {
		t.Fatalf("a2 (same /64 as a1) = (%v, %q), want (false, \"per_source\"): should share a1's bucket", ok, kind)
	}
	if ok, kind := p.AdmitFlow("r1", b1, 10); !ok || kind != "" {
		t.Fatalf("b1 (different /64) = (%v, %q), want (true, \"\"): should have its own bucket", ok, kind)
	}
}
