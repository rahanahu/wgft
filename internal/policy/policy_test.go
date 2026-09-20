package policy

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/proto"
)

func rate(s string) *proto.Rate {
	r, err := proto.ParseRate(s)
	if err != nil {
		panic(err)
	}
	return &r
}

func TestOrderMatchesDesign(t *testing.T) {
	// design.md 6.1, 7a.2 節: deny, allow, per-source meter, per-source concurrent flow cap,
	// aggregate new-flow rate, aggregate packet rate.
	want := []Step{
		StepSourceDeny, StepSourceAllow, StepPerSourceRate,
		StepPerSourceConcurrentFlows, StepAggregateNewFlowRate, StepAggregatePacketRate,
	}
	if !reflect.DeepEqual(Order, want) {
		t.Fatalf("Order = %v, want %v", Order, want)
	}
	for _, s := range Order {
		if s.String() == "" {
			t.Fatalf("Step(%d).String() is empty", s)
		}
	}
}

// TestStepDropKindMatchesPersistedStrings pins the exact drop-counter strings design.md 7a.9 節
// requires (deny, allow, per_source, src_flow, new_flow, packet): the ones
// internal/dataplane/linuxkernel/nft and internal/policy/goengine write into the counters vpsd
// accumulates in SQLite (7 節). Every step must map to one of these, no step may
// share a kind with another, and the set must be exactly these six.
func TestStepDropKindMatchesPersistedStrings(t *testing.T) {
	want := map[Step]string{
		StepSourceDeny:               "deny",
		StepSourceAllow:              "allow",
		StepPerSourceRate:            "per_source",
		StepPerSourceConcurrentFlows: "src_flow",
		StepAggregateNewFlowRate:     "new_flow",
		StepAggregatePacketRate:      "packet",
	}
	seen := map[string]Step{}
	for _, s := range Order {
		kind := s.DropKind()
		if kind == "" {
			t.Fatalf("Step(%v).DropKind() is empty", s)
		}
		if kind != want[s] {
			t.Fatalf("Step(%v).DropKind() = %q, want %q", s, kind, want[s])
		}
		if other, dup := seen[kind]; dup {
			t.Fatalf("DropKind %q shared by %v and %v", kind, other, s)
		}
		seen[kind] = s
	}
	if len(seen) != 6 {
		t.Fatalf("got %d distinct drop kinds, want 6: %v", len(seen), seen)
	}
}

func TestBuildSkipsDisabledRules(t *testing.T) {
	rules := []model.Rule{
		{ID: "r_on", Proto: proto.UDP, Enabled: true, NewFlowRate: rate("100/second")},
		{ID: "r_off", Proto: proto.UDP, Enabled: false, NewFlowRate: rate("100/second")},
	}
	got := Build(rules, AdmissionLimits{})
	if len(got.Rules) != 1 || got.Rules[0].RuleID != "r_on" {
		t.Fatalf("Build().Rules = %+v, want only r_on", got.Rules)
	}
}

func TestBuildCarriesRuleFields(t *testing.T) {
	allow := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	deny := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	rules := []model.Rule{{
		ID: "r1", Proto: proto.TCP, Enabled: true,
		SourceAllow: allow, SourceDeny: deny,
		PerSourceRate: rate("10/second"), NewFlowRate: rate("100/second"), PacketRate: rate("5000/second"),
	}}
	got := Build(rules, AdmissionLimits{})
	want := []RulePolicy{{
		RuleID: "r1", Proto: proto.TCP,
		SourceAllow: allow, SourceDeny: deny,
		PerSourceRate: rate("10/second"), NewFlowRate: rate("100/second"), PacketRate: rate("5000/second"),
	}}
	if !reflect.DeepEqual(got.Rules, want) {
		t.Fatalf("Build().Rules = %+v, want %+v", got.Rules, want)
	}
}

func TestBuildCarriesExplicitLimits(t *testing.T) {
	got := Build(nil, AdmissionLimits{UDPPerSource: 300, TCPPerSource: 150})
	want := PerSourceFlowCaps{UDP: 300, TCP: 150}
	if got.PerSourceFlowCaps != want {
		t.Fatalf("Build().PerSourceFlowCaps = %+v, want %+v", got.PerSourceFlowCaps, want)
	}
}

// TestBuildZeroLimitsYieldDefaults locks down the zero-value rule AdmissionLimits carries over
// from the limits type it was split out of (design.md 7a.5, 7a.10 節): a zero-value
// AdmissionLimits{} must mean "use the default per-source caps" (256/128), never "no cap". Build
// must derive PerSourceFlowCaps through AdmissionLimits.UDPPerSourceCap()/TCPPerSourceCap() rather
// than reading the raw fields directly, so this stays true regardless of how PerSourceFlowCaps is
// computed.
func TestBuildZeroLimitsYieldDefaults(t *testing.T) {
	got := Build(nil, AdmissionLimits{})
	want := PerSourceFlowCaps{UDP: UDPPerSource, TCP: TCPPerSource}
	if got.PerSourceFlowCaps != want {
		t.Fatalf("Build(nil, AdmissionLimits{}).PerSourceFlowCaps = %+v, want the defaults %+v", got.PerSourceFlowCaps, want)
	}
}

// TestBuildPerSourceOffDisablesCap confirms that explicitly disabling a protocol's cap
// (PerSourceOff, as cmd/wgft's config layer produces for WGFT_MAX_*_FLOWS_PER_SOURCE=0)
// still comes out as 0 in the IR, distinct from the zero-value-means-default case above.
func TestBuildPerSourceOffDisablesCap(t *testing.T) {
	got := Build(nil, AdmissionLimits{UDPPerSource: PerSourceOff, TCPPerSource: PerSourceOff})
	want := PerSourceFlowCaps{UDP: 0, TCP: 0}
	if got.PerSourceFlowCaps != want {
		t.Fatalf("Build with PerSourceOff: PerSourceFlowCaps = %+v, want %+v", got.PerSourceFlowCaps, want)
	}
}

func TestBuildRuleWithNoAdmissionFields(t *testing.T) {
	// A rule with no source restrictions and no rates still gets a RulePolicy entry (matching
	// nft.emit, which always evaluates whether to emit deny/allow/rate rows per enabled rule; it
	// just emits none of them here). Only Enabled gates participation (design.md 7a.2 節: rule-level
	// condition).
	rules := []model.Rule{{ID: "r1", Proto: proto.UDP, Enabled: true}}
	got := Build(rules, AdmissionLimits{})
	if len(got.Rules) != 1 {
		t.Fatalf("Build().Rules = %+v, want one entry", got.Rules)
	}
	if got.Rules[0].SourceAllow != nil || got.Rules[0].SourceDeny != nil ||
		got.Rules[0].PerSourceRate != nil || got.Rules[0].NewFlowRate != nil || got.Rules[0].PacketRate != nil {
		t.Fatalf("Build().Rules[0] = %+v, want all admission fields unset", got.Rules[0])
	}
}

// TestNormalizePrefixes mirrors internal/dataplane/linuxkernel/nft's TestIntervalElements cases
// (build_test.go), because design.md 7a.9 節 says NormalizePrefixes must merge and sort the same
// way that helper already does for the nftables set, just returning a CIDR list instead of set
// elements. Keeping the two test tables in lockstep is how a future change to one merge is caught
// against the other.
func TestNormalizePrefixes(t *testing.T) {
	pfx := func(ss ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, s := range ss {
			out = append(out, netip.MustParsePrefix(s))
		}
		return out
	}
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"1 つの CIDR", []string{"203.0.113.0/24"}, []string{"203.0.113.0/24"}},
		{"順序を昇順に直す", []string{"203.0.113.0/24", "198.51.100.0/24"},
			[]string{"198.51.100.0/24", "203.0.113.0/24"}},
		{"重なりを併合", []string{"10.0.0.0/8", "10.1.0.0/16"}, []string{"10.0.0.0/8"}},
		{"隣接を併合", []string{"10.0.0.0/25", "10.0.0.128/25"}, []string{"10.0.0.0/24"}},
		{"ホストビットを落とす(マスク)", []string{"203.0.113.77/24"}, []string{"203.0.113.0/24"}},
		{"0.0.0.0/0", []string{"0.0.0.0/0"}, []string{"0.0.0.0/0"}},
		{"末尾まで続く区間", []string{"255.255.255.0/24"}, []string{"255.255.255.0/24"}},
		{"併合しても単一の CIDR にならない区間はそのまま残す",
			[]string{"10.0.1.0/25", "10.0.0.0/24"}, []string{"10.0.0.0/24", "10.0.1.0/25"}},
		{"空", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizePrefixes(pfx(tt.in...))
			want := pfx(tt.want...)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("NormalizePrefixes(%v) = %v, want %v", tt.in, got, want)
			}
		})
	}
}

// TestNormalizePrefixesMatchesBasicJSONOrder pins that, for the exact source_deny list
// testdata/basic.json declares for r_udp (203.0.113.0/24, 198.51.100.128/25: two CIDRs that are
// neither overlapping nor adjacent), NormalizePrefixes only sorts them and produces the same order
// internal/dataplane/linuxkernel/nft's own intervalElements already derives independently
// (testdata/basic.nft's deny_2 set: "198.51.100.128/25, 203.0.113.0/24"). This is the case the
// task must not disturb: Build now normalizes before nft.emit ever sees the list, but since
// intervalElements re-merges regardless (and merging is idempotent), the emitted set is unchanged.
func TestNormalizePrefixesMatchesBasicJSONOrder(t *testing.T) {
	got := NormalizePrefixes([]netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("198.51.100.128/25"),
	})
	want := []netip.Prefix{
		netip.MustParsePrefix("198.51.100.128/25"),
		netip.MustParsePrefix("203.0.113.0/24"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NormalizePrefixes = %v, want %v", got, want)
	}
}

// TestBuildNormalizesSourcePrefixes confirms Build itself applies NormalizePrefixes to both lists,
// not just that the helper exists.
func TestBuildNormalizesSourcePrefixes(t *testing.T) {
	rules := []model.Rule{{
		ID: "r1", Proto: proto.TCP, Enabled: true,
		SourceAllow: []netip.Prefix{netip.MustParsePrefix("10.0.0.128/25"), netip.MustParsePrefix("10.0.0.0/25")},
		SourceDeny:  []netip.Prefix{netip.MustParsePrefix("203.0.113.77/24")},
	}}
	got := Build(rules, AdmissionLimits{})
	wantAllow := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
	wantDeny := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	if !reflect.DeepEqual(got.Rules[0].SourceAllow, wantAllow) {
		t.Errorf("Build().Rules[0].SourceAllow = %v, want %v (merged adjacent /25s)", got.Rules[0].SourceAllow, wantAllow)
	}
	if !reflect.DeepEqual(got.Rules[0].SourceDeny, wantDeny) {
		t.Errorf("Build().Rules[0].SourceDeny = %v, want %v (masked)", got.Rules[0].SourceDeny, wantDeny)
	}
}

func TestNormalizePrefixesKeepsNonIPv4(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("2001:db8::/64"),
		netip.MustParsePrefix("192.0.2.0/25"),
		netip.MustParsePrefix("192.0.2.128/25"),
	}
	got := NormalizePrefixes(in)
	want := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/64")}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("NormalizePrefixes = %v, want %v", got, want)
	}
}
