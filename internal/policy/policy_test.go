package policy

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/rahanahu/wgft/internal/flowcap"
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

func TestBuildSkipsDisabledRules(t *testing.T) {
	rules := []model.Rule{
		{ID: "r_on", Proto: proto.UDP, Enabled: true, NewFlowRate: rate("100/second")},
		{ID: "r_off", Proto: proto.UDP, Enabled: false, NewFlowRate: rate("100/second")},
	}
	got := Build(rules, flowcap.Limits{})
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
	got := Build(rules, flowcap.Limits{})
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
	got := Build(nil, flowcap.Limits{UDPPerSource: 300, TCPPerSource: 150})
	want := PerSourceFlowCaps{UDP: 300, TCP: 150}
	if got.PerSourceFlowCaps != want {
		t.Fatalf("Build().PerSourceFlowCaps = %+v, want %+v", got.PerSourceFlowCaps, want)
	}
}

// TestBuildZeroLimitsYieldDefaults locks down the fix for the zero-value footgun internal/flowcap
// already fixed for Limits itself (design.md 7a.5 節 review): a zero-value flowcap.Limits{} must
// mean "use the default per-source caps" (256/128), never "no cap". Build must derive
// PerSourceFlowCaps through flowcap.Limits.UDPPerSourceCap()/TCPPerSourceCap() rather than reading
// the raw fields directly, so this stays true regardless of how PerSourceFlowCaps is computed.
func TestBuildZeroLimitsYieldDefaults(t *testing.T) {
	got := Build(nil, flowcap.Limits{})
	want := PerSourceFlowCaps{UDP: flowcap.UDPPerSource, TCP: flowcap.TCPPerSource}
	if got.PerSourceFlowCaps != want {
		t.Fatalf("Build(nil, flowcap.Limits{}).PerSourceFlowCaps = %+v, want the defaults %+v", got.PerSourceFlowCaps, want)
	}
}

// TestBuildPerSourceOffDisablesCap confirms that explicitly disabling a protocol's cap
// (flowcap.PerSourceOff, as internal/flowcap's own config layer produces for WGFT_MAX_*_FLOWS_PER_SOURCE=0)
// still comes out as 0 in the IR, distinct from the zero-value-means-default case above.
func TestBuildPerSourceOffDisablesCap(t *testing.T) {
	got := Build(nil, flowcap.Limits{UDPPerSource: flowcap.PerSourceOff, TCPPerSource: flowcap.PerSourceOff})
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
	got := Build(rules, flowcap.Limits{})
	if len(got.Rules) != 1 {
		t.Fatalf("Build().Rules = %+v, want one entry", got.Rules)
	}
	if got.Rules[0].SourceAllow != nil || got.Rules[0].SourceDeny != nil ||
		got.Rules[0].PerSourceRate != nil || got.Rules[0].NewFlowRate != nil || got.Rules[0].PacketRate != nil {
		t.Fatalf("Build().Rules[0] = %+v, want all admission fields unset", got.Rules[0])
	}
}
