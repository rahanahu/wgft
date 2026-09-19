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

func TestBuildSkipsDisabledRules(t *testing.T) {
	rules := []model.Rule{
		{ID: "r_on", Proto: proto.UDP, Enabled: true, NewFlowRate: rate("100/second")},
		{ID: "r_off", Proto: proto.UDP, Enabled: false, NewFlowRate: rate("100/second")},
	}
	got := Build(rules, Settings{})
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
	got := Build(rules, Settings{})
	want := []RulePolicy{{
		RuleID: "r1", Proto: proto.TCP,
		SourceAllow: allow, SourceDeny: deny,
		PerSourceRate: rate("10/second"), NewFlowRate: rate("100/second"), PacketRate: rate("5000/second"),
	}}
	if !reflect.DeepEqual(got.Rules, want) {
		t.Fatalf("Build().Rules = %+v, want %+v", got.Rules, want)
	}
}

func TestBuildCarriesSettings(t *testing.T) {
	got := Build(nil, Settings{UDPPerSourceFlows: 256, TCPPerSourceFlows: 128})
	want := PerSourceFlowCaps{UDP: 256, TCP: 128}
	if got.PerSourceFlowCaps != want {
		t.Fatalf("Build().PerSourceFlowCaps = %+v, want %+v", got.PerSourceFlowCaps, want)
	}
}

func TestBuildRuleWithNoAdmissionFields(t *testing.T) {
	// A rule with no source restrictions and no rates still gets a RulePolicy entry (matching
	// nft.emit, which always evaluates whether to emit deny/allow/rate rows per enabled rule; it
	// just emits none of them here). Only Enabled gates participation (design.md 7a.2 節: rule-level
	// condition).
	rules := []model.Rule{{ID: "r1", Proto: proto.UDP, Enabled: true}}
	got := Build(rules, Settings{})
	if len(got.Rules) != 1 {
		t.Fatalf("Build().Rules = %+v, want one entry", got.Rules)
	}
	if got.Rules[0].SourceAllow != nil || got.Rules[0].SourceDeny != nil ||
		got.Rules[0].PerSourceRate != nil || got.Rules[0].NewFlowRate != nil || got.Rules[0].PacketRate != nil {
		t.Fatalf("Build().Rules[0] = %+v, want all admission fields unset", got.Rules[0])
	}
}
