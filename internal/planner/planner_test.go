package planner

import (
	"math/rand"
	"net/netip"
	"reflect"
	"testing"

	"github.com/rahanahu/wgft/internal/flowcap"
	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/proto"
)

func pr(lo, hi uint16) proto.PortRange { return proto.PortRange{Lo: lo, Hi: hi} }

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestBuildSkipsDisabledAndUnknownAgent(t *testing.T) {
	in := Input{
		Rules: []model.Rule{
			{ID: "r_on", Agent: "home", Proto: proto.UDP, ListenPort: pr(1000, 1000), Enabled: true},
			{ID: "r_off", Agent: "home", Proto: proto.UDP, ListenPort: pr(1001, 1001), Enabled: false},
			{ID: "r_unknown_agent", Agent: "ghost", Proto: proto.UDP, ListenPort: pr(1002, 1002), Enabled: true},
		},
		Agents: []Agent{{Name: "home", Addr: addr("10.200.0.2")}},
	}
	got := Build(in)
	if len(got.Ports) != 1 || got.Ports[0].RuleID != "r_on" {
		t.Fatalf("Build().Ports = %+v, want only r_on", got.Ports)
	}
}

func TestBuildJoinsPolicy(t *testing.T) {
	rate := func(s string) *proto.Rate { r, _ := proto.ParseRate(s); return &r }
	in := Input{
		Rules: []model.Rule{
			{ID: "r1", Agent: "home", Proto: proto.TCP, ListenPort: pr(443, 443), Target: "192.168.1.1:443",
				Forwarding: model.Relay, SourceMetadata: model.ProxyV2, Enabled: true, NewFlowRate: rate("50/second")},
		},
		Limits: flowcap.Limits{UDPPerSource: 256, TCPPerSource: 128},
		Agents: []Agent{{Name: "home", Addr: addr("10.200.0.2")}},
	}
	got := Build(in)
	if len(got.Ports) != 1 {
		t.Fatalf("Build().Ports = %+v, want one entry", got.Ports)
	}
	pp := got.Ports[0]
	if pp.Agent != "home" || pp.AgentAddr != addr("10.200.0.2") || pp.Target != "192.168.1.1:443" {
		t.Fatalf("Build().Ports[0] route = %+v", pp)
	}
	if pp.Forwarding != model.Relay || pp.SourceMetadata != model.ProxyV2 {
		t.Fatalf("Build().Ports[0] forwarding = %v/%v, want Relay/ProxyV2", pp.Forwarding, pp.SourceMetadata)
	}
	if pp.Policy.RuleID != "r1" || pp.Policy.NewFlowRate == nil || *pp.Policy.NewFlowRate != *rate("50/second") {
		t.Fatalf("Build().Ports[0].Policy = %+v", pp.Policy)
	}
	// PortPlan.Policy must be the same value as the matching Plan.Admission.Rules entry (a view of
	// it, not a second source of truth); see PortPlan.Policy's doc comment.
	if len(got.Admission.Rules) != 1 || !reflect.DeepEqual(got.Admission.Rules[0], pp.Policy) {
		t.Fatalf("Plan.Admission.Rules = %+v, want it to contain exactly Ports[0].Policy = %+v", got.Admission.Rules, pp.Policy)
	}
	if got.Admission.PerSourceFlowCaps.UDP != 256 || got.Admission.PerSourceFlowCaps.TCP != 128 {
		t.Fatalf("Plan.Admission.PerSourceFlowCaps = %+v, want {256 128}", got.Admission.PerSourceFlowCaps)
	}
}

// TestBuildAdmissionCarriesPerSourceFlowCaps は、Plan.Admission が
// WGFT_MAX_*_FLOWS_PER_SOURCE(flowcap.Limits 経由)の値を運ぶことを確かめる。ゼロ値の
// flowcap.Limits{} は「上限なし」ではなく既定値(256/128)を意味し(internal/flowcap が
// Limits 自身について直した規約と同じ)、flowcap.PerSourceOff は明示的に無効にする。
// この解決は internal/policy.Build が行うので、ここでは Plan がその結果をそのまま運ぶことだけを見る。
func TestBuildAdmissionCarriesPerSourceFlowCaps(t *testing.T) {
	in := func(limits flowcap.Limits) Input {
		return Input{
			Rules:  []model.Rule{{ID: "r1", Agent: "home", Proto: proto.UDP, ListenPort: pr(1000, 1000), Enabled: true}},
			Limits: limits,
			Agents: []Agent{{Name: "home", Addr: addr("10.200.0.2")}},
		}
	}

	if got := Build(in(flowcap.Limits{})).Admission.PerSourceFlowCaps; got.UDP != flowcap.UDPPerSource || got.TCP != flowcap.TCPPerSource {
		t.Fatalf("Build(zero Limits{}).Admission.PerSourceFlowCaps = %+v, want the defaults {%d %d}",
			got, flowcap.UDPPerSource, flowcap.TCPPerSource)
	}
	if got := Build(in(flowcap.Limits{UDPPerSource: flowcap.PerSourceOff, TCPPerSource: flowcap.PerSourceOff})).Admission.PerSourceFlowCaps; got.UDP != 0 || got.TCP != 0 {
		t.Fatalf("Build(PerSourceOff).Admission.PerSourceFlowCaps = %+v, want {0 0}", got)
	}
	if got := Build(in(flowcap.Limits{UDPPerSource: 300, TCPPerSource: 150})).Admission.PerSourceFlowCaps; got.UDP != 300 || got.TCP != 150 {
		t.Fatalf("Build(explicit Limits).Admission.PerSourceFlowCaps = %+v, want {300 150}", got)
	}
}

// TestBuildDeterministic は、入力ルールとエージェントの順序をどう変えても、Plan.Ports は
// (Proto, ListenPort.Lo, RuleID) の順、Plan.Peers は Agent の順に必ず並ぶことを確かめる
// (design.md 7a.2 節: Planner は決定的である)。
func TestBuildDeterministic(t *testing.T) {
	rules := []model.Rule{
		{ID: "r_udp_hi", Agent: "b", Proto: proto.UDP, ListenPort: pr(5000, 5000), Enabled: true},
		{ID: "r_tcp", Agent: "a", Proto: proto.TCP, ListenPort: pr(1000, 1000), Enabled: true},
		{ID: "r_udp_lo_b", Agent: "b", Proto: proto.UDP, ListenPort: pr(2000, 2000), Enabled: true},
		{ID: "r_udp_lo_a", Agent: "a", Proto: proto.UDP, ListenPort: pr(2000, 2000), Enabled: true},
	}
	agents := []Agent{{Name: "b", Addr: addr("10.200.0.3")}, {Name: "a", Addr: addr("10.200.0.2")}}

	base := Build(Input{Rules: rules, Agents: agents})
	wantPortOrder := []string{"r_tcp", "r_udp_lo_a", "r_udp_lo_b", "r_udp_hi"}
	var gotPortOrder []string
	for _, pp := range base.Ports {
		gotPortOrder = append(gotPortOrder, pp.RuleID)
	}
	if !reflect.DeepEqual(gotPortOrder, wantPortOrder) {
		t.Fatalf("Plan.Ports order = %v, want %v", gotPortOrder, wantPortOrder)
	}
	wantPeerOrder := []string{"a", "b"}
	var gotPeerOrder []string
	for _, p := range base.Peers {
		gotPeerOrder = append(gotPeerOrder, p.Agent)
	}
	if !reflect.DeepEqual(gotPeerOrder, wantPeerOrder) {
		t.Fatalf("Plan.Peers order = %v, want %v", gotPeerOrder, wantPeerOrder)
	}

	rnd := rand.New(rand.NewSource(1))
	for i := 0; i < 20; i++ {
		shuffledRules := append([]model.Rule{}, rules...)
		rnd.Shuffle(len(shuffledRules), func(i, j int) { shuffledRules[i], shuffledRules[j] = shuffledRules[j], shuffledRules[i] })
		shuffledAgents := append([]Agent{}, agents...)
		rnd.Shuffle(len(shuffledAgents), func(i, j int) { shuffledAgents[i], shuffledAgents[j] = shuffledAgents[j], shuffledAgents[i] })

		got := Build(Input{Rules: shuffledRules, Agents: shuffledAgents})
		if !reflect.DeepEqual(got, base) {
			t.Fatalf("Build() is not order-independent:\n  got  %+v\n  want %+v", got, base)
		}
	}
}

func TestTransparentAndRelayHelpers(t *testing.T) {
	in := Input{
		Rules: []model.Rule{
			{ID: "r_dnat", Agent: "home", Proto: proto.UDP, ListenPort: pr(1000, 1000), Forwarding: model.Transparent, Enabled: true},
			{ID: "r_relay", Agent: "home", Proto: proto.TCP, ListenPort: pr(443, 443), Forwarding: model.Relay, Enabled: true},
		},
		Agents: []Agent{{Name: "home", Addr: addr("10.200.0.2")}},
	}
	plan := Build(in)
	if got := plan.Transparent(); len(got) != 1 || got[0].RuleID != "r_dnat" {
		t.Fatalf("Plan.Transparent() = %+v, want only r_dnat", got)
	}
	if got := plan.Relay(); len(got) != 1 || got[0].RuleID != "r_relay" {
		t.Fatalf("Plan.Relay() = %+v, want only r_relay", got)
	}
}

func TestBuildEmptyInput(t *testing.T) {
	got := Build(Input{})
	if len(got.Ports) != 0 || len(got.Peers) != 0 {
		t.Fatalf("Build(Input{}) = %+v, want an empty Plan", got)
	}
}
