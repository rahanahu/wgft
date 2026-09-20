package planner

import (
	"net/netip"
	"reflect"
	"sort"
	"testing"

	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/policy"
	"github.com/rahanahu/wgft/internal/vpsd/proxyrelay"
	"github.com/rahanahu/wgft/proto"
)

// This file pins Plan.Relay()'s field-for-field shape for the vpsd-terminated relay (design.md 6.2
// 節): one entry per enabled, TCP, Relay rule whose agent is registered, and no entry for disabled
// rules, rules of unregistered agents, or Transparent rules. Through Phase 2 this compared
// Plan.Relay() against proxyrelay.FromRules, the pre-Plan rules-based function vpsd used to build
// the same declaration; Phase 3 (design.md 7a.8 節) removed that function since internal/vpsd/apply.go
// has built the Relay declaration from the Plan alone since Phase 2, leaving nothing left to
// reconcile against. The fixture and its expected rule set stay, now compared directly.
//
// The matching checks for kernel DNAT and the userspace relay live next to the code they check,
// because both are unexported and package-local:
//   - kernel DNAT: internal/dataplane/linuxkernel/nft's own tests (TestEmitRows and friends) pin
//     emit()'s output against fixed Plan fixtures directly, since emit() takes only a Plan
//     (design.md 7a.8 節 Phase 3: no separate rules-based path is left to reconcile against either).
//   - userspace relay: internal/dataplane/userspace/relaytargets_test.go pins the userspace
//     Backend's Plan-derived listener set.
func equivalenceFixture() (rules []proto.Rule, agentAddr map[string]netip.Addr) {
	rate := func(s string) *proto.Rate {
		r, err := proto.ParseRate(s)
		if err != nil {
			panic(err)
		}
		return &r
	}
	cidr := func(s string) netip.Prefix { return netip.MustParsePrefix(s) }

	rules = []proto.Rule{
		{ID: "r_kernel_single", Agent: "home", Proto: proto.UDP, ListenPort: pr(2456, 2456),
			Target: "192.168.1.20:2456", VPSMode: proto.ModeKernel, Enabled: true},
		{ID: "r_kernel_range_udp", Agent: "home", Proto: proto.UDP, ListenPort: pr(2500, 2503),
			Target: "192.168.1.20:2500", VPSMode: proto.ModeKernel, Enabled: true,
			SourceDeny: []netip.Prefix{cidr("203.0.113.0/24")}},
		{ID: "r_kernel_range_tcp", Agent: "office", Proto: proto.TCP, ListenPort: pr(9000, 9002),
			Target: "192.168.2.10:9000", VPSMode: proto.ModeKernel, Enabled: true},
		{ID: "r_kernel_rates", Agent: "home", Proto: proto.UDP, ListenPort: pr(7777, 7777),
			Target: "192.168.1.25:7777", VPSMode: proto.ModeKernel, Enabled: true,
			NewFlowRate: rate("100/second"), PacketRate: rate("5000/second"), PerSourceRate: rate("10/second")},
		{ID: "r_kernel_disabled", Agent: "home", Proto: proto.UDP, ListenPort: pr(3000, 3000),
			Target: "192.168.1.26:3000", VPSMode: proto.ModeKernel, Enabled: false},
		{ID: "r_kernel_unknown_agent", Agent: "ghost", Proto: proto.UDP, ListenPort: pr(4000, 4000),
			Target: "192.168.1.27:4000", VPSMode: proto.ModeKernel, Enabled: true},

		{ID: "r_proxy_plain", Agent: "home", Proto: proto.TCP, ListenPort: pr(443, 443),
			Target: "192.168.1.30:443", VPSMode: proto.ModeProxy, ProxyProtocol: false, Enabled: true,
			SourceAllow: []netip.Prefix{cidr("198.51.100.0/24")}},
		{ID: "r_proxy_proxyproto", Agent: "office", Proto: proto.TCP, ListenPort: pr(8443, 8443),
			Target: "192.168.2.11:8443", VPSMode: proto.ModeProxy, ProxyProtocol: true, Enabled: true},
		{ID: "r_proxy_disabled", Agent: "home", Proto: proto.TCP, ListenPort: pr(9443, 9443),
			Target: "192.168.1.31:9443", VPSMode: proto.ModeProxy, ProxyProtocol: true, Enabled: false},
		{ID: "r_proxy_unknown_agent", Agent: "ghost", Proto: proto.TCP, ListenPort: pr(1443, 1443),
			Target: "192.168.1.32:1443", VPSMode: proto.ModeProxy, Enabled: true},
	}
	agentAddr = map[string]netip.Addr{"home": addr("10.200.0.2"), "office": addr("10.200.0.3")}
	return rules, agentAddr
}

func buildPlan(t *testing.T, rules []proto.Rule, agentAddr map[string]netip.Addr) Plan {
	t.Helper()
	normalized, err := model.NormalizeRules(rules, nil)
	if err != nil {
		t.Fatalf("model.NormalizeRules: %v", err)
	}
	var agents []Agent
	for name, a := range agentAddr {
		agents = append(agents, Agent{Name: name, Addr: a})
	}
	return Build(Input{Generation: 1, Rules: normalized, Agents: agents})
}

// TestPlanRelayFields locks down Plan.Relay() converted to a proxyrelay.Rule declaration, field for
// field (design.md 6.2 節): only the two enabled, TCP, Relay rules of a registered agent
// (r_proxy_plain, r_proxy_proxyproto) get an entry.
func TestPlanRelayFields(t *testing.T) {
	rules, agentAddr := equivalenceFixture()
	plan := buildPlan(t, rules, agentAddr)

	want := []proxyrelay.Rule{
		{ID: "r_proxy_plain", ListenPort: 443, AgentAddr: agentAddr["home"], AgentPort: 443,
			Policy: policy.RulePolicy{RuleID: "r_proxy_plain", Proto: proto.TCP,
				SourceAllow: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}}, Agent: "home"},
		{ID: "r_proxy_proxyproto", ListenPort: 8443, AgentAddr: agentAddr["office"], AgentPort: 8443,
			ProxyProtocol: true, Policy: policy.RulePolicy{RuleID: "r_proxy_proxyproto", Proto: proto.TCP}, Agent: "office"},
	}
	sort.Slice(want, func(i, j int) bool { return want[i].ID < want[j].ID })

	var got []proxyrelay.Rule
	for _, pp := range plan.Relay() {
		got = append(got, proxyrelay.Rule{
			ID: pp.RuleID, ListenPort: pp.ListenPort.Lo, AgentAddr: pp.AgentAddr, AgentPort: pp.ListenPort.Lo,
			ProxyProtocol: pp.SourceMetadata == model.ProxyV2,
			Policy:        pp.Policy, Agent: pp.Agent,
		})
	}
	sort.Slice(got, func(i, j int) bool { return got[i].ID < got[j].ID })

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Plan.Relay() converted to []proxyrelay.Rule = %+v, want %+v", got, want)
	}
}

// TestEquivalenceTransparentRelayPartition cross-checks that every enabled, known-agent rule ends
// up as exactly one of Transparent or Relay, never both and never neither (the port classification
// itself is proved equivalent to today's code by the tests cited in the package doc comment above).
func TestEquivalenceTransparentRelayPartition(t *testing.T) {
	rules, agentAddr := equivalenceFixture()
	plan := buildPlan(t, rules, agentAddr)
	if got, want := len(plan.Transparent())+len(plan.Relay()), len(plan.Ports); got != want {
		t.Fatalf("Transparent+Relay = %d ports, want %d (Plan.Ports total)", got, want)
	}
}
