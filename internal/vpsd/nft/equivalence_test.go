package nft

import (
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/flowcap"
	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/proto"
)

// This file proves the Phase 1 "no behaviour change" completion criterion (design.md 7a.8 節) for
// DataplaneMode=Kernel: the set of rules planner.Build classifies as Forwarding=Transparent equals
// the set of rules the real, unmodified emit() gives a "dnat" row (design.md 6.1 節), and, given the
// same ProxyListening/per-source-cap inputs, the set that gets a "src_flow" row (design.md 6.1,
// 7a.5 節) matches what the Plan implies once combined with those inputs. emit() runs against the
// in-memory recorder from build_test.go, not a transcription, so a future change to emit's filters
// shows up here.

func equivalenceFixtureRules() []proto.Rule {
	return []proto.Rule{
		{ID: "r_kernel_single", Agent: "home", Proto: proto.UDP, ListenPort: pr(2456, 2456),
			Target: "192.168.1.20:2456", VPSMode: proto.ModeKernel, Enabled: true},
		{ID: "r_kernel_range", Agent: "home", Proto: proto.UDP, ListenPort: pr(2500, 2503),
			Target: "192.168.1.20:2500", VPSMode: proto.ModeKernel, Enabled: true,
			SourceDeny: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}},
		{ID: "r_kernel_rates", Agent: "home", Proto: proto.UDP, ListenPort: pr(7777, 7777),
			Target: "192.168.1.25:7777", VPSMode: proto.ModeKernel, Enabled: true,
			NewFlowRate: rate("100/second")},
		{ID: "r_kernel_disabled", Agent: "home", Proto: proto.UDP, ListenPort: pr(3000, 3000),
			Target: "192.168.1.26:3000", VPSMode: proto.ModeKernel, Enabled: false},
		{ID: "r_kernel_unknown_agent", Agent: "ghost", Proto: proto.UDP, ListenPort: pr(4000, 4000),
			Target: "192.168.1.27:4000", VPSMode: proto.ModeKernel, Enabled: true},
		{ID: "r_proxy_listening", Agent: "home", Proto: proto.TCP, ListenPort: pr(443, 443),
			Target: "192.168.1.30:443", VPSMode: proto.ModeProxy, Enabled: true},
		{ID: "r_proxy_not_listening", Agent: "home", Proto: proto.TCP, ListenPort: pr(8443, 8443),
			Target: "192.168.1.31:8443", VPSMode: proto.ModeProxy, Enabled: true},
		{ID: "r_proxy_disabled", Agent: "home", Proto: proto.TCP, ListenPort: pr(9443, 9443),
			Target: "192.168.1.32:9443", VPSMode: proto.ModeProxy, Enabled: false},
	}
}

// commentIDs picks the rule IDs out of comments of the form Comment(ruleID, kind) ("wgft:ID:kind";
// see build.go's Comment) whose kind matches wantKind.
func commentIDs(comments []string, wantKind string) map[string]bool {
	out := map[string]bool{}
	for _, c := range comments {
		parts := strings.SplitN(c, ":", 3)
		if len(parts) != 3 || parts[0] != "wgft" || parts[2] != wantKind {
			continue
		}
		out[parts[1]] = true
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestEquivalencePlannerTransparentMatchesDNAT(t *testing.T) {
	rules := equivalenceFixtureRules()
	agentAddr := map[string]netip.Addr{"home": netip.MustParseAddr("10.200.0.2")}
	cfg := Config{
		WGInterface: "wg0", AgentAddr: agentAddr,
		UDPPerSourceCap: 256, TCPPerSourceCap: 128,
		ProxyListening: map[uint16]bool{443: true},
	}

	rec := newRecorder()
	if err := emit(rec, rules, cfg); err != nil {
		t.Fatalf("emit: %v", err)
	}
	wantDNAT := commentIDs(rec.comments("nat_pre"), "dnat")
	wantSrcFlow := commentIDs(rec.comments("filter_pre"), "src_flow")

	normalized, err := model.NormalizeRules(rules, nil)
	if err != nil {
		t.Fatalf("model.NormalizeRules: %v", err)
	}
	var agents []planner.Agent
	for name, a := range agentAddr {
		agents = append(agents, planner.Agent{Name: name, Addr: a})
	}
	plan := planner.Build(planner.Input{
		Rules:  normalized,
		Limits: flowcap.Limits{UDPPerSource: cfg.UDPPerSourceCap, TCPPerSource: cfg.TCPPerSourceCap},
		Agents: agents,
	})

	gotDNAT := map[string]bool{}
	for _, pp := range plan.Transparent() {
		gotDNAT[pp.RuleID] = true
	}
	if !reflect.DeepEqual(gotDNAT, wantDNAT) {
		t.Fatalf("Plan.Transparent() rule IDs = %v, want emit()'s dnat rows = %v", sortedKeys(gotDNAT), sortedKeys(wantDNAT))
	}

	// The per-source concurrent flow cap (design.md 6.1, 7a.5 節) also covers Relay rules, but only
	// on ports vpsd is actually listening on (ProxyListening); Plan alone does not know that, since
	// Phase 1 has no Runtime yet, so this test supplies it the same way emit()'s caller does.
	gotSrcFlow := map[string]bool{}
	for _, pp := range plan.Transparent() {
		if cfg.perSourceCap(pp.Proto) > 0 {
			gotSrcFlow[pp.RuleID] = true
		}
	}
	for _, pp := range plan.Relay() {
		if cfg.ProxyListening[pp.ListenPort.Lo] && cfg.perSourceCap(pp.Proto) > 0 {
			gotSrcFlow[pp.RuleID] = true
		}
	}
	if !reflect.DeepEqual(gotSrcFlow, wantSrcFlow) {
		t.Fatalf("planner-derived src_flow rule IDs = %v, want emit()'s src_flow rows = %v", sortedKeys(gotSrcFlow), sortedKeys(wantSrcFlow))
	}
}
