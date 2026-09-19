package vpsd

import (
	"net/netip"
	"reflect"
	"sort"
	"testing"

	"github.com/rahanahu/wgft/internal/flowcap"
	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/internal/vpsd/proxyrelay"
	"github.com/rahanahu/wgft/proto"
)

// TestRelayRulesMatchFromRules checks that the Relay declaration vpsd now builds from the Plan
// (relayRules) equals the one it built from the stored rules before Phase 2
// (proxyrelay.FromRules; design.md 7a.8 節: no behaviour change). Both sides are the real functions.
func TestRelayRulesMatchFromRules(t *testing.T) {
	pr := func(lo, hi uint16) proto.PortRange { return proto.PortRange{Lo: lo, Hi: hi} }
	cidr := netip.MustParsePrefix
	rules := []proto.Rule{
		{ID: "r_plain", Agent: "home", Proto: proto.TCP, ListenPort: pr(443, 443), Target: "192.168.1.30:443",
			VPSMode: proto.ModeProxy, Enabled: true, SourceAllow: []netip.Prefix{cidr("198.51.100.0/24")}},
		{ID: "r_pp", Agent: "office", Proto: proto.TCP, ListenPort: pr(8443, 8443), Target: "192.168.2.11:8443",
			VPSMode: proto.ModeProxy, ProxyProtocol: true, Enabled: true, SourceDeny: []netip.Prefix{cidr("203.0.113.0/24")}},
		{ID: "r_disabled", Agent: "home", Proto: proto.TCP, ListenPort: pr(9443, 9443), Target: "192.168.1.31:9443",
			VPSMode: proto.ModeProxy, ProxyProtocol: true, Enabled: false},
		{ID: "r_unknown_agent", Agent: "ghost", Proto: proto.TCP, ListenPort: pr(1443, 1443), Target: "192.168.1.32:1443",
			VPSMode: proto.ModeProxy, Enabled: true},
		{ID: "r_transparent", Agent: "home", Proto: proto.TCP, ListenPort: pr(9000, 9002), Target: "192.168.1.33:9000",
			VPSMode: proto.ModeKernel, Enabled: true},
		{ID: "r_transparent_udp", Agent: "home", Proto: proto.UDP, ListenPort: pr(2456, 2456), Target: "192.168.1.34:2456",
			VPSMode: proto.ModeKernel, Enabled: true},
	}
	agentAddr := map[string]netip.Addr{"home": netip.MustParseAddr("10.200.0.2"), "office": netip.MustParseAddr("10.200.0.3")}

	normalized, err := model.NormalizeRules(rules, nil)
	if err != nil {
		t.Fatalf("model.NormalizeRules: %v", err)
	}
	var agents []planner.Agent
	for name, a := range agentAddr {
		agents = append(agents, planner.Agent{Name: name, Addr: a})
	}
	plan := planner.Build(planner.Input{Rules: normalized, Limits: flowcap.Limits{}, Agents: agents})

	got, want := relayRules(plan.Relay()), proxyrelay.FromRules(rules, agentAddr)
	byID := func(rs []proxyrelay.Rule) { sort.Slice(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID }) }
	byID(got)
	byID(want)
	if len(want) != 2 {
		t.Fatalf("fixture: FromRules gave %d rules, want 2", len(want))
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("relayRules(plan.Relay()) = %+v\nwant proxyrelay.FromRules(...) = %+v", got, want)
	}
}
