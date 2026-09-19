package userspace

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/rahanahu/wgft/internal/dataplane/userspace/relay"
	"github.com/rahanahu/wgft/internal/flowcap"
	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/proto"
)

// TestRelayTargetsFromPlan pins the listener set the userspace backend opens for a rule set
// (design.md 6.3 節). Until Phase 2 the server built this map from the stored rules directly, and
// the Phase 1 equivalence test proved that the Plan's Transparent ports, expanded per port, gave
// the same map for this fixture. The Backend now builds it from the Plan (relayTargets); the
// expected value below is that pre-Backend map, so the Plan-fed path keeps its behaviour: only
// enabled vps_mode = kernel rules of known agents, one entry per port of a range, dialled at the
// agent's wg address and the same port.
func TestRelayTargetsFromPlan(t *testing.T) {
	rules := []proto.Rule{
		{ID: "r_udp_single", Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2456, Hi: 2456},
			Target: "192.168.1.20:2456", VPSMode: proto.ModeKernel, Enabled: true},
		{ID: "r_tcp_range", Agent: "office", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 9000, Hi: 9002},
			Target: "192.168.2.10:9000", VPSMode: proto.ModeKernel, Enabled: true},
		{ID: "r_disabled", Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 3000, Hi: 3000},
			Target: "192.168.1.21:3000", VPSMode: proto.ModeKernel, Enabled: false},
		{ID: "r_unknown_agent", Agent: "ghost", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 4000, Hi: 4000},
			Target: "192.168.1.22:4000", VPSMode: proto.ModeKernel, Enabled: true},
		{ID: "r_proxy", Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 443, Hi: 443},
			Target: "192.168.1.30:443", VPSMode: proto.ModeProxy, Enabled: true},
	}
	normalized, err := model.NormalizeRules(rules, nil)
	if err != nil {
		t.Fatalf("model.NormalizeRules: %v", err)
	}
	plan := planner.Build(planner.Input{Rules: normalized, Limits: flowcap.Limits{}, Agents: []planner.Agent{
		{Name: "home", Addr: netip.MustParseAddr("10.200.0.2")},
		{Name: "office", Addr: netip.MustParseAddr("10.200.0.3")},
	}})

	want := map[relay.Key]relay.Desired{
		{Proto: proto.UDP, Port: 2456}: {Target: "10.200.0.2:2456", RuleID: "r_udp_single"},
		{Proto: proto.TCP, Port: 9000}: {Target: "10.200.0.3:9000", RuleID: "r_tcp_range"},
		{Proto: proto.TCP, Port: 9001}: {Target: "10.200.0.3:9001", RuleID: "r_tcp_range"},
		{Proto: proto.TCP, Port: 9002}: {Target: "10.200.0.3:9002", RuleID: "r_tcp_range"},
	}
	if got := relayTargets(plan); !reflect.DeepEqual(got, want) {
		t.Fatalf("relayTargets(plan) = %+v, want %+v", got, want)
	}
}
