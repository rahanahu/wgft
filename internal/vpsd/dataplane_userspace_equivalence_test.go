package vpsd

import (
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"testing"

	"github.com/rahanahu/wgft/internal/agent/relay"
	"github.com/rahanahu/wgft/internal/flowcap"
	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/proto"
)

// TestPlannerTransparentMatchesUserspaceRelay proves the Phase 1 "no behaviour change" completion
// criterion (design.md 7a.8 節) for DataplaneMode=Userspace: planner.Build's Plan.Transparent(),
// expanded one port at a time, equals the real userspaceRelayTargets (the pure function
// userspaceDataplane.ApplyNFT calls, design.md 6.3 節) on the same input. userspaceRelayTargets is
// called directly here, not transcribed, so a future change to its filter shows up as a failing
// assertion in this test.
func TestPlannerTransparentMatchesUserspaceRelay(t *testing.T) {
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
	agentAddr := map[string]netip.Addr{
		"home":   netip.MustParseAddr("10.200.0.2"),
		"office": netip.MustParseAddr("10.200.0.3"),
	}

	want := userspaceRelayTargets(rules, agentAddr)

	normalized, err := model.NormalizeRules(rules, nil)
	if err != nil {
		t.Fatalf("model.NormalizeRules: %v", err)
	}
	var agents []planner.Agent
	for name, a := range agentAddr {
		agents = append(agents, planner.Agent{Name: name, Addr: a})
	}
	plan := planner.Build(planner.Input{Rules: normalized, Limits: flowcap.Limits{}, Agents: agents})

	got := map[relay.Key]relay.Desired{}
	for _, pp := range plan.Transparent() {
		for p := int(pp.ListenPort.Lo); p <= int(pp.ListenPort.Hi); p++ {
			got[relay.Key{Proto: pp.Proto, Port: uint16(p)}] = relay.Desired{
				Target: net.JoinHostPort(pp.AgentAddr.String(), strconv.Itoa(p)), RuleID: pp.RuleID,
			}
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Plan.Transparent() expanded per-port = %+v, want userspaceRelayTargets(...) = %+v", got, want)
	}
}
