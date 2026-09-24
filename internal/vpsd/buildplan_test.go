//go:build linux

package vpsd

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/proto"
)

// TestBuildPlanExcludedReasons checks the reasons buildPlan gives the rules of the Desired set it
// does not forward; the admin API reports them as not_active (design.md 7a.3 節).
func TestBuildPlanExcludedReasons(t *testing.T) {
	port := func(p uint16) proto.PortRange { return proto.PortRange{Lo: p, Hi: p} }
	rules := []proto.Rule{
		{ID: "r_on", Agent: "home", Proto: proto.TCP, ListenPort: port(443), Target: "192.168.1.30:443", VPSMode: proto.ModeKernel, Enabled: true},
		{ID: "r_off", Agent: "home", Proto: proto.TCP, ListenPort: port(444), Target: "192.168.1.30:444", VPSMode: proto.ModeKernel},
		{ID: "r_ghost", Agent: "ghost", Proto: proto.TCP, ListenPort: port(445), Target: "192.168.1.30:445", VPSMode: proto.ModeKernel, Enabled: true},
		{ID: "r_bad", Agent: "home", Proto: proto.TCP, ListenPort: port(446), Target: "192.168.1.30:446", VPSMode: proto.ModeKernel, ProxyProtocol: true, Enabled: true},
	}
	d := &Daemon{}
	plan, excluded := d.buildPlan(rules, map[string]netip.Addr{"home": netip.MustParseAddr("10.200.0.2")}, nil)
	if len(plan.Ports) != 1 || plan.Ports[0].RuleID != "r_on" {
		t.Fatalf("plan ports = %+v, want only r_on", plan.Ports)
	}
	if excluded["r_off"] != "disabled" {
		t.Errorf("r_off: reason %q, want disabled", excluded["r_off"])
	}
	if excluded["r_ghost"] != "agent \"ghost\" is not registered" {
		t.Errorf("r_ghost: reason %q", excluded["r_ghost"])
	}
	if !strings.HasPrefix(excluded["r_bad"], "invalid: ") {
		t.Errorf("an invalid stored row: reason %q, want it to start with invalid:", excluded["r_bad"])
	}
	if _, ok := excluded["r_on"]; ok || len(excluded) != 3 {
		t.Errorf("excluded = %v, want r_off, r_ghost and r_bad", excluded)
	}
}

// TestBuildPlanLeavesADisabledAgentsRulesOut is the example of design.md 5.1 節: rules A and C are
// enabled and B is disabled, all on one agent. While the agent is disabled none of the three is in
// the Plan; B keeps its own reason, so the operator is told to fix the rule rather than the agent,
// and A and C name the disabled agent. Another agent's rule is untouched, and the stored rules
// themselves are not modified. Once the agent is enabled again, A and C are back and B stays out.
func TestBuildPlanLeavesADisabledAgentsRulesOut(t *testing.T) {
	port := func(p uint16) proto.PortRange { return proto.PortRange{Lo: p, Hi: p} }
	rules := []proto.Rule{
		{ID: "r_a", Agent: "home", Proto: proto.TCP, ListenPort: port(443), Target: "192.168.1.30:443", VPSMode: proto.ModeKernel, Enabled: true},
		{ID: "r_b", Agent: "home", Proto: proto.UDP, ListenPort: port(444), Target: "192.168.1.30:444", VPSMode: proto.ModeKernel},
		{ID: "r_c", Agent: "home", Proto: proto.TCP, ListenPort: port(445), Target: "192.168.1.30:445", VPSMode: proto.ModeProxy, Enabled: true},
		{ID: "r_o", Agent: "other", Proto: proto.TCP, ListenPort: port(446), Target: "192.168.1.31:446", VPSMode: proto.ModeKernel, Enabled: true},
	}
	addrs := map[string]netip.Addr{"home": netip.MustParseAddr("10.200.0.2"), "other": netip.MustParseAddr("10.200.0.3")}
	d := &Daemon{}

	plan, excluded := d.buildPlan(rules, addrs, map[string]bool{"home": true})
	if len(plan.Ports) != 1 || plan.Ports[0].RuleID != "r_o" {
		t.Fatalf("plan ports = %+v, want only the other agent's r_o", plan.Ports)
	}
	for _, id := range []string{"r_a", "r_c"} {
		if excluded[id] != `agent "home" is disabled` {
			t.Errorf("%s: reason %q, want the disabled agent named", id, excluded[id])
		}
	}
	if excluded["r_b"] != "disabled" {
		t.Errorf("r_b: reason %q, want its own disabled first", excluded["r_b"])
	}
	if !rules[0].Enabled || rules[1].Enabled || !rules[2].Enabled {
		t.Errorf("buildPlan modified the stored rules: %+v", rules)
	}

	plan, excluded = d.buildPlan(rules, addrs, nil)
	got := map[string]bool{}
	for _, p := range plan.Ports {
		got[p.RuleID] = true
	}
	if !got["r_a"] || !got["r_c"] || !got["r_o"] || got["r_b"] || len(excluded) != 1 {
		t.Errorf("after enable: plan %v, excluded %v; want A, C and the other agent's rule, B still excluded", got, excluded)
	}
}
