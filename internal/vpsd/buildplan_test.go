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
	plan, excluded := d.buildPlan(rules, map[string]netip.Addr{"home": netip.MustParseAddr("10.200.0.2")})
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
