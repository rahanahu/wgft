package conntrack

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/proto"
)

// TestRulesFromPlan は、Transparent のポートだけが収束の対象になり(Relay と、無効・未登録の
// ルールは対象外)、SourceDeny/SourceAllow が Plan.Admission 由来の値と一致することを確かめる。
func TestRulesFromPlan(t *testing.T) {
	rules := []model.Rule{
		{ID: "r_kernel", Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2456, Hi: 2456},
			Forwarding: model.Transparent, Enabled: true,
			SourceDeny: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}},
		{ID: "r_relay", Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 443, Hi: 443},
			Forwarding: model.Relay, Enabled: true},
		{ID: "r_off", Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 3000, Hi: 3000},
			Forwarding: model.Transparent, Enabled: false},
	}
	agents := []planner.Agent{{Name: "home", Addr: netip.MustParseAddr("10.200.0.2")}}
	plan := planner.Build(planner.Input{Rules: rules, Agents: agents})

	got := RulesFromPlan(plan)
	if len(got) != 1 {
		t.Fatalf("RulesFromPlan = %+v, want 1 rule (only the Transparent, enabled one)", got)
	}
	want := Rule{Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2456, Hi: 2456},
		AgentAddr: netip.MustParseAddr("10.200.0.2"), SourceDeny: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}
	if !reflect.DeepEqual(got[0], want) {
		t.Errorf("RulesFromPlan()[0] = %+v, want %+v", got[0], want)
	}
}
