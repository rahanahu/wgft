package userspace

import (
	"net/netip"
	"testing"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/flowcap"
	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/proto"
)

// TestCommitTakesAdmissionFromPlan checks that a Commit installs the admission policy, the
// per-source flow caps included, from the Plan alone (design.md 7a.2, 7a.5 節). The only rule is a Relay
// rule, which the frontend serves, so the relay opens no host listener here.
func TestCommitTakesAdmissionFromPlan(t *testing.T) {
	rules, err := model.NormalizeRules([]proto.Rule{{
		ID: "r_proxy", Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 443, Hi: 443},
		Target: "192.168.1.30:443", VPSMode: proto.ModeProxy, Enabled: true,
		SourceDeny: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	plan := planner.Build(planner.Input{
		Rules:  rules,
		Limits: flowcap.Limits{UDPPerSource: 7, TCPPerSource: flowcap.PerSourceOff},
		Agents: []planner.Agent{{Name: "home", Addr: netip.MustParseAddr("10.200.0.2")}},
	})

	b := New(Options{Limits: flowcap.Limits{UDPPerSource: 1, TCPPerSource: 1}})
	p, err := b.Prepare(dataplane.Desired{Plan: plan})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if _, err := p.Commit(nil); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if d, _ := b.policy.AdmitFlow("r_proxy", netip.MustParseAddr("203.0.113.9"), 0); d.Allow || d.Kind != "deny" {
		t.Errorf("a source in the rule's source_deny: %+v, want drop:deny after Commit", d)
	}
	if d, _ := b.policy.AdmitFlow("r_proxy", netip.MustParseAddr("198.51.100.1"), 0); !d.Allow {
		t.Error("a source outside source_deny must be admitted")
	}
	// The per-source caps come from the Plan (TCP off), not from Options.Limits (1): 200 concurrent
	// Relay connections from one source, above both 1 and the default 128, are all admitted.
	for i := range 200 {
		if _, ok := b.AdmitRelayFlow("r_proxy", netip.MustParseAddr("198.51.100.1")); !ok {
			t.Fatalf("Relay connection %d refused; the Plan turns the TCP per-source cap off", i+1)
		}
	}
	if drops := b.policy.Drops(); len(drops) != 1 || drops[0].Kind != "deny" {
		t.Errorf("drops = %+v, want the one deny", drops)
	}
	if len(relayTargets(plan)) != 0 {
		t.Errorf("a Relay rule must not become a relay listener")
	}
}
