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

// TestCommitTakesAdmissionFromPlan checks that a Commit installs the admission policy and the
// per-source flow caps from the Plan alone (design.md 7a.2, 7a.5 節). The only rule is a Relay
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
	if err := p.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if ok, _ := b.policy.AdmitFlow("r_proxy", netip.MustParseAddr("203.0.113.9"), 0); ok {
		t.Error("a source in the rule's source_deny must be refused after Commit")
	}
	if ok, _ := b.policy.AdmitFlow("r_proxy", netip.MustParseAddr("198.51.100.1"), 0); !ok {
		t.Error("a source outside source_deny must be admitted")
	}
	// The per-source caps come from the Plan (7 and off), not from Options.Limits (1 and 1).
	if b.udpCap.PerSource != 7 || b.tcpCap.PerSource != 0 {
		t.Errorf("per-source caps = UDP %d, TCP %d, want 7 and 0 from the Plan", b.udpCap.PerSource, b.tcpCap.PerSource)
	}
	if len(relayTargets(plan)) != 0 {
		t.Errorf("a Relay rule must not become a relay listener")
	}
}
