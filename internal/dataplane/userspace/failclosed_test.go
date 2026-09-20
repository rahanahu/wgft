package userspace

import (
	"net"
	"net/netip"
	"strconv"
	"testing"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// freeTCPPort returns a TCP port nothing listens on right now.
func freeTCPPort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

// A Transparent rule whose host listener cannot be bound is a rule-local failure (design.md 7a.3
// 節): Prepare reports it, Commit serves none of it and leaves it out of the evaluator, and the
// other rule is served. Binding happens in Prepare, so Commit cannot fail part way.
func TestPrepareBindFailureIsFailClosed(t *testing.T) {
	blocked, free := freeTCPPort(t), freeTCPPort(t)
	blocker, err := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(int(blocked))))
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	rules, err := model.NormalizeRules([]proto.Rule{
		{ID: "r_blocked", Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: blocked, Hi: blocked},
			Target: "192.168.1.30:80", VPSMode: proto.ModeKernel, Enabled: true,
			SourceDeny: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}},
		{ID: "r_free", Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: free, Hi: free},
			Target: "192.168.1.31:80", VPSMode: proto.ModeKernel, Enabled: true},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	plan := planner.Build(planner.Input{Rules: rules,
		Agents: []planner.Agent{{Name: "home", Addr: netip.MustParseAddr("10.200.0.2")}}})

	b := New(Options{Limits: resource.Limits{}, Logf: t.Logf})
	defer b.relay.Close()
	p, err := b.Prepare(dataplane.Desired{Plan: plan})
	if err != nil {
		t.Fatalf("a bind failure must not fail Prepare as a whole: %v", err)
	}
	if p.Failed()["r_blocked"] == nil || len(p.Failed()) != 1 {
		t.Fatalf("Failed = %v, want only r_blocked", p.Failed())
	}
	if _, err := p.Commit(nil); err != nil {
		t.Fatal(err)
	}
	st := b.relay.Status()
	if len(st) != 1 || st[0].RuleID != "r_free" {
		t.Errorf("listeners = %+v, want only r_free", st)
	}
	// the failed rule's policy is not installed, so the evaluator refuses its flows fail-closed and
	// counts no drop, even for a source its policy would admit
	if d, _ := b.policy.AdmitFlow("r_blocked", netip.MustParseAddr("198.51.100.1"), 0); d.Allow || d.Kind != "" {
		t.Errorf("a flow of the failed rule: %+v; want an uncounted refusal (its admission policy was installed)", d)
	}
}
