package userspace

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
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

// bindCollision reports whether err is a failed bind because the number is already taken. The
// number came from freeTCPPort or freeUDPPort, which close the socket before the code under test
// binds it, so any other process on the host can take the number in between (an outgoing
// connection's source port included). Prepare reports the failure as text, so the message is
// matched as well as the errno.
func bindCollision(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "address already in use") || strings.Contains(msg, "Only one usage of each socket address")
}

// retryOnBindCollision runs attempt up to bindAttempts times with fresh ports, as long as it
// reports that its bind lost the number to someone else. attempt must report a collision before it
// asserts anything, and must release what it opened. Address-in-use in every attempt fails the test, as it could also be a product fault.
func retryOnBindCollision(t *testing.T, attempt func() (collided bool)) {
	t.Helper()
	const bindAttempts = 5
	for i := 1; i <= bindAttempts; i++ {
		if !attempt() {
			return
		}
		t.Logf("attempt %d of %d: the port picked for the test was taken before the bind; retrying with new ports", i, bindAttempts)
	}
	t.Fatalf("a bind failed with address-in-use in all %d attempts", bindAttempts)
}

// A Transparent rule whose host listener cannot be bound is a rule-local failure (design.md 7a.3
// 節): Prepare reports it, Commit serves none of it and leaves it out of the evaluator, and the
// other rule is served. Binding happens in Prepare, so Commit cannot fail part way.
func TestPrepareBindFailureIsFailClosed(t *testing.T) {
	// bind the blocker itself on port 0 and read back the assigned port, instead of picking a
	// number with freeTCPPort and then binding it: nothing else can ever steal a number that was
	// never released. free then stays with plain freeTCPPort, and is guaranteed distinct from
	// blocked because blocked is still held open when free is picked.
	blocker, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	blocked := uint16(blocker.Addr().(*net.TCPAddr).Port)
	// free is picked and closed before Prepare binds it, so another process can take it in the gap.
	// Only that collision on r_free repeats the attempt; r_blocked failing is the point of the test.
	var b *Backend
	var p dataplane.Prepared
	retryOnBindCollision(t, func() bool {
		free := freeTCPPort(t)
		b2, p2, collided := prepareBlockedAndFree(t, blocked, free)
		if collided {
			return true
		}
		b, p = b2, p2
		return false
	})
	defer b.relay.Close()
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

// prepareBlockedAndFree builds a Backend and prepares one rule on the squatted port and one on
// free. collided reports that r_free, not r_blocked, failed with address-in-use; the Backend is
// then released.
func prepareBlockedAndFree(t *testing.T, blocked, free uint16) (b *Backend, p dataplane.Prepared, collided bool) {
	t.Helper()
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

	b = New(Options{Limits: resource.Limits{}, Logf: t.Logf})
	p, err = b.Prepare(dataplane.Desired{Plan: plan})
	if err != nil {
		b.relay.Close()
		t.Fatalf("a bind failure must not fail Prepare as a whole: %v", err)
	}
	if bindCollision(p.Failed()["r_free"]) {
		p.Rollback()
		b.relay.Close()
		return nil, nil, true
	}
	return b, p, false
}
