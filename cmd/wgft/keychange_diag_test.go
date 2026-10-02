package main

import (
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/agent/controlapi"
	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/doctor"
	"github.com/rahanahu/wgft/proto"
)

// stillForwardingTexts are the generic disconnected-agent phrases that claim the agent's rules may
// still forward. They are wrong once the server refused the key the agent uses (design.md 5.2,
// 10.2a and 10.2c 節), so no key_change_limited finding may carry them.
var stillForwardingTexts = []string{
	"may still be forwarding", "existing traffic can still flow", "keep being forwarded",
}

func assertNoStillForwarding(t *testing.T, label, text string) {
	t.Helper()
	for _, bad := range stillForwardingTexts {
		if strings.Contains(text, bad) {
			t.Errorf("%s says %q, which a refused key change contradicts: %q", label, bad, text)
		}
	}
}

// server doctor's agent.connection for an agent whose new key the server refused by the key change
// limit and that has not had a key accepted since (design.md 10.2a 節). The status follows the same
// handshake split as agent_disconnected, so the summary and the exit code do not change; the reason
// and the text do.
func TestServerDoctorKeyChangeRefused(t *testing.T) {
	r := tcpRule()

	t.Run("refused now, handshake recent", func(t *testing.T) {
		in := disconnectedButTunnelledInput(r)
		in.Agents[0].KeyChangeRefusedAt = at(2 * time.Minute)
		checks := diagnose(r, in)
		c := checkOf(t, checks, checkConnection)
		if c.Status != statusUnknown || c.Reason != doctor.ReasonKeyChangeLimited {
			t.Fatalf("agent.connection = %s/%s, want %s/%s", c.Status, c.Reason, statusUnknown, doctor.ReasonKeyChangeLimited)
		}
		for _, want := range []string{
			"the control connection is down", "refused a public key change from this agent 2m0s ago",
			"has not accepted a key from it since", "forwards nothing until this server accepts it",
			"The handshake 20s ago can be from the agent's previous key",
		} {
			if !strings.Contains(c.Detail, want) {
				t.Errorf("detail must hold %q, got %q", want, c.Detail)
			}
		}
		assertNoStillForwarding(t, "detail", c.Detail)
		assertNoStillForwarding(t, "next", c.Next)
		for _, want := range []string{"do not run wgft agent rotate-key again", "wgft agent rotate-key --help", "add --probe"} {
			if !strings.Contains(c.Next, want) {
				t.Errorf("next must hold %q, got %q", want, c.Next)
			}
		}
		if got := displayStatus(c); got != "DEGRADED" {
			t.Errorf("displayStatus = %q, want DEGRADED", got)
		}
		rep := buildReport([]proto.Rule{r}, in)
		if rep.Rules[0].Status != statusUnknown {
			t.Errorf("rule status = %q, want %q", rep.Rules[0].Status, statusUnknown)
		}
		if err := doctorExit(rep); err != nil {
			t.Errorf("exit must stay 0 as for agent_disconnected, got %v", err)
		}
		var out strings.Builder
		writeRuleReport(&out, rep, false)
		assertNoStillForwarding(t, "the rule report", out.String())
	})

	t.Run("refused now, UDP rule", func(t *testing.T) {
		u := udpRule()
		in := disconnectedButTunnelledInput(u)
		in.Agents[0].KeyChangeRefusedAt = at(time.Minute)
		c := checkOf(t, diagnose(u, in), checkConnection)
		if strings.Contains(c.Next, "add --probe") {
			t.Errorf("a UDP rule must not be sent to --probe, got %q", c.Next)
		}
	})

	t.Run("refused now, handshake stale", func(t *testing.T) {
		in := disconnectedButTunnelledInput(r)
		in.Agents[0].LastHandshake = at(5 * time.Minute)
		in.Agents[0].KeyChangeRefusedAt = at(4 * time.Minute)
		checks := diagnose(r, in)
		c := checkOf(t, checks, checkConnection)
		if c.Status != statusFailed || c.Reason != doctor.ReasonKeyChangeLimited {
			t.Fatalf("agent.connection = %s/%s, want %s/%s", c.Status, c.Reason, statusFailed, doctor.ReasonKeyChangeLimited)
		}
		if strings.Contains(c.Detail, "The handshake") {
			t.Errorf("a stale handshake is tunnel.handshake's finding, not this one: %q", c.Detail)
		}
		assertNoStillForwarding(t, "detail", c.Detail)
		if got := firstFailed(checks); got != checkHandshake {
			t.Errorf("first failed = %q, want %q", got, checkHandshake)
		}
	})

	t.Run("never refused", func(t *testing.T) {
		c := checkOf(t, diagnose(r, disconnectedButTunnelledInput(r)), checkConnection)
		if c.Reason != reasonAgentDisconnected {
			t.Errorf("reason = %q, want %q", c.Reason, reasonAgentDisconnected)
		}
	})

	t.Run("connected with a record", func(t *testing.T) {
		// An established stream stays up when a later declaration is refused (design.md 5.2 節).
		// The connected agent's check reads as before.
		in := healthyInput(r)
		in.Agents[0].KeyChangeRefusedAt = at(time.Minute)
		c := checkOf(t, diagnose(r, in), checkConnection)
		if c.Status != statusOK {
			t.Errorf("agent.connection = %s/%s, want ok", c.Status, c.Reason)
		}
	})
}

// agent ls shows the refusal record of a disconnected agent in STREAM, as a past event with its
// age; a connected agent shows its address and an agent with no record shows "-".
func TestAgentLsShowsKeyChangeRefusal(t *testing.T) {
	refused := time.Now().Add(-2 * time.Minute).Format(time.RFC3339)
	agents := []admin.AgentInfo{
		{Name: "refused", Address: "10.200.0.2", KeyChangeRefusedAt: refused},
		{Name: "plain", Address: "10.200.0.3"},
		{Name: "live", Address: "10.200.0.4", Connected: true, StreamFrom: "203.0.113.10", KeyChangeRefusedAt: refused},
	}
	adminURL := newAgentCLITestServer(t, agents)
	stdout, _, err := runAgentCmd(t, adminURL, "ls")
	if err != nil {
		t.Fatalf("agent ls: %v", err)
	}
	if got := agentLsFields(t, stdout, "refused").stream; !strings.HasPrefix(got, "key change refused 2m") || !strings.HasSuffix(got, " ago") {
		t.Errorf("refused agent's STREAM = %q, want key change refused 2m... ago", got)
	}
	if got := agentLsFields(t, stdout, "plain").stream; got != "-" {
		t.Errorf("never refused agent's STREAM = %q, want -", got)
	}
	if got := agentLsFields(t, stdout, "live").stream; got != "203.0.113.10" {
		t.Errorf("connected agent's STREAM = %q, want its address", got)
	}
}

// agent doctor's stream.connection after the server refused the agent's key by the limit: the
// reason is key_change_limited and the advice no longer says held rules keep forwarding. An agent
// connected again reads OK, and another disconnect reason keeps the generic advice.
func TestAgentDoctorKeyChangeRefused(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	in := agentDoctorInput{Now: now}
	reason := `failed to get reader: received close frame: status = StatusPolicyViolation and reason = "public key changes are limited; retry later"`
	run := func(s controlapi.DoctorStream) agentDoctorCheck {
		c := agentDoctorCheck{ID: agentCheckStreamConn}
		agentStreamConnCheck(&c, in, &s)
		return c
	}

	for _, s := range []controlapi.DoctorStream{
		{DisconnectedAt: now.Add(-time.Minute), DisconnectReason: reason, KeyChangeLimited: true},
		{DisconnectedAt: now.Add(-time.Minute), DisconnectReason: reason},
		{DisconnectedAt: now.Add(-time.Minute), DisconnectReason: "some reason", KeyChangeLimited: true},
	} {
		c := run(s)
		if c.Status != statusUnknown || c.Reason != agentReasonKeyChangeLimited {
			t.Errorf("%+v: %s/%s, want %s/%s", s, c.Status, c.Reason, statusUnknown, agentReasonKeyChangeLimited)
		}
		assertNoStillForwarding(t, "next", c.Next)
		assertNoStillForwarding(t, "detail", c.Detail)
		for _, want := range []string{"forwards nothing until the server accepts it", "do not run wgft agent rotate-key again"} {
			if !strings.Contains(c.Next, want) {
				t.Errorf("next must hold %q, got %q", want, c.Next)
			}
		}
		if !strings.Contains(c.Detail, "the last attempt ended at 2026-09-23T11:59:00Z, 1m0s ago, refused by the server's key change limit") {
			t.Errorf("detail must date the refusal as the last attempt, got %q", c.Detail)
		}
	}

	if c := run(controlapi.DoctorStream{Connected: true, DisconnectedAt: now.Add(-time.Minute), DisconnectReason: reason, KeyChangeLimited: true}); c.Status != statusOK {
		t.Errorf("accepted since: %s/%s, want ok", c.Status, c.Reason)
	}
	c := run(controlapi.DoctorStream{DisconnectedAt: now.Add(-time.Minute), DisconnectReason: "read tcp: connection reset by peer"})
	if c.Reason != agentReasonReconnecting || !strings.Contains(c.Next, "keep being forwarded") {
		t.Errorf("another disconnect: %s %q, want reconnecting with the generic advice", c.Reason, c.Next)
	}
}
