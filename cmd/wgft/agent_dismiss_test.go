package main

import (
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/admin"
)

// TestAgentDismissWarningFound confirms a matching warning is actually dismissed: the admin
// API's DismissWarning is called and the CLI reports success (design.md 5.2 節).
func TestAgentDismissWarningFound(t *testing.T) {
	backend := &fakeAgentBackend{warnings: []admin.Warning{
		{Agent: "home", Kind: "ip-flapping", Detail: "", At: "2026-09-24T00:00:00Z"},
	}}
	adminURL := newAgentCLITestServerBackend(t, backend)
	stdout, _, err := runAgentCmd(t, adminURL, "dismiss-warning", "home", "ip-flapping")
	if err != nil {
		t.Fatalf("agent dismiss-warning: %v", err)
	}
	if want := "dismissed warning for home: ip-flapping\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if !backend.dismissCalled {
		t.Errorf("DismissWarning was not called even though a matching warning exists")
	}
}

// TestAgentDismissWarningFoundWithDetail confirms the pre-check also honors the optional
// [detail] argument: a warning of the same agent and kind but a different detail does not
// count as a match (design.md 5.2 節: ip-mismatch's detail selects one pair of addresses).
func TestAgentDismissWarningFoundWithDetail(t *testing.T) {
	backend := &fakeAgentBackend{warnings: []admin.Warning{
		{Agent: "home", Kind: "ip-mismatch", Detail: "stream 203.0.113.5 / wg 203.0.113.9", At: "2026-09-24T00:00:00Z"},
	}}
	adminURL := newAgentCLITestServerBackend(t, backend)
	stdout, _, err := runAgentCmd(t, adminURL, "dismiss-warning", "home", "ip-mismatch", "stream 203.0.113.5 / wg 203.0.113.9")
	if err != nil {
		t.Fatalf("agent dismiss-warning: %v", err)
	}
	if want := "dismissed warning for home: ip-mismatch\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if !backend.dismissCalled {
		t.Errorf("DismissWarning was not called even though a matching warning exists")
	}
}

// TestAgentDismissWarningNoneForAgent confirms that dismissing a warning that does not exist
// (no warning at all for the named agent) says so plainly instead of claiming success, does
// not call the admin API's DismissWarning, and still exits 0 (the operation - "make sure this
// warning is gone" - is trivially complete; design.md 7a.11 節's common one-shot guarantee is
// about completing the requested operation, not a positive finding).
func TestAgentDismissWarningNoneForAgent(t *testing.T) {
	backend := &fakeAgentBackend{warnings: nil}
	adminURL := newAgentCLITestServerBackend(t, backend)
	stdout, _, err := runAgentCmd(t, adminURL, "dismiss-warning", "home", "ip-flapping")
	if err != nil {
		t.Fatalf("agent dismiss-warning: %v", err)
	}
	if want := "no ip-flapping warning for home to dismiss; nothing changed\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if strings.Contains(stdout, "dismissed") {
		t.Errorf("stdout = %q, must not claim a warning was dismissed when there was none", stdout)
	}
	if backend.dismissCalled {
		t.Errorf("DismissWarning was called even though no warning matches")
	}
}

// TestAgentDismissWarningWrongKind confirms the pre-check matches on kind too: a warning for
// the same agent but a different kind does not count as a match.
func TestAgentDismissWarningWrongKind(t *testing.T) {
	backend := &fakeAgentBackend{warnings: []admin.Warning{
		{Agent: "home", Kind: "ip-mismatch", Detail: "stream 203.0.113.5 / wg 203.0.113.9", At: "2026-09-24T00:00:00Z"},
	}}
	adminURL := newAgentCLITestServerBackend(t, backend)
	stdout, _, err := runAgentCmd(t, adminURL, "dismiss-warning", "home", "ip-flapping")
	if err != nil {
		t.Fatalf("agent dismiss-warning: %v", err)
	}
	if want := "no ip-flapping warning for home to dismiss; nothing changed\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if backend.dismissCalled {
		t.Errorf("DismissWarning was called even though no warning matches")
	}
}

// TestAgentDismissWarningWrongAgent confirms the pre-check matches on agent too: a warning of
// the same kind and detail, but for a different agent, does not count as a match. Without this
// check, a mutation that drops the agent comparison entirely still passes every other test here,
// since they all use a single agent name.
func TestAgentDismissWarningWrongAgent(t *testing.T) {
	backend := &fakeAgentBackend{warnings: []admin.Warning{
		{Agent: "office", Kind: "ip-flapping", Detail: "", At: "2026-09-24T00:00:00Z"},
	}}
	adminURL := newAgentCLITestServerBackend(t, backend)
	stdout, _, err := runAgentCmd(t, adminURL, "dismiss-warning", "home", "ip-flapping")
	if err != nil {
		t.Fatalf("agent dismiss-warning: %v", err)
	}
	if want := "no ip-flapping warning for home to dismiss; nothing changed\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if backend.dismissCalled {
		t.Errorf("DismissWarning was called even though the only matching warning belongs to a different agent")
	}
}

// TestAgentDismissWarningDetailMismatch confirms a warning of the same agent and kind but a
// different detail than the one given does not count as a match, and that the CLI says a
// warning exists but does not match the given detail, rather than the plainer "no warning at
// all" wording (which would be misleading: a warning is there, just not that one).
func TestAgentDismissWarningDetailMismatch(t *testing.T) {
	backend := &fakeAgentBackend{warnings: []admin.Warning{
		{Agent: "home", Kind: "ip-mismatch", Detail: "stream 203.0.113.5 / wg 203.0.113.9", At: "2026-09-24T00:00:00Z"},
	}}
	adminURL := newAgentCLITestServerBackend(t, backend)
	stdout, _, err := runAgentCmd(t, adminURL, "dismiss-warning", "home", "ip-mismatch", "stream 198.51.100.1 / wg 198.51.100.2")
	if err != nil {
		t.Fatalf("agent dismiss-warning: %v", err)
	}
	if want := "no ip-mismatch warning for home matches that detail; nothing changed. See wgft agent warnings for the current entries.\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if backend.dismissCalled {
		t.Errorf("DismissWarning was called even though no warning matches the given detail")
	}
}

// TestAgentDismissWarningNoDetailGivenMatchesNonEmptyDetail confirms the CLI's main usage
// without a [detail] argument: an ip-mismatch warning always has a non-empty Detail (it records
// the pair of addresses), and omitting [detail] on the command line must still match and dismiss
// it. Without this check, a mutation that always compares Detail exactly (dropping the
// detail == "" shortcut) still passes every other test here, since they either give no warnings
// with a non-empty Detail while detail == "", or give a Detail while passing one that matches.
func TestAgentDismissWarningNoDetailGivenMatchesNonEmptyDetail(t *testing.T) {
	backend := &fakeAgentBackend{warnings: []admin.Warning{
		{Agent: "home", Kind: "ip-mismatch", Detail: "stream 203.0.113.5 / wg 203.0.113.9", At: "2026-09-24T00:00:00Z"},
	}}
	adminURL := newAgentCLITestServerBackend(t, backend)
	stdout, _, err := runAgentCmd(t, adminURL, "dismiss-warning", "home", "ip-mismatch")
	if err != nil {
		t.Fatalf("agent dismiss-warning: %v", err)
	}
	if want := "dismissed warning for home: ip-mismatch\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if !backend.dismissCalled {
		t.Errorf("DismissWarning was not called even though omitting [detail] should match any detail for this agent and kind")
	}
}

// TestAgentDismissWarningListFails confirms that when the pre-check itself cannot read the
// warning list, the command fails outright (exit non-zero) rather than guessing either way.
func TestAgentDismissWarningListFails(t *testing.T) {
	backend := &fakeAgentBackend{warningsErr: errBoom}
	adminURL := newAgentCLITestServerBackend(t, backend)
	stdout, _, err := runAgentCmd(t, adminURL, "dismiss-warning", "home", "ip-flapping")
	if err == nil {
		t.Fatalf("agent dismiss-warning: want an error, got none; stdout=%q", stdout)
	}
	if code := exitCode(err); code != 1 {
		t.Errorf("exitCode = %d, want 1", code)
	}
	if backend.dismissCalled {
		t.Errorf("DismissWarning was called even though the warning list could not be read")
	}
}

var errBoom = boomError("boom")

type boomError string

func (e boomError) Error() string { return string(e) }
