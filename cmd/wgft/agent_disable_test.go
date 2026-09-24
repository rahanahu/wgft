package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/store"
)

// newAgentCLITestServerBackend is newAgentCLITestServer's counterpart for tests
// (TestAgentDisable*/TestAgentEnable*) that need to control DisableAgent/EnableAgent's
// response or error directly, rather than only the Agents() list.
func newAgentCLITestServerBackend(t *testing.T, b *fakeAgentBackend) (adminURL string) {
	t.Helper()
	srv := httptest.NewServer(admin.New(b))
	t.Cleanup(srv.Close)
	return srv.URL
}

// TestAgentDisableChanged confirms the success wording and exit code 0 when a disable
// actually changes the agent's state (design.md 5.1, 7a.11 節: changed:true).
func TestAgentDisableChanged(t *testing.T) {
	adminURL := newAgentCLITestServerBackend(t, &fakeAgentBackend{
		disableRes: admin.AgentDisabledResponse{Name: "home", Disabled: true, Changed: true, Generation: 12},
	})
	stdout, _, err := runAgentCmd(t, adminURL, "disable", "home")
	if err != nil {
		t.Fatalf("agent disable: %v", err)
	}
	want := "disabled agent home at generation 12: its rules stop forwarding and open sessions are cut; registration, keys and rule settings are kept. Undo: wgft agent enable home\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

// TestAgentDisableUnchanged confirms that disabling an already-disabled agent says nothing
// changed rather than repeating the "disabled at generation" wording, and still exits 0
// (design.md 5.1 節: an idempotent repeat does not advance the generation).
func TestAgentDisableUnchanged(t *testing.T) {
	adminURL := newAgentCLITestServerBackend(t, &fakeAgentBackend{
		disableRes: admin.AgentDisabledResponse{Name: "home", Disabled: true, Changed: false, Generation: 12},
	})
	stdout, _, err := runAgentCmd(t, adminURL, "disable", "home")
	if err != nil {
		t.Fatalf("agent disable: %v", err)
	}
	want := "agent home is already disabled; nothing changed\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

// TestAgentDisableUnknownName confirms a 404 (unknown agent, store.AgentNotFoundError)
// surfaces as a non-zero exit with a message naming the agent, matching how "agent revoke"
// and the other mutating agent subcommands already report a plain admin API error
// (design.md 7a.11 節; the common one-shot guarantee is success 0, failure non-zero).
func TestAgentDisableUnknownName(t *testing.T) {
	adminURL := newAgentCLITestServerBackend(t, &fakeAgentBackend{
		disableErr: &store.AgentNotFoundError{Name: "ghost"},
	})
	stdout, stderr, err := runAgentCmd(t, adminURL, "disable", "ghost")
	if err == nil {
		t.Fatalf("agent disable ghost: want an error, got none; stdout=%q", stdout)
	}
	if got := exitCode(err); got != 1 {
		t.Errorf("exitCode = %d, want 1", got)
	}
	if !strings.Contains(err.Error(), "ghost") || !strings.Contains(err.Error(), "not registered") {
		t.Errorf("error = %q, want it to name the agent and say it is not registered", err.Error())
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty on failure", stdout)
	}
	_ = stderr
}

// TestAgentDisableSavedNotPublished confirms a 422 with saved:true (dataplane publish
// failed after the database write succeeded) is reported as a failure that says the change
// is saved but not published yet, and that the retry publishes it (design.md 5.1 節).
func TestAgentDisableSavedNotPublished(t *testing.T) {
	adminURL := newAgentCLITestServerBackend(t, &fakeAgentBackend{
		disableErr: &admin.AgentChangeError{Saved: true, Err: fmt.Errorf(
			"saved: agent home is disabled in the server database, but the change is not published yet: %w; the server retries every 30s", errors.New("nft: busy"))},
	})
	_, _, err := runAgentCmd(t, adminURL, "disable", "home")
	if err == nil {
		t.Fatalf("agent disable home: want an error, got none")
	}
	if got := exitCode(err); got != 1 {
		t.Errorf("exitCode = %d, want 1", got)
	}
	msg := err.Error()
	for _, want := range []string{"saved", "not published yet", "retries every 30s"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error = %q, want it to contain %q", msg, want)
		}
	}
}

// TestAgentEnableRefused confirms a 422 with saved:false (enable's write-time check
// refused, so nothing was saved) is reported as a refusal that carries the server's reason,
// distinct in wording from the saved-but-not-published case above (design.md 5.1 節).
func TestAgentEnableRefused(t *testing.T) {
	adminURL := newAgentCLITestServerBackend(t, &fakeAgentBackend{
		enableErr: &admin.AgentChangeError{Saved: false, Err: fmt.Errorf(
			"refused to enable agent home; nothing changed: %w", errors.New("port 2456/tcp is bound by another process"))},
	})
	_, _, err := runAgentCmd(t, adminURL, "enable", "home")
	if err == nil {
		t.Fatalf("agent enable home: want an error, got none")
	}
	if got := exitCode(err); got != 1 {
		t.Errorf("exitCode = %d, want 1", got)
	}
	msg := err.Error()
	for _, want := range []string{"refused", "nothing changed", "port 2456/tcp is bound"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error = %q, want it to contain %q", msg, want)
		}
	}
	if strings.Contains(msg, "not published yet") {
		t.Errorf("error = %q, must not read like the saved-but-unpublished case: nothing was saved here", msg)
	}
}

// TestAgentEnableChanged is TestAgentDisableChanged's mirror for enable.
func TestAgentEnableChanged(t *testing.T) {
	adminURL := newAgentCLITestServerBackend(t, &fakeAgentBackend{
		enableRes: admin.AgentDisabledResponse{Name: "home", Disabled: false, Changed: true, Generation: 13},
	})
	stdout, _, err := runAgentCmd(t, adminURL, "enable", "home")
	if err != nil {
		t.Fatalf("agent enable: %v", err)
	}
	want := "enabled agent home at generation 13: its rules forward again as each rule's own enabled setting decides\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

// TestAgentEnableUnchanged is TestAgentDisableUnchanged's mirror for enable.
func TestAgentEnableUnchanged(t *testing.T) {
	adminURL := newAgentCLITestServerBackend(t, &fakeAgentBackend{
		enableRes: admin.AgentDisabledResponse{Name: "home", Disabled: false, Changed: false, Generation: 13},
	})
	stdout, _, err := runAgentCmd(t, adminURL, "enable", "home")
	if err != nil {
		t.Fatalf("agent enable: %v", err)
	}
	want := "agent home is already enabled; nothing changed\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

// TestAgentLsShowsDisabledState confirms `agent ls`'s plain-table STATE column distinguishes a
// disabled agent, with how long ago (via ago(), design.md 7a.11 節's timestamp convention), from
// an enabled one, using "enabled"/"disabled" rather than a health word since disabled is a
// declared state (design.md 5.1 節). It also confirms --json still passes AgentInfo's
// disabled/disabled_at through unchanged (7a.11 節: agent ls --json is []admin.AgentInfo, output
// as-is, not folded into the plain table's STATE word).
func TestAgentLsShowsDisabledState(t *testing.T) {
	disabledAt := time.Now().Add(-90 * time.Minute).Format(time.RFC3339)
	agents := []admin.AgentInfo{
		{Name: "home", Address: "10.200.0.2", Connected: true, Disabled: false},
		{Name: "office", Address: "10.200.0.3", Connected: true, Disabled: true, DisabledAt: disabledAt},
	}
	adminURL := newAgentCLITestServer(t, agents)

	stdout, _, err := runAgentCmd(t, adminURL, "ls")
	if err != nil {
		t.Fatalf("agent ls: %v", err)
	}
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(lines) < 1 {
		t.Fatalf("agent ls: no output")
	}
	header := lines[0]
	stateCol := strings.Index(header, "STATE")
	addrCol := strings.Index(header, "ADDRESS")
	if stateCol < 0 || addrCol < 0 || stateCol >= addrCol {
		t.Fatalf("agent ls header = %q, want STATE between NAME and ADDRESS", header)
	}
	var homeLine, officeLine string
	for _, l := range lines[1:] {
		if strings.HasPrefix(l, "home ") {
			homeLine = l
		}
		if strings.HasPrefix(l, "office ") {
			officeLine = l
		}
	}
	homeState := strings.TrimSpace(homeLine[stateCol:addrCol])
	officeState := strings.TrimSpace(officeLine[stateCol:addrCol])
	if homeState != "enabled" {
		t.Errorf("enabled agent's STATE = %q, want \"enabled\"", homeState)
	}
	// "disabled " plus ago()'s output, which always ends in " ago"; requiring both the prefix
	// and the "ago" suffix, rather than just the "disabled" prefix, is what catches ago() being
	// dropped (STATE collapsing to the bare word "disabled" with nothing after it).
	if !strings.HasPrefix(officeState, "disabled ") || !strings.HasSuffix(officeState, "ago") {
		t.Errorf("disabled agent's STATE = %q, want \"disabled <duration> ago\"", officeState)
	}

	stdoutJSON, _, err := runAgentCmd(t, adminURL, "ls", "--json")
	if err != nil {
		t.Fatalf("agent ls --json: %v", err)
	}
	var got []admin.AgentInfo
	if err := json.Unmarshal([]byte(stdoutJSON), &got); err != nil {
		t.Fatalf("agent ls --json: invalid JSON: %v\n%s", err, stdoutJSON)
	}
	var office *admin.AgentInfo
	for i := range got {
		if got[i].Name == "office" {
			office = &got[i]
		}
	}
	if office == nil {
		t.Fatalf("agent ls --json: no entry for office in %s", stdoutJSON)
	}
	if !office.Disabled {
		t.Errorf("agent ls --json: office.disabled = false, want true")
	}
	if office.DisabledAt != disabledAt {
		t.Errorf("agent ls --json: office.disabled_at = %q, want %q", office.DisabledAt, disabledAt)
	}
}
