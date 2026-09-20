package startup_test

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/startup"
)

// Error names the category and the subject before the reason, so one journal line tells an operator
// which kind of failure this is and what it is about (design.md 11b 節).
func TestErrorNamesCategoryAndSubject(t *testing.T) {
	for _, tc := range []struct {
		err  *startup.Refusal
		want string
	}{
		{startup.Config("WGFT_MTU", "%q is not an integer between 576 and 9216", "big"),
			`refusing to start [config WGFT_MTU]: "big" is not an integer between 576 and 9216`},
		{startup.Prerequisite("CAP_NET_ADMIN", "kernel mode needs CAP_NET_ADMIN"),
			"refusing to start [prerequisite CAP_NET_ADMIN]: kernel mode needs CAP_NET_ADMIN"},
		{startup.Conflict("WGFT_JOIN", "this join string is already used"),
			"refusing to start [conflict WGFT_JOIN]: this join string is already used"},
		{startup.ModeGate("WGFT_MODE", "changing mode from kernel to userspace: leftovers remain"),
			"refusing to start [mode-gate WGFT_MODE]: changing mode from kernel to userspace: leftovers remain"},
		{&startup.Refusal{Category: startup.CategoryPrerequisite, Reason: "no reason to name a subject"},
			"refusing to start [prerequisite]: no reason to name a subject"},
	} {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("Error() = %q, want %q", got, tc.want)
		}
	}
}

// A hint added by the layer that knows the fix appears after the reason, once.
func TestHintIsAppended(t *testing.T) {
	r := startup.Config("/etc/wgft/server.env", "permission denied")
	r.Hint = "chmod 0644 /etc/wgft/server.env"
	if got := r.Error(); !strings.HasSuffix(got, ". chmod 0644 /etc/wgft/server.env") {
		t.Errorf("Error() = %q, want the hint at the end", got)
	}
}

// Of and IsRefusal find a refusal through wrapping, and say no to an ordinary error and to nil.
// Every layer wraps: internal/vpsd adds the interface name, the agent adds "re-register failed".
func TestOfSeesThroughWrapping(t *testing.T) {
	r := startup.Conflict("WGFT_WG_ADDRESS", "differs from the recorded one")
	wrapped := fmt.Errorf("server: %w", fmt.Errorf("mode: %w", r))
	if got := startup.Of(wrapped); got != r {
		t.Errorf("Of(wrapped) = %v, want the refusal itself", got)
	}
	if !startup.IsRefusal(wrapped) {
		t.Error("IsRefusal(wrapped) = false, want true")
	}
	if startup.IsRefusal(errors.New("listen tcp :8443: address already in use")) {
		t.Error("IsRefusal(ordinary error) = true; a retryable failure must stay exit code 1")
	}
	if startup.IsRefusal(nil) {
		t.Error("IsRefusal(nil) = true, want false")
	}
	if got := startup.Of(nil); got != nil {
		t.Errorf("Of(nil) = %v, want nil", got)
	}
}

// Wrapping keeps the underlying error reachable with errors.Is, which is how an unreadable config
// file keeps os.ErrPermission while still being a refusal.
func TestWrappingKeepsTheCause(t *testing.T) {
	r := startup.Config("/etc/wgft/agent.env", "permission denied").Wrapping(os.ErrPermission)
	if !errors.Is(r, os.ErrPermission) {
		t.Error("errors.Is(refusal, os.ErrPermission) = false, want true")
	}
	if errors.Is(startup.Config("WGFT_MODE", "unknown mode"), os.ErrPermission) {
		t.Error("a refusal with no cause must not match an unrelated target")
	}
}
