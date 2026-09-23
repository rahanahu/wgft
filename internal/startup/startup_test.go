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

// A command that starts nothing marks the refusal, and only the opening words change: a one-shot
// run cannot refuse to start, it can only stop (design.md 11b 節). The category, the subject, the
// reason, the hint, the wrapped cause and the type itself, which decides exit code 3, stay put.
func TestOneShotChangesOnlyTheOpeningWords(t *testing.T) {
	r := startup.Config("/etc/wgft/agent.env", "permission denied").Wrapping(os.ErrPermission)
	r.Hint = "run it as the user the agent runs as"
	if got := startup.OneShot(r); got != error(r) {
		t.Errorf("OneShot returned %v, want the same error", got)
	}
	want := "cannot continue [config /etc/wgft/agent.env]: permission denied. run it as the user the agent runs as"
	if got := r.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !startup.IsRefusal(r) || !errors.Is(r, os.ErrPermission) {
		t.Error("marking the refusal lost its type or its cause; exit code 3 and errors.Is must not move")
	}
	// The mark reaches a refusal through wrapping, which is how a command's entry point marks
	// one that a lower layer raised and an upper layer wrapped.
	inner := startup.Prerequisite("wg", "no kernel module")
	if err := startup.OneShot(fmt.Errorf("server: %w", inner)); err == nil {
		t.Fatal("OneShot dropped the error")
	}
	if !strings.HasPrefix(inner.Error(), "cannot continue [") {
		t.Errorf("a wrapped refusal was not marked: %q", inner.Error())
	}
	// An ordinary error and nil pass through untouched.
	plain := errors.New("listen tcp :8443: address already in use")
	if got := startup.OneShot(plain); got != plain {
		t.Errorf("OneShot(ordinary) = %v, want it unchanged", got)
	}
	if got := startup.OneShot(nil); got != nil {
		t.Errorf("OneShot(nil) = %v, want nil", got)
	}
}

// An unmarked refusal keeps the startup wording. The zero value is what every layer builds, so a
// refusal nobody marks reads the way the server's and the agent's startup have always read.
func TestUnmarkedRefusalKeepsTheStartupWording(t *testing.T) {
	if got := startup.Config("WGFT_MTU", "out of range").Error(); !strings.HasPrefix(got, "refusing to start [") {
		t.Errorf("Error() = %q, want it to start with the startup wording", got)
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
