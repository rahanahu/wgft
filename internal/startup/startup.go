// Package startup holds the one refusal type the server, the agent and cmd/wgft share for a
// failure that makes wgft refuse to start (design.md 11b 節).
//
// The centre of the semantics is not the exit code's number but two questions: can a retry fix
// this, and can it not be fixed without a person acting. The rule is asymmetric. A failure that a
// retry may fix is an ordinary error and becomes exit code 1, so the shipped units' Restart=on-failure
// brings the forwarder back by itself. A *Refusal is the other side: cmd/wgft maps it to exit code
// 3, which the units name in RestartPreventExitStatus=3, so systemd stops restarting it. That is
// only allowed when the cause is provably the configured value itself, or provably cannot go away
// without an operator; when in doubt it is an ordinary error, because a wrong exit code 3 keeps the
// forwarder down for good, which is worse than a noisy restart loop.
//
// Every refusal carries the cause's category, so an operator can tell a value to edit from a host
// that is missing something, and the setting or resource it is about. The package imports nothing
// from this module: every layer, from cmd/wgft down to internal/dataplane/linuxkernel/wg, may
// import it without breaking the dependency directions of design.md 7a.7 節
// (internal/dataplane/deps_test.go checks that).
package startup

import (
	"errors"
	"fmt"
)

// Category is why a refusal cannot heal by itself. The four values are the whole set
// (design.md 11b 節); the string form goes into messages and `wgft server check`.
type Category string

const (
	// CategoryConfig is the configured value itself: malformed, out of range, or missing where it
	// is required. Judged from the values alone, at the door (buildServerOptions and the agent's
	// option building), before anything is touched.
	CategoryConfig Category = "config"
	// CategoryPrerequisite is something the host must provide and that retrying cannot bring:
	// kernel WireGuard support, CAP_NET_ADMIN, a server database no older binary can read.
	CategoryPrerequisite Category = "prerequisite"
	// CategoryConflict is a configured value or credential that contradicts state which already
	// exists: the recorded wg address range, a spent join string, a name already registered.
	// Releasing it always takes an operator (teardown --purge, a new join string, revoke).
	CategoryConflict Category = "conflict"
	// CategoryModeGate is the mode change gate: leftovers of the old mode that only
	// `wgft server teardown` removes (design.md 9, 11a 節).
	CategoryModeGate Category = "mode-gate"
)

// Refusal is a startup failure that retrying cannot fix. Nothing has been changed by the time it
// is returned: every refusal is raised before, or instead of, the write it guards.
type Refusal struct {
	// Category is the cause's kind (above).
	Category Category
	// Subject is what the refusal is about: a WGFT_* setting, or the resource concerned
	// ("CAP_NET_ADMIN", "server database"). May be empty when the reason names it itself.
	Subject string
	// Reason is the failure in one sentence, and how to fix it where that is not obvious.
	Reason string
	// Hint is an optional extra sentence the caller adds later, when the layer that found the
	// failure cannot know the fix (cmd/wgft's unreadable config file: only the command knows
	// which permissions to suggest).
	Hint string
	// Err is the underlying error, kept only where a caller tests for it with errors.Is (an
	// unreadable config file keeps os.ErrPermission). Nil otherwise: most refusals are judgements
	// on a value, not wrappers around a failure.
	Err error
}

// Unwrap exposes Err, so errors.Is reaches the underlying error through a refusal.
func (e *Refusal) Unwrap() error { return e.Err }

// Wrapping keeps err as the refusal's underlying error and returns the same refusal.
func (e *Refusal) Wrapping(err error) *Refusal {
	e.Err = err
	return e
}

// Error names the category and the subject before the reason, so an operator reading one line of
// the journal can tell a value to edit from a host to fix, and grep for either.
func (e *Refusal) Error() string {
	s := "refusing to start [" + string(e.Category)
	if e.Subject != "" {
		s += " " + e.Subject
	}
	s += "]: " + e.Reason
	if e.Hint != "" {
		s += ". " + e.Hint
	}
	return s
}

// Config, Prerequisite, Conflict and ModeGate build a refusal of that category. The format is
// fmt's, so a wrapped error can be printed with %v.
func Config(subject, format string, a ...any) *Refusal {
	return &Refusal{Category: CategoryConfig, Subject: subject, Reason: fmt.Sprintf(format, a...)}
}

func Prerequisite(subject, format string, a ...any) *Refusal {
	return &Refusal{Category: CategoryPrerequisite, Subject: subject, Reason: fmt.Sprintf(format, a...)}
}

func Conflict(subject, format string, a ...any) *Refusal {
	return &Refusal{Category: CategoryConflict, Subject: subject, Reason: fmt.Sprintf(format, a...)}
}

func ModeGate(subject, format string, a ...any) *Refusal {
	return &Refusal{Category: CategoryModeGate, Subject: subject, Reason: fmt.Sprintf(format, a...)}
}

// Of returns the *Refusal in err's chain, or nil when err is an ordinary (retryable) error.
func Of(err error) *Refusal {
	var r *Refusal
	if errors.As(err, &r) {
		return r
	}
	return nil
}

// IsRefusal reports whether err is a refusal, that is whether wgft must not be restarted on it.
func IsRefusal(err error) bool { return Of(err) != nil }
