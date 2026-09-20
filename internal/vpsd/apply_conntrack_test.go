package vpsd

import (
	"bytes"
	"errors"
	"log"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
	"github.com/rahanahu/wgft/internal/platform/linux"
)

// TestApplyThenReadConntrackOrder proves the fix for the startup bug found on a module-less
// kernel-mode host (docs/design.md 改訂の記録 2026-09-20): applyThenReadConntrack must apply the
// table before reading the conntrack UDP timeouts, because applying table inet wgft (which
// contains ct expressions) is what makes the kernel auto-load nf_conntrack on a host where
// nothing else has loaded it yet. A fake sysctl reader here fails unless it is called after the
// fake apply has already run, standing in for that real-kernel dependency without a kernel.
//
// This test fails if the two calls are swapped back to the old order (readTimeouts before apply):
// verified by hand while writing this test, by moving the apply() call after the readTimeouts()
// call in applyThenReadConntrack and re-running go test, which failed with "read before apply";
// restored afterwards.
func TestApplyThenReadConntrackOrder(t *testing.T) {
	var order []string
	applied := false
	apply := func() error {
		order = append(order, "apply")
		applied = true
		return nil
	}
	readTimeouts := func() (linux.UDPTimeouts, error) {
		order = append(order, "read")
		if !applied {
			return linux.UDPTimeouts{}, errors.New("read before apply")
		}
		return linux.UDPTimeouts{Timeout: 30, TimeoutStream: 120}, nil
	}
	warn := func() string {
		order = append(order, "warn")
		return ""
	}

	got, err := applyThenReadConntrack(apply, readTimeouts, warn)
	if err != nil {
		t.Fatalf("applyThenReadConntrack: %v", err)
	}
	want := linux.UDPTimeouts{Timeout: 30, TimeoutStream: 120}
	if got != want {
		t.Errorf("timeouts = %+v, want %+v", got, want)
	}
	if wantOrder := "apply,read,warn"; strings.Join(order, ",") != wantOrder {
		t.Errorf("call order = %v, want %s", order, wantOrder)
	}
}

// TestApplyThenReadConntrackApplyFailureStopsBeforeRead confirms a failing apply (e.g. the
// reconcile transaction itself failing) is returned unwrapped and never reaches the conntrack
// read, so a failure unrelated to conntrack keeps its own error and exit-code classification.
func TestApplyThenReadConntrackApplyFailureStopsBeforeRead(t *testing.T) {
	applyErr := errors.New("failed to apply nftables: boom")
	readCalled := false
	_, err := applyThenReadConntrack(
		func() error { return applyErr },
		func() (linux.UDPTimeouts, error) {
			readCalled = true
			return linux.UDPTimeouts{}, nil
		},
		func() string { return "" },
	)
	if !errors.Is(err, applyErr) {
		t.Errorf("err = %v, want %v", err, applyErr)
	}
	if readCalled {
		t.Error("readTimeouts must not be called when apply fails")
	}
}

// TestApplyThenReadConntrackReadFailureAfterApplyIsStartupRefusal is the regression test for the
// production bug: on a host where nf_conntrack never loads even once the table is applied (not
// the auto-load case, a genuinely broken environment), the failure must become a
// *wg.StartupRefusal so cmd/wgft's exitCode maps it to exit 3 (systemd's
// RestartPreventExitStatus=3), not the generic exit 1 that let the real unit restart every 2
// seconds. warn must not run either: there is nothing meaningful to log once ReadUDPTimeouts has
// already failed for the same sysctl family.
func TestApplyThenReadConntrackReadFailureAfterApplyIsStartupRefusal(t *testing.T) {
	warnCalled := false
	readErr := errors.New("open /proc/sys/net/netfilter/nf_conntrack_udp_timeout: no such file or directory")
	_, err := applyThenReadConntrack(
		func() error { return nil },
		func() (linux.UDPTimeouts, error) { return linux.UDPTimeouts{}, readErr },
		func() string { warnCalled = true; return "" },
	)
	if err == nil {
		t.Fatal("want an error, got nil")
	}
	var refusal *wg.StartupRefusal
	if !errors.As(err, &refusal) {
		t.Fatalf("err = %v (%T), want a *wg.StartupRefusal", err, err)
	}
	if !strings.Contains(refusal.Reason, "table inet wgft") || !strings.Contains(refusal.Reason, readErr.Error()) {
		t.Errorf("reason = %q, want it to name table inet wgft and wrap %q", refusal.Reason, readErr)
	}
	if warnCalled {
		t.Error("warn must not be called when the conntrack read itself failed")
	}
}

// TestApplyThenReadConntrackLogsWarning confirms the conntrack-table-size warning (design.md
// 7a.10 節) still reaches the startup log, now read after apply instead of before it.
func TestApplyThenReadConntrackLogsWarning(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	_, err := applyThenReadConntrack(
		func() error { return nil },
		func() (linux.UDPTimeouts, error) { return linux.UDPTimeouts{}, nil },
		func() string { return "nf_conntrack_max=4096 is below wgft's recommended minimum of 65536" },
	)
	if err != nil {
		t.Fatalf("applyThenReadConntrack: %v", err)
	}
	if !strings.Contains(buf.String(), "warning: nf_conntrack_max=4096 is below wgft's recommended minimum of 65536") {
		t.Errorf("missing conntrack warning in log: %q", buf.String())
	}
}
