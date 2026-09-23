package userspace

import (
	"testing"

	"github.com/rahanahu/wgft/internal/resource"
)

// TestBackendBudgetsComeFromTheLimits pins the wiring of the process-wide flow budgets in
// userspace mode (design.md 7, 7a.10 節). Two things it holds are invisible from the outside once
// the process runs: the configured WGFT_MAX_TCP_FLOWS and WGFT_MAX_UDP_FLOWS must reach the relay
// rather than leaving it on its defaults, and TCPPool must hand out the very pool the relay judges
// against, since the server gives it to its Relay frontend so both count against one budget and one
// per-rule cap. The Backend no longer holds pool fields of its own, so nothing structural enforces
// either; this test does.
func TestBackendBudgetsComeFromTheLimits(t *testing.T) {
	// Numbers no default could produce, so a Backend that silently fell back is visible here.
	const tcpTotal, udpTotal = 111, 222
	if tcpTotal == resource.TCPTotal || udpTotal == resource.UDPTotal {
		t.Fatal("pick totals that differ from the defaults, or the test proves nothing")
	}
	b := New(Options{Limits: resource.Limits{TCPTotal: tcpTotal, UDPTotal: udpTotal}, Logf: t.Logf})

	if got := b.TCPPool().Total(); got != tcpTotal {
		t.Errorf("TCP budget = %d, want %d: the configured limit must reach the relay", got, tcpTotal)
	}
	if got := b.UDPPool().Total(); got != udpTotal {
		t.Errorf("UDP budget = %d, want %d: the configured limit must reach the relay", got, udpTotal)
	}
	if b.TCPPool() != b.relay.TCPPool() {
		t.Error("the TCP pool the server hands to its Relay frontend must be the one the relay judges against")
	}
	if b.UDPPool() != b.relay.UDPPool() {
		t.Error("the UDP pool the admin API reports must be the one the relay judges against")
	}
}
