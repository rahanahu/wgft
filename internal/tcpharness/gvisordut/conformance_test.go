package gvisordut

import (
	"testing"

	"github.com/rahanahu/wgft/internal/tcpharness"
)

// Known lists where wgft's gVisor configuration is known to differ from the scenarios'
// expectations, which follow the RFCs and Linux. Each entry needs a reason.
var Known = map[string]string{
	"handshake-mss-floor/synack": "wgft drops SYNs with an MSS below 536 at the TUN ingress on purpose (internal/nettun/ingress.go tcpSynMinMSS)",
}

// TestConformance runs the scenarios against nettun's gVisor Device. It needs no privileges.
func TestConformance(t *testing.T) {
	if testing.Short() {
		t.Skip("real-time TCP scenarios; skipped with -short")
	}
	tcpharness.Run(t, Engine(Known), tcpharness.Scenarios)
}
