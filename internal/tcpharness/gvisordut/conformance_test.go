package gvisordut

import (
	"testing"

	"github.com/rahanahu/wgft/internal/tcpharness"
)

// Known lists where wgft's gVisor configuration is known to differ from the scenarios'
// expectations, which follow the RFCs and the pinned Linux reference.
var Known = map[string]tcpharness.Known{
	"handshake-mss-floor/mss535.synack": {
		Observed: "no SYN-ACK",
		Reason:   "wgft drops SYNs with an MSS below 536 at the TUN ingress on purpose: internal/nettun/ingress.go tcpSynMinMSS",
	},
	"retransmit-rto/backoff-from-first": {
		Observed: "second gap / first gap below 1.5",
		Reason: "gVisor's default loss detection is RACK-TLP, RFC 8985: the first retransmission is a tail loss probe " +
			"after 2 SRTT plus 200 ms, and the RTO that follows starts unbacked; the reference Linux has TLP off",
	},
	"paws/old.dupack": {
		Observed: "ACK of base+4",
		Reason:   "the pinned gVisor does not implement PAWS, gVisor's rcv.go: it accepts the old segment and acknowledges it",
	},
	"paws/old.not-delivered": {
		Observed: "4 bytes, error nil",
		Reason:   "the pinned gVisor does not implement PAWS, gVisor's rcv.go: the old segment's bytes reach the application",
	},
}

// TestConformance runs the scenarios against nettun's gVisor Device. It needs no privileges.
func TestConformance(t *testing.T) {
	if testing.Short() {
		t.Skip("real-time TCP scenarios; skipped with -short")
	}
	tcpharness.Run(t, Engine(Known), tcpharness.Scenarios)
}
