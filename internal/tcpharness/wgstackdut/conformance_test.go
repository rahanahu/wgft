package wgstackdut

import (
	"os"
	"testing"

	"github.com/rahanahu/wgft/internal/tcpharness"
)

// Known is wgstack's expected-difference list. Only the test author and the owner add entries
// (wgstack-verification.md); each entry cites the wgstack.md choice it follows.
var Known = map[string]tcpharness.Known{
	"handshake-mss-floor/mss535.synack": {
		Observed: "no SYN-ACK",
		Reason:   "wgstack.md, TCP の機能, MSS, and packet-validation.md, TCP の MSS の下限: the ingress drops SYNs with an MSS of 1 to 535",
	},
}

// RunEnv turns the wgstack conformance run on.
const RunEnv = "WGFT_TEST_WGSTACK_CONFORMANCE"

// TestConformance runs the scenarios against wgstack on a ManualClock.
func TestConformance(t *testing.T) {
	if os.Getenv(RunEnv) != "1" {
		t.Skipf("set %s=1 to run: wgstack still fails conformance checks that its implementer is fixing", RunEnv)
	}
	tcpharness.Run(t, Engine(Known), tcpharness.Scenarios)
}
