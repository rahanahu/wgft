package wgstackdut

import (
	"os"
	"testing"

	"github.com/rahanahu/wgft/internal/tcpharness"
	"github.com/rahanahu/wgft/internal/tcpharness/rustdut"
)

// Known is wgstack's expected-difference list. Only the test author and the owner add entries
// (wgstack-verification.md); each entry cites the wgstack.md choice it follows.
var Known = map[string]tcpharness.Known{
	"limited-transmit/first-dupack.new-data": {
		Observed: "0 new segments",
		Reason: "wgstack-performance.md, RACK-TLP: wgstack always runs RACK, and at the testbench's near-zero RTT its reorder " +
			"window is about zero, so it resends the first segment at the first SACK instead of sending new data; " +
			"limited-transmit-rack checks Limited Transmit on a path with an RTT",
	},
	"limited-transmit/second-dupack.new-data": {
		Observed: "0 new segments",
		Reason:   "as limited-transmit/first-dupack.new-data: RACK has already resent the first segment",
	},
	"limited-transmit/no-retransmit-before-third": {
		Observed: "1 retransmissions",
		Reason:   "wgstack-performance.md, RACK-TLP: RACK, always on, resends the first segment before any duplicate-ACK threshold",
	},
	"rfc2525-stretch-ack-burst/every-second-segment": {
		Observed: "an ACK covers more than two segments; all acknowledged",
		Reason: "wgstack-rs.md, per-wake ACK merging: the core makes at most one content-free ACK per connection per wake, " +
			"so a burst of twelve segments injected before the poll gets one ACK over all twelve, past the " +
			"every-second-segment SHOULD of RFC 5681 4.2. Measured: 1 ACK for 12 segments on the Rust core and on the frozen Go wgstack",
	},
	"rfc2525-stretch-ack-burst-ooo/dupack-per-segment": {
		Observed: "1 duplicate ACKs",
		Reason: "wgstack-rs.md, per-wake ACK merging: eight out-of-order segments injected before the poll get one duplicate ACK, " +
			"not one each as RFC 5681 3.2 asks. Measured: 1 duplicate ACK for 8 segments on the frozen Go wgstack. " +
			"The Rust core sends one per segment, so known-wgstack-rs.json has no such row",
	},
	"icmp-echo/oversized": {
		Observed: "no reply",
		Reason: "wgstack.md, Linux との一致を確かめていない選択, MTU を超える echo request: wgstack does not fragment what it " +
			"sends, so it does not answer an echo whose reply exceeds the MTU; Linux and gVisor send it in fragments",
	},
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
		t.Skipf("set %s=1 to run: wgstack still fails the SACK recovery and RACK-TLP scenarios its implementer is building", RunEnv)
	}
	tcpharness.Run(t, Engine(Known), tcpharness.Scenarios)
}

// TestCongestion checks wgstack's CUBIC and HyStart++ against RFC 9438 and RFC 9406 with the
// testbench as the path. wgstack-performance.md assigns these checks to the test author in
// place of a comparison with Linux.
func TestCongestion(t *testing.T) {
	if os.Getenv(RunEnv) != "1" {
		t.Skipf("set %s=1 to run", RunEnv)
	}
	tcpharness.Run(t, Engine(nil), tcpharness.CongestionScenarios)
}

// TestRustdutConformance runs the scenarios through rustdut against the DUT binary that
// rustdut.BinEnv names. Against the Go wgstack's dutserve it is the frozen Go wgstack, so this
// list applies; the Rust wgstack's list is rustdut's own file (test-tooling.md section 2).
func TestRustdutConformance(t *testing.T) {
	if os.Getenv(rustdut.BinEnv) == "" {
		t.Skipf("set %s to the Go wgstack's dutserve to run", rustdut.BinEnv)
	}
	tcpharness.Run(t, rustdut.Engine(Known), tcpharness.Scenarios)
}

// TestRustdutCongestion runs the CUBIC and HyStart++ scenarios through rustdut.
func TestRustdutCongestion(t *testing.T) {
	if os.Getenv(rustdut.BinEnv) == "" {
		t.Skipf("set %s to the Go wgstack's dutserve to run", rustdut.BinEnv)
	}
	tcpharness.Run(t, rustdut.Engine(nil), tcpharness.CongestionScenarios)
}
