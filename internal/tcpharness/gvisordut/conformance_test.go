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
	"timewait-reuse/newer-ts-smaller-isn.synack": {
		Observed: "no SYN-ACK",
		Reason: "the pinned gVisor reuses a TIME-WAIT four-tuple only for a SYN beyond the old RCV.NXT, the sequence rule of " +
			"RFC 1122; it ignores the newer timestamp that RFC 6191 2 accepts, and drops the SYN without a reply",
	},
	"listener-close/half-open.rst-at-close": {
		Observed: "no RST at the close",
		Reason: "gVisor drops a closed listener's half-open handshakes without a RST; the final ACK then draws the closed " +
			"port's RST. wgstack.md resets them at the close",
	},
	"ack-unsent/ack-reply": {
		Observed: "ACK of base+4",
		Reason:   "the pinned gVisor accepts data on a segment that acknowledges unsent bytes and acknowledges that data, against RFC 9293 3.10.7.4",
	},
	"ack-unsent/not-delivered": {
		Observed: "4 bytes, error nil",
		Reason:   "the pinned gVisor accepts data on a segment that acknowledges unsent bytes and delivers it, against RFC 9293 3.10.7.4",
	},
	"synrcvd-syn/same-syn.synack-again": {
		Observed: "no SYN-ACK",
		Reason:   "gVisor answers a retransmitted SYN in SYN-RECEIVED with an ACK; Linux and wgstack retransmit the SYN-ACK",
	},
	"sack-rto-islands/islands-not-resent": {
		Observed: "SACKed resent",
		Reason: "gVisor's RTO expunges its SACK scoreboard, retransmitTimerExpired calling scoreboard.Reset in tcp/snd.go, " +
			"so after the RTO it resends the island the latest ACK no longer lists",
	},
	"sack-renege/resends-sacked": {
		Observed: "no segment",
		Reason: "gVisor does not detect a renege; it resends the dropped data only at its RTO, about 200 ms after the " +
			"reneging ACK, where Linux's tcp_check_sack_reneging re-arms the timer to max(SRTT/2, 10 ms)",
	},
	"limited-transmit/first-dupack.new-data": {
		Observed: "0 new segments",
		Reason: "gVisor's default RACK, on the testbench's near-zero RTT, marks the first segment lost at the first SACK " +
			"and resends it instead of sending new data; Limited Transmit belongs to the duplicate-threshold rule",
	},
	"limited-transmit/second-dupack.new-data": {
		Observed: "0 new segments",
		Reason:   "as limited-transmit/first-dupack.new-data: the first segment was already resent by RACK",
	},
	"limited-transmit/no-retransmit-before-third": {
		Observed: "1 retransmissions",
		Reason:   "gVisor's RACK resends the first segment at the first SACK, before any duplicate-ACK threshold",
	},
	"tlp-tail-loss/recovers-before-rto": {
		Observed: "recovered at the RTO floor plus one RTT or later",
		Reason: "gVisor sends the tail loss probe at about 2 SRTT, but probeTimerExpired calls postXmit(dataSent, false), " +
			"which arms the RTO rather than RACK's reorder timer, so after the probe's SACK the other tail segment is " +
			"resent only at the RTO, about 200 ms later: gVisor's tcp/rack.go",
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
