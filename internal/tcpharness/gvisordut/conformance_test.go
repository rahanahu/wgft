package gvisordut

import (
	"testing"

	"github.com/rahanahu/wgft/internal/tcpharness"
)

// Known lists where wgft's gVisor configuration is known to differ from the scenarios'
// expectations, which follow the RFCs and the pinned Linux reference.
var Known = map[string]tcpharness.Known{
	"icmp-frag-needed-acked/ignored": {
		Observed: "applied: largest packet 972 bytes",
		Reason: "gVisor does not check the quoted sequence number of Fragmentation Needed, RFC 5927 4.1; " +
			"packet-validation.md, the ICMP error ingress, notes this. wgstack checks it",
	},
	"icmp-frag-needed-unsent/ignored": {
		Observed: "applied: largest packet 972 bytes",
		Reason:   "as icmp-frag-needed-acked/ignored, for a sequence number beyond SND.NXT",
	},
	"handshake-mss-floor/mss535.synack": {
		Observed: "no SYN-ACK",
		Reason:   "wgft drops SYNs with an MSS below 536 at the TUN ingress on purpose: internal/nettun/ingress.go tcpSynMinMSS",
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
	"limited-transmit-rack/first-dupack.new-data": {
		Observed: "0 new segments",
		Reason: "on a 400 ms path, with RACK's reorder window keeping the first segment unmarked, gVisor sends no " +
			"new data on the first two duplicate ACKs in this scenario",
	},
	"limited-transmit-rack/second-dupack.new-data": {
		Observed: "0 new segments",
		Reason:   "as limited-transmit-rack/first-dupack.new-data",
	},
	"limited-transmit/no-retransmit-before-third": {
		Observed: "1 retransmissions",
		Reason:   "gVisor's RACK resends the first segment at the first SACK, before any duplicate-ACK threshold",
	},
	"tlp-tail-loss/recovers-before-rto": {
		Observed: "recovered at the RTO floor plus one RTT or later",
		Reason: "gVisor's RACK ignores the ACK of a retransmission whose RTT is below its minimum RTT, and takes that minimum " +
			"from data ACKs only, not from the handshake: update in gVisor's tcp/rack.go. On this path the probe's ACK comes " +
			"back after the same 50 ms as the flight's, so a sub-millisecond difference decides. When the sample is ignored, " +
			"the probe's SACK marks nothing lost and the other tail segment waits for the RTO, about 200 ms after the probe; " +
			"otherwise RACK resends it at once and recovery ends about 145 ms after the ACK, as it did in 4 of 12 runs",
		Sometimes: true,
	},
	"chained-recovery/reduced": {
		Observed: "above the bound",
		Reason: "gVisor makes no second reduction for a hole it resends inside the first recovery: TCPInfo showed ssthresh at " +
			"40, half the 80-segment window, from the first recovery through the rounds after the second, where Linux halves " +
			"again to 20. After the recovery gVisor's window then about doubles each round in congestion avoidance, TCPInfo " +
			"showing cwnd 45, 91 and 183 with ssthresh 40; the cause of that growth in gVisor's sender is not identified",
	},
	"reorder-wait-recovery/reduced": {
		Observed: "above the bound",
		Reason: "gVisor reduces to half the window, 72 to 36, but in congestion avoidance after the recovery its window about " +
			"doubles each round, as in chained-recovery/reduced: the third round after the recovery carries 76 segments against " +
			"a bound of 54; the cause of that growth in gVisor's sender is not identified",
	},
	"rto-after-burst/ssthresh.not-collapsed": {
		Observed: "below it",
		Reason: "gVisor's Reno sets ssthresh at an RTO to Outstanding/2, reno.go reduceSlowStartThreshold, Outstanding being " +
			"the pipe SetPipe computed; in the failing runs TCPInfo showed ssthresh 2 after the RTO and gVisor sent one or two " +
			"segments a round. Other runs go on to about 17 segments; what decides between them is not identified",
		Sometimes: true,
	},
	"rto-after-burst/completes": {
		Observed:  "not acknowledged",
		Reason:    "as rto-after-burst/ssthresh.not-collapsed: sending one or two segments a round, gVisor does not repair the burst within the rounds the scenario runs",
		Sometimes: true,
	},
	"rcv-overflow-hold/read-hole.window-update": {
		Observed: "no such ACK in time",
		Reason: "gVisor sends no ACK when a read frees its buffer while out-of-order data waits behind a hole; the window " +
			"it opened reaches the sender only with the ACK of the segment that fills the hole. Linux's read updates the window " +
			"at once, tcp_cleanup_rbuf, and so does wgstack",
	},
	"rcv-overflow-hold/read-hole.sack-kept": {
		Observed: "no ACK in time",
		Reason:   "as rcv-overflow-hold/read-hole.window-update: no ACK follows the read",
	},
	"rcv-overflow-hold-perf/read-hole.window-update": {
		Observed: "no such ACK in time",
		Reason:   "as rcv-overflow-hold/read-hole.window-update",
	},
	"rcv-overflow-hold-perf/read-hole.sack-kept": {
		Observed: "no ACK in time",
		Reason:   "as rcv-overflow-hold/read-hole.window-update: no ACK follows the read",
	},
	"rcv-overflow-hold/edge.dropped":      ovfBeyond,
	"rcv-overflow-hold/hole.ack":          ovfBeyondAck,
	"rcv-overflow-hold-perf/edge.dropped": ovfBeyond,
	"rcv-overflow-hold-perf/hole.ack":     ovfBeyondAck,
	"rcv-window-pacing/window.step":       pacingJump,
	"rcv-window-pacing/window.band": {
		Observed: "above the band",
		Reason:   "as rcv-window-pacing/window.step: gVisor's window settles at about 2 MB, three to four times the reference Linux's",
	},
	"rcv-window-pacing/loss.edge-kept":                pacingEdge,
	"rcv-window-pacing-fixed/loss.edge-kept":          pacingEdge,
	"rcv-window-pacing-fixed/window.step":             pacingJump,
	"rcv-overflow-read-half/fill.window-honored":      ovfShrink,
	"rcv-overflow-read-all/fill.window-honored":       ovfShrink,
	"rcv-overflow-read-half-perf/fill.window-honored": ovfShrink,
	"paws/old.dupack": {
		Observed: "ACK of base+4",
		Reason:   "the pinned gVisor does not implement PAWS, gVisor's rcv.go: it accepts the old segment and acknowledges it",
	},
	"paws/old.not-delivered": {
		Observed: "4 bytes, error nil",
		Reason:   "the pinned gVisor does not implement PAWS, gVisor's rcv.go: the old segment's bytes reach the application",
	},
}

// ovfShrink is gVisor's shrinking window as its buffer fills.
var ovfShrink = tcpharness.Known{
	Observed: "it drops some",
	Reason: "as its buffer fills with data the application does not read, gVisor closes its window less than a scale unit " +
		"short of a right edge it advertised before and drops what the testbench sent up to that edge; RFC 7323 2.4 has " +
		"the receiver honor every segment in window for any ACK it sent, and Linux and wgstack take it. Whether the drop " +
		"happens turns on how the segments and gVisor's ACKs interleave",
	Sometimes: true,
}

// pacingJump is gVisor opening its window at once.
var pacingJump = tcpharness.Known{
	Observed: "some do",
	Reason: "gVisor's receive buffer moderation opens the advertised window by about 2 MB in one ACK once the reads " +
		"have measured the path, where Linux and wgstack open it by rcv_ssthresh's step per arriving segment; " +
		"a step of this kind is what wgstack-performance.md found behind the slow recovery after a queue overflow when " +
		"an earlier window growth of wgstack's took it",
}

// pacingEdge is gVisor's right edge moving on while a hole stays.
var pacingEdge = tcpharness.Known{
	Observed: "it grows",
	Reason: "on some runs gVisor moves its right edge on by some hundred bytes while the first hole of the loss round " +
		"stays, which Linux and wgstack, their window at its limit, do not; what decides it is not identified",
	Sometimes: true,
}

// ovfBeyond and ovfBeyondAck are gVisor taking a segment past its right edge.
var (
	ovfBeyond = tcpharness.Known{
		Observed: "it reports data there",
		Reason: "while its buffer still has room, gVisor takes the whole segment that starts at the right edge it advertised, " +
			"whose window field is smaller than that room; Linux drops a segment that starts at its right edge, and wgstack " +
			"takes only what its rounded window field hid. Whether the advertised edge lies short of the room turns on timing",
		Sometimes: true,
	}
	ovfBeyondAck = tcpharness.Known{
		Observed:  "ACK past the right edge",
		Reason:    "as rcv-overflow-hold/edge.dropped: filling the hole also acknowledges the segment past the right edge",
		Sometimes: true,
	}
)

// TestConformance runs the scenarios against nettun's gVisor Device. It needs no privileges.
func TestConformance(t *testing.T) {
	t.Parallel() // independent Devices; the package then takes about as long as its longest test
	if testing.Short() {
		t.Skip("real-time TCP scenarios; skipped with -short")
	}
	tcpharness.Run(t, Engine(Known), tcpharness.Scenarios)
}
