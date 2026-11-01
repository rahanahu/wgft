package tcpharness

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Scenarios is the conformance set, in the order of how much a wrong TCP in wgstack's completion
// feature set would break the relay. Every TCP scenario is a passive open on IPv4 at the fixed
// MTU, the only shape of TCP wgft's agent terminates. The ICMP and UDP families follow.
var Scenarios = []Scenario{
	script("handshake-options"),
	script("handshake-bare"),
	script("handshake-mss-floor"),
	script("ooo-sack"),
	{Name: "retransmit-rto", Refs: "RFC 6298 5; packetimpact tcp_retransmits", Run: retransmitRTO},
	{Name: "newreno-recovery", Refs: "RFC 5681 3.2, RFC 6582 3.2; packetimpact tcp_rack for the RACK variant", Run: newRenoRecovery},
	{Name: "sack-multi-hole", Refs: "RFC 6675 4 and 5, RFC 6937; wgstack-performance.md, SACK recovery", Run: sackMultiHole},
	{Name: "sack-rto-keeps-sacked", Refs: "RFC 6675 5.1; wgstack-performance.md, the scoreboard records", Run: sackRTOKeepsSACKed},
	{Name: "sack-rto-islands", Refs: "RFC 6675 5.1, RFC 2018 4; wgstack-performance.md, the scoreboard records", Run: sackRTOIslands},
	{Name: "sack-pmtu-split", Refs: "RFC 1191, RFC 9293 3.7.3; wgstack-performance.md, the scoreboard records", Run: sackPMTUSplit},
	{Name: "sack-renege", Refs: "RFC 2018 8, RFC 6675 5.1; Linux tcp_check_sack_reneging; wgstack-performance.md, the scoreboard records", Run: sackRenege},
	{Name: "limited-transmit", Refs: "RFC 3042, RFC 6675 5", Run: limitedTransmit},
	{Name: "limited-transmit-rack", Refs: "RFC 3042, RFC 8985 6.2", Run: limitedTransmitRACK, Linux: rackLinux},
	{Name: "rack-reorder", Refs: "RFC 8985 6.2 and 7; wgstack-performance.md, RACK-TLP", Run: rackReorder, Linux: rackLinux},
	{Name: "tlp-tail-loss", Refs: "RFC 8985 7; packetimpact tcp_rack", Run: tlpTailLoss, Linux: rackLinux},
	{Name: "thin-stream-loss", Refs: "RFC 8985 6 and 7; wgstack-performance.md, thin streams", Run: thinStream, Linux: rackLinux},
	{Name: "window-scale", Refs: "RFC 7323 2.2 and 2.3, RFC 9293 3.8.6", Run: windowScale},
	script("paws"),
	{Name: "zero-window-probe", Refs: "RFC 9293 3.8.6.1; packetimpact tcp_zero_window_probe, tcp_zero_window_probe_retransmit", Run: zeroWindowProbe},
	script("rfc5961"),
	script("fin-passive-close"),
	script("half-close"),
	script("close-unread-rst"),
	script("active-close-fin-ack"),
	script("timewait-reuse"),
	script("early-ack"),
	script("ack-unsent"),
	script("synrcvd-syn"),
	script("close-ooo-only"),
	script("fin-zero-window"),
	script("listener-close"),
	script("icmp-frag-needed"),
	script("icmp-frag-needed-acked"),
	script("icmp-frag-needed-unsent"),
	script("icmp-frag-needed-source"),
	script("icmp-frag-needed-other-flow"),
	script("icmp-frag-needed-floor"),
	script("icmp-echo"),
	script("udp-datagram"),
	script("udp-large"),
	script("udp-reassembly"),
	script("udp-reassembly-timeout"),
	script("udp-closed-port"),
	script("rfc2525-initial-window"),
	script("rfc2525-rto-slow-start"),
	script("rfc2525-synack-rto"),
	{Name: "rfc2525-window-deflation", Refs: "RFC 2525 2.8, RFC 6582 3.2", Run: rfc2525WindowDeflation},
	{Name: "rfc2525-stretch-ack", Refs: "RFC 2525 2.13, RFC 5681 4.2, RFC 1122 4.2.3.2", Run: rfc2525StretchACK},
	script("rfc2525-close-fin"),
	script("rfc2525-data-after-close"),
	{Name: "chained-recovery", Refs: "RFC 5681 3.1, RFC 6675 5, RFC 9438 4.6, which allow up to beta x FlightSize; the bound is the reference Linux's, tcp_enter_recovery and tcp_fastretrans_alert", Run: chainedRecovery},
	{Name: "reorder-wait-recovery", Refs: "RFC 8985 6.2, RFC 5681 3.1, RFC 9438 4.6, which allow up to beta x FlightSize; the bound is the reference Linux's, tcp_enter_recovery", Run: reorderWaitRecovery, Linux: rackLinux},
	{Name: "rcv-overflow-hold", Refs: ovfRefs, Run: rcvOverflowHold},
	{Name: "rcv-overflow-read-half", Refs: ovfRefs, Run: rcvOverflowRead(true)},
	{Name: "rcv-overflow-read-all", Refs: ovfRefs, Run: rcvOverflowRead(false)},
	{Name: "rcv-overflow-hold-perf", Refs: ovfRefs, Run: rcvOverflowHold, Performance: true},
	{Name: "rcv-overflow-read-half-perf", Refs: ovfRefs, Run: rcvOverflowRead(true), Performance: true},
	{Name: "rcv-window-pacing", Refs: pacingRefs, Run: rcvWindowPacing(true), Performance: true},
	{Name: "rcv-window-pacing-fixed", Refs: pacingRefs, Run: rcvWindowPacing(false)},
	{Name: "rto-after-burst", Refs: "RFC 5681 3.1, RFC 6298 5; the band is the reference Linux's, tcp_enter_loss", Run: rtoAfterBurst},
}

func pattern(n int, salt byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7) ^ salt
	}
	return b
}

func isData(s Segment) bool { return len(s.Payload) > 0 }
func isPureAck(s Segment) bool {
	return s.Flags&(FlagSYN|FlagFIN|FlagRST) == 0 && s.Has(FlagACK) && len(s.Payload) == 0
}

// segDesc describes a segment for a check's observation without its numbers.
func segDesc(s Segment, ok bool) string {
	if !ok {
		return "no segment"
	}
	return fmt.Sprintf("%s len=%d", FlagString(s.Flags), len(s.Payload))
}

// errKind names an error for a check's observation the same way on every engine.
func errKind(err error) string {
	switch {
	case err == nil:
		return "nil"
	case errString(err) == "timeout":
		return "timeout"
	case errors.Is(err, io.EOF):
		return "EOF"
	case errors.Is(err, net.ErrClosed):
		return "closed"
	case strings.Contains(err.Error(), "connection reset"):
		return "reset"
	}
	return "error"
}

func yesNo(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}

// alive checks that the connection still carries data in both directions after a scenario's
// stimulus: the DUT's application sends four bytes the testbench receives, and the testbench
// sends four the application reads.
func alive(h *H, id string, p *Peer, c Conn) {
	h.T.Helper()
	_, werr := c.Write([]byte("ping"))
	s, ok := p.Await(2*time.Second, isData)
	h.Check(id+".dut-sends", werr == nil && ok && s.Seq == p.RcvNxt && string(s.Payload) == "ping",
		"the application's write reaches the testbench", yesNo(werr == nil && ok && string(s.Payload) == "ping", "ping arrived", "write error "+errKind(werr)+"; "+segDesc(s, ok)))
	if ok {
		p.RcvNxt = s.Seq + s.Len()
	}
	p.SendData([]byte("pong"))
	got, err := readFull(c, 4, 2*time.Second)
	h.Check(id+".dut-receives", err == nil && string(got) == "pong", "the application reads the testbench's data",
		fmt.Sprintf("%d bytes, error %s", len(got), errKind(err)))
}

// receive collects the DUT's data until n bytes have arrived in order, acknowledging each
// in-order segment, and returns them with the number of segments that repeated bytes already
// received.
func receive(p *Peer, n int, d time.Duration) ([]byte, int) {
	got, dups, _ := receiveMax(p, n, d)
	return got, dups
}

// receiveMax is receive, and it also returns the largest payload of any data segment it saw.
func receiveMax(p *Peer, n int, d time.Duration) ([]byte, int, int) {
	var got []byte
	dups, maxLen := 0, 0
	for len(got) < n {
		s, ok := p.Await(d, isData)
		if !ok {
			break
		}
		maxLen = max(maxLen, len(s.Payload))
		switch {
		case s.Seq == p.RcvNxt:
			got = append(got, s.Payload...)
			p.RcvNxt += uint32(len(s.Payload))
			p.SendAck()
		case int32(s.Seq-p.RcvNxt) < 0:
			dups++
		}
	}
	return got, dups, maxLen
}

// ackDesc describes an ACK relative to base, or its absence.
func ackDesc(s Segment, ok bool, base uint32) string {
	if !ok {
		return "no ACK in time"
	}
	return fmt.Sprintf("ACK of base+%d", int32(s.Ack-base))
}

func sackDesc(s Segment, ok bool, base uint32) string {
	if !ok {
		return "no ACK in time"
	}
	var parts []string
	for _, b := range s.Opts.SACK {
		parts = append(parts, fmt.Sprintf("[base+%d,base+%d)", int32(b.Left-base), int32(b.Right-base)))
	}
	if len(parts) == 0 {
		return "no SACK block"
	}
	return strings.Join(parts, " ")
}

func zeroWindowProbe(h *H) {
	const port = 8006
	l := h.Listen(port)
	p, _, c := h.Connect(l, port, StandardSYN())
	if _, err := c.Write(pattern(1000, 0x44)); err != nil {
		h.T.Fatalf("write: %v", err)
	}
	n := 0
	for n < 1000 {
		s, ok := p.Await(2*time.Second, func(s Segment) bool { return isData(s) && s.Seq == p.RcvNxt })
		if !ok {
			break
		}
		n += len(s.Payload)
		p.RcvNxt += uint32(len(s.Payload))
	}
	h.Require("first-data", n == 1000, "the first 1000 bytes arrive", fmt.Sprintf("%d bytes", n))
	// The testbench's receive buffer is full: one ACK takes the data and closes the window. The
	// ACK must advance: Linux takes a smaller window only from an ACK that acknowledges new data
	// or carries a newer sequence number, stricter than RFC 9293 3.10.7.4.
	p.Window = 0
	p.SendAck()
	// The DUT handles segments in order, so its ACK of one more byte from the testbench shows that
	// it has taken in the zero window before the application writes again.
	p.SendData([]byte("z"))
	za, ok := p.Await(time.Second, func(s Segment) bool { return isPureAck(s) && s.Ack == p.SndNxt })
	h.Require("zero-window-taken", ok, "the DUT acknowledges a byte sent after the zero-window ACK", segDesc(za, ok))
	closed := h.Now()
	second := pattern(500, 0x55)
	if _, err := c.Write(second); err != nil {
		h.T.Fatalf("write: %v", err)
	}
	var probes []time.Time
	var forms []string
	intoWindow := false
	for len(probes) < 3 {
		s, ok := p.Next(5 * time.Second)
		if !ok {
			break
		}
		switch {
		case s.Seq == p.RcvNxt-1 && len(s.Payload) <= 1:
			forms = append(forms, fmt.Sprintf("seq=una-1,len=%d", len(s.Payload)))
		case s.Seq == p.RcvNxt && len(s.Payload) == 1:
			forms = append(forms, "seq=una,len=1") // RFC 9293 3.8.6.1 allows one new byte
		case len(s.Payload) > 0:
			intoWindow = true
			continue
		default:
			continue
		}
		probes = append(probes, h.Now())
		p.SendAck() // still a zero window
	}
	h.Check("no-data-into-zero-window", !intoWindow, "no data beyond a zero window other than a 1-byte probe", yesNo(intoWindow, "data beyond the window", "none"))
	h.Check("probes", len(probes) == 3, "three zero-window probes within 5 s of each other", fmt.Sprintf("%d probes", len(probes)))
	if len(probes) > 0 {
		h.Measure("probe1_ms", probes[0].Sub(closed).Milliseconds())
		h.Measure("probe-form", forms[0])
	}
	if len(probes) == 3 {
		g1, g2 := probes[1].Sub(probes[0]), probes[2].Sub(probes[1])
		h.Measure("probe-gap1_ms", g1.Milliseconds())
		h.Measure("probe-gap2_ms", g2.Milliseconds())
		h.Check("probe-backoff", g2 >= g1*3/2, "the probe interval backs off", fmt.Sprintf("second gap / first gap %s 1.5", yesNo(g2 >= g1*3/2, "at least", "below")))
	}
	// Open the window: the 500 bytes follow.
	p.Window = 512 // 64 KiB with the testbench's window scale of 7
	p.SendAck()
	s, ok := p.Await(3*time.Second, func(s Segment) bool { return isData(s) && s.Seq == p.RcvNxt })
	h.Check("resume", ok && bytes.HasPrefix(second, s.Payload), "the queued data follows the window update", segDesc(s, ok))
}
