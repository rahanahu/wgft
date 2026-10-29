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
// feature set would break the relay. Every scenario is a passive open on IPv4 at the fixed MTU,
// the only shape of TCP wgft's agent terminates.
var Scenarios = []Scenario{
	{Name: "handshake-options", Refs: "RFC 9293 3.5 and 3.7.1, RFC 7323 2.2 and 3.2, RFC 2018 2; packetimpact tcp_handshake_window_size", Run: handshakeOptions},
	{Name: "handshake-bare", Refs: "RFC 9293 3.7.1 MUST-15 default send MSS 536, RFC 7323 2.2 and 3.2, RFC 2018 2", Run: handshakeBare},
	{Name: "handshake-mss-floor", Refs: "RFC 9293 3.7.1; wgft's TUN-ingress floor of 536, packet-validation.md", Run: handshakeMSSFloor},
	{Name: "ooo-sack", Refs: "RFC 9293 3.10.7.4, RFC 2018 3 and 4, RFC 5681 4.2; gVisor e2e tcp_sack_test.go", Run: oooSACK},
	{Name: "retransmit-rto", Refs: "RFC 6298 5; packetimpact tcp_retransmits", Run: retransmitRTO},
	{Name: "newreno-recovery", Refs: "RFC 5681 3.2, RFC 6582 3.2; packetimpact tcp_rack for the RACK variant", Run: newRenoRecovery},
	{Name: "window-scale", Refs: "RFC 7323 2.2 and 2.3, RFC 9293 3.8.6", Run: windowScale},
	{Name: "paws", Refs: "RFC 7323 5.3; packetimpact tcp_paws_mechanism", Run: paws},
	{Name: "zero-window-probe", Refs: "RFC 9293 3.8.6.1; packetimpact tcp_zero_window_probe, tcp_zero_window_probe_retransmit", Run: zeroWindowProbe},
	{Name: "rfc5961", Refs: "RFC 5961 3.2 and 4.2, RFC 9293 3.10.7.4; packetimpact tcp_outside_the_window, tcp_unacc_seq_ack", Run: rfc5961},
	{Name: "fin-passive-close", Refs: "RFC 9293 3.6 and 3.10.7.4 CLOSE-WAIT and LAST-ACK", Run: finPassiveClose},
	{Name: "half-close", Refs: "RFC 9293 3.6, 3.8.1 and 3.10.7.4 FIN-WAIT-1, FIN-WAIT-2 and TIME-WAIT; packetimpact tcp_fin_retransmission", Run: halfClose},
	{Name: "close-unread-rst", Refs: "RFC 9293 3.6, RFC 2525 2.17", Run: closeUnreadRST},
	{Name: "active-close-fin-ack", Refs: "RFC 9293 3.6 and 3.10.7.4 FIN-WAIT-1, RFC 1122 4.2.3.2", Run: activeCloseFINACK},
	{Name: "timewait-reuse", Refs: "RFC 6191 2 and 3, RFC 9293 3.10.7.4 TIME-WAIT; packetimpact tcp_timewait_reset", Run: timeWaitReuse},
	{Name: "early-ack", Refs: "RFC 1122 4.2.3.2, RFC 9293 3.8.6.3; wgstack.md, the choices not yet checked against Linux: quickack, the window after the handshake, the IP ID", Run: earlyACK},
	{Name: "ack-unsent", Refs: "RFC 9293 3.10.7.4, RFC 5961 5.2; packetimpact tcp_unacc_seq_ack", Run: ackUnsent},
	{Name: "synrcvd-syn", Refs: "RFC 9293 3.10.7.4 SYN-RECEIVED, RFC 5961 4; packetimpact tcp_synrcvd_reset", Run: synRcvdSYN},
	{Name: "close-ooo-only", Refs: "RFC 9293 3.6, RFC 2525 2.17; wgstack.md: Close with only out-of-order data", Run: closeOOOOnly},
	{Name: "fin-zero-window", Refs: "RFC 9293 3.8.6.1; wgstack.md: the FIN while the window is 0", Run: finZeroWindow},
	{Name: "listener-close", Refs: "RFC 9293 3.10.4 and 3.10.7.1; packetimpact tcp_noaccept_close_rst, tcp_listen_backlog", Run: listenerClose},
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
	var got []byte
	dups := 0
	for len(got) < n {
		s, ok := p.Await(d, isData)
		if !ok {
			break
		}
		switch {
		case s.Seq == p.RcvNxt:
			got = append(got, s.Payload...)
			p.RcvNxt += uint32(len(s.Payload))
			p.SendAck()
		case int32(s.Seq-p.RcvNxt) < 0:
			dups++
		}
	}
	return got, dups
}

func handshakeOptions(h *H) {
	const port = 8001
	l := h.Listen(port)
	p, sa, c := h.Connect(l, port, StandardSYN())
	mss := "no MSS option"
	if sa.Opts.MSS != nil {
		mss = fmt.Sprintf("MSS %d", *sa.Opts.MSS)
	}
	h.Check("synack.mss", sa.Opts.MSS != nil && int(*sa.Opts.MSS) == MTU-40, fmt.Sprintf("an MSS option of MTU-40=%d", MTU-40), mss)
	h.Check("synack.sack-permitted", sa.Opts.SACKPermitted, "SACK-permitted answered", yesNo(sa.Opts.SACKPermitted, "SACK-permitted", "no SACK-permitted"))
	h.Check("synack.wscale", sa.Opts.WS >= 0 && sa.Opts.WS <= 14, "a window scale of at most 14", fmt.Sprintf("window scale %d", sa.Opts.WS))
	tsOK := sa.Opts.TS != nil && sa.Opts.TS.Ecr == p.SynTSVal
	h.Check("synack.timestamps", tsOK, "timestamps answered with TSecr echoing the SYN's TSval",
		yesNo(sa.Opts.TS == nil, "no timestamps", yesNo(tsOK, "TSecr echoes the SYN", "TSecr differs from the SYN's TSval")))
	h.Check("synack.window", sa.Window > 0, "a nonzero window in the SYN-ACK", yesNo(sa.Window > 0, "nonzero", "zero"))
	h.Measure("synack.window", sa.Window)
	h.Measure("synack.wscale", sa.Opts.WS)
	h.Measure("synack.df", sa.DF)
	h.Measure("synack.ttl", sa.TTL)
	alive(h, "established", p, c)
	// Every non-RST segment on a connection with timestamps carries the option, RFC 7323 3.2.
	_, _ = c.Write([]byte("ts"))
	s, ok := p.Await(2*time.Second, isData)
	h.Check("established.timestamps", ok && s.Opts.TS != nil, "a data segment carries timestamps",
		yesNo(ok, yesNo(ok && s.Opts.TS != nil, "timestamps", "no timestamps"), "no data segment"))
}

func handshakeBare(h *H) {
	const port = 8002
	l := h.Listen(port)
	p, sa, c := h.Connect(l, port, NoOptions())
	h.Check("synack.no-wscale", sa.Opts.WS < 0, "no window scale when the SYN had none", yesNo(sa.Opts.WS < 0, "none", "window scale"))
	h.Check("synack.no-timestamps", sa.Opts.TS == nil, "no timestamps when the SYN had none", yesNo(sa.Opts.TS == nil, "none", "timestamps"))
	h.Check("synack.no-sack-permitted", !sa.Opts.SACKPermitted, "no SACK-permitted when the SYN had none", yesNo(!sa.Opts.SACKPermitted, "none", "SACK-permitted"))
	h.Check("synack.mss", sa.Opts.MSS != nil, "the SYN-ACK still carries an MSS option", yesNo(sa.Opts.MSS != nil, "MSS option", "no MSS option"))
	// Without an MSS option the DUT must assume 536, RFC 9293 MUST-15.
	data := pattern(4000, 0x11)
	if _, err := c.Write(data); err != nil {
		h.T.Fatalf("write: %v", err)
	}
	maxLen, total := 0, 0
	for total < len(data) {
		s, ok := p.Await(3*time.Second, isData)
		if !ok {
			break
		}
		maxLen = max(maxLen, len(s.Payload))
		if s.Seq == p.RcvNxt {
			total += len(s.Payload)
			p.RcvNxt += uint32(len(s.Payload))
			p.SendAck()
		}
	}
	h.Check("default-mss", total == len(data) && maxLen <= 536, "all 4000 bytes in segments of at most 536 bytes",
		fmt.Sprintf("%d bytes, largest segment %d", total, maxLen))
	h.Measure("max-segment", maxLen)
}

// handshakeMSSFloor probes the MSS floor from both sides. A SYN with MSS 536 is the positive
// control every engine answers, so a probe that is dropped for another reason, such as a bad
// checksum, cannot pass for the floor. A SYN with MSS 535 is answered by Linux and dropped by
// wgft's agent on purpose.
func handshakeMSSFloor(h *H) {
	const port = 8003
	h.Listen(port)
	// An MSS option of 0 is read as no option: 536, RFC 9293 3.7.1; the floor does not apply.
	mss0 := h.NewPeer(port)
	o0 := NoOptions()
	zero := uint16(0)
	o0.MSS = &zero
	mss0.Send(Segment{Src: mss0.Local, Dst: mss0.Remote, Seq: mss0.ISS, Flags: FlagSYN, Window: 65535, Opts: o0})
	sa0, ok0 := mss0.Await(time.Second, func(s Segment) bool { return s.Has(FlagSYN | FlagACK) })
	ok0 = ok0 && sa0.Ack == mss0.ISS+1
	h.Check("mss0.synack", ok0, "a SYN with an MSS option of 0 is answered within 1 s", synackString(mss0, sa0, ok0))
	if ok0 {
		mss0.Send(Segment{Src: mss0.Local, Dst: mss0.Remote, Seq: mss0.ISS + 1, Flags: FlagRST})
	}
	for _, mss := range []uint16{536, 535} {
		p := h.NewPeer(port)
		o := NoOptions()
		o.MSS = &mss
		p.Send(Segment{Src: p.Local, Dst: p.Remote, Seq: p.ISS, Flags: FlagSYN, Window: 65535, Opts: o})
		sa, ok := p.Await(time.Second, func(s Segment) bool { return s.Has(FlagSYN | FlagACK) })
		ok = ok && sa.Ack == p.ISS+1
		h.Check(fmt.Sprintf("mss%d.synack", mss), ok, fmt.Sprintf("a SYN with MSS %d is answered within 1 s", mss), synackString(p, sa, ok))
		if ok {
			p.Send(Segment{Src: p.Local, Dst: p.Remote, Seq: p.ISS + 1, Flags: FlagRST})
		}
	}
}

func oooSACK(h *H) {
	const port = 8005
	l := h.Listen(port)
	p, _, c := h.Connect(l, port, StandardSYN())
	h.Require("sack-negotiated", p.SACK, "SACK negotiated", yesNo(p.SACK, "SACK", "no SACK"))
	base := p.SndNxt
	data := pattern(3000, 0x33)
	// RFC 5681 4.2 and RFC 9293 3.10.7.4: an out-of-order segment and a segment that fills a hole
	// are acknowledged at once, so each answer must come within Prompt, not a delayed-ACK timer.
	p.Send(p.Segment(FlagACK|FlagPSH, base+1000, data[1000:2000]))
	a1, ok := p.Await(h.Prompt(), isPureAck)
	h.Check("dupack1", ok && a1.Ack == base, "an out-of-order segment is acknowledged at once with ack=RCV.NXT", ackDesc(a1, ok, base))
	h.Check("sack1", ok && len(a1.Opts.SACK) > 0 && a1.Opts.SACK[0] == SACKBlock{base + 1000, base + 2000},
		"the first SACK block covers the received segment", sackDesc(a1, ok, base))
	p.Send(p.Segment(FlagACK|FlagPSH, base+2000, data[2000:3000]))
	a2, ok := p.Await(h.Prompt(), isPureAck)
	h.Check("dupack2", ok && a2.Ack == base, "the second out-of-order segment is acknowledged at once", ackDesc(a2, ok, base))
	h.Check("sack2", ok && len(a2.Opts.SACK) > 0 && a2.Opts.SACK[0] == SACKBlock{base + 1000, base + 3000},
		"the first SACK block merges both segments", sackDesc(a2, ok, base))
	start := h.Now()
	p.Send(p.Segment(FlagACK|FlagPSH, base, data[:1000]))
	p.SndNxt = base + 3000
	a3, ok := p.Await(h.Prompt(), func(s Segment) bool { return s.Has(FlagACK) && s.Ack == base+3000 })
	h.Check("hole-filled", ok, "filling the hole acknowledges all 3000 bytes at once", ackDesc(a3, ok, base))
	h.Measure("hole-ack_ms", h.Now().Sub(start).Milliseconds())
	h.Check("hole-filled.no-sack", ok && len(a3.Opts.SACK) == 0, "no SACK block once nothing is out of order", sackDesc(a3, ok, base))
	got, err := readFull(c, 3000, 2*time.Second)
	h.Check("reassembled", err == nil && bytes.Equal(got, data), "the application reads the 3000 bytes in order",
		fmt.Sprintf("%d bytes, equal %v, error %s", len(got), bytes.Equal(got, data), errKind(err)))
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

func rfc5961(h *H) {
	const port = 8007
	l := h.Listen(port)

	// Each part uses its own connection, so a per-connection challenge-ACK rate limit, such as
	// Linux's tcp_invalid_ratelimit of 500 ms, cannot suppress the next part's ACK.
	isChallenge := func(p *Peer) func(Segment) bool {
		return func(a Segment) bool { return isPureAck(a) && a.Ack == p.SndNxt && a.Seq == p.RcvNxt }
	}
	p, _, c := h.Connect(l, port, StandardSYN())
	p.Send(p.Segment(FlagRST, p.SndNxt+1, nil))
	a, ok := p.Next(time.Second)
	h.Check("rst-in-window.challenge-ack", ok && isChallenge(p)(a), "an in-window RST that is not at RCV.NXT draws a challenge ACK", segDesc(a, ok))
	alive(h, "rst-in-window", p, c)

	p, _, c = h.Connect(l, port, StandardSYN())
	syn := p.Segment(FlagSYN, p.SndNxt, nil)
	mss := uint16(MTU - 40)
	syn.Opts.MSS = &mss
	p.Send(syn)
	a, ok = p.Next(time.Second)
	h.Check("syn-in-window.challenge-ack", ok && isChallenge(p)(a), "a SYN on an established connection draws a challenge ACK", segDesc(a, ok))
	alive(h, "syn-in-window", p, c)

	p, _, c = h.Connect(l, port, StandardSYN())
	p.Send(p.Segment(FlagRST, p.SndNxt+1<<30, nil))
	s, quiet := p.Quiet(500 * time.Millisecond)
	h.Check("rst-out-of-window.ignored", quiet, "an RST far outside the window is dropped without a reply", segDesc(s, !quiet))
	alive(h, "rst-out-of-window", p, c)

	p, _, c = h.Connect(l, port, StandardSYN())
	p.Send(p.Segment(FlagRST, p.SndNxt, nil))
	_, err := readFull(c, 1, time.Second)
	h.Check("rst-exact.resets", errKind(err) == "reset", "an RST at RCV.NXT resets the connection and the application's read fails", "read error "+errKind(err))
	s, quiet = p.Quiet(300 * time.Millisecond)
	h.Check("rst-exact.no-reply", quiet, "nothing answers the RST", segDesc(s, !quiet))
}
