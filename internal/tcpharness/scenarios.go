package tcpharness

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"
)

// Scenarios is the conformance set, in priority order. Every scenario is a passive open on IPv4
// at the fixed MTU, the only shape of TCP wgft's agent terminates.
var Scenarios = []Scenario{
	{Name: "handshake-options", Refs: "RFC 9293 3.5 and 3.7.1, RFC 7323 2.2 and 3.2, RFC 2018 2; packetimpact tcp_handshake_window_size", Run: handshakeOptions},
	{Name: "handshake-bare", Refs: "RFC 9293 3.7.1 (MUST-15 default send MSS 536), RFC 7323 2.2 and 3.2, RFC 2018 2", Run: handshakeBare},
	{Name: "handshake-mss-floor", Refs: "RFC 9293 3.7.1; wgft's TUN-ingress floor of 536 (internal/nettun/ingress.go)", Run: handshakeMSSFloor},
	{Name: "retransmit-rto", Refs: "RFC 6298 5, RFC 8985 7 (TLP); packetimpact tcp_retransmits, tcp_rack", Run: retransmitRTO},
	{Name: "ooo-sack", Refs: "RFC 9293 3.10.7.4, RFC 2018 3 and 4, RFC 5681 4.2; gVisor e2e tcp_sack_test.go", Run: oooSACK},
	{Name: "zero-window-probe", Refs: "RFC 9293 3.8.6.1; packetimpact tcp_zero_window_probe, tcp_zero_window_probe_retransmit", Run: zeroWindowProbe},
	{Name: "rfc5961", Refs: "RFC 5961 3.2 and 4.2, RFC 9293 3.10.7.4; packetimpact tcp_outside_the_window, tcp_unacc_seq_ack", Run: rfc5961},
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

// alive checks that the connection still carries data in both directions after a scenario's
// stimulus: the DUT's application sends a byte the testbench receives, and the testbench sends
// one the application reads.
func alive(h *H, id string, p *Peer, c Conn) {
	h.T.Helper()
	_, werr := c.Write([]byte("ping"))
	s, ok := p.Await(2*time.Second, isData)
	h.Check(id+".dut-sends", werr == nil && ok && s.Seq == p.RcvNxt && string(s.Payload) == "ping",
		"the application's write reaches the testbench: write err=%v segment=%v", werr, s)
	if ok {
		p.RcvNxt = s.Seq + s.Len()
	}
	p.SendData([]byte("pong"))
	got, err := readFull(c, 4, 2*time.Second)
	h.Check(id+".dut-receives", err == nil && string(got) == "pong", "the application reads the testbench's data: %q err=%s", got, errString(err))
}

func handshakeOptions(h *H) {
	const port = 8001
	l := h.Listen(port)
	p, sa, c := h.Connect(l, port, StandardSYN())
	h.Check("synack.mss", sa.Opts.MSS != nil && int(*sa.Opts.MSS) == MTU-40, "MSS option is MTU-40=%d: %v", MTU-40, sa)
	h.Check("synack.sack-permitted", sa.Opts.SACKPermitted, "SACK-permitted answered: %v", sa)
	h.Check("synack.wscale", sa.Opts.WS >= 0 && sa.Opts.WS <= 14, "window scale answered, at most 14: %v", sa)
	h.Check("synack.timestamps", sa.Opts.TS != nil && sa.Opts.TS.Ecr == p.SynTSVal, "timestamps answered, TSecr echoes the SYN's TSval %d: %v", p.SynTSVal, sa)
	h.Check("synack.window", sa.Window > 0, "nonzero window in the SYN-ACK: %d", sa.Window)
	h.Measure("synack.window", sa.Window)
	h.Measure("synack.wscale", sa.Opts.WS)
	h.Measure("synack.df", sa.DF)
	h.Measure("synack.ttl", sa.TTL)
	alive(h, "established", p, c)
	// Every non-RST segment on a connection with timestamps carries the option (RFC 7323 3.2).
	_, _ = c.Write([]byte("ts"))
	s, ok := p.Await(2*time.Second, isData)
	h.Check("established.timestamps", ok && s.Opts.TS != nil, "a data segment carries timestamps: %v", s)
}

func handshakeBare(h *H) {
	const port = 8002
	l := h.Listen(port)
	p, sa, c := h.Connect(l, port, NoOptions())
	h.Check("synack.no-wscale", sa.Opts.WS < 0, "no window scale when the SYN had none: %v", sa)
	h.Check("synack.no-timestamps", sa.Opts.TS == nil, "no timestamps when the SYN had none: %v", sa)
	h.Check("synack.no-sack-permitted", !sa.Opts.SACKPermitted, "no SACK-permitted when the SYN had none: %v", sa)
	h.Check("synack.mss", sa.Opts.MSS != nil, "the SYN-ACK still carries an MSS option: %v", sa)
	// Without an MSS option the DUT must assume 536 (RFC 9293 MUST-15).
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
	h.Check("default-mss", total == len(data) && maxLen <= 536, "%d of %d bytes in segments of at most %d bytes (limit 536)", total, len(data), maxLen)
	h.Measure("max-segment", maxLen)
}

// handshakeMSSFloor sends a SYN with an MSS below 536. A Linux host accepts it; wgft's agent
// drops it at the TUN ingress on purpose, which is the known difference this scenario keeps
// visible.
func handshakeMSSFloor(h *H) {
	const port = 8003
	h.Listen(port)
	p := h.NewPeer(port)
	mss := uint16(500)
	o := NoOptions()
	o.MSS = &mss
	p.Send(Segment{Src: p.Local, Dst: p.Remote, Seq: p.ISS, Flags: FlagSYN, Window: 65535, Opts: o})
	sa, ok := p.Await(time.Second, func(s Segment) bool { return s.Has(FlagSYN | FlagACK) })
	h.Check("synack", ok, "a SYN with MSS 500 is answered within 1 s: %v", sa)
	if ok {
		p.Send(Segment{Src: p.Local, Dst: p.Remote, Seq: p.ISS + 1, Flags: FlagRST})
	}
}

func retransmitRTO(h *H) {
	const port = 8004
	l := h.Listen(port)
	p, _, c := h.Connect(l, port, StandardSYN())
	data := pattern(1000, 0x22)
	if _, err := c.Write(data); err != nil {
		h.T.Fatalf("write: %v", err)
	}
	first, ok := p.Await(2*time.Second, isData)
	h.Require("first-transmission", ok && first.Seq == p.RcvNxt, "data segment at RcvNxt: %v", first)
	sent := []time.Time{h.Now()}
	same := true
	for range 3 {
		s, ok := p.Await(6*time.Second, isData)
		if !ok {
			break
		}
		sent = append(sent, h.Now())
		if s.Seq != first.Seq || !bytes.HasPrefix(first.Payload, s.Payload) && !bytes.HasPrefix(s.Payload, first.Payload) {
			same = false
		}
	}
	h.Check("retransmitted", len(sent) == 4, "three retransmissions of the unacknowledged segment arrive: %d", len(sent)-1)
	h.Check("same-data", same, "every retransmission starts at the lost segment and carries its bytes")
	var gaps []time.Duration
	for i := 1; i < len(sent); i++ {
		gaps = append(gaps, sent[i].Sub(sent[i-1]))
		h.Measure(fmt.Sprintf("gap%d_ms", i), sent[i].Sub(sent[i-1]).Milliseconds())
	}
	if len(gaps) == 3 {
		// RFC 6298 5.5: the timer backs off. The first gap may be a tail loss probe (RFC 8985),
		// so the doubling is checked between the later two.
		h.Check("backoff", gaps[2] >= gaps[1]*3/2, "the third gap %v is at least 1.5 times the second %v", gaps[2], gaps[1])
	}
	p.RcvNxt = first.Seq + uint32(len(first.Payload))
	p.SendAck()
	if len(gaps) > 0 {
		quiet := gaps[len(gaps)-1] * 3
		s, ok := p.Quiet(quiet)
		h.Check("stops-after-ack", ok, "no further retransmission for %v after the ACK: %v", quiet, s)
	}
}

func oooSACK(h *H) {
	const port = 8005
	l := h.Listen(port)
	p, _, c := h.Connect(l, port, StandardSYN())
	h.Require("sack-negotiated", p.SACK, "SACK negotiated")
	base := p.SndNxt
	data := pattern(3000, 0x33)
	p.Send(p.Segment(FlagACK|FlagPSH, base+1000, data[1000:2000]))
	a1, ok := p.Await(time.Second, isPureAck)
	h.Check("dupack1", ok && a1.Ack == base, "an out-of-order segment is acknowledged at once with ack=RCV.NXT: %v", a1)
	h.Check("sack1", ok && len(a1.Opts.SACK) > 0 && a1.Opts.SACK[0] == SACKBlock{base + 1000, base + 2000},
		"the first SACK block covers the received segment: %v", a1.Opts.SACK)
	p.Send(p.Segment(FlagACK|FlagPSH, base+2000, data[2000:3000]))
	a2, ok := p.Await(time.Second, isPureAck)
	h.Check("dupack2", ok && a2.Ack == base, "the second out-of-order segment is acknowledged at once: %v", a2)
	h.Check("sack2", ok && len(a2.Opts.SACK) > 0 && a2.Opts.SACK[0] == SACKBlock{base + 1000, base + 3000},
		"the first SACK block merges both segments: %v", a2.Opts.SACK)
	start := h.Now()
	p.Send(p.Segment(FlagACK|FlagPSH, base, data[:1000]))
	p.SndNxt = base + 3000
	a3, ok := p.Await(time.Second, func(s Segment) bool { return s.Has(FlagACK) && s.Ack == base+3000 })
	h.Check("hole-filled", ok, "filling the hole acknowledges all 3000 bytes within 1 s: %v", a3)
	h.Measure("hole-ack_ms", h.Now().Sub(start).Milliseconds())
	h.Check("hole-filled.no-sack", ok && len(a3.Opts.SACK) == 0, "no SACK block once nothing is out of order: %v", a3.Opts.SACK)
	got, err := readFull(c, 3000, 2*time.Second)
	h.Check("reassembled", err == nil && bytes.Equal(got, data), "the application reads the 3000 bytes in order: %d bytes err=%s", len(got), errString(err))
}

func zeroWindowProbe(h *H) {
	const port = 8006
	l := h.Listen(port)
	p, _, c := h.Connect(l, port, StandardSYN())
	if _, err := c.Write(pattern(1000, 0x44)); err != nil {
		h.T.Fatalf("write: %v", err)
	}
	d1, ok := p.Await(2*time.Second, isData)
	h.Require("first-data", ok && d1.Seq == p.RcvNxt, "first data segment: %v", d1)
	p.RcvNxt += uint32(len(d1.Payload))
	for p.RcvNxt-p.DutISS-1 < 1000 { // the 1000 bytes may come in more than one segment
		s, ok := p.Await(2*time.Second, isData)
		if !ok {
			break
		}
		p.RcvNxt = s.Seq + uint32(len(s.Payload))
	}
	// The testbench's receive buffer is full: acknowledge everything with a zero window.
	p.Window = 0
	p.SendAck()
	// The DUT handles segments in order, so its ACK of one more byte from the testbench shows that
	// it has taken in the zero window before the application writes again.
	p.SendData([]byte("z"))
	za, ok := p.Await(time.Second, func(s Segment) bool { return isPureAck(s) && s.Ack == p.SndNxt })
	h.Require("zero-window-taken", ok, "the DUT acknowledges a byte sent after the zero-window ACK: %v", za)
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
	h.Check("no-data-into-zero-window", !intoWindow, "the DUT sends no data beyond a zero window other than a 1-byte probe")
	h.Check("probes", len(probes) == 3, "three zero-window probes within 5 s of each other: %d %v", len(probes), forms)
	if len(probes) > 0 {
		h.Measure("probe1_ms", probes[0].Sub(closed).Milliseconds())
		h.Measure("probe-form", forms[0])
	}
	if len(probes) == 3 {
		g1, g2 := probes[1].Sub(probes[0]), probes[2].Sub(probes[1])
		h.Measure("probe-gap1_ms", g1.Milliseconds())
		h.Measure("probe-gap2_ms", g2.Milliseconds())
		h.Check("probe-backoff", g2 >= g1*3/2, "the probe interval backs off: %v then %v", g1, g2)
	}
	// Open the window: the 500 bytes follow.
	p.Window = 512 // 64 KiB with the testbench's window scale of 7
	p.SendAck()
	s, ok := p.Await(3*time.Second, func(s Segment) bool { return isData(s) && s.Seq == p.RcvNxt })
	h.Check("resume", ok && bytes.HasPrefix(second, s.Payload), "the queued data follows the window update: %v", s)
}

func rfc5961(h *H) {
	const port = 8007
	l := h.Listen(port)

	// Each part uses its own connection, so a per-connection challenge-ACK rate limit (Linux's
	// tcp_invalid_ratelimit, 500 ms) cannot suppress the next part's ACK.
	p, _, c := h.Connect(l, port, StandardSYN())
	p.Send(p.Segment(FlagRST, p.SndNxt+1, nil))
	a, ok := p.Await(time.Second, func(Segment) bool { return true })
	h.Check("rst-in-window.challenge-ack", ok && isPureAck(a) && a.Ack == p.SndNxt && a.Seq == p.RcvNxt,
		"an in-window RST that is not at RCV.NXT draws a challenge ACK: %v", a)
	alive(h, "rst-in-window", p, c)

	p, _, c = h.Connect(l, port, StandardSYN())
	syn := p.Segment(FlagSYN, p.SndNxt, nil)
	mss := uint16(MTU - 40)
	syn.Opts.MSS = &mss
	p.Send(syn)
	a, ok = p.Await(time.Second, func(Segment) bool { return true })
	h.Check("syn-in-window.challenge-ack", ok && isPureAck(a) && a.Ack == p.SndNxt && a.Seq == p.RcvNxt,
		"a SYN on an established connection draws a challenge ACK: %v", a)
	alive(h, "syn-in-window", p, c)

	p, _, c = h.Connect(l, port, StandardSYN())
	p.Send(p.Segment(FlagRST, p.SndNxt+1<<30, nil))
	s, quiet := p.Quiet(500 * time.Millisecond)
	h.Check("rst-out-of-window.ignored", quiet, "an RST far outside the window is dropped without a reply: %v", s)
	alive(h, "rst-out-of-window", p, c)

	p, _, c = h.Connect(l, port, StandardSYN())
	p.Send(p.Segment(FlagRST, p.SndNxt, nil))
	_, err := readFull(c, 1, time.Second)
	h.Check("rst-exact.resets", err != nil && !errors.Is(err, io.EOF) && errString(err) != "timeout",
		"an RST at RCV.NXT resets the connection; the application's read fails: %s", errString(err))
	s, quiet = p.Quiet(300 * time.Millisecond)
	h.Check("rst-exact.no-reply", quiet, "nothing answers the RST: %v", s)
}
