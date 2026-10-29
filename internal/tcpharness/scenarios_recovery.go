package tcpharness

import (
	"bytes"
	"fmt"
	"time"
)

func ratio(a, b time.Duration, min float64) string {
	return fmt.Sprintf("%s %.1f", yesNo(float64(a) >= min*float64(b), "at least", "below"), min)
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
	h.Require("first-transmission", ok && first.Seq == p.RcvNxt, "a data segment at RcvNxt", segDesc(first, ok))
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
	h.Check("retransmitted", len(sent) == 4, "three retransmissions of the unacknowledged segment", fmt.Sprintf("%d retransmissions", len(sent)-1))
	h.Check("same-data", same, "every retransmission starts at the lost segment and carries its bytes", yesNo(same, "same bytes", "other bytes"))
	var gaps []time.Duration
	for i := 1; i < len(sent); i++ {
		gaps = append(gaps, sent[i].Sub(sent[i-1]))
		h.Measure(fmt.Sprintf("gap%d_ms", i), sent[i].Sub(sent[i-1]).Milliseconds())
	}
	if len(gaps) == 3 {
		// RFC 6298: the first retransmission waits for an RTO of at least the 200 ms minimum
		// that Linux and wgstack use, and every later one doubles it.
		h.Check("first-gap-is-rto", gaps[0] >= 180*time.Millisecond, "the first retransmission comes after an RTO of at least 200 ms",
			yesNo(gaps[0] >= 180*time.Millisecond, "at least 180 ms", "below 180 ms"))
		h.Check("backoff-from-first", gaps[1] >= gaps[0]*3/2, "the second gap is at least 1.5 times the first", "second gap / first gap "+ratio(gaps[1], gaps[0], 1.5))
		h.Check("backoff", gaps[2] >= gaps[1]*3/2, "the third gap is at least 1.5 times the second", "third gap / second gap "+ratio(gaps[2], gaps[1], 1.5))
	}
	p.RcvNxt = first.Seq + uint32(len(first.Payload))
	p.SendAck()
	if len(gaps) > 0 {
		quiet := gaps[len(gaps)-1] * 3
		s, ok := p.Quiet(quiet)
		h.Check("stops-after-ack", ok, "no further retransmission after the ACK", segDesc(s, !ok))
	}
}

// newRenoRecovery loses the second and the fourth segment of the initial flight on a connection
// without SACK. Three duplicate ACKs must start a fast retransmission of the first hole, the
// partial ACK that follows must retransmit the second hole at once, RFC 6582 3.2 step 3, and
// nothing else is retransmitted. The congestion window during recovery is not compared: Linux
// sizes it with PRR, RFC 6937, a difference the design accepts.
func newRenoRecovery(h *H) {
	const port = 8008
	l := h.Listen(port)
	p, _, c := h.Connect(l, port, NoSACKSYN())
	h.Require("no-sack", !p.SACK, "SACK not negotiated", yesNo(p.SACK, "SACK", "no SACK"))
	const n = 10
	mss := MTU - 40
	data := pattern(n*mss, 0x66)
	if _, err := c.Write(data); err != nil {
		h.T.Fatalf("write: %v", err)
	}
	base := p.RcvNxt
	var flight []Segment
	for len(flight) < n {
		s, ok := p.Await(50*time.Millisecond, isData)
		if !ok {
			break
		}
		flight = append(flight, s)
	}
	sentAt := h.Now()
	h.Measure("initial-flight", len(flight))
	h.Require("initial-flight", len(flight) >= 6, "an initial flight of at least 6 segments; RFC 6928 allows 10", fmt.Sprintf("%d segments", len(flight)))
	// got maps a sequence offset from base to the bytes the testbench has received there.
	got := map[uint32][]byte{}
	high := uint32(0) // offset past the highest byte sent so far
	for _, s := range flight {
		got[s.Seq-base] = s.Payload
		high = max(high, s.Seq-base+uint32(len(s.Payload)))
	}
	hole1, hole2 := flight[1], flight[3]
	var rexmits []uint32
	note := func(s Segment) {
		off := s.Seq - base
		if !isData(s) || off >= uint32(len(data)) {
			return
		}
		if off < high {
			rexmits = append(rexmits, s.Seq)
		}
		got[off] = s.Payload
		high = max(high, off+uint32(len(s.Payload)))
	}

	// Segment 1 arrives; 2 is lost; 3, 5 and 6 arrive and each draws a duplicate ACK of 2. New
	// data after the first two duplicate ACKs is allowed, RFC 3042 limited transmit; a
	// retransmission is not.
	p.RcvNxt = hole1.Seq
	p.SendAck()
	p.SendAck()
	p.SendAck()
	for {
		s, ok := p.Next(50 * time.Millisecond)
		if !ok {
			break
		}
		note(s)
	}
	h.Check("two-dupacks.no-retransmit", len(rexmits) == 0, "no retransmission after two duplicate ACKs", fmt.Sprintf("%d retransmissions", len(rexmits)))
	p.SendAck()
	fr, ok := p.Await(h.Prompt(), func(s Segment) bool { note(s); return isData(s) && s.Seq == hole1.Seq })
	h.Check("fast-retransmit", ok, "the third duplicate ACK retransmits the first hole at once", rexmitDesc(fr, ok, hole1.Seq))
	h.Check("fast-retransmit.before-rto", ok && h.Now().Sub(sentAt) < 180*time.Millisecond, "the retransmission comes before an RTO could",
		yesNo(ok && h.Now().Sub(sentAt) < 180*time.Millisecond, "before 180 ms", "at 180 ms or later"))

	// The rest of the flight arrived after the holes: one duplicate ACK for each of those
	// segments, as a receiver sends them. They also give Linux's PRR the delivery count it needs
	// to send during recovery.
	for range len(flight) - 6 {
		p.SendAck()
	}
	for {
		s, ok := p.Next(20 * time.Millisecond)
		if !ok {
			break
		}
		note(s)
	}
	// The retransmission fills hole 1; segment 4 is still missing: a partial ACK.
	p.RcvNxt = hole2.Seq
	p.SendAck() // RFC 6582 3.2 step 3
	pr, ok := p.Await(h.Prompt(), func(s Segment) bool { note(s); return isData(s) && s.Seq == hole2.Seq })
	h.Check("partial-ack-retransmit", ok, "a partial ACK retransmits the next hole at once", rexmitDesc(pr, ok, hole2.Seq))

	// Everything sent so far has arrived; the rest of the data follows in order.
	p.RcvNxt = base + high
	p.SendAck()
	if left := len(data) - int(high); left > 0 {
		got[high] = receive(p, left, 2*time.Second)
	}
	s, quiet := p.Quiet(300 * time.Millisecond)
	h.Check("stops-after-full-ack", quiet, "no retransmission after the full ACK", segDesc(s, !quiet))
	h.Check("only-holes", len(rexmits) == 2 && rexmits[0] == hole1.Seq && rexmits[1] == hole2.Seq,
		"exactly the two holes are retransmitted, each once", fmt.Sprintf("%d retransmissions", len(rexmits)))
	var stream []byte
	for off := uint32(0); off < uint32(len(data)); {
		b, ok := got[off]
		if !ok || len(b) == 0 {
			break
		}
		stream = append(stream, b...)
		off += uint32(len(b))
	}
	h.Check("stream-intact", bytes.Equal(stream, data), "the testbench assembles exactly the bytes the application wrote",
		fmt.Sprintf("%d of %d bytes, equal %v", len(stream), len(data), bytes.Equal(stream, data)))
}

func rexmitDesc(s Segment, ok bool, want uint32) string {
	switch {
	case !ok:
		return "no retransmission in time"
	case s.Seq != want:
		return "a segment at another sequence number"
	}
	return "the hole retransmitted"
}
