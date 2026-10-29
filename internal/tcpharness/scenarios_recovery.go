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
