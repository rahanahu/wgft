package tcpharness

import (
	"fmt"
	"time"
)

// atOnce is the segments of segs that the DUT sent together with the first, by the DUT's own
// timestamps: what one window let out, without a tail loss probe that a RACK-TLP sender may send
// a little later with new data, RFC 8985 7.3. On a ClockedDUT "together" is the same
// millisecond, since its clock does not move while it sends a window, and its probe can come
// 1 ms later at the testbench's near-zero RTT; on real time it is within 5 ms, well under the
// 10 ms Linux and gVisor wait at least before a probe.
func atOnce(h *H, segs []Segment) []Segment {
	if len(segs) == 0 || segs[0].Opts.TS == nil {
		return segs
	}
	within := int32(5)
	if _, clocked := h.DUT.(ClockedDUT); clocked {
		within = 0
	}
	t0 := segs[0].Opts.TS.Val
	var out []Segment
	for _, s := range segs {
		if s.Opts.TS == nil || int32(s.Opts.TS.Val-t0) <= within {
			out = append(out, s)
		}
	}
	return out
}

// The RFC 2525 family: the known TCP implementation problems of RFC 2525 that the other
// scenarios do not already show, for a passive-open stack that sends and receives.
// wgstack-verification.md lists each problem and the scenario that covers it. The straight-line
// members are scripts under scripts/; the two here react to what the DUT sends.

// rfc2525WindowDeflation loses one segment of a flight of ten without SACK and answers the rest
// with eight duplicate ACKs, which inflate a NewReno sender's window. 2.8, failure of window
// deflation after loss recovery: the ACK that ends recovery lets out no more than about
// ssthresh, half the flight, at once, not the inflated window.
func rfc2525WindowDeflation(h *H) {
	const port = 8304
	l := h.Listen(port)
	p, _, c := h.Connect(l, port, NoSACKSYN())
	data := pattern(30*segSize(p), 0xd4)
	if _, err := c.Write(data); err != nil {
		h.T.Fatalf("write: %v", err)
	}
	segs, _ := burst(p)
	h.Require("flight", len(segs) >= 10, "an initial flight of ten segments", fmt.Sprintf("%d segments", len(segs)))
	segs = segs[:10]
	// the first arrives, the second is lost, the other eight draw duplicate ACKs
	p.RcvNxt = segs[0].Seq + uint32(len(segs[0].Payload))
	p.SendAck()
	var during []Segment
	for range 8 {
		p.SendAck()
		during = append(during, h.Collect(h.Prompt()+20*time.Millisecond)...)
	}
	high := segs[9].Seq + uint32(len(segs[9].Payload))
	resent := false
	flight := len(segs) // segments outstanding when the resend starts recovery
	for _, s := range during {
		if s.Seq == segs[1].Seq {
			resent = true
		}
		if !resent && isData(s) && !after(high, s.Seq) {
			flight++ // new data before the resend, as Limited Transmit sends
		}
		if after(s.Seq+uint32(len(s.Payload)), high) {
			high = s.Seq + uint32(len(s.Payload))
		}
	}
	if !resent {
		s, ok := p.Await(time.Second, func(s Segment) bool { return isData(s) && s.Seq == segs[1].Seq })
		h.Require("fast-retransmit", ok, "the lost segment is resent", segDesc(s, ok))
	}
	// Collect does not track the flow's timestamps, so the ACK echoes the newest TSval itself:
	// an older one would tell a sender with Eifel's undo, RFC 3522, that the original of the
	// resend had arrived, and it would undo the window reduction this scenario checks.
	for _, s := range during {
		if s.Opts.TS != nil && int32(s.Opts.TS.Val-p.TSRecent) > 0 {
			p.TSRecent = s.Opts.TS.Val
		}
	}
	// everything sent so far has arrived: the full ACK ends recovery
	p.RcvNxt = high
	p.SendAck()
	all, _ := burst(p)
	released := atOnce(h, all)
	// ssthresh is half the flight for NewReno and 0.7 of it for CUBIC. A window still inflated by
	// the eight duplicate ACKs lets out ssthresh and about eight more: 15 for a flight of 10 at
	// 0.7, 13 at 0.5. The bound sits between, at ssthresh and three more, room for a sender that
	// rounds up and sends a segment or two beyond ssthresh as it leaves recovery, as gVisor's
	// seven of ten does.
	bound := (7*flight+9)/10 + 3
	h.Check("deflated", len(released) <= bound, fmt.Sprintf("RFC 2525 2.8: the ACK that ends recovery lets out at most ssthresh and three more: %d for a flight of %d at 0.7", bound, flight),
		fmt.Sprintf("%d segments at once", len(released)))
	h.Measure("segments-after-recovery", len(released))
	h.Measure("flight-at-loss", flight)
}

// rfc2525StretchACK sends twelve full segments in order, one at a time, and reads every ACK.
// 2.13, stretch ACK violation: RFC 5681 4.2 and RFC 1122 4.2.3.2 ask for an ACK at least for
// every second full-sized segment, so no ACK covers more than two new segments.
func rfc2525StretchACK(h *H) {
	const port = 8305
	l := h.Listen(port)
	p, _, _ := h.Connect(l, port, StandardSYN())
	size := segSize(p)
	last := p.SndNxt
	worst := 0
	for range 12 {
		p.SendData(pattern(size, 0xd5))
		for _, s := range h.Collect(h.Prompt()) {
			if s.Src != p.Remote || !s.Has(FlagACK) || !after(s.Ack, last) {
				continue
			}
			worst = max(worst, int(s.Ack-last)/size)
			last = s.Ack
		}
	}
	// whatever the delayed-ACK timer still holds comes within its bound
	for _, s := range h.Collect(500 * time.Millisecond) {
		if s.Src == p.Remote && s.Has(FlagACK) && after(s.Ack, last) {
			worst = max(worst, int(s.Ack-last)/size)
			last = s.Ack
		}
	}
	h.Check("every-second-segment", worst <= 2 && last == p.SndNxt, "RFC 2525 2.13: no ACK covers more than two full segments, and all twelve are acknowledged",
		fmt.Sprintf("the widest ACK covers %d segments; %v", worst, yesNo(last == p.SndNxt, "all acknowledged", "not all acknowledged")))
}

// burstSegments is how many full segments the burst variants of the stretch-ACK scenario inject
// before the DUT reads anything: more than the two a receiver may leave unacknowledged, and few
// enough to stay inside the receive window every engine opens.
const burstSegments = 12

// ackSpan counts the pure ACKs of the DUT that advance the cumulative ACK, and the most full
// segments one of them covered.
type ackSpan struct{ acks, widest int }

// take counts the ACKs among segs that advance last, which is updated. size is a full segment.
func (a *ackSpan) take(p *Peer, segs []Segment, last *uint32, size int) {
	for _, s := range segs {
		if s.Src != p.Remote || !isPureAck(s) || !after(s.Ack, *last) {
			continue
		}
		a.acks++
		a.widest = max(a.widest, (int(s.Ack-*last)+size-1)/size)
		*last = s.Ack
	}
}

// rfc2525StretchACKBurst is rfc2525StretchACK with the twelve segments injected back to back,
// before the DUT reads or polls, as wireguard-go writes a received batch to the Device before it
// reads (compare cubic-ack-burst). A receiver that sends one ACK per wake instead of one per two
// segments covers the whole burst with one ACK. The number of ACKs and the widest one are
// measured; the check is the one-by-one scenario's, RFC 5681 4.2 and RFC 9293 3.8.6.3, that no
// ACK covers more than two full segments.
func rfc2525StretchACKBurst(h *H) {
	const port = 8308
	l := h.Listen(port)
	p, _, _ := h.Connect(l, port, StandardSYN())
	size := segSize(p)
	last := p.SndNxt
	for range burstSegments {
		p.SendData(pattern(size, 0xd6))
	}
	var span ackSpan
	span.take(p, h.Collect(h.Prompt()), &last, size)
	immediate := span.acks
	// whatever the delayed-ACK timer still holds comes within its bound
	span.take(p, h.Collect(500*time.Millisecond), &last, size)
	h.Measure("segments", burstSegments)
	h.Measure("acks", span.acks)
	h.Measure("acks-before-delayed-timer", immediate)
	h.Measure("widest-ack-segments", span.widest)
	h.Check("every-second-segment", span.widest <= 2 && last == p.SndNxt, "RFC 5681 4.2: no ACK covers more than two full segments of a burst of twelve, and all twelve are acknowledged",
		yesNo(span.widest <= 2, "no ACK covers more than two segments", "an ACK covers more than two segments")+"; "+
			yesNo(last == p.SndNxt, "all acknowledged", "not all acknowledged"))
}

// rfc2525StretchACKBurstOOO leaves a hole at the start of the receive window and injects eight
// out-of-order segments back to back. RFC 5681 3.2 asks for an immediate duplicate ACK for each,
// so the sender can count to the third. A receiver that sends one ACK per wake answers the eight
// with one. The duplicate ACKs are counted and measured, and the check is that there is one for
// each segment. Filling the hole then has to be acknowledged in full.
func rfc2525StretchACKBurstOOO(h *H) {
	const port = 8309
	const ooo = 8
	l := h.Listen(port)
	p, _, _ := h.Connect(l, port, StandardSYN())
	size := segSize(p)
	hole := p.SndNxt
	// the first segment is lost; the ones after it arrive out of order
	p.SndNxt += uint32(size)
	for range ooo {
		p.SendData(pattern(size, 0xd7))
	}
	dups := 0
	count := func(segs []Segment) {
		for _, s := range segs {
			if s.Src == p.Remote && isPureAck(s) && s.Ack == hole {
				dups++
			}
		}
	}
	count(h.Collect(h.Prompt()))
	// a duplicate ACK that a delayed timer holds is not the immediate one RFC 5681 3.2 asks for
	immediate := dups
	count(h.Collect(500 * time.Millisecond))
	h.Measure("out-of-order-segments", ooo)
	h.Measure("dupacks", immediate)
	h.Measure("dupacks-with-delayed", dups)
	h.Check("dupack-per-segment", immediate >= ooo, "RFC 5681 3.2: an immediate duplicate ACK for each of eight out-of-order segments sent back to back",
		fmt.Sprintf("%d duplicate ACKs", immediate))
	// the segment that fills the hole is acknowledged up to the end of the burst
	end := hole + uint32(size)*(ooo+1)
	p.SndNxt = hole
	p.SendData(pattern(size, 0xd7))
	p.SndNxt = end
	last := hole
	var span ackSpan
	span.take(p, h.Collect(h.Prompt()), &last, size)
	span.take(p, h.Collect(500*time.Millisecond), &last, size)
	h.Check("hole-filled", last == end, "RFC 5681 4.2: the segment that fills the hole is acknowledged with everything the receiver holds",
		yesNo(last == end, "all acknowledged", "not all acknowledged"))
}
