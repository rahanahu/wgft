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
// wgstack-verification.md lists each problem and the scenario that covers it.

// rfc2525InitialWindow writes far more than an initial window and counts what leaves before any
// ACK. 2.1, no initial slow start: the burst stays within RFC 6928's ten segments, the initial
// window Linux and wgstack use. 2.3, uninitialized CWND: with an MSS of 536 the window counts in
// 536-byte segments, not in the MSS the stack would have used before it knew the peer's.
func rfc2525InitialWindow(h *H) {
	const port = 8301
	l := h.Listen(port)
	for _, mss := range []uint16{MTU - 40, 536} {
		syn := StandardSYN()
		syn.MSS = &mss
		p, _, c := h.Connect(l, port, syn)
		if _, err := c.Write(pattern(30*int(mss), 0xd1)); err != nil {
			h.T.Fatalf("write: %v", err)
		}
		id := fmt.Sprintf("mss%d", mss)
		all, _ := burst(p)
		segs := atOnce(h, all)
		sent := 0
		for _, s := range segs {
			sent += len(s.Payload)
		}
		later := len(all) - len(segs)
		h.Measure(fmt.Sprintf("mss%d-later-new-segments", mss), later)
		// one later segment is a tail loss probe of new data; more would be a second window
		h.Check(id+".one-probe-at-most", later <= 1 && len(all) <= 11, "after the first window, at most one more new segment comes before any ACK: a tail loss probe",
			fmt.Sprintf("%d later segments, %d in all", later, len(all)))
		largest := 0
		for _, s := range segs {
			largest = max(largest, len(s.Payload))
		}
		h.Check(id+".at-most-iw10", len(segs) <= 10 && sent <= 10*int(mss), fmt.Sprintf("RFC 2525 2.1 and 2.3: the first burst is at most ten segments of at most %d bytes", mss),
			fmt.Sprintf("%d segments, %d bytes, the largest %d", len(segs), sent, largest))
		h.Check(id+".segment-size", largest <= int(mss), "no segment carries more than the peer's MSS", fmt.Sprintf("the largest %d bytes", largest))
		h.Measure(id+"-initial-segments", len(segs))
		c.Abort()
	}
}

// rfc2525RTOSlowStart loses a whole flight. 2.2, no slow start after a retransmission timeout,
// and 2.14, a retransmission of several packets: the RTO resends one segment and nothing more
// until it is acknowledged, and the acknowledgment lets out at most two, as a window of one
// segment growing in slow start does.
func rfc2525RTOSlowStart(h *H) {
	const port = 8302
	l := h.Listen(port)
	p, _, c := h.Connect(l, port, NoSACKSYN())
	segs, _ := flight(h, p, c, 6, 0xd2)
	rto, ok := p.Await(2*time.Second, isData)
	h.Require("rto", ok && rto.Seq == segs[0].Seq, "the RTO resends the first segment", segDesc(rto, ok))
	more, _ := burst(p)
	extra := 0
	for _, s := range more {
		if s.Seq != rto.Seq {
			extra++
		}
	}
	h.Check("one-segment", extra == 0, "RFC 2525 2.2 and 2.14: the RTO sends one segment and waits for its ACK", fmt.Sprintf("%d more segments", extra))
	p.RcvNxt = rto.Seq + uint32(len(rto.Payload))
	p.SendAck()
	next, _ := burst(p)
	h.Check("slow-start", len(next) >= 1 && len(next) <= 2, "the ACK of the resend lets out one or two segments, a window of one in slow start",
		fmt.Sprintf("%d segments", len(next)))
}

// rfc2525SynAckRTO leaves a SYN-ACK unanswered. 2.7, an initial RTO too low: RFC 6298 2.1 sets
// the RTO to 1 s until an RTT is measured, which Linux and wgstack use, so the SYN-ACK is resent
// no sooner than about 1 s.
func rfc2525SynAckRTO(h *H) {
	const port = 8303
	h.Listen(port)
	p := h.NewPeer(port)
	syn := StandardSYN()
	syn.TS = &Timestamps{Val: p.TSVal()}
	p.Send(Segment{Src: p.Local, Dst: p.Remote, Seq: p.ISS, Flags: FlagSYN, Window: 65535, Opts: syn})
	first, ok := p.Await(2*time.Second, func(s Segment) bool { return s.Has(FlagSYN | FlagACK) })
	h.Require("synack", ok, "a SYN-ACK", segDesc(first, ok))
	at := h.Now()
	_, ok = p.Await(5*time.Second, func(s Segment) bool { return s.Has(FlagSYN | FlagACK) })
	gap := h.Now().Sub(at)
	if ok {
		h.Measure("synack-resent-after_ms", gap.Milliseconds())
	}
	h.Check("initial-rto", ok && gap >= 900*time.Millisecond, "RFC 2525 2.7: an unanswered SYN-ACK is resent after the initial RTO of 1 s, not sooner",
		yesNo(!ok, "not resent within 5 s", yesNo(gap >= 900*time.Millisecond, "after 1 s or more", "before 900 ms")))
}

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

// rfc2525CloseFIN writes three segments, holds their ACK back and closes. 2.15, failure to send
// FIN notification promptly: the FIN goes at once after the data, within the window, not after
// the data is acknowledged.
func rfc2525CloseFIN(h *H) {
	const port = 8306
	l := h.Listen(port)
	p, _, c := h.Connect(l, port, StandardSYN())
	segs, data := flight(h, p, c, 3, 0xd6)
	end := segs[0].Seq + uint32(len(data))
	c.Close()
	f, ok := p.Await(h.Prompt(), isFIN)
	h.Check("fin-prompt", ok && f.Seq+uint32(len(f.Payload)) == end || ok && f.Seq == end, "RFC 2525 2.15: Close sends the FIN at once after the unacknowledged data", segDesc(f, ok))
}

// rfc2525DataAfterClose closes the application's side fully, lets the testbench acknowledge the
// FIN without closing its own, then sends data. 2.16, failure to send a RST after a half-duplex
// close: no application can read the data any more, so the DUT resets the connection.
func rfc2525DataAfterClose(h *H) {
	const port = 8307
	l := h.Listen(port)
	p, _, c := h.Connect(l, port, StandardSYN())
	c.Close()
	f, ok := p.Await(time.Second, isFIN)
	h.Require("fin", ok, "Close sends a FIN", segDesc(f, ok))
	p.RcvNxt = f.Seq + f.Len()
	p.SendAck()
	p.SendData([]byte("late"))
	// Await looks only at this connection's four-tuple, the FIN_WAIT_2 one
	r, ok := p.Await(time.Second, isRST)
	h.Check("rst", ok, "RFC 2525 2.16: data for a closed application draws a RST", segDesc(r, ok))
	if ok {
		h.Check("rst.seq", r.Seq == p.RcvNxt, "the RST carries SND.NXT, past the FIN, as RFC 9293 3.10.7.4 asks for a segment that acknowledges it",
			yesNo(r.Seq == p.RcvNxt, "SND.NXT", "another number"))
	}
}
