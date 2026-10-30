package tcpharness

import (
	"fmt"
	"time"
)

// The RACK-TLP family, RFC 8985, as wgstack-performance.md's RACK step asks. RACK and TLP time
// losses against the RTT, so the testbench answers every segment after the path delay it
// emulates, rackRTT unless a scenario says otherwise; the DUT's SRTT and minimum RTT are then
// about that delay. The reference Linux turns RACK and TLP back on for this family: rackLinux.

const rackRTT = 50 * time.Millisecond

// reorderRTT is rack-reorder's path delay, longer than rackRTT so that the reorder window and the
// time to the probe outgrow a slow testbench's delays.
const reorderRTT = 100 * time.Millisecond

var rackLinux = [][2]string{
	{"net/ipv4/tcp_recovery", "1"},
	{"net/ipv4/tcp_early_retrans", "3"},
}

// rackConnect opens a connection whose handshake RTT is about rtt, the path delay the scenario
// emulates.
func rackConnect(h *H, l Listener, port uint16, rtt time.Duration) (*Peer, Conn) {
	h.T.Helper()
	// 5 ms short of rtt: the handshake sets the minimum RTT, and RACK ignores the ACK of a
	// retransmission that comes back faster than the minimum RTT, which a later sample a little
	// under rtt would otherwise be.
	p, _, c := h.ConnectWith(l, port, Dial{SYN: StandardSYN(), AckDelay: rtt - 5*time.Millisecond})
	h.Require("sack", p.SACK, "SACK negotiated", yesNo(p.SACK, "SACK", "no SACK"))
	return p, c
}

// answerAfter returns a segment handler that has r take every data segment, after delay and
// unless lost says to drop it, and sends the ACK r builds at that moment rtt later, echoing the
// segment's own TSval as a receiver does.
func answerAfter(lp *loop, p *Peer, r *receiver, w *rexmitWatch, rtt time.Duration, lost func(Segment) bool, delay func(Segment) time.Duration) func(Segment) {
	return func(s Segment) {
		if w != nil {
			w.note(s)
		}
		if !isData(s) || lost != nil && lost(s) {
			return
		}
		ecr := uint32(0)
		if s.Opts.TS != nil {
			ecr = s.Opts.TS.Val
		}
		d := time.Duration(0)
		if delay != nil {
			d = delay(s)
		}
		lp.after(d, func() {
			// the ACK says what the receiver holds when the segment arrives, and travels back
			// over the path delay
			r.take(s)
			a := r.ack(ecr)
			lp.after(rtt, func() { p.Send(a) })
		})
	}
}

// rackReorder sends a three-segment flight whose second segment is late. Within the reorder
// window, a quarter of the minimum RTT, the late segment fills the hole and nothing is resent;
// lost outright, it is resent after the reorder window, well before the TLP probe and the RTO,
// on one duplicate ACK only, where RFC 6675's threshold of three would wait for the RTO. The path
// is reorderRTT long, so the reorder window, about 24 ms, leaves the late segment's 5 ms room for
// a slow testbench, and the one RTT the resend is given lies well between the reorder window and
// the probe, about 2 RTT after the duplicate ACK.
func rackReorder(h *H) {
	const port = 8040
	const rtt = reorderRTT
	l := h.Listen(port)

	p, c := rackConnect(h, l, port, rtt)
	segs, data := flight(h, p, c, 3, 0xb1)
	r := newReceiver(p)
	lp := &loop{h: h}
	feed := answerAfter(lp, p, r, nil, rtt, nil, func(s Segment) time.Duration {
		if s.Seq == segs[1].Seq {
			return 5 * time.Millisecond // arrives 5 ms after the third segment
		}
		return 0
	})
	for _, s := range segs {
		feed(s)
	}
	w := newWatch(segs)
	end := dataEnd(r, data)
	lp.run(p, 4*rtt, answerAfter(lp, p, r, w, rtt, nil, nil), func() bool { return false })
	h.Check("within-window.no-retransmit", !w.has(segs[1].Seq), "a segment 5 ms late, within the reorder window, is not resent",
		yesNo(w.has(segs[1].Seq), "resent", "not resent"))
	h.Check("within-window.completes", !after(end, r.cum), "the flight completes", yesNo(!after(end, r.cum), "complete", "incomplete"))

	p, c = rackConnect(h, l, port, rtt)
	segs, data = flight(h, p, c, 3, 0xb2)
	r = newReceiver(p)
	lp = &loop{h: h}
	lost := segs[1].Seq
	feed = answerAfter(lp, p, r, nil, rtt, func(s Segment) bool { return s.Seq == lost }, nil)
	for _, s := range segs {
		feed(s)
	}
	var dupackAt, resentAt time.Time
	lp.after(rtt, func() { dupackAt = h.Now() }) // the ACK of the third segment, a duplicate
	w = newWatch(segs)
	on := answerAfter(lp, p, r, w, rtt, nil, nil)
	end = dataEnd(r, data)
	lp.run(p, 2*time.Second, func(s Segment) {
		if isData(s) && s.Seq == lost && resentAt.IsZero() {
			resentAt = h.Now()
		}
		on(s)
	}, func() bool { return !after(end, r.cum) })
	gap := resentAt.Sub(dupackAt)
	ok := !resentAt.IsZero() && !dupackAt.IsZero() && gap < rtt
	if !resentAt.IsZero() {
		h.Measure("beyond-window.resent-after-dupack_ms", gap.Milliseconds())
	}
	h.Check("beyond-window.resent-early", ok, "a lost segment is resent within one RTT of a single duplicate ACK, after the reorder window and before TLP or RTO",
		yesNo(resentAt.IsZero(), "not resent", yesNo(ok, "within one RTT", "one RTT or later")))
	h.Check("beyond-window.completes", !after(end, r.cum), "the flight completes", yesNo(!after(end, r.cum), "complete", "incomplete"))
}

// tlpTailLoss loses the last two segments of a flight. Nothing after them can show the loss, so
// RFC 8985's tail loss probe resends the last segment about 2 SRTT after the ACK of the rest,
// before the RTO, and the probe's SACK reveals the other loss.
func tlpTailLoss(h *H) {
	const port = 8041
	l := h.Listen(port)
	p, c := rackConnect(h, l, port, rackRTT)
	segs, data := flight(h, p, c, 8, 0xb3)
	r := newReceiver(p)
	lp := &loop{h: h}
	n := len(segs)
	feed := answerAfter(lp, p, r, nil, rackRTT, func(s Segment) bool { return s.Seq == segs[n-2].Seq || s.Seq == segs[n-1].Seq }, nil)
	for _, s := range segs {
		feed(s)
	}
	var ackAt, probeAt time.Time
	lp.after(rackRTT, func() { ackAt = h.Now() }) // the last ACK, of all but the two tail segments
	w := newWatch(segs)
	on := answerAfter(lp, p, r, w, rackRTT, nil, nil)
	end := dataEnd(r, data)
	lp.run(p, 3*time.Second, func(s Segment) {
		if isData(s) && probeAt.IsZero() {
			probeAt = h.Now()
		}
		on(s)
	}, func() bool { return !after(end, r.cum) })
	pto := probeAt.Sub(ackAt)
	if !probeAt.IsZero() {
		h.Measure("probe-after-ack_ms", pto.Milliseconds())
	}
	// A loaded machine can stop the testbench while it holds an ACK back, so that the handshake's
	// ACK or the flight's leave late. The DUT then measures a longer RTT than rackRTT, and its
	// probe and its recovery come later by twice and three times the excess. The upper bounds
	// follow the RTT the testbench actually gave; the lower bound does not, since a late ACK
	// cannot make the probe early. On a ClockedDUT the excess is zero.
	excess := max(lp.late, p.AckHeld-(rackRTT-5*time.Millisecond), 0)
	h.Measure("path-delay-excess_ms", excess.Milliseconds())
	// The probe comes about 2 SRTT after the ACK; an RTO would come no earlier than its 200 ms
	// floor, so 170 ms leaves the RTO out with a margin.
	probeBound := 170*time.Millisecond + 2*excess
	ok := !probeAt.IsZero() && pto >= rackRTT*3/2 && pto <= probeBound
	h.Check("probe-at-2srtt", ok, "the first segment after the ACK of the rest is a probe about 2 SRTT later, from 1.5 RTT to 170 ms and twice the testbench's excess delay",
		yesNo(probeAt.IsZero(), "nothing sent", yesNo(ok, "from 1.5 RTT to the bound", "outside 1.5 RTT to the bound")))
	done := !after(end, r.cum)
	took := h.Now().Sub(ackAt)
	h.Measure("recovered-after-ack_ms", took.Milliseconds())
	// Through the probe, recovery ends near 2 SRTT plus one RTT after the ACK; through an RTO, no
	// earlier than the 200 ms floor plus one RTT, 250 ms.
	fast, rto := 225*time.Millisecond+3*excess, 250*time.Millisecond+excess
	got := "within the probe's bound"
	switch {
	case !done:
		got = "not recovered"
	case took < fast:
	case took >= rto:
		got = "recovered at the RTO floor plus one RTT or later"
	default:
		got = "recovered between the probe's bound and the RTO floor plus one RTT"
	}
	h.Check("recovers-before-rto", done && took < fast, "both tail segments are acknowledged within 225 ms of the ACK and three times the testbench's excess delay, sooner than an RTO of at least 200 ms and one RTT could", got)
	intact(h, r, data)
}

// thinStream writes four 200-byte messages 20 ms apart, as a game or an SSH session does, and loses
// the third. Only the fourth follows it, so there is one duplicate ACK: RACK resends the third
// after the reorder window, or TLP probes the tail; either way it recovers before an RTO.
func thinStream(h *H) {
	const port = 8042
	const msgs, size = 4, 200
	l := h.Listen(port)
	p, c := rackConnect(h, l, port, rackRTT)
	r := newReceiver(p)
	lp := &loop{h: h}
	on := answerAfter(lp, p, r, nil, rackRTT, nil, nil)
	highest := p.RcvNxt
	news := 0
	var lostSeq uint32
	var lostAt, resentAt time.Time
	handle := func(s Segment) {
		if isData(s) {
			switch {
			case !after(highest, s.Seq): // new data
				highest = s.Seq + uint32(len(s.Payload))
				news++
				if news == 3 {
					lostSeq, lostAt = s.Seq, h.Now()
					return // lost on the path
				}
			case news >= 3 && s.Seq == lostSeq && resentAt.IsZero():
				resentAt = h.Now()
			}
		}
		on(s)
	}
	for i := range msgs {
		lp.after(time.Duration(i)*20*time.Millisecond, func() { c.Write(pattern(size, byte(0xc0+i))) })
	}
	end := p.RcvNxt + msgs*size
	lp.run(p, 3*time.Second, handle, func() bool { return !after(end, r.cum) })
	took := resentAt.Sub(lostAt)
	ok := !resentAt.IsZero() && !lostAt.IsZero() && took < 200*time.Millisecond
	if ok || !resentAt.IsZero() {
		h.Measure("resent-after-send_ms", took.Milliseconds())
	}
	h.Check("recovers-before-rto", ok, "the lost message is resent within 200 ms of its first send, before an RTO",
		yesNo(resentAt.IsZero(), "not resent", yesNo(ok, "within 200 ms", "200 ms or later")))
	h.Check("completes", !after(end, r.cum), "all four messages are acknowledged", fmt.Sprintf("%d of %d bytes", int(r.cum-(end-msgs*size)), msgs*size))
}
