package tcpharness

import (
	"fmt"
	"time"
)

func isFIN(s Segment) bool { return s.Has(FlagFIN) }
func isRST(s Segment) bool { return s.Has(FlagRST) }

// acks returns a matcher for an ACK that covers everything up to seq.
func acks(seq uint32) func(Segment) bool {
	return func(s Segment) bool { return s.Has(FlagACK) && !s.Has(FlagRST) && s.Ack == seq }
}

// delivered checks Deliverer where the engine offers it: after the close, the connection reports
// within 1 s that it has delivered everything.
func delivered(h *H, id string, c Conn) {
	h.T.Helper()
	d, ok := c.(Deliverer)
	if !ok {
		return
	}
	deadline := time.Now().Add(time.Second)
	for !d.Delivered() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	h.Check(id, d.Delivered(), "Delivered reports the closed connection as delivered", yesNo(d.Delivered(), "delivered", "not delivered"))
}

// finPassiveClose closes from the testbench's side first: the DUT acknowledges the FIN, the
// application reads the data and then EOF, may still send in CLOSE-WAIT, and its Close sends a FIN
// after that data.
func finPassiveClose(h *H) {
	const port = 8011
	l := h.Listen(port)
	p, _, c := h.Connect(l, port, StandardSYN())
	p.SendFIN([]byte("bye"))
	// RFC 9293 does not ask for an immediate ACK here, and Linux delays it by its delayed-ACK
	// timer, about 40 ms; RFC 1122 4.2.3.2 bounds a delayed ACK at 500 ms.
	a, ok := p.Await(500*time.Millisecond, acks(p.SndNxt))
	h.Check("fin.acked", ok, "the DUT acknowledges the data and the FIN within the 500 ms delayed-ACK bound", segDesc(a, ok))
	got, err := readFull(c, 3, time.Second)
	h.Check("data-before-fin", err == nil && string(got) == "bye", "the application reads the data that came with the FIN", fmt.Sprintf("%q, error %s", got, errKind(err)))
	_, err = readFull(c, 1, time.Second)
	h.Check("eof", errKind(err) == "EOF", "the next read returns EOF", "error "+errKind(err))

	_, werr := c.Write([]byte("after"))
	s, ok := p.Await(time.Second, isData)
	h.Check("close-wait.sends", werr == nil && ok && s.Seq == p.RcvNxt && string(s.Payload) == "after", "the application can still send in CLOSE-WAIT",
		fmt.Sprintf("write error %s; %s", errKind(werr), segDesc(s, ok)))
	if ok {
		p.RcvNxt = s.Seq + uint32(len(s.Payload))
		p.SendAck()
	}
	c.Close()
	f, ok := p.Await(time.Second, isFIN)
	fAt := h.Now()
	h.Check("last-ack.fin", ok && f.Seq == p.RcvNxt, "Close sends a FIN after the data", segDesc(f, ok))
	var ackTS uint32
	if ok {
		p.RcvNxt = f.Seq + f.Len()
		ackTS = p.SendFreshAck()
	}
	// A FIN resent before the ACK got there, as a tail loss probe on a loaded machine, is passed
	// over; anything sent once the DUT had the ACK fails the check.
	s, quiet, stale := p.QuietSince(500*time.Millisecond, ackTS, f, fAt, c)
	h.Check("closed.quiet", quiet, "nothing follows the ACK of the DUT's FIN", segDesc(s, !quiet))
	h.Measure("resent-before-the-ack", stale)
	delivered(h, "delivered", c)
}

// halfClose is the relay's pattern: CloseWrite sends a FIN, the application keeps reading what
// the testbench still sends, and the testbench's FIN moves the DUT to TIME-WAIT, where a
// retransmitted FIN is acknowledged again.
func halfClose(h *H) {
	const port = 8012
	l := h.Listen(port)
	p, _, c := h.Connect(l, port, StandardSYN())
	if err := c.CloseWrite(); err != nil {
		h.T.Fatalf("CloseWrite: %v", err)
	}
	f, ok := p.Await(time.Second, isFIN)
	h.Require("fin-wait-1.fin", ok && f.Seq == p.RcvNxt, "CloseWrite sends a FIN at once", segDesc(f, ok))
	sentAt := h.Now()
	f2, ok := p.Await(3*time.Second, func(s Segment) bool { return isFIN(s) && s.Seq == f.Seq })
	h.Check("fin-retransmitted", ok, "an unacknowledged FIN is retransmitted", segDesc(f2, ok))
	if ok {
		h.Measure("fin-retransmit_ms", h.Now().Sub(sentAt).Milliseconds())
	}
	p.RcvNxt = f.Seq + 1
	p.SendAck()

	p.SendData([]byte("more"))
	got, err := readFull(c, 4, time.Second)
	h.Check("fin-wait-2.receives", err == nil && string(got) == "more", "the application reads data after its own FIN", fmt.Sprintf("%q, error %s", got, errKind(err)))
	a, ok := p.Await(time.Second, acks(p.SndNxt))
	h.Check("fin-wait-2.acks-data", ok, "the DUT acknowledges data in FIN-WAIT-2", segDesc(a, ok))

	p.SendFIN(nil)
	a, ok = p.Await(time.Second, acks(p.SndNxt))
	h.Check("time-wait.acks-fin", ok, "the DUT acknowledges the testbench's FIN", segDesc(a, ok))
	_, err = readFull(c, 1, time.Second)
	h.Check("eof", errKind(err) == "EOF", "the application's read returns EOF", "error "+errKind(err))

	p.Send(p.Segment(FlagFIN|FlagACK, p.SndNxt-1, nil)) // the testbench's FIN once more
	a, ok = p.Await(h.Prompt(), acks(p.SndNxt))
	h.Check("time-wait.reacks-fin", ok, "a retransmitted FIN in TIME-WAIT is acknowledged again at once", segDesc(a, ok))

	c.Close()
	s, quiet := p.Quiet(300 * time.Millisecond)
	h.Check("closed.quiet", quiet, "Close in TIME-WAIT sends nothing", segDesc(s, !quiet))
	delivered(h, "delivered", c)
}

// closeUnreadRST closes a connection whose received data the application never read. RFC 9293
// 3.6 and Linux end it with a RST, not a FIN, so the peer learns the data was lost.
func closeUnreadRST(h *H) {
	const port = 8013
	l := h.Listen(port)
	p, _, c := h.Connect(l, port, StandardSYN())
	p.SendData(pattern(100, 0x81))
	a, ok := p.Await(time.Second, acks(p.SndNxt))
	h.Require("data.acked", ok, "the DUT acknowledges the data", segDesc(a, ok))
	c.Close()
	r, ok := p.Await(time.Second, func(s Segment) bool { return isRST(s) || isFIN(s) })
	h.Check("rst-not-fin", ok && isRST(r) && !isFIN(r), "Close with unread data sends a RST and no FIN", segDesc(r, ok))
	h.Check("rst.seq", ok && isRST(r) && r.Seq == p.RcvNxt, "the RST carries SND.NXT", yesNo(ok && r.Seq == p.RcvNxt, "SND.NXT", "another number"))
	p.SendData([]byte("x"))
	r, ok = p.Await(time.Second, isRST)
	h.Check("after.rst", ok, "data for the reset connection draws a RST", segDesc(r, ok))
}

// closeToTimeWait has the application close first and the testbench answer with its FIN, so the
// DUT holds the four-tuple in TIME-WAIT.
func closeToTimeWait(h *H, l Listener, port uint16) *Peer {
	h.T.Helper()
	p, _, c := h.Connect(l, port, StandardSYN())
	c.Close()
	f, ok := p.Await(time.Second, isFIN)
	h.Require("close.fin", ok && f.Seq == p.RcvNxt, "Close sends a FIN", segDesc(f, ok))
	// The FIN is acknowledged first and the testbench's own FIN follows, through FIN-WAIT-2; the
	// combined FIN|ACK is the active-close-fin-ack scenario's.
	p.RcvNxt = f.Seq + 1
	p.SendAck()
	p.SendFIN(nil)
	a, ok := p.Await(time.Second, acks(p.SndNxt))
	h.Require("time-wait.entered", ok, "the DUT acknowledges the testbench's FIN and enters TIME-WAIT", segDesc(a, ok))
	return p
}

// activeCloseFINACK closes from the application first and answers with one segment that both
// acknowledges the DUT's FIN and carries the testbench's FIN, as a peer whose application closes
// at once does. RFC 9293 3.10.7.4 FIN-WAIT-1: the DUT enters TIME-WAIT and acknowledges the FIN;
// the ACK may be delayed, so it is bounded by RFC 1122's 500 ms.
func activeCloseFINACK(h *H) {
	const port = 8016
	l := h.Listen(port)
	p, _, c := h.Connect(l, port, StandardSYN())
	c.Close()
	f, ok := p.Await(time.Second, isFIN)
	h.Require("fin", ok && f.Seq == p.RcvNxt, "Close sends a FIN", segDesc(f, ok))
	p.RcvNxt = f.Seq + 1
	p.SendFIN(nil)
	a, ok := p.Await(500*time.Millisecond, acks(p.SndNxt))
	h.Check("fin-ack.acked", ok, "a FIN that also acknowledges the DUT's FIN is acknowledged within 500 ms", segDesc(a, ok))
	p.Send(p.Segment(FlagFIN|FlagACK, p.SndNxt-1, nil))
	a, ok = p.Await(h.Prompt(), acks(p.SndNxt))
	h.Check("time-wait.reacks-fin", ok, "a retransmitted FIN in TIME-WAIT is acknowledged again at once", segDesc(a, ok))
	delivered(h, "delivered", c)
}

// timeWaitReuse sends new SYNs to a four-tuple in TIME-WAIT at the DUT. RFC 6191 accepts one
// whose timestamp is newer than the old connection's, or, without timestamps, whose sequence
// number is beyond it; a SYN that is older on both counts is not accepted.
func timeWaitReuse(h *H) {
	const port = 8014
	l := h.Listen(port)

	old := closeToTimeWait(h, l, port)
	n := old.Reincarnate(old.SndNxt + 100000)
	syn := StandardSYN()
	syn.TS = &Timestamps{Val: n.TSVal()}
	n.WS = syn.WS
	n.Send(Segment{Src: n.Local, Dst: n.Remote, Seq: n.ISS, Flags: FlagSYN, Window: 65535, Opts: syn})
	sa, ok := n.Await(time.Second, func(s Segment) bool { return s.Has(FlagSYN | FlagACK) })
	ok = ok && sa.Ack == n.ISS+1
	h.Check("newer.synack", ok, "a SYN with a newer timestamp and a larger ISN opens a new connection", synackString(n, sa, ok))
	if ok {
		n.adopt(syn, sa)
		n.SendAck()
		alive(h, "newer", n, h.Accept(l))
	}

	// RFC 6191 2 takes a newer timestamp as enough, even with an ISN below the old connection's
	// RCV.NXT, where RFC 1122's sequence rule alone would refuse the SYN.
	old = closeToTimeWait(h, l, port)
	m := old.Reincarnate(old.SndNxt - 100000)
	syn = StandardSYN()
	syn.TS = &Timestamps{Val: m.TSVal()}
	m.WS = syn.WS
	m.Send(Segment{Src: m.Local, Dst: m.Remote, Seq: m.ISS, Flags: FlagSYN, Window: 65535, Opts: syn})
	sa, ok = m.Next(time.Second)
	ok = ok && sa.Has(FlagSYN|FlagACK) && sa.Ack == m.ISS+1
	h.Check("newer-ts-smaller-isn.synack", ok, "a SYN with a newer timestamp and a smaller ISN opens a new connection", synackString(m, sa, ok))
	h.Measure("newer-ts-smaller-isn.reply", segDesc(sa, sa.Src.IsValid()))
	if ok {
		m.adopt(syn, sa)
		m.SendAck()
		alive(h, "newer-ts-smaller-isn", m, h.Accept(l))
	}

	old = closeToTimeWait(h, l, port)
	o := old.Reincarnate(old.SndNxt - 100000)
	o.tsBase = old.TSVal() - 100000
	syn = StandardSYN()
	syn.TS = &Timestamps{Val: o.TSVal()}
	o.Send(Segment{Src: o.Local, Dst: o.Remote, Seq: o.ISS, Flags: FlagSYN, Window: 65535, Opts: syn})
	s, ok := o.Next(time.Second)
	h.Check("older.no-synack", !(ok && s.Has(FlagSYN|FlagACK)), "a SYN older in timestamp and sequence does not open a connection", segDesc(s, ok))
	h.Measure("older.reply", segDesc(s, ok))
}

// listenerClose closes a listener that holds an established connection nobody accepted and a
// handshake that has not finished. wgstack.md resets both at the close. The port then refuses
// SYNs with a RST and can be listened on again at once.
func listenerClose(h *H) {
	const port = 8015
	l, err := h.DUT.Listen(port)
	if err != nil {
		h.T.Fatalf("listen: %v", err)
	}
	queued, _ := h.Handshake(port, Dial{SYN: StandardSYN()})
	queued.SendData([]byte("q"))
	a, ok := queued.Await(time.Second, acks(queued.SndNxt))
	h.Require("queued.established", ok, "the unaccepted connection acknowledges data", segDesc(a, ok))

	half := h.NewPeer(port)
	syn := StandardSYN()
	syn.TS = &Timestamps{Val: half.TSVal()}
	half.Send(Segment{Src: half.Local, Dst: half.Remote, Seq: half.ISS, Flags: FlagSYN, Window: 65535, Opts: syn})
	sa, ok := half.Await(time.Second, func(s Segment) bool { return s.Has(FlagSYN | FlagACK) })
	h.Require("half-open.synack", ok, "the second SYN is answered", segDesc(sa, ok))
	half.WS = syn.WS
	half.adopt(syn, sa)

	// Both flows are watched together: Peer.Next would drop the other flow's segments.
	l.Close()
	var qr, hr *Segment
	for _, s := range h.Collect(500 * time.Millisecond) {
		switch {
		case s.Dst == queued.Local && isRST(s) && qr == nil:
			qr = &s
		case s.Dst == half.Local && isRST(s) && hr == nil:
			hr = &s
		}
	}
	h.Check("queued.rst", qr != nil && qr.Seq == queued.RcvNxt, "the unaccepted connection is reset at SND.NXT at the close",
		yesNo(qr == nil, "no RST at the close", yesNo(qr != nil && qr.Seq == queued.RcvNxt, "RST at SND.NXT", "RST at another number")))
	// wgstack.md: the listener's Close resets its half-open rows at once.
	h.Check("half-open.rst-at-close", hr != nil, "the half-open connection is reset at the close", yesNo(hr != nil, "RST at the close", "no RST at the close"))
	if hr == nil {
		// Whatever the engine did with the row, the closed port answers the final ACK.
		half.SendAck()
		r, ok := half.Await(time.Second, isRST)
		h.Measure("half-open.final-ack-reply", segDesc(r, ok))
	}

	closed := h.NewPeer(port)
	closed.Send(Segment{Src: closed.Local, Dst: closed.Remote, Seq: closed.ISS, Flags: FlagSYN, Window: 65535, Opts: StandardSYN()})
	r, ok := closed.Next(time.Second)
	h.Check("closed-port.rst", ok && r.Has(FlagRST|FlagACK) && r.Ack == closed.ISS+1, "a SYN to the closed port draws RST|ACK", segDesc(r, ok))

	l2, err := h.DUT.Listen(port)
	h.Require("relisten", err == nil, "the port can be listened on again at once", "error "+errString(err))
	h.T.Cleanup(func() { l2.Close() })
	p, _, c := h.Connect(l2, port, StandardSYN())
	alive(h, "relisten", p, c)
}
