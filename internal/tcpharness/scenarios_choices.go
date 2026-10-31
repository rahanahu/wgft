package tcpharness

import (
	"fmt"
	"time"
)

// The scenarios in this file aim at the choices wgstack.md lists under "Linux との一致を確かめていない
// 選択": they check what every engine must do, and measure the choice itself, so a run shows which
// way Linux goes.

// earlyACK measures the ACK of the first data segment: Linux acknowledges it at once in quickack
// mode, wgstack by the delayed-ACK rule, a difference the design accepts. It also measures the
// window after the handshake and the IPv4 IDs.
func earlyACK(h *H) {
	const port = 8017
	l := h.Listen(port)
	p, sa, c := h.Connect(l, port, StandardSYN())
	h.Measure("synack.ip-id", sa.ID)
	start := h.Now()
	p.SendData(pattern(100, 0x91))
	a, ok := p.Await(500*time.Millisecond, acks(p.SndNxt))
	h.Check("first-data.acked", ok, "the first data segment is acknowledged within the 500 ms delayed-ACK bound", segDesc(a, ok))
	if ok {
		h.Measure("first-data.ack_ms", h.Now().Sub(start).Milliseconds())
		h.Measure("first-data.ack-ip-id", a.ID)
		h.Measure("first-data.window", p.DutWindow)
	}
	got, err := readFull(c, 100, time.Second)
	h.Check("first-data.delivered", err == nil && len(got) == 100, "the application reads the data", fmt.Sprintf("%d bytes, error %s", len(got), errKind(err)))
}

// ackUnsent sends data whose ACK acknowledges bytes the DUT never sent. RFC 9293 3.10.7.4 drops
// the segment and sends an ACK; RFC 5961 5.2 keeps the ACK. wgstack sends it within its rate
// limit; the design reads Linux as dropping silently.
func ackUnsent(h *H) {
	const port = 8018
	l := h.Listen(port)
	p, _, c := h.Connect(l, port, StandardSYN())
	bad := p.Segment(FlagACK|FlagPSH, p.SndNxt, []byte("BAD!"))
	bad.Ack = p.RcvNxt + 1000
	p.Send(bad)
	r, ok := p.Next(500 * time.Millisecond)
	h.Measure("reply", segDesc(r, ok))
	h.Check("ack-reply", ok && isPureAck(r) && r.Ack == p.SndNxt, "an ACK that does not cover the dropped segment answers it, RFC 9293 3.10.7.4", ackDesc(r, ok && isPureAck(r), p.SndNxt))
	got, err := readFull(c, 4, 300*time.Millisecond)
	dropped := len(got) == 0 && errKind(err) == "timeout"
	h.Check("not-delivered", dropped, "the segment's bytes are not delivered", fmt.Sprintf("%d bytes, error %s", len(got), errKind(err)))
	if !dropped {
		h.T.Logf("the bytes were delivered, so the testbench's next bytes would overlap them; after.* not reached")
		return
	}
	alive(h, "after", p, c)
}

// synRcvdSYN sends more SYNs to a handshake in SYN-RECEIVED. The same SYN again draws the
// SYN-ACK again. A SYN with another ISN inside the window is reset and the row dropped, the
// choice wgstack.md made from Linux's tcp_check_req; one outside the window draws an ACK and the
// handshake can still finish.
func synRcvdSYN(h *H) {
	const port = 8019
	l := h.Listen(port)
	syn := StandardSYN()

	p := h.NewPeer(port)
	syn.TS = &Timestamps{Val: p.TSVal()}
	first := Segment{Src: p.Local, Dst: p.Remote, Seq: p.ISS, Flags: FlagSYN, Window: 65535, Opts: syn}
	p.Send(first)
	sa, ok := p.Await(time.Second, func(s Segment) bool { return s.Has(FlagSYN | FlagACK) })
	h.Require("synack", ok && sa.Ack == p.ISS+1, "the SYN is answered", synackString(p, sa, ok))
	// 300 ms: well before a SYN-ACK retransmission timer of 1 s could answer instead
	p.Send(first)
	r, ok := p.Next(300 * time.Millisecond)
	h.Measure("same-syn.reply", segDesc(r, ok))
	ok = ok && r.Has(FlagSYN|FlagACK)
	h.Check("same-syn.synack-again", ok && r.Seq == sa.Seq, "the same SYN again draws the same SYN-ACK", synackString(p, r, ok))
	other := first
	other.Seq = p.ISS + 1000
	p.Send(other)
	r, ok = p.Next(300 * time.Millisecond)
	h.Measure("other-syn-in-window.reply", segDesc(r, ok))
	h.Check("other-syn-in-window.rst", ok && isRST(r), "a SYN with another ISN inside the window is reset", segDesc(r, ok))

	q := h.NewPeer(port)
	syn.TS = &Timestamps{Val: q.TSVal()}
	q.WS = syn.WS
	q.Send(Segment{Src: q.Local, Dst: q.Remote, Seq: q.ISS, Flags: FlagSYN, Window: 65535, Opts: syn})
	sa, ok = q.Await(time.Second, func(s Segment) bool { return s.Has(FlagSYN | FlagACK) })
	h.Require("second.synack", ok && sa.Ack == q.ISS+1, "the second peer's SYN is answered", synackString(q, sa, ok))
	far := Segment{Src: q.Local, Dst: q.Remote, Seq: q.ISS + 1<<30, Flags: FlagSYN, Window: 65535, Opts: syn}
	q.Send(far)
	r, ok = q.Next(300 * time.Millisecond)
	h.Measure("other-syn-out-of-window.reply", segDesc(r, ok))
	h.Check("other-syn-out-of-window.ack", ok && isPureAck(r) && r.Ack == q.ISS+1, "a SYN far outside the window draws an ACK", segDesc(r, ok))
	q.adopt(syn, sa)
	q.SendAck()
	alive(h, "out-of-window.row-kept", q, h.Accept(l))
}

// closeOOOOnly closes a connection that holds only out-of-order data. No in-order data is unread,
// so the close is a FIN, as wgstack.md chose; data the testbench sends after the application
// closed then draws a RST.
func closeOOOOnly(h *H) {
	const port = 8020
	l := h.Listen(port)
	p, _, c := h.Connect(l, port, StandardSYN())
	p.Send(p.Segment(FlagACK|FlagPSH, p.SndNxt+1000, pattern(500, 0x92)))
	a, ok := p.Await(h.Prompt(), isPureAck)
	h.Require("ooo.dupack", ok && a.Ack == p.SndNxt, "the out-of-order segment is acknowledged at once", ackDesc(a, ok, p.SndNxt))
	c.Close()
	r, ok := p.Await(time.Second, func(s Segment) bool { return isRST(s) || isFIN(s) })
	h.Check("fin-not-rst", ok && isFIN(r) && !isRST(r), "Close with only out-of-order data sends a FIN", segDesc(r, ok))
	if ok && isFIN(r) {
		p.RcvNxt = r.Seq + 1
		p.SendAck()
	}
	p.SendData([]byte("new"))
	r, ok = p.Await(time.Second, isRST)
	h.Check("new-data.rst", ok, "data after the application closed draws a RST", segDesc(r, ok))
}

// finZeroWindow half-closes while the testbench's window is 0. The FIN takes a sequence number,
// so it lies beyond a zero window; wgstack.md sends it anyway. The run measures whether the DUT
// sends the FIN before the window opens, and checks that it sends it once the window opens.
func finZeroWindow(h *H) {
	const port = 8021
	l := h.Listen(port)
	p, _, c := h.Connect(l, port, StandardSYN())
	if _, err := c.Write([]byte("0123456789")); err != nil {
		h.T.Fatalf("write: %v", err)
	}
	d, ok := p.Await(time.Second, func(s Segment) bool { return isData(s) && s.Seq == p.RcvNxt })
	h.Require("data", ok, "the data arrives", segDesc(d, ok))
	p.RcvNxt += uint32(len(d.Payload))
	p.Window = 0
	p.SendAck() // takes the data and closes the window in one ACK
	p.SendData([]byte("z"))
	za, ok := p.Await(time.Second, func(s Segment) bool { return isPureAck(s) && s.Ack == p.SndNxt })
	h.Require("zero-window-taken", ok, "the DUT acknowledges a byte sent after the zero-window ACK", segDesc(za, ok))
	if err := c.CloseWrite(); err != nil {
		h.T.Fatalf("CloseWrite: %v", err)
	}
	fin := false
	var seen []string
	deadline := h.Now().Add(time.Second)
	for !fin {
		s, ok := p.Next(max(deadline.Sub(h.Now()), 0))
		if !ok {
			break
		}
		seen = append(seen, segDesc(s, true))
		fin = isFIN(s)
	}
	h.Measure("fin-into-zero-window", yesNo(fin, "sent before the window opened", "held until the window opens"))
	h.Measure("zero-window.segments", fmt.Sprint(seen))
	if !fin {
		p.Window = 512
		p.SendAck()
		f, ok := p.Await(time.Second, isFIN)
		fin = ok && f.Seq == p.RcvNxt
	}
	h.Check("fin-sent", fin, "the FIN is sent by the time the window opens", yesNo(fin, "FIN", "no FIN"))
}
