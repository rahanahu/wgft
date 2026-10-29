package tcpharness

import (
	"bytes"
	"fmt"
	"io"
	"time"
)

// windowScale checks both directions of RFC 7323's window scale. As a sender the DUT keeps its
// flight within the testbench's window, scaled when both sides offered a scale and unscaled when
// the testbench offered none; applying its own shift to an unscaled window is the classic bug.
// As a receiver it accepts every byte within the window it advertised, including flights past
// 64 KiB that only a scaled window allows.
func windowScale(h *H) {
	const port = 8009
	l := h.Listen(port)
	mss := uint16(MTU - 40)

	// The window is small from the SYN on, so the testbench never shrinks it.
	scaled := Dial{SYN: StandardSYN(), SynWindow: 1024, Window: 8} // 8 << 7 = 1024 bytes
	p, _, c := h.ConnectWith(l, port, scaled)
	h.Require("scaled.negotiated", p.WS == 7, "window scale negotiated", fmt.Sprintf("shift %d", p.WS))
	sendWithin(h, "scaled", p, c, 1024, pattern(6000, 0x71))

	bare := Options{MSS: &mss, WS: -1, TS: &Timestamps{}}
	p, _, c = h.ConnectWith(l, port, Dial{SYN: bare, Window: 2000})
	h.Require("unscaled.negotiated", p.WS < 0, "no window scale", fmt.Sprintf("shift %d", p.WS))
	sendWithin(h, "unscaled", p, c, 2000, pattern(8000, 0x72))

	p, _, c = h.Connect(l, port, StandardSYN())
	ownScale(h, p, c)
}

// sendWithin has the application write data and receives it in rounds, acknowledging after each
// round with the same window, and checks that the DUT never has more than window bytes in
// flight.
func sendWithin(h *H, id string, p *Peer, c Conn, window int, data []byte) {
	h.T.Helper()
	if _, err := c.Write(data); err != nil {
		h.T.Fatalf("write: %v", err)
	}
	var got []byte
	flight := 0
	for round := 0; len(got) < len(data) && round < 40; round++ {
		una := p.RcvNxt
		buf := map[uint32][]byte{}
		for {
			s, ok := p.Await(80*time.Millisecond, isData)
			if !ok {
				break
			}
			flight = max(flight, int(s.Seq-una)+len(s.Payload))
			buf[s.Seq] = s.Payload
		}
		for {
			b, ok := buf[p.RcvNxt]
			if !ok || len(b) == 0 {
				break
			}
			got = append(got, b...)
			p.RcvNxt += uint32(len(b))
		}
		p.SendAck()
	}
	h.Measure(id+".largest-flight", flight)
	h.Check(id+".within-window", flight <= window, fmt.Sprintf("at most %d bytes in flight", window),
		yesNo(flight <= window, "within the window", "beyond the window"))
	h.Check(id+".delivered", bytes.Equal(got, data), fmt.Sprintf("all %d bytes arrive in order", len(data)),
		fmt.Sprintf("%d bytes, equal %v", len(got), bytes.Equal(got, data)))
}

// ownScale sends the DUT as much as its advertised window allows while the application reads,
// and checks that every byte is acknowledged.
func ownScale(h *H, p *Peer, c Conn) {
	h.T.Helper()
	const total = 400 << 10
	data := pattern(total, 0x73)
	read := make(chan []byte, 1)
	go func() {
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		b, _ := io.ReadAll(io.LimitReader(c, total))
		read <- b
	}()
	mss := MTU - 40
	start := p.SndNxt
	maxWindow, maxFlight := p.DutWindow, 0
	stalled, resent := 0, 0
	for p.SndNxt-start < total && stalled < 20 {
		// Send a whole window at once, then take the ACKs that have come in.
		avail := int(p.DutAck + uint32(p.DutWindow) - p.SndNxt)
		if avail <= 0 {
			if _, ok := p.Await(300*time.Millisecond, func(s Segment) bool { return s.Has(FlagACK) }); !ok {
				stalled++
				resent += resend(p, data, start)
			}
			maxWindow = max(maxWindow, p.DutWindow)
			continue
		}
		for avail > 0 && p.SndNxt-start < total {
			off := int(p.SndNxt - start)
			n := min(avail, mss, total-off)
			p.SendData(data[off : off+n])
			avail -= n
		}
		maxFlight = max(maxFlight, int(p.SndNxt-p.DutAck))
		for {
			if _, ok := p.Next(20 * time.Millisecond); !ok {
				break
			}
			maxWindow = max(maxWindow, p.DutWindow)
		}
	}
	ok := false
	for range 10 {
		if _, ok = p.Await(300*time.Millisecond, acks(p.SndNxt)); ok || p.DutAck == p.SndNxt {
			ok = true
			break
		}
		resent += resend(p, data, start)
	}
	h.Measure("own-scale.largest-window", maxWindow)
	h.Measure("own-scale.largest-flight", maxFlight)
	// A receiver may drop in-window segments, so the testbench retransmits what is not
	// acknowledged after 300 ms, as a sender would; how often it had to is a measurement.
	h.Measure("own-scale.testbench-resent-segments", resent)
	h.Check("own-scale.all-acked", ok && p.SndNxt-start == total, fmt.Sprintf("all %d bytes sent within the DUT's window are acknowledged", total),
		fmt.Sprintf("%d bytes sent, all acknowledged %v", p.SndNxt-start, ok))
	if maxFlight > 65535 {
		h.Check("own-scale.beyond-64k", ok, "a flight past 64 KiB, possible only with a scaled window, is accepted", yesNo(ok, "accepted", "not acknowledged"))
	} else {
		h.T.Logf("the DUT never offered more than 64 KiB in flight, %d bytes; own-scale.beyond-64k not reached", maxFlight)
	}
	got := <-read
	h.Check("own-scale.delivered", bytes.Equal(got, data), "the application reads every byte in order",
		fmt.Sprintf("%d bytes, equal %v", len(got), bytes.Equal(got, data)))
}

// paws sends a data segment whose timestamp is older than the last one the DUT accepted. RFC
// 7323 5.3 drops it and answers with an ACK; the bytes must not reach the application.
func paws(h *H) {
	const port = 8010
	l := h.Listen(port)
	p, _, c := h.Connect(l, port, StandardSYN())
	h.Require("timestamps", p.TS, "timestamps negotiated", yesNo(p.TS, "timestamps", "none"))
	p.SendData([]byte("fresh1"))
	got, err := readFull(c, 6, time.Second)
	h.Require("fresh.delivered", err == nil && string(got) == "fresh1", "a current segment is delivered", fmt.Sprintf("%d bytes, error %s", len(got), errKind(err)))
	a, ok := p.Await(time.Second, acks(p.SndNxt))
	h.Require("fresh.acked", ok, "the current segment is acknowledged", segDesc(a, ok))

	old := p.Segment(FlagACK|FlagPSH, p.SndNxt, []byte("OLD!"))
	old.Opts.TS.Val = p.TSVal() - 100000 // 100 s older than the clock
	p.Send(old)
	a, ok = p.Await(time.Second, func(s Segment) bool { return s.Has(FlagACK) })
	h.Check("old.dupack", ok && a.Ack == p.SndNxt, "the old segment draws an ACK that does not cover it", ackDesc(a, ok, p.SndNxt))
	got, err = readFull(c, 4, 300*time.Millisecond)
	dropped := len(got) == 0 && errKind(err) == "timeout"
	h.Check("old.not-delivered", dropped, "the old segment's bytes are not delivered", fmt.Sprintf("%d bytes, error %s", len(got), errKind(err)))
	if !dropped {
		h.T.Logf("the old bytes were delivered, so the same bytes with a current timestamp would be a duplicate; retry.delivered not reached")
		return
	}
	p.SendData([]byte("NEW!"))
	got, err = readFull(c, 4, time.Second)
	h.Check("retry.delivered", err == nil && string(got) == "NEW!", "the same bytes with a current timestamp are delivered",
		fmt.Sprintf("%q, error %s", got, errKind(err)))
}

// resend retransmits the unacknowledged bytes from the DUT's latest ACK up to SndNxt, at most
// the DUT's window, and returns the number of segments sent.
func resend(p *Peer, data []byte, start uint32) int {
	mss := MTU - 40
	n := 0
	for off := p.DutAck; off != p.SndNxt && int(off-p.DutAck) < p.DutWindow; n++ {
		i := int(off - start)
		k := min(mss, int(p.SndNxt-off))
		p.Send(p.Segment(FlagACK|FlagPSH, off, data[i:i+k]))
		off += uint32(k)
	}
	return n
}
