package tcpharness

import (
	"bytes"
	"fmt"
	"sync"
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

// ownScale checks the DUT's own window scale as a receiver. A warm-up sends in-order data while
// the application reads, until every byte is acknowledged and the DUT advertises a window that
// reaches more than 64 KiB past RCV.NXT. The testbench then holds back one segment and sends the
// span after it out of order, so the span ends more than 64 KiB past RCV.NXT: a receiver that
// read its own advertised window unscaled would drop the far end of it. Once the DUT's SACK shows
// it holds the whole span, the held-back segment must draw at once a cumulative ACK of
// everything. The testbench resends nothing in that phase, so a dropped segment cannot be hidden.
func ownScale(h *H, p *Peer, c Conn) {
	h.T.Helper()
	mss := MTU - 40
	span := 65536 + 16*mss // ends past 64 KiB even after the held-back segment
	need := mss + span     // the window the hold-back phase needs
	const warmMax = 2 << 20
	data := pattern(warmMax+need, 0x73)

	var mu sync.Mutex
	var read []byte
	go func() {
		buf := make([]byte, 64<<10)
		c.SetReadDeadline(time.Now().Add(20 * time.Second))
		for {
			n, err := c.Read(buf)
			mu.Lock()
			read = append(read, buf[:n]...)
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	readLen := func() int { mu.Lock(); defer mu.Unlock(); return len(read) }

	start := p.SndNxt
	maxWindow, resent, stalled := 0, 0, 0
	for p.SndNxt-start < warmMax && stalled < 20 {
		if p.DutAck == p.SndNxt && p.DutWindow >= need {
			break
		}
		avail := int(p.DutAck + uint32(p.DutWindow) - p.SndNxt)
		if p.SndNxt != p.DutAck && (avail <= 0 || p.DutWindow < need) {
			// wait for the ACK of everything, and resend what it does not cover, as a sender would
			if _, ok := p.Await(300*time.Millisecond, acks(p.SndNxt)); !ok && p.DutAck != p.SndNxt {
				stalled++
				resent += resend(p, data, start)
			}
			maxWindow = max(maxWindow, p.DutWindow)
			continue
		}
		if avail <= 0 { // everything acknowledged into a closed window: wait for an update
			if _, ok := p.Await(300*time.Millisecond, func(s Segment) bool { return s.Has(FlagACK) }); !ok {
				stalled++
			}
			continue
		}
		for avail > 0 && p.SndNxt-start < warmMax {
			off := int(p.SndNxt - start)
			n := min(avail, mss)
			p.SendData(data[off : off+n])
			avail -= n
		}
		for {
			if _, ok := p.Next(20 * time.Millisecond); !ok {
				break
			}
			maxWindow = max(maxWindow, p.DutWindow)
		}
	}
	h.Measure("own-scale.largest-window", maxWindow)
	h.Measure("own-scale.warm-up-bytes", p.SndNxt-start)
	h.Measure("own-scale.testbench-resent-segments", resent)
	ready := p.DutAck == p.SndNxt && p.DutWindow >= need
	h.Require("own-scale.window-past-64k", ready, fmt.Sprintf("after the warm-up the DUT acknowledges everything and advertises at least %d bytes", need),
		yesNo(ready, "it does", "it does not"))

	base := p.SndNxt
	off := int(base - start)
	end := base + uint32(need)
	for o := mss; o < need; o += mss {
		k := min(mss, need-o)
		p.Send(p.Segment(FlagACK|FlagPSH, base+uint32(o), data[off+o:off+o+k]))
	}
	held, ok := p.Await(time.Second, func(s Segment) bool {
		for _, b := range s.Opts.SACK {
			if b.Left == base+uint32(mss) && b.Right == end {
				return true
			}
		}
		return false
	})
	h.Check("own-scale.span-held", ok, "the DUT holds the whole out-of-order span past 64 KiB, as its SACK shows", sackDesc(held, ok, base))
	p.Send(p.Segment(FlagACK|FlagPSH, base, data[off:off+mss]))
	p.SndNxt = end
	a, ok := p.Await(h.Prompt(), func(s Segment) bool { return s.Has(FlagACK) && s.Ack == end })
	h.Check("own-scale.beyond-64k", ok, "filling the hole acknowledges everything up to more than 64 KiB past RCV.NXT at once", ackDesc(a, ok, base))

	want := data[:int(end-start)]
	deadline := time.Now().Add(2 * time.Second)
	for readLen() < len(want) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	got := append([]byte(nil), read...)
	mu.Unlock()
	h.Check("own-scale.delivered", bytes.Equal(got, want), "the application reads every byte in order",
		fmt.Sprintf("%d of %d bytes, equal %v", len(got), len(want), bytes.Equal(got, want)))
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
