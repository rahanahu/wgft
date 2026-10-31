package tcpharness

import (
	"bytes"
	"fmt"
	"sync"
	"time"
)

// The receive-overflow family checks a receiver whose application stops reading while the
// testbench keeps sending, the way wgstack-performance.md, Linux's receiver after a queue
// overflow, describes Linux's: the window shrinks as unread and out-of-order data fill the
// buffer, the right edge never moves back (RFC 9293 3.8.6, SHLD-14), out-of-order segments inside
// the window are held and reported at once with the segment's block first (RFC 5681 4.2, RFC
// 2018 4), segments from the right edge on are dropped, and a read reopens the window with an
// update at once. Every check is a relation the reference Linux shows, not a window size, since
// Linux opens its window from about 64 KB while wgstack advertises its floor from the handshake.
//
// rcvOverflowHold and rcvOverflowRead run on the pinned conformance values. The -perf scenarios
// run the same scripts on the performance configuration of the measurement plan: the reference
// Linux autotunes its buffer and wgstack has its boost from the accept, the case in which a
// boost once opened the window to the whole reservation while nothing was read.

// holdFloor is the 256 KiB floor every connection of wgft's agent has, the SO_RCVBUF the
// reference Linux's listeners get (linuxdut.SocketFloor).
const holdFloor = 256 << 10

// holdBound bounds how far past the first unread byte a DUT advertises while its application
// reads nothing: twice the floor, the receive memory Linux keeps for that SO_RCVBUF, which it
// doubles for its bookkeeping. Linux counts that memory by the allocation of each segment, so it
// holds more than 256 KiB of payload in it: about 300 KB in this family's runs.
// wgstack-performance.md, the receive window and boost: a connection that reads nothing keeps
// its window limit at the floor, as Linux raises its buffer only from reads, so a boost must not
// open the window towards the 4 MiB reservation.
const holdBound = 2 * holdFloor

// ovfFlow is one connection of the receive-overflow scenarios: it tracks every ACK's right edge
// while the testbench sends the stream data from start on.
type ovfFlow struct {
	h     *H
	p     *Peer
	c     Conn
	mss   int
	start uint32
	data  []byte
	right uint32 // the largest right edge advertised so far
	// the right edge of the latest ACK, the edge the testbench sends up to, as a sender's SND.WND
	// follows the latest window, RFC 9293 3.10.7.4
	last uint32
	// ACKs whose right edge lay a scale unit or more below an earlier one, the first of them, and
	// ACKs whose right edge lay less below it, which the rounding of a scaled window gives
	retracted     int
	firstRetract  string
	rounded       int
	holdMax       int  // the largest right edge past start before the first read
	reading       bool // the application has started to read
	acks, segsOut int  // ACKs seen and data segments sent
	// the most bytes the DUT dropped at once inside a window it had advertised, which RFC 7323 2.4
	// does not allow: the receiver MUST honor as in window any segment that was in window for any
	// ACK it sent
	droppedInWindow int
	largestWindow   int
}

func ovfOpen(h *H, port uint16) *ovfFlow {
	h.T.Helper()
	l := h.Listen(port)
	p, _, c := h.Connect(l, port, StandardSYN())
	h.Require("negotiated", p.SACK && p.TS && p.DutWS >= 0, "SACK, timestamps and window scale negotiated",
		fmt.Sprintf("SACK %v, timestamps %v, shift %d", p.SACK, p.TS, p.DutWS))
	f := &ovfFlow{h: h, p: p, c: c, mss: MTU - 40, start: p.SndNxt, data: pattern(4<<20, 0x5a)}
	f.right = p.DutAck + uint32(p.DutWindow)
	f.last = f.right
	return f
}

// unit is the DUT's window scale unit, 2^shift bytes. The window field is the window divided by
// it, so a receiver that rounds its window down advertises a right edge up to one unit short of
// its own: RFC 7323 2.4 notes that such an edge can lie below an earlier one, and has the
// receiver track its actual largest edge and honor every segment in window for any ACK it sent.
// The checks therefore allow an edge less than one unit below an earlier one and a DUT that takes
// less than one unit past the largest advertised edge, and the Measure lines record both.
func (f *ovfFlow) unit() uint32 { return 1 << f.p.DutWS }

// edge is the right edge an ACK advertises.
func (f *ovfFlow) edge(s Segment) uint32 {
	return s.Ack + uint32(int(s.Window)<<f.p.DutWS)
}

// next is Peer.Next that records the right edge of every ACK.
func (f *ovfFlow) next(d time.Duration) (Segment, bool) {
	s, ok := f.p.Next(d)
	if !ok || !s.Has(FlagACK) || s.Has(FlagSYN) || s.Has(FlagRST) {
		return s, ok
	}
	f.acks++
	f.largestWindow = max(f.largestWindow, int(s.Window)<<f.p.DutWS)
	e := f.edge(s)
	f.last = e
	switch {
	case !after(f.right, e):
		f.right = e
	case f.right-e < f.unit():
		f.rounded++
	default:
		f.retracted++
		if f.firstRetract == "" {
			f.firstRetract = fmt.Sprintf("an ACK's right edge %d bytes below an earlier one", int32(f.right-e))
		}
	}
	if !f.reading {
		f.holdMax = max(f.holdMax, int(int32(f.right-f.start)))
	}
	return s, ok
}

// await returns the first segment within d that match accepts.
func (f *ovfFlow) await(d time.Duration, match func(Segment) bool) (Segment, bool) {
	deadline := f.h.Now().Add(d)
	for {
		s, ok := f.next(max(deadline.Sub(f.h.Now()), 0))
		if !ok {
			return Segment{}, false
		}
		if match(s) {
			return s, true
		}
	}
}

// at is the stream data from sequence number seq, n bytes.
func (f *ovfFlow) at(seq uint32, n int) []byte {
	o := int(seq - f.start)
	return f.data[o : o+n]
}

// fill sends the stream in order as a sender that leaves keep bytes of the advertised window
// unused once the DUT has acknowledged data, or a quarter of the largest window if that is less.
// It sends one round of segments at a time and waits after each round for the ACK of everything,
// within the 500 ms RFC 1122 4.2.3.2 allows a delayed ACK. It stops when less than one segment
// fits, or for keep 0 when the window is closed, or once limit bytes past start are sent. It
// returns false when an ACK did not come.
func (f *ovfFlow) fill(keep int, limit int) bool {
	f.h.T.Helper()
	for range 400 {
		room := int(int32(f.last - f.p.SndNxt))
		if f.acks > 0 { // the SYN-ACK's window is unscaled and often smaller than the later ones
			room -= min(keep, f.largestWindow/4)
		}
		room = min(room, limit-int(f.p.SndNxt-f.start))
		if room <= 0 || keep > 0 && room < f.mss {
			return true
		}
		for room > 0 {
			n := min(f.mss, room)
			f.p.SendData(f.at(f.p.SndNxt, n))
			room -= n
			f.segsOut++
		}
		sent := f.p.SndNxt
		a, ok := f.await(500*time.Millisecond, func(s Segment) bool {
			return isPureAck(s) && (s.Ack == sent || s.Window == 0 && after(sent, s.Ack))
		})
		if !ok {
			return false
		}
		if a.Ack != sent {
			// The DUT closed its window short of what it had offered and dropped the rest. Once its
			// ACKs settle, the testbench sends again from the latest acknowledgment, as a sender
			// would after a retransmission timeout.
			for {
				if _, ok := f.next(250 * time.Millisecond); !ok {
					break
				}
			}
			f.droppedInWindow = max(f.droppedInWindow, int(int32(sent-f.p.DutAck)))
			f.p.SndNxt = f.p.DutAck
		}
	}
	return true
}

// stream sends the stream in order up to limit bytes past start within the advertised window,
// waiting for window updates while the application reads, and returns false when the window
// stayed closed or the ACK of everything did not come.
func (f *ovfFlow) stream(limit int) bool {
	f.h.T.Helper()
	for int(f.p.SndNxt-f.start) < limit {
		if !f.fill(0, limit) {
			return false
		}
		if int(f.p.SndNxt-f.start) >= limit {
			break
		}
		// The window is closed: the application's reads open it. The reader runs on real time, so
		// the wait is counted in real time too, also on a DUT on the harness's clock.
		right := f.last
		grew := func(Segment) bool { return after(f.last, right) }
		opened := false
		for deadline := time.Now().Add(5 * time.Second); !opened && time.Now().Before(deadline); {
			_, opened = f.await(time.Millisecond, grew)
			if _, clocked := f.h.DUT.(ClockedDUT); clocked && !opened {
				time.Sleep(time.Millisecond)
			}
		}
		if !opened {
			return false
		}
	}
	return true
}

// covers reports whether a SACK block of s contains [l, r).
func covers(s Segment, l, r uint32) bool {
	for _, b := range s.Opts.SACK {
		if !after(b.Left, l) && !after(r, b.Right) {
			return true
		}
	}
	return false
}

// reaches reports whether a SACK block of s or its acknowledgment number lies past seq.
func reaches(s Segment, seq uint32) bool {
	if after(s.Ack, seq) {
		return true
	}
	for _, b := range s.Opts.SACK {
		if after(b.Right, seq) {
			return true
		}
	}
	return false
}

// reader reads the connection in the background into got, once started.
type reader struct {
	mu  sync.Mutex
	got []byte
}

func startReader(c Conn, d time.Duration) *reader {
	r := &reader{}
	go func() {
		buf := make([]byte, 64<<10)
		c.SetReadDeadline(time.Now().Add(d))
		for {
			n, err := c.Read(buf)
			r.mu.Lock()
			r.got = append(r.got, buf[:n]...)
			r.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return r
}

// wait waits up to d of real time for n bytes and returns what arrived.
func (r *reader) wait(n int, d time.Duration) []byte {
	deadline := time.Now().Add(d)
	for {
		r.mu.Lock()
		k := len(r.got)
		r.mu.Unlock()
		if k >= n || !time.Now().Before(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.got...)
}

// junk is data the testbench sends where the DUT must drop it; the stream never carries it, so
// the delivered bytes show whether the DUT kept it.
func junk(n int) []byte { return bytes.Repeat([]byte{0xee}, n) }

// finish checks the properties every receive-overflow script ends with: the right edge never
// moved back by a scale unit or more, the right edge stayed within holdBound while nothing was
// read, and the stream arrived in order without the dropped bytes.
func (f *ovfFlow) finish(r *reader, from uint32) {
	h := f.h
	h.T.Helper()
	h.Measure("right-edge.rounded-below", f.rounded)
	h.Check("right-edge.kept", f.retracted == 0, "no ACK moves the right edge of the window back by a scale unit or more",
		yesNo(f.retracted == 0, "none did", fmt.Sprintf("%d did; %s", f.retracted, f.firstRetract)))
	h.Measure("hold.largest-right-edge", f.holdMax)
	h.Check("hold.bounded", f.holdMax <= holdBound,
		fmt.Sprintf("while the application reads nothing, the right edge stays within %d bytes of the first unread byte", holdBound),
		yesNo(f.holdMax <= holdBound, "within", "beyond"))
	want := f.data[from-f.start : f.p.SndNxt-f.start]
	got := r.wait(len(want), 5*time.Second)
	h.Check("delivered", bytes.Equal(got, want), "the application reads the stream in order, without the dropped bytes",
		fmt.Sprintf("%d of %d bytes, equal %v, dropped bytes inside %v", len(got), len(want), bytes.Equal(got, want), bytes.Contains(got, junk(64))))
}

func (f *ovfFlow) measureFill(id string) {
	f.h.Measure(id+".acks-per-segment", fmt.Sprintf("%d/%d", f.acks, f.segsOut))
	f.h.Measure(id+".dropped-inside-window-bytes", f.droppedInWindow)
	f.h.Check(id+".window-honored", f.droppedInWindow == 0, "the DUT takes every byte sent inside a window it advertised",
		yesNo(f.droppedInWindow == 0, "it does", "it drops some"))
	f.h.Measure(id+".largest-window", f.largestWindow)
}

// rcvOverflowHold fills the window with in-order data the application does not read, up to 30
// segments or a quarter of the largest window short of the right edge, then holds back one
// segment and sends the rest of the window out of order, then one segment at the right edge and one beyond it. It checks that each
// segment inside the window is held and reported at once with its block first, that the window
// field of those duplicate ACKs stays the same, that the segments from the right edge on are
// dropped, that reading every in-order byte while the hole stays reopens the window at once
// without forgetting the held data, and that filling the hole acknowledges up to the right edge
// and no further. The stream then goes on into the reopened window.
func rcvOverflowHold(h *H) { rcvOverflowHoldOn(h, 8401) }

func rcvOverflowHoldOn(h *H, port uint16) {
	f := ovfOpen(h, port)
	p := f.p
	mss := f.mss
	// A quarter of the largest window is left at most, so that twice what is left stays within
	// the window limit: Linux updates the window on a read only then (tcp_cleanup_rbuf, as
	// wgstack-performance.md's ACK timing describes), and the performance family's Linux
	// advertises about 64 KB.
	ok := f.fill(30*mss, 1<<20)
	h.Require("fill.acked", ok, "every round of in-order data is acknowledged within 500 ms", yesNo(ok, "each was", "an ACK did not come"))
	f.measureFill("fill")
	hole := p.SndNxt
	oooStart := hole + uint32(mss)
	edge0 := f.last
	h.Measure("ooo.window-bytes", int32(edge0-hole))

	// The rest of the window, out of order, one segment at a time, up to the largest edge the DUT
	// advertised: RFC 7323 2.4 has it honor what was in window for any ACK it sent, and the edge
	// segment below starts there, so no gap is left between the two.
	off := oooStart
	missed, notFirst, sent := 0, 0, 0
	windows := map[uint16]bool{}
	for after(f.right, off) && sent < 80 {
		n := min(mss, int(f.right-off))
		p.Send(p.Segment(FlagACK|FlagPSH, off, f.at(off, n)))
		sent++
		l, r := off, off+uint32(n)
		a, ok := f.await(h.Prompt(), func(s Segment) bool { return isPureAck(s) && s.Ack == hole && covers(s, l, r) })
		switch {
		case !ok:
			missed++
		case a.Opts.SACK[0] != SACKBlock{oooStart, r}:
			notFirst++
			windows[a.Window] = true
		default:
			windows[a.Window] = true
		}
		off = r
	}
	oooEnd := off
	h.Measure("ooo.segments", sent)
	h.Check("ooo.dupack", missed == 0, "every out-of-order segment inside the window draws at once an ACK of the hole that reports it",
		fmt.Sprintf("%d of %d did not", missed, sent))
	h.Check("ooo.sack-first", notFirst == 0, "the first SACK block of each of those ACKs is the held span up to the segment",
		fmt.Sprintf("%d of %d were not", notFirst, sent-missed))
	h.Check("ooo.window-steady", len(windows) <= 1 && f.last == edge0,
		"while the buffer is full the duplicate ACKs keep the same window field and right edge",
		fmt.Sprintf("%d window values, right edge %s", len(windows), yesNo(f.last == edge0, "kept", "moved")))

	// From the right edge on, the DUT drops what it gets: one segment at the edge, one beyond. The
	// segment at the edge carries the stream, since the DUT may take what its rounded window field
	// hid, less than a scale unit; the one beyond carries bytes the stream never has.
	edge := f.right
	p.Send(p.Segment(FlagACK|FlagPSH, edge, f.at(edge, mss)))
	a, ok := f.await(h.Prompt(), func(s Segment) bool { return isPureAck(s) && s.Ack == hole })
	h.Check("edge.ack", ok, "a segment at the right edge draws at once an ACK of the hole", ackDesc(a, ok, hole))
	slack := edge + f.unit() - 1
	h.Check("edge.dropped", !ok || !reaches(a, slack), "that ACK reports nothing a scale unit or more past the right edge",
		yesNo(!ok || !reaches(a, slack), "it reports nothing there", "it reports data there"))
	heldEnd := oooEnd
	if ok && len(a.Opts.SACK) > 0 && a.Opts.SACK[0].Left == oooStart && after(a.Opts.SACK[0].Right, heldEnd) && !after(a.Opts.SACK[0].Right, slack) {
		heldEnd = a.Opts.SACK[0].Right
	}
	h.Measure("edge.taken-bytes", int32(heldEnd-edge))
	beyond := edge + 2*uint32(mss)
	p.Send(p.Segment(FlagACK|FlagPSH, beyond, junk(mss)))
	answers := 0
	held := false
	for {
		s, ok := f.next(h.Prompt())
		if !ok {
			break
		}
		if isPureAck(s) {
			answers++
			held = held || reaches(s, beyond)
		}
	}
	h.Measure("beyond.acks", answers)
	h.Check("beyond.dropped", !held, "a segment beyond the right edge is not reported as held", yesNo(held, "reported", "not reported"))

	// The application reads every in-order byte; the hole stays.
	rem := int(int32(f.last - hole))
	f.reading = true
	got, err := readFull(f.c, int(hole-f.start), 5*time.Second)
	h.Require("read-hole.read", err == nil && bytes.Equal(got, f.data[:hole-f.start]), "the application reads the in-order data",
		fmt.Sprintf("%d bytes, error %s", len(got), errKind(err)))
	u, ok := f.await(h.Prompt(), func(s Segment) bool {
		return isPureAck(s) && s.Ack == hole && int(s.Window)<<p.DutWS >= max(2*rem, mss)
	})
	h.Check("read-hole.window-update", ok, "the read draws at once an ACK whose window is at least twice what was left",
		yesNo(ok, "it does", "no such ACK in time"))
	kept := ok && len(u.Opts.SACK) > 0 && u.Opts.SACK[0] == SACKBlock{oooStart, heldEnd}
	h.Check("read-hole.sack-kept", kept, "that ACK still reports the held span first",
		yesNo(kept, "it does", yesNo(ok, "it does not", "no ACK in time")))
	if ok {
		h.Measure("read-hole.window", int(u.Window)<<p.DutWS)
	}

	// Filling the hole acknowledges the held span, up to the right edge and no further.
	r := startReader(f.c, 20*time.Second)
	p.Send(p.Segment(FlagACK|FlagPSH, hole, f.at(hole, mss)))
	p.SndNxt = heldEnd
	a, ok = f.await(h.Prompt(), func(s Segment) bool { return isPureAck(s) && after(s.Ack, hole) })
	holeGot := "no ACK in time"
	switch {
	case ok && a.Ack == heldEnd:
		holeGot = "ACK of everything held"
	case ok && after(a.Ack, heldEnd):
		holeGot = "ACK past the right edge"
	case ok:
		holeGot = "ACK short of what it held"
	}
	h.Check("hole.ack", ok && a.Ack == heldEnd, "filling the hole acknowledges at once everything it held, up to the right edge", holeGot)
	if ok && after(a.Ack, heldEnd) && !after(a.Ack, edge+uint32(mss)) {
		p.SndNxt = a.Ack // it took the segment at the edge, which carried the stream
	}
	h.Check("hole.no-sack", ok && len(a.Opts.SACK) == 0, "no SACK block once nothing is out of order", sackDesc(a, ok, hole))

	ok = f.stream(int(heldEnd-f.start) + 2*holdFloor)
	h.Check("resume.acked", ok, "the stream goes on into the reopened window", yesNo(ok, "it does", "the window stayed closed or an ACK did not come"))
	f.finish(r, hole)
}

// rcvOverflowRead fills the window until it closes, with in-order data the application does not
// read, then sends one segment at RCV.NXT, the right edge of the closed window. It checks that the
// segment draws at once an ACK of RCV.NXT and is dropped, and that the application's read reopens
// the window at once. half reads half of the data first, as a slow reader does; otherwise the
// application reads all of it.
func rcvOverflowRead(half bool) func(h *H) {
	return func(h *H) { rcvOverflowReadOn(h, 8402, half) }
}

func rcvOverflowReadOn(h *H, port uint16, half bool) {
	f := ovfOpen(h, port)
	p := f.p
	mss := f.mss
	ok := f.fill(0, 1<<20)
	h.Require("fill.acked", ok, "every round of in-order data is acknowledged within 500 ms", yesNo(ok, "each was", "an ACK did not come"))
	f.measureFill("fill")
	closed := f.last == p.SndNxt && p.DutAck == p.SndNxt
	h.Require("fill.closed", closed, "the window closes once the testbench has sent up to its right edge",
		yesNo(closed, "it does", fmt.Sprintf("%d bytes left", int32(f.last-p.SndNxt))))

	// The segment carries the stream: the DUT may take what its rounded window field hid.
	p.Send(p.Segment(FlagACK|FlagPSH, p.SndNxt, f.at(p.SndNxt, mss)))
	a, ok := f.await(h.Prompt(), func(s Segment) bool { return isPureAck(s) })
	taken := ok && !after(p.SndNxt, a.Ack) && !reaches(a, p.SndNxt+f.unit()-1)
	h.Check("closed.ack", taken, "a segment into the closed window draws at once an ACK that takes less than a scale unit of it",
		ackDesc(a, ok, p.SndNxt))
	if taken {
		h.Measure("closed.taken-bytes", int32(a.Ack-p.SndNxt))
		h.Measure("closed.window", int(a.Window)<<p.DutWS)
		p.SndNxt = a.Ack
	}

	held := int(p.SndNxt - f.start)
	n := held
	if half {
		n = held / 2
	}
	rem := int(int32(f.last - p.SndNxt))
	f.reading = true
	got, err := readFull(f.c, n, 5*time.Second)
	h.Require("read", err == nil && bytes.Equal(got, f.data[:n]), "the application reads the data",
		fmt.Sprintf("%d bytes, error %s", len(got), errKind(err)))
	u, ok := f.await(h.Prompt(), func(s Segment) bool {
		return isPureAck(s) && s.Ack == p.SndNxt && int(s.Window)<<p.DutWS >= max(2*rem, mss)
	})
	h.Check("read.window-update", ok, "the read draws at once an ACK that reopens the window", yesNo(ok, "it does", "no such ACK in time"))
	if ok {
		h.Measure("read.window", int(u.Window)<<p.DutWS)
	}
	r := startReader(f.c, 20*time.Second)
	ok = f.stream(held + 2*holdFloor)
	h.Check("resume.acked", ok, "the stream goes on into the reopened window", yesNo(ok, "it does", "the window stayed closed or an ACK did not come"))
	f.finish(r, f.start+uint32(n))
}

const ovfRefs = "RFC 9293 3.8.6 and 3.10.7.4, RFC 1122 4.2.3.3, RFC 2018 4, RFC 5681 4.2; wgstack-performance.md, Linux's receiver after a queue overflow"
