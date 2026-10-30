package tcpharness

import (
	"bytes"
	"fmt"
	"time"
)

// The SACK recovery family: RFC 6675 loss recovery with RFC 6937 PRR and RFC 3042 Limited
// Transmit, as wgstack-performance.md's SACK step asks. The reference Linux runs these with its
// pinned configuration, in which SACK is on and RACK, TLP and F-RTO are off, so its recovery is
// RFC 6675's duplicate-threshold rule with PRR.

// segSize is the payload the DUT puts in a full segment to p: MSS less the timestamps option.
func segSize(p *Peer) int {
	n := MTU - 40
	if p.TS {
		n -= 12
	}
	return n
}

// flight has the application write n full segments, n small enough for any initial window of
// ten, and collects the burst the DUT sends before any ACK. Segment sizes differ between engines,
// gVisor leaving room for SACK blocks, so the scenarios work from the segments the DUT sent.
func flight(h *H, p *Peer, c Conn, n int, salt byte) ([]Segment, []byte) {
	h.T.Helper()
	data := pattern(n*segSize(p), salt)
	if _, err := c.Write(data); err != nil {
		h.T.Fatalf("write: %v", err)
	}
	segs, sent := burst(p)
	h.Require("flight", sent == len(data) && len(segs) >= n, fmt.Sprintf("the %d bytes leave in one initial burst of at least %d segments", len(data), n),
		fmt.Sprintf("%d bytes in %d segments", sent, len(segs)))
	return segs, data
}

// burst collects the new data segments the DUT sends until it pauses for 30 ms. A segment that
// repeats earlier bytes, such as gVisor's tail loss probe on a near-zero RTT, is left out.
func burst(p *Peer) ([]Segment, int) {
	var segs []Segment
	sent := 0
	high := p.RcvNxt
	for {
		s, ok := p.Await(30*time.Millisecond, isData)
		if !ok {
			return segs, sent
		}
		if after(high, s.Seq) {
			p.h.T.Logf("a retransmission during the initial burst is left out: %v", s)
			continue
		}
		segs = append(segs, s)
		sent += len(s.Payload)
		high = s.Seq + uint32(len(s.Payload))
	}
}

// dataEnd is the sequence number after the last byte of data written from r's base.
func dataEnd(r *receiver, data []byte) uint32 { return r.base + uint32(len(data)) }

// rexmitWatch notes which sequence numbers below high the DUT sends again.
type rexmitWatch struct {
	high  uint32
	seen  map[uint32]int
	fresh int // new segments, beyond high
}

func newWatch(segs []Segment) *rexmitWatch {
	last := segs[len(segs)-1]
	return &rexmitWatch{high: last.Seq + uint32(len(last.Payload)), seen: map[uint32]int{}}
}

func (w *rexmitWatch) note(s Segment) {
	if !isData(s) {
		return
	}
	if after(w.high, s.Seq) {
		w.seen[s.Seq]++
		return
	}
	w.high = max32(w.high, s.Seq+uint32(len(s.Payload)))
	w.fresh++
}

func (w *rexmitWatch) has(seq uint32) bool { return w.seen[seq] > 0 }

// onlyOf reports whether every retransmission is at one of the allowed sequence numbers.
func (w *rexmitWatch) onlyOf(allowed ...uint32) bool {
	ok := map[uint32]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	for s := range w.seen {
		if !ok[s] {
			return false
		}
	}
	return true
}

// dupacks has the receiver take each listed segment and answer with an ACK carrying its SACK
// blocks, one ACK per segment, as a receiver does.
func dupacks(r *receiver, segs []Segment, idx ...int) {
	for _, i := range idx {
		r.take(segs[i])
		r.p.Send(r.ack(r.p.TSRecent))
	}
}

// arriving is every index from 1 to the end of segs except the lost ones.
func arriving(segs []Segment, lost ...int) []int {
	skip := map[int]bool{}
	for _, l := range lost {
		skip[l] = true
	}
	var out []int
	for i := 1; i < len(segs); i++ {
		if !skip[i] {
			out = append(out, i)
		}
	}
	return out
}

// collect hands every segment of p's flow within d to w and to r, when r is not nil.
func collect(p *Peer, d time.Duration, w *rexmitWatch, r *receiver) {
	deadline := p.h.Now().Add(d)
	for {
		s, ok := p.Next(max(deadline.Sub(p.h.Now()), 0))
		if !ok {
			return
		}
		w.note(s)
		if r != nil {
			r.take(s)
		}
	}
}

// finish acknowledges in order whatever the DUT sends until everything up to end is in, and
// reports whether it got there within d.
func finish(p *Peer, r *receiver, w *rexmitWatch, end uint32, d time.Duration) bool {
	deadline := p.h.Now().Add(d)
	p.Send(r.ack(p.TSRecent))
	for after(end, r.cum) {
		s, ok := p.Next(max(deadline.Sub(p.h.Now()), 0))
		if !ok {
			return false
		}
		w.note(s)
		if isData(s) {
			r.take(s)
			p.Send(r.ack(p.TSRecent))
		}
	}
	return true
}

func intact(h *H, r *receiver, data []byte) {
	h.T.Helper()
	got := r.stream(len(data))
	h.Check("stream-intact", bytes.Equal(got, data), "the testbench assembles exactly the bytes the application wrote",
		fmt.Sprintf("%d of %d bytes, equal %v", len(got), len(data), bytes.Equal(got, data)))
}

// sackMultiHole loses three segments of one window of nine. With the SACK blocks of the six
// segments that arrived, at least three of them above the last hole, RFC 6675 marks all three
// holes lost, and PRR lets it resend them as those ACKs
// arrive, so all three come back before the testbench has to send a new cumulative ACK: about one
// round trip, where NewReno needs one per hole. Nothing SACKed is sent again.
func sackMultiHole(h *H) {
	const port = 8030
	l := h.Listen(port)
	p, _, c := h.Connect(l, port, StandardSYN())
	h.Require("sack", p.SACK, "SACK negotiated", yesNo(p.SACK, "SACK", "no SACK"))
	segs, data := flight(h, p, c, 9, 0xa1)
	start := h.Now()
	r := newReceiver(p)
	w := newWatch(segs)
	r.take(segs[0])
	p.Send(r.ack(p.TSRecent))
	dupacks(r, segs, arriving(segs, 1, 3, 5)...) // the second, fourth and sixth segments are lost
	collect(p, h.Prompt()+50*time.Millisecond, w, r)
	all := w.has(segs[1].Seq) && w.has(segs[3].Seq) && w.has(segs[5].Seq)
	h.Check("all-holes-in-one-round", all, "the three holes are resent before any new cumulative ACK",
		fmt.Sprintf("holes resent: %v %v %v", w.has(segs[1].Seq), w.has(segs[3].Seq), w.has(segs[5].Seq)))
	h.Check("before-rto", all && h.Now().Sub(start) < 180*time.Millisecond, "the holes are resent before an RTO could fire",
		yesNo(all && h.Now().Sub(start) < 180*time.Millisecond, "before 180 ms", "not before 180 ms"))
	ok := finish(p, r, w, dataEnd(r, data), 2*time.Second)
	h.Check("completes", ok, "everything is acknowledged within 2 s", yesNo(ok, "complete", "incomplete"))
	before := len(w.seen)
	collect(p, 300*time.Millisecond, w, nil)
	h.Check("sacked-not-resent", w.onlyOf(segs[1].Seq, segs[3].Seq, segs[5].Seq), "no SACKed segment is sent again",
		fmt.Sprintf("%d distinct segments resent", len(w.seen)))
	h.Check("quiet-after", len(w.seen) == before, "nothing is resent after the full ACK", fmt.Sprintf("%d more", len(w.seen)-before))
	intact(h, r, data)
}

// sackRTOKeepsSACKed makes the fast retransmissions of two holes fail too, so recovery ends in an
// RTO. RFC 6675 5.1: after the RTO the sender resends only what was not SACKed. The holes are
// three SACKed segments apart, so once the first is repaired the window after the RTO has room for
// a SACKed segment that a go-back-N resend would send again.
func sackRTOKeepsSACKed(h *H) {
	const port = 8031
	l := h.Listen(port)
	p, _, c := h.Connect(l, port, StandardSYN())
	h.Require("sack", p.SACK, "SACK negotiated", yesNo(p.SACK, "SACK", "no SACK"))
	segs, data := flight(h, p, c, 8, 0xa2)
	r := newReceiver(p)
	w := newWatch(segs)
	r.take(segs[0])
	p.Send(r.ack(p.TSRecent))
	dupacks(r, segs, arriving(segs, 1, 5)...)          // the second and sixth are lost
	collect(p, h.Prompt()+50*time.Millisecond, w, nil) // the fast retransmissions are lost as well
	fast := len(w.seen)
	h.Measure("fast-retransmissions", fast)
	// The RTO: the next transmission of the first hole.
	before := w.seen[segs[1].Seq]
	rto, ok := p.Await(3*time.Second, func(s Segment) bool { w.note(s); return isData(s) && s.Seq == segs[1].Seq })
	h.Require("rto", ok && w.seen[segs[1].Seq] > before, "an RTO resends the first hole", segDesc(rto, ok))
	w.seen = map[uint32]int{} // count only what follows the RTO
	w.seen[segs[1].Seq] = 1
	r.take(rto)
	ok = finish(p, r, w, dataEnd(r, data), 3*time.Second)
	h.Check("completes", ok, "everything is acknowledged within 3 s of the RTO", yesNo(ok, "complete", "incomplete"))
	collect(p, 300*time.Millisecond, w, nil) // a go-back-N resend arrives after the cumulative ACK
	h.Check("sacked-not-resent-after-rto", w.onlyOf(segs[1].Seq, segs[5].Seq), "after the RTO only the two holes are resent",
		fmt.Sprintf("%d distinct segments resent after the RTO", len(w.seen)))
	intact(h, r, data)
}

// sackPMTUSplit lowers the path MTU to 1000 bytes while a full-sized flight is unacknowledged and
// partly SACKed. The DUT resends what was not SACKed, split into segments that fit the new MTU,
// and does not resend the SACKed segments.
func sackPMTUSplit(h *H) {
	const port = 8032
	const newMTU = 1000
	l := h.Listen(port)
	p, _, c := h.Connect(l, port, StandardSYN())
	segs, data := flight(h, p, c, 8, 0xa3)
	h.Require("sack", p.SACK, "SACK negotiated", yesNo(p.SACK, "SACK", "no SACK"))
	r := newReceiver(p)
	w := newWatch(segs)
	// The first segment arrives, the second is lost, the third and fourth arrive: two duplicate
	// ACKs, too few SACKed bytes for RFC 6675 to call the second lost before the ICMP.
	r.take(segs[0])
	p.Send(r.ack(p.TSRecent))
	dupacks(r, segs, 2, 3)
	collect(p, 20*time.Millisecond, w, r)
	p.h.DUT.Inject(FragNeeded(PeerAddr, segs[1].Marshal(), newMTU))
	start := h.Now()
	over := 0
	deadline := h.Now().Add(3 * time.Second)
	end := dataEnd(r, data)
	for after(end, r.cum) {
		s, ok := p.Next(max(deadline.Sub(h.Now()), 0))
		if !ok {
			break
		}
		w.note(s)
		if !isData(s) {
			continue
		}
		if len(s.Marshal()) > newMTU {
			over++
		}
		r.take(s)
		p.Send(r.ack(p.TSRecent))
	}
	done := !after(end, r.cum)
	h.Measure("completed_ms", h.Now().Sub(start).Milliseconds())
	h.Check("completes", done, "the flight is resent and acknowledged within 3 s", yesNo(done, "complete", "incomplete"))
	h.Check("within-new-mtu", over == 0, fmt.Sprintf("every segment after the ICMP fits the new MTU of %d", newMTU), fmt.Sprintf("%d segments too large", over))
	collect(p, 300*time.Millisecond, w, nil)
	h.Check("sacked-not-resent", !w.has(segs[2].Seq) && !w.has(segs[3].Seq), "the two SACKed segments are not resent",
		fmt.Sprintf("SACKed segments resent: %v %v", w.has(segs[2].Seq), w.has(segs[3].Seq)))
	intact(h, r, data)
}

// sackRenege has the receiver discard what it SACKed: after the hole is resent, the testbench's
// cumulative ACK stops at the first SACKed segment and carries no SACK block. The sender must
// clear its SACK marks and resend from the cumulative ACK, as Linux's tcp_check_sack_reneging
// does, instead of waiting forever on data it believes delivered.
func sackRenege(h *H) {
	const port = 8033
	l := h.Listen(port)
	p, _, c := h.Connect(l, port, StandardSYN())
	h.Require("sack", p.SACK, "SACK negotiated", yesNo(p.SACK, "SACK", "no SACK"))
	segs, data := flight(h, p, c, 8, 0xa4)
	r := newReceiver(p)
	w := newWatch(segs)
	r.take(segs[0])
	p.Send(r.ack(p.TSRecent))
	dupacks(r, segs, arriving(segs, 1)...) // the second is lost
	hole, ok := p.Await(time.Second, func(s Segment) bool { w.note(s); return isData(s) && s.Seq == segs[1].Seq })
	h.Require("hole-resent", ok, "the hole is resent", segDesc(hole, ok))
	// The receiver reneges: it keeps only segments 1 and 2.
	fresh := newReceiver(p)
	fresh.base = r.base
	fresh.cum = r.base
	fresh.take(segs[0])
	fresh.take(hole)
	p.Send(fresh.ack(p.TSRecent))
	s3, ok := p.Await(time.Second, func(s Segment) bool { w.note(s); return isData(s) && s.Seq == segs[2].Seq })
	h.Check("resends-sacked", ok, "the first segment the receiver dropped is resent within 1 s", segDesc(s3, ok))
	if ok {
		fresh.take(s3)
	}
	done := finish(p, fresh, w, dataEnd(fresh, data), 3*time.Second)
	h.Check("completes", done, "everything is acknowledged within 3 s", yesNo(done, "complete", "incomplete"))
	intact(h, fresh, data)
}

// limitedTransmit has the application write more than the initial window and loses the first
// segment. RFC 3042: each of the first two duplicate ACKs lets the sender send one new segment,
// and it retransmits nothing before the third. The duplicate ACKs come 20
// ms apart, as the arrivals of the segments that cause them would space them.
func limitedTransmit(h *H) {
	const port = 8034
	l := h.Listen(port)
	p, _, c := h.Connect(l, port, StandardSYN())
	h.Require("sack", p.SACK, "SACK negotiated", yesNo(p.SACK, "SACK", "no SACK"))
	data := pattern(15*segSize(p), 0xa5)
	if _, err := c.Write(data); err != nil {
		h.T.Fatalf("write: %v", err)
	}
	segs, sent := burst(p)
	h.Require("window-full", len(segs) >= 4 && sent < len(data), "the initial window sends some segments and holds the rest back",
		fmt.Sprintf("%d of %d bytes in %d segments", sent, len(data), len(segs)))
	r := newReceiver(p)
	w := newWatch(segs)
	// 20 ms between the duplicate ACKs, as segments arriving one after another space them; sent
	// back to back, the second reaches Linux before it has sent the first new segment on.
	for i, id := range []string{"first-dupack.new-data", "second-dupack.new-data"} {
		before := w.fresh
		dupacks(r, segs, 1+i)
		collect(p, 20*time.Millisecond, w, nil)
		h.Check(id, w.fresh-before == 1, "the duplicate ACK lets exactly one new segment out within 20 ms", fmt.Sprintf("%d new segments", w.fresh-before))
	}
	h.Check("no-retransmit-before-third", len(w.seen) == 0, "nothing is resent after two duplicate ACKs", fmt.Sprintf("%d retransmissions", len(w.seen)))
}
