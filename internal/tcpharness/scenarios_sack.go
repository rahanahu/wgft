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

// sackRTT is the handshake RTT of the SACK family. A minimum RTT above zero gives a RACK sender a
// reorder window above zero: with a zero window and a clock too coarse to order the segments of
// one burst, as on Windows, gVisor's RACK marks segments sent in the same tick as the latest
// SACKed one lost, and resends segments a later ACK of the same burst SACKs.
const sackRTT = 20 * time.Millisecond

// sackConnect opens a connection for the SACK family, with its handshake RTT.
func sackConnect(h *H, l Listener, port uint16) (*Peer, Conn) {
	h.T.Helper()
	p, _, c := h.ConnectWith(l, port, Dial{SYN: StandardSYN(), AckDelay: sackRTT})
	return p, c
}

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
	return flightOf(h, p, c, n*segSize(p), n, salt)
}

// flightOf is flight for size bytes in at least n segments.
func flightOf(h *H, p *Peer, c Conn, size, n int, salt byte) ([]Segment, []byte) {
	h.T.Helper()
	data := pattern(size, salt)
	if _, err := c.Write(data); err != nil {
		h.T.Fatalf("write: %v", err)
	}
	segs, sent := burstUntil(p, len(data))
	h.Require("flight", sent == len(data) && len(segs) >= n, fmt.Sprintf("the %d bytes leave in one initial burst of at least %d segments", len(data), n),
		fmt.Sprintf("%d bytes in %d segments", sent, len(segs)))
	return segs, data
}

// burst collects the new data segments the DUT sends until it pauses for 30 ms. A segment that
// repeats earlier bytes, such as gVisor's tail loss probe on a near-zero RTT, is left out.
func burst(p *Peer) ([]Segment, int) { return burstUntil(p, 0) }

// burstUntil is burst, but it returns as soon as n bytes of new data are in, when n is above 0.
// A scenario that emulates a path delay answers the flight then, not 30 ms later: the pause would
// lengthen the RTT the DUT sees on that flight past the one it measured on the handshake, and on
// a loaded machine let the tail loss probe, due about 2 SRTT after the flight, fire before the
// answer arrives.
func burstUntil(p *Peer, n int) ([]Segment, int) {
	var segs []Segment
	sent := 0
	high := p.RcvNxt
	for n <= 0 || sent < n {
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
	return segs, sent
}

// dataEnd is the sequence number after the last byte of data written from r's base.
func dataEnd(r *receiver, data []byte) uint32 { return r.base + uint32(len(data)) }

// rexmitWatch notes which sequence numbers below high the DUT sends again.
type rexmitWatch struct {
	high   uint32
	seen   map[uint32]int
	ranges []SACKBlock // the byte ranges sent again
	fresh  int         // new segments, beyond high
	// informed, when set, keeps out of ranges a resend whose TSecr is older than informedTS: one
	// the DUT sent before it had the ACK that carried the SACK blocks, such as a tail loss probe
	// that fires while a slow testbench is still answering.
	informed   bool
	informedTS uint32
	probes     int // resends kept out of ranges
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
		if w.informed && s.Opts.TS != nil && int32(s.Opts.TS.Ecr-w.informedTS) < 0 {
			w.probes++
			return
		}
		w.ranges = append(w.ranges, SACKBlock{s.Seq, s.Seq + uint32(len(s.Payload))})
		return
	}
	w.high = max32(w.high, s.Seq+uint32(len(s.Payload)))
	w.fresh++
}

func (w *rexmitWatch) has(seq uint32) bool { return w.seen[seq] > 0 }

// resentIn reports whether a byte of any of the ranges was sent again. Ranges, not sequence
// numbers, are compared, because a resend may be cut differently from the original, as after
// a lower path MTU.
func (w *rexmitWatch) resentIn(ranges ...SACKBlock) bool {
	for _, x := range w.ranges {
		for _, r := range ranges {
			if after(x.Right, r.Left) && after(r.Right, x.Left) {
				return true
			}
		}
	}
	return false
}

// reset forgets the retransmissions seen so far.
func (w *rexmitWatch) reset() { w.seen, w.ranges = map[uint32]int{}, nil }

// rangesOf returns the byte ranges of the listed segments.
func rangesOf(segs []Segment, idx ...int) []SACKBlock {
	var out []SACKBlock
	for _, i := range idx {
		out = append(out, SACKBlock{segs[i].Seq, segs[i].Seq + uint32(len(segs[i].Payload))})
	}
	return out
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
	p, c := sackConnect(h, l, port)
	h.Require("sack", p.SACK, "SACK negotiated", yesNo(p.SACK, "SACK", "no SACK"))
	segs, data := flight(h, p, c, 9, 0xa1)
	start := h.Now()
	r := newReceiver(p)
	w := newWatch(segs)
	r.take(segs[0])
	// a resend the DUT makes before it has these ACKs knows nothing of their SACK blocks
	w.informed, w.informedTS = true, p.TSVal()
	p.Send(r.ack(p.TSRecent))
	dupacks(r, segs, arriving(segs, 1, 3, 5)...) // the second, fourth and sixth segments are lost
	holes := func() bool { return w.has(segs[1].Seq) && w.has(segs[3].Seq) && w.has(segs[5].Seq) }
	// the time the last hole arrived, not the end of the watch, which ends 150 ms after start
	var allAt time.Time
	deadline := h.Now().Add(h.Prompt() + 50*time.Millisecond)
	for {
		s, ok := p.Next(max(deadline.Sub(h.Now()), 0))
		if !ok {
			break
		}
		w.note(s)
		r.take(s)
		if allAt.IsZero() && holes() {
			allAt = h.Now()
		}
	}
	all := !allAt.IsZero()
	h.Check("all-holes-in-one-round", all, "the three holes are resent before any new cumulative ACK",
		fmt.Sprintf("holes resent: %v %v %v", w.has(segs[1].Seq), w.has(segs[3].Seq), w.has(segs[5].Seq)))
	if all {
		h.Measure("holes-resent_ms", allAt.Sub(start).Milliseconds())
	}
	h.Check("before-rto", all && allAt.Sub(start) < 180*time.Millisecond, "the holes are resent before an RTO could fire",
		yesNo(all && allAt.Sub(start) < 180*time.Millisecond, "before 180 ms", "not before 180 ms"))
	ok := finish(p, r, w, dataEnd(r, data), 2*time.Second)
	h.Check("completes", ok, "everything is acknowledged within 2 s", yesNo(ok, "complete", "incomplete"))
	before := len(w.seen)
	collect(p, 300*time.Millisecond, w, nil)
	sacked := rangesOf(segs, arriving(segs, 1, 3, 5)...)
	h.Check("sacked-not-resent", !w.resentIn(sacked...), "no SACKed byte is sent again once the SACK blocks are in",
		yesNo(w.resentIn(sacked...), "SACKed resent", "none"))
	h.Measure("resends-before-the-sack", w.probes)
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
	p, c := sackConnect(h, l, port)
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
	w.reset() // count only what follows the RTO
	r.take(rto)
	// The ACK of the repaired hole opens the window after the RTO. The testbench takes the burst
	// it lets out before it answers again, so a go-back-N resend of SACKed data shows.
	p.Send(r.ack(p.TSRecent))
	collect(p, 50*time.Millisecond, w, r)
	ok = finish(p, r, w, dataEnd(r, data), 3*time.Second)
	h.Check("completes", ok, "everything is acknowledged within 3 s of the RTO", yesNo(ok, "complete", "incomplete"))
	collect(p, 300*time.Millisecond, w, nil)
	sacked := rangesOf(segs, arriving(segs, 1, 5)...)
	h.Check("sacked-not-resent-after-rto", !w.resentIn(sacked...), "after the RTO no SACKed byte is resent",
		yesNo(w.resentIn(sacked...), "SACKed resent", "none"))
	intact(h, r, data)
}

// sackRTOIslands loses every other segment of a ten-segment flight, the first included, so the
// RTO comes with five SACKed islands. After the RTO resend repairs the first hole, the island
// after it joins the cumulative ACK and four remain, one more than the three SACK blocks an ACK
// carries with timestamps. A sender that kept its scoreboard across the RTO still skips the
// island no ACK mentions any more; one that rebuilt it from the latest ACK resends it.
func sackRTOIslands(h *H) {
	const port = 8035
	l := h.Listen(port)
	p, c := sackConnect(h, l, port)
	h.Require("sack", p.SACK, "SACK negotiated", yesNo(p.SACK, "SACK", "no SACK"))
	// 13400 bytes: ten segments on every engine, gVisor's 1340-byte segments included
	segs, data := flightOf(h, p, c, 10*1340, 10, 0xa6)
	h.Require("ten-segments", len(segs) == 10, "ten segments", fmt.Sprintf("%d segments", len(segs)))
	r := newReceiver(p)
	w := newWatch(segs)
	islands := []int{1, 3, 5, 7, 9}
	dupacks(r, segs, islands...)
	collect(p, h.Prompt()+50*time.Millisecond, w, nil) // the fast retransmissions are lost
	before := w.seen[segs[0].Seq]
	rto, ok := p.Await(3*time.Second, func(s Segment) bool { w.note(s); return isData(s) && s.Seq == segs[0].Seq })
	h.Require("rto", ok && w.seen[segs[0].Seq] > before, "an RTO resends the first segment", segDesc(rto, ok))
	w.reset()
	r.take(rto)
	a := r.ack(p.TSRecent)
	h.Measure("sack-blocks-after-rto", len(a.Opts.SACK))
	p.Send(a)
	collect(p, 50*time.Millisecond, w, r)
	ok = finish(p, r, w, dataEnd(r, data), 3*time.Second)
	h.Check("completes", ok, "everything is acknowledged within 3 s of the RTO", yesNo(ok, "complete", "incomplete"))
	collect(p, 300*time.Millisecond, w, nil)
	sacked := rangesOf(segs, islands...)
	h.Check("islands-not-resent", !w.resentIn(sacked...), "after the RTO no island is resent, not even the one the ACKs no longer mention",
		yesNo(w.resentIn(sacked...), "SACKed resent", "none"))
	intact(h, r, data)
}

// sackPMTUSplit lowers the path MTU to 1000 bytes while a full-sized flight is unacknowledged and
// partly SACKed. The DUT resends what was not SACKed, split into segments that fit the new MTU,
// and does not resend the SACKed segments.
func sackPMTUSplit(h *H) {
	const port = 8032
	const newMTU = 1000
	l := h.Listen(port)
	p, c := sackConnect(h, l, port)
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
	// The burst the ICMP lets out is taken whole before the testbench answers, so a sender that
	// builds segments as they are pulled still shows whether it resends SACKed bytes.
	w.reset()
	deadline := h.Now().Add(3 * time.Second)
	for {
		s, ok := p.Next(50 * time.Millisecond)
		if !ok {
			break
		}
		w.note(s)
		if isData(s) {
			if len(s.Marshal()) > newMTU {
				over++
			}
			r.take(s)
		}
	}
	sackedRange := SACKBlock{segs[2].Seq, segs[3].Seq + uint32(len(segs[3].Payload))}
	resentSACKed := w.resentIn(sackedRange)
	p.Send(r.ack(p.TSRecent))
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
	resentSACKed = resentSACKed || w.resentIn(sackedRange)
	h.Check("sacked-not-resent", !resentSACKed, "no byte of the two SACKed segments is resent",
		yesNo(resentSACKed, "SACKed resent", "none"))
	intact(h, r, data)
}

// sackRenege has the receiver discard what it SACKed: after the hole is resent, the testbench's
// cumulative ACK stops at the first SACKed segment and carries no SACK block. The sender must
// clear its SACK marks and resend from the cumulative ACK, as Linux's tcp_check_sack_reneging
// does, instead of waiting forever on data it believes delivered.
func sackRenege(h *H) {
	const port = 8033
	l := h.Listen(port)
	p, c := sackConnect(h, l, port)
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
	// Linux re-arms its timer to max(SRTT/2, 10 ms) on a renege; 150 ms is below the RTO floor.
	s3, ok := p.Await(150*time.Millisecond, func(s Segment) bool { w.note(s); return isData(s) && s.Seq == segs[2].Seq })
	h.Check("resends-sacked", ok, "the first segment the receiver dropped is resent within 150 ms, before an RTO", segDesc(s3, ok))
	if ok {
		fresh.take(s3)
	}
	done := finish(p, fresh, w, dataEnd(fresh, data), 3*time.Second)
	h.Check("completes", done, "everything is acknowledged within 3 s", yesNo(done, "complete", "incomplete"))
	intact(h, fresh, data)
}

// limitedTransmit has the application write more than the initial window and loses the first
// segment. RFC 3042: each of the first two duplicate ACKs lets the sender send one new segment,
// and it retransmits nothing before the third. The duplicate ACKs come 20 ms apart, as the
// arrivals of the segments that cause them would space them. This variant runs at the
// testbench's near-zero RTT with the reference Linux's RACK off, so it covers RFC 3042 under the
// duplicate-threshold rule alone.
func limitedTransmit(h *H) { limitedTransmitAt(h, 8034, 0) }

// limitedTransmitRACK is limitedTransmit on a path with an RTT of ltRTT and the reference
// Linux's RACK on. RFC 8985's reorder window, a quarter of the minimum RTT, is then longer than
// the two duplicate ACKs and the time the checks watch after them, so a RACK sender keeps the
// first segment unmarked and Limited Transmit applies as on a real path.
func limitedTransmitRACK(h *H) { limitedTransmitAt(h, 8036, ltRTT) }

// ltRTT is the path delay of limitedTransmitRACK. The handshake's RTT, 5 ms less, is the minimum
// RTT, so the reorder window is at least ltReorder, about 99 ms: 59 ms more than the 40 ms from
// the first duplicate ACK to the end of the checks, room for a slow testbench.
const ltRTT = 400 * time.Millisecond

// ltReorder is the shortest reorder window a RACK sender can have on ltRTT's path: a quarter of
// the handshake's RTT, less 1 ms for a clock that counts whole milliseconds.
const ltReorder = (ltRTT-5*time.Millisecond)/4 - time.Millisecond

// ltAttempts bounds how often limitedTransmitRACK starts over when the testbench was too slow
// for its checks to mean anything.
const ltAttempts = 3

// ltObservation is what one attempt of limitedTransmitAt saw: the new segments after each
// duplicate ACK and the retransmissions, counting only what reached the testbench before the
// reorder window could have ended.
type ltObservation struct {
	fresh   [2]int
	rexmits int
	// late counts the retransmissions that came once the reorder window could have ended, which
	// RFC 8985 allows; they are measured, not checked.
	late int
	// probes counts the resends sent before the DUT had the first duplicate ACK.
	probes int
	// slow is set when the testbench sent the second duplicate ACK so late that a retransmission
	// it caused could only arrive after the reorder window, out of the checks' reach.
	slow bool
}

func limitedTransmitAt(h *H, port uint16, rtt time.Duration) {
	l := h.Listen(port)
	var o ltObservation
	for i := 1; ; i++ {
		o = limitedTransmitOnce(h, l, port, rtt)
		if !o.slow || i == ltAttempts {
			break
		}
		h.T.Logf("attempt %d: the testbench sent the second duplicate ACK too late for the reorder window; starting over", i)
	}
	h.Measure("testbench-too-slow", o.slow)
	h.Measure("resends-before-the-first-dupack", o.probes)
	if rtt > 0 {
		h.Measure("resent-after-the-reorder-window", o.late)
	}
	for i, id := range []string{"first-dupack.new-data", "second-dupack.new-data"} {
		h.Check(id, o.fresh[i] == 1, "the duplicate ACK lets exactly one new segment out within 20 ms", fmt.Sprintf("%d new segments", o.fresh[i]))
	}
	h.Check("no-retransmit-before-third", o.rexmits == 0, "nothing is resent after two duplicate ACKs", fmt.Sprintf("%d retransmissions", o.rexmits))
}

// limitedTransmitOnce runs limitedTransmitAt on a new connection.
func limitedTransmitOnce(h *H, l Listener, port uint16, rtt time.Duration) ltObservation {
	d := Dial{SYN: StandardSYN()}
	if rtt > 0 {
		d.AckDelay = rtt - 5*time.Millisecond // the minimum RTT, below every later sample
	}
	p, _, c := h.ConnectWith(l, port, d)
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
	if rtt > 0 {
		// the first duplicate ACK comes back one path delay after the flight left
		collect(p, rtt, w, nil)
	}
	// On RACK's path, a RACK sender may resend the first segment once the reorder window from
	// the first duplicate ACK is over; whatever reaches the testbench before then is checked.
	// Without a path delay the reorder window is about zero, so everything is checked.
	o := ltObservation{rexmits: len(w.seen)}
	var window time.Time
	in := func() bool { return rtt == 0 || h.Now().Before(window) }
	// 20 ms between the duplicate ACKs, as segments arriving one after another space them; sent
	// back to back, the second reaches Linux before it has sent the first new segment on.
	// A resend whose TSecr is older than the first duplicate ACK was sent before the DUT had it,
	// such as a tail loss probe a slow testbench let fire; it answers no duplicate ACK and is
	// measured, not counted.
	w.informed, w.informedTS = true, p.TSVal()
	resent := map[uint32]bool{}
	for seq := range w.seen {
		resent[seq] = true
	}
	for i := range 2 {
		if i == 0 {
			window = h.Now().Add(ltReorder)
		} else if rtt > 0 && h.Now().After(window.Add(-ltReorder/2)) {
			// a retransmission this ACK caused could reach the testbench only after the window
			o.slow = true
		}
		dupacks(r, segs, 1+i)
		deadline := h.Now().Add(20 * time.Millisecond)
		for {
			s, ok := p.Next(max(deadline.Sub(h.Now()), 0))
			if !ok {
				break
			}
			high, fresh, probes := w.high, w.fresh, w.probes
			w.note(s)
			again := isData(s) && after(high, s.Seq) && w.probes == probes && !resent[s.Seq]
			if again {
				resent[s.Seq] = true
			}
			switch {
			case !in() && again:
				o.late++
			case !in():
			case again:
				o.fresh[i] += w.fresh - fresh
				o.rexmits++
			default:
				o.fresh[i] += w.fresh - fresh
			}
		}
	}
	o.probes = w.probes
	if o.slow {
		c.Abort()
	}
	return o
}
