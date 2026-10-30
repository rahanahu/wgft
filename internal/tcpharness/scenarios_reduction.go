package tcpharness

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

// The loss-response family: what the DUT sends after a congestion window reduction, read as the
// data it sends in each round trip. RFC 5681 3.1 and RFC 9438 4.6 set ssthresh at a loss to no
// more than beta times FlightSize, beta being 0.5 for Reno and 0.7 for CUBIC. FlightSize is the
// data sent and not cumulatively acknowledged, so read literally it counts SACKed bytes, and beta
// times that span may come out above the window the sender had: a "reduction" that raises the
// rate. The reference Linux reduces from its congestion window, cwnd >> 1 for the pinned Reno, as
// RFC 9438 4.6 allows, and the family holds the DUT to that: what follows a loss is at most beta
// times the window before it. The bounds are the reference Linux's behaviour, not the RFCs' text.
//
// The testbench is the path: it answers a round's segments with one ACK each, back to back, and
// then collects what the DUT sends for lossRTT, which is the next round. Every engine sends its
// response to an ACK within a millisecond, so on real time and on a ClockedDUT alike a round is
// the window the DUT had for that round trip.

// lossRTT is the round trip of the family: long enough that the RACK reorder window, a quarter
// of it, and every response to an ACK fall inside one round, and below the 200 ms RTO floor plus
// the RTT, so no round sees an RTO by accident.
const lossRTT = 100 * time.Millisecond

// lossBeta bounds a reduction: CUBIC's beta, the larger of the two the RFCs give, with the slack
// lossSlack for a sender that rounds up or sends a segment or two beyond ssthresh as it leaves
// recovery, as rfc2525-window-deflation allows.
const (
	lossBeta  = 0.7
	lossSlack = 3
)

// reductionBound is the most a round after a reduction from before segments may carry.
func reductionBound(before int) int { return int(lossBeta*float64(before)+0.999) + lossSlack }

// bulkFlow is one connection whose application always has data to send, read round by round.
type bulkFlow struct {
	h     *H
	p     *Peer
	r     *receiver
	chunk []byte
	// rounds is the size of every flight so far, for the log.
	rounds []int
}

// bulkOpen opens a connection with a handshake RTT just under lossRTT and has the application
// write without pause.
func bulkOpen(h *H, port uint16, salt byte) *bulkFlow {
	h.T.Helper()
	l := h.Listen(port)
	p, _, c := h.ConnectWith(l, port, Dial{SYN: StandardSYN(), AckDelay: lossRTT - 5*time.Millisecond})
	h.Require("sack", p.SACK && p.TS, "SACK and timestamps negotiated", fmt.Sprintf("SACK %v, timestamps %v", p.SACK, p.TS))
	f := &bulkFlow{h: h, p: p, r: newReceiver(p), chunk: pattern(64<<10, salt)}
	filled := make(chan struct{})
	go func() {
		for i := 0; ; i++ {
			if i == 3 {
				close(filled)
			}
			if _, err := c.Write(f.chunk); err != nil {
				if i < 3 {
					close(filled)
				}
				return
			}
		}
	}()
	select {
	case <-filled:
	case <-time.After(5 * time.Second):
		h.T.Fatalf("the application's writes did not fill the send buffer")
	}
	return f
}

// collect takes every data segment of the flow the DUT sends within d.
func (f *bulkFlow) collect(d time.Duration) []Segment {
	var out []Segment
	deadline := f.h.Now().Add(d)
	for {
		s, ok := f.p.Next(max(deadline.Sub(f.h.Now()), 0))
		if !ok {
			return out
		}
		if isData(s) {
			out = append(out, s)
		}
	}
}

// first is the initial window: what the DUT sends in the first round trip.
func (f *bulkFlow) first() []Segment {
	fl := f.collect(lossRTT)
	f.rounds = append(f.rounds, len(fl))
	return fl
}

// round has every segment of flight arrive, in the order order gives, except those lost says the
// path dropped, answers each with an ACK echoing the segment's own TSval, and returns what the
// DUT sends in the next round trip.
func (f *bulkFlow) round(flight []Segment, lost func(i int) bool, order []int) []Segment {
	if order == nil {
		order = make([]int, len(flight))
		for i := range order {
			order[i] = i
		}
	}
	for _, i := range order {
		if lost != nil && lost(i) {
			continue
		}
		s := flight[i]
		f.r.take(s)
		ecr := f.p.TSRecent
		if s.Opts.TS != nil {
			ecr = s.Opts.TS.Val
		}
		f.p.Send(f.r.ack(ecr))
	}
	if _, clocked := f.h.DUT.(ClockedDUT); clocked {
		time.Sleep(2 * time.Millisecond) // the application refills the send buffer on its own goroutine
	}
	next := f.collect(lossRTT)
	f.rounds = append(f.rounds, len(next))
	return next
}

// slowStartTo runs loss-free rounds until a flight carries at least n segments.
func (f *bulkFlow) slowStartTo(flight []Segment, n int) []Segment {
	for i := 0; len(flight) < n && i < 8; i++ {
		flight = f.round(flight, nil, nil)
	}
	f.h.Require("slow-start", len(flight) >= n, fmt.Sprintf("slow start reaches %d segments in a round", n), fmt.Sprintf("%d segments", len(flight)))
	return flight
}

// log reports the size of every round so far.
func (f *bulkFlow) log() {
	var b []string
	for _, n := range f.rounds {
		b = append(b, fmt.Sprint(n))
	}
	f.h.Measure("rounds", strings.Join(b, " "))
}

// intact checks that what the testbench assembled in order is the application's stream: the
// chunk written again and again.
func (f *bulkFlow) intact() {
	n := int(f.r.cum - f.r.base)
	got := f.r.stream(n)
	want := bytes.Repeat(f.chunk, n/len(f.chunk)+1)[:n]
	f.h.Check("stream-intact", bytes.Equal(got, want), "the bytes acknowledged in order are the application's stream",
		fmt.Sprintf("%d bytes in order, equal %v", n, bytes.Equal(got, want)))
}

// seqEnd is the sequence number after s.
func seqEnd(s Segment) uint32 { return s.Seq + uint32(len(s.Payload)) }

// highest is the sequence number after the highest byte of segs, or from if that is higher.
func highest(from uint32, segs []Segment) uint32 {
	for _, s := range segs {
		from = max32(from, seqEnd(s))
	}
	return from
}

// indexOf is the index of the first segment of segs that starts at seq, or -1.
func indexOf(segs []Segment, seq uint32) int {
	for i, s := range segs {
		if s.Seq == seq {
			return i
		}
	}
	return -1
}

// reductionCheck compares the largest of the rounds after a reduction with the bound.
func reductionCheck(h *H, id string, before int, after ...int) {
	got := 0
	for _, n := range after {
		got = max(got, n)
	}
	bound := reductionBound(before)
	h.Measure(id+".before", before)
	h.Measure(id+".after", got)
	h.Check(id, got <= bound, fmt.Sprintf("the reference Linux reduces from its congestion window, not from the span outstanding, which RFC 5681 3.1 and "+
		"RFC 9438 4.6 allow: in the %d rounds after the recovery, a round carries at most beta x the %d segments of the round before the loss and %d more: %d",
		len(after), before, lossSlack, bound), fmt.Sprintf("%s the bound", yesNo(got <= bound, "within", "above")))
}

// chainedRecovery loses a segment of an 80-segment window, and then a new segment the DUT sends
// during that recovery. The resend of the first loss reaches the testbench last of its round, so
// the ACK that ends the first recovery already carries the SACK blocks above the second hole and
// a second recovery follows at once. A DUT that keeps sending through the first recovery, as
// Linux's PRR does, has by then sent about a window beyond the second hole on top of the round
// that holds it, most of it SACKed: a reduction computed from that span, not from the window,
// comes out above the window of the first recovery. The check is that the rounds after the second
// recovery carry at most beta times the round of the first.
func chainedRecovery(h *H) {
	f := bulkOpen(h, 8401, 0xe1)
	defer f.log()
	flight := f.slowStartTo(f.first(), 80)
	a := flight[0]
	// the first segment is lost: the others draw SACK blocks and the first recovery
	r1 := f.round(flight, func(i int) bool { return i == 0 }, nil)
	ia := indexOf(r1, a.Seq)
	h.Require("first-recovery", ia >= 0, "the SACK blocks of the rest of the window make the DUT resend the first segment within the round",
		yesNo(ia >= 0, "resent", "not resent"))
	// the second hole: the first new segment the DUT sends after the resend, beyond everything it
	// sent before, so beyond the first recovery's recovery point
	point := highest(seqEnd(flight[len(flight)-1]), r1[:ia])
	ib := -1
	for i := ia + 1; i < len(r1); i++ {
		if !after(point, r1[i].Seq) {
			ib = i
			break
		}
	}
	h.Require("new-data-in-recovery", ib >= 0 && len(r1)-ib > 3, "the DUT sends new data during the first recovery, with more than three segments after the first of it",
		fmt.Sprintf("%s new segments after the resend", yesNo(ib >= 0, fmt.Sprint(len(r1)-ib), "0")))
	b := r1[ib]
	// the resend of the first loss arrives last; the second hole is lost
	order := make([]int, 0, len(r1))
	for i := range r1 {
		if i != ia {
			order = append(order, i)
		}
	}
	order = append(order, ia)
	r2 := f.round(r1, func(i int) bool { return i == ib }, order)
	r3 := f.round(r2, nil, nil)
	resent := indexOf(r2, b.Seq) >= 0 || indexOf(r3, b.Seq) >= 0
	h.Check("second-hole-resent", resent, "the second hole is resent within two rounds", yesNo(resent, "resent", "not resent"))
	// the second recovery starts as r2 goes out and ends while the testbench acknowledges r2,
	// so r3 and r4 are the first two rounds after it
	r4 := f.round(r3, nil, nil)
	reductionCheck(h, "reduced", len(r1), len(r3), len(r4))
	f.round(r4, nil, nil)
	h.Check("completes", after(f.r.cum, seqEnd(b)), "everything up to the second hole is acknowledged", yesNo(after(f.r.cum, seqEnd(b)), "acknowledged", "not acknowledged"))
	f.intact()
}

// reorderWaitRecovery has the DUT see reordering once, so that RACK keeps a reorder window of a
// quarter of the minimum RTT, then loses the first segment of a 40-segment window. While the
// reorder window runs, the SACK blocks of the other 39 lower the DUT's data in flight and it
// sends new data, so when it marks the first segment lost it has about two windows outstanding,
// half of them SACKed. The reduction is from the window, 40 segments, not from that span.
func reorderWaitRecovery(h *H) {
	f := bulkOpen(h, 8402, 0xe2)
	defer f.log()
	flight := f.first()
	h.Require("initial-window", len(flight) >= 6, "an initial window of at least six segments", fmt.Sprintf("%d segments", len(flight)))
	// the fourth segment arrives after the fifth: an original segment fills a hole below a SACKed
	// one, which RFC 8985 6.2 counts as reordering
	order := []int{0, 1, 2, 4, 3}
	for i := 5; i < len(flight); i++ {
		order = append(order, i)
	}
	flight = f.round(flight, nil, order)
	flight = f.slowStartTo(flight, 40)
	before := len(flight)
	a := flight[0]
	r1 := f.round(flight, func(i int) bool { return i == 0 }, nil)
	ia := indexOf(r1, a.Seq)
	h.Require("loss-detected", ia >= 0, "the first segment is resent within the round", yesNo(ia >= 0, "resent", "not resent"))
	h.Measure("new-before-resend", ia)
	// the recovery ends while the testbench acknowledges r1, so r2 is the first round after it;
	// the third round after it shows a window that grows much faster than congestion avoidance
	r2 := f.round(r1, nil, nil)
	r3 := f.round(r2, nil, nil)
	r4 := f.round(r3, nil, nil)
	reductionCheck(h, "reduced", before, len(r2), len(r3), len(r4))
	f.round(r4, nil, nil)
	h.Check("completes", after(f.r.cum, seqEnd(a)), "the lost segment is acknowledged", yesNo(after(f.r.cum, seqEnd(a)), "acknowledged", "not acknowledged"))
	f.intact()
}

// rtoAfterBurst grows the window to 40 segments, loses a quarter of it in one burst, and then
// every segment until the RTO fires. After the RTO the DUT slow-starts from one segment and
// leaves slow start at ssthresh, which the rounds show: the first round that grows by less than
// 1.7 times carries about ssthresh. A ssthresh between 1.7 and 2 times the round before shows one
// round of congestion avoidance late, a segment above it.
//
// RFC 5681 3.1 sets ssthresh after an RTO to no more than half of FlightSize, and RFC 6675 5.1
// sets nothing for it, so the RFCs' text allows any value down to two segments. The reference
// Linux keeps the recovery's ssthresh at an RTO inside it, tcp_enter_loss, here half the window,
// and the family holds the DUT to that band: not above the window before the loss, which lets
// through a sender that takes half of FlightSize with the SACKed span counted, and not below a
// quarter of it, which lets through a sender that halves at the recovery and again at the RTO, so
// a sender that counts nothing in flight and collapses to two segments fails.
func rtoAfterBurst(h *H) {
	f := bulkOpen(h, 8403, 0xe3)
	defer f.log()
	flight := f.slowStartTo(f.first(), 40)
	w := len(flight)
	lo, hi := w/4, w/2
	hole := flight[lo]
	// the burst is lost; the rest draws SACK blocks and recovery, whose segments are all lost
	rec := f.round(flight, func(i int) bool { return i >= lo && i < hi }, nil)
	h.Measure("sent-in-recovery", len(rec))
	start := h.Now()
	rto, ok := f.p.Await(3*time.Second, isData)
	h.Require("rto", ok, "a segment is resent within 3 s", segDesc(rto, ok))
	h.Measure("rto-after_ms", h.Now().Sub(start).Milliseconds())
	h.Check("rto.first-hole", rto.Seq == hole.Seq, "the RTO resends the first segment of the lost burst", yesNo(rto.Seq == hole.Seq, "the first hole", "another segment"))
	fl := append([]Segment{rto}, f.collect(lossRTT)...)
	sizes := []int{len(fl)}
	f.rounds = append(f.rounds, len(fl))
	ss, ended := 0, false
	for range 12 {
		fl = f.round(fl, nil, nil)
		sizes = append(sizes, len(fl))
		if ended {
			break // one more round, for the log
		}
		if n := len(sizes); float64(sizes[n-1]) < 1.7*float64(sizes[n-2]) {
			ss, ended = sizes[n-1], true // a round of none, as a stalled sender's, ends it too
		}
	}
	h.Measure("ssthresh-implied", ss)
	h.Measure("window-before-loss", w)
	h.Require("leaves-slow-start", ended, "slow start after the RTO ends within 12 rounds", yesNo(ended, "ended", "did not end"))
	h.Check("ssthresh.not-above-window", ss <= w, fmt.Sprintf("the reference Linux keeps the recovery's ssthresh at the RTO, tcp_enter_loss, and RFC 5681 3.1 "+
		"allows no more than half of FlightSize: after the RTO, slow start ends at most at the window before the loss, %d segments", w),
		yesNo(ss <= w, "at or below it", "above it"))
	low := w / 4
	h.Check("ssthresh.not-collapsed", ss >= low, fmt.Sprintf("the reference Linux keeps the recovery's ssthresh at the RTO, tcp_enter_loss, where RFC 5681 3.1 "+
		"would allow two segments: slow start after the RTO goes on to at least a quarter of the window before the loss, %d segments, not to two", low),
		yesNo(ss >= low, "at or above it", "below it"))
	h.Check("completes", after(f.r.cum, seqEnd(flight[hi-1])), "the lost burst is acknowledged", yesNo(after(f.r.cum, seqEnd(flight[hi-1])), "acknowledged", "not acknowledged"))
	f.intact()
}
