package tcpharness

import (
	"fmt"
	"sync"
	"time"
)

// pacingRTT is the path the rcv-window-pacing scripts act out. wgstack-performance.md proposes 50
// ms with segments 0.5 ms apart; a DUT on the harness's clock moves in steps of 1 ms, so 80
// segments take 80 ms there, and 100 ms keeps the rounds from overlapping on every engine.
const (
	pacingRTT = 100 * time.Millisecond
	pacingGap = 500 * time.Microsecond
)

// The last round loses its first segment and pacingSecondHole. The read that filling the first
// hole frees, the segments before the second hole, stays small, so it does not raise the window
// limit's measurement; the out-of-order data behind the second hole, pacingHeld segments, is one
// and a half times that read, so how the free space counts it decides partial.window.
const (
	pacingSecondHole = 10
	pacingHeld       = 15
	pacingLossRound  = pacingSecondHole + 1 + pacingHeld
)

// pacingRounds is how many segments each round carries: wgstack-performance.md's 10, 20, 40 and
// 80, then rounds of 80 that hold the reads steady, so the window limit the reads measured stops
// rising and the window grows up to it, and the loss round.
var pacingRounds = []int{10, 20, 40, 80, 80, 80, 80, 80, pacingLossRound}

// pacingSteadyRounds is how many rounds before the loss round must not grow the largest window
// past the round before them: the window has reached the window limit.
const pacingSteadyRounds = 2

// The band for the largest window the reads lead to on the performance family, from the
// reference Linux's in this script: three quarters of the smallest it reached and one and a half
// times the largest, over the runs measured. Linux's buffer autotuning sets its window limit from
// what the application read in one RTT (tcp_rcv_space_adjust), and wgstack-performance.md has
// wgstack follow the same rule; how far Linux gets turns on where its RTT intervals fall.
// The values are 6.1's. The reference 7.2 sizes its buffer more tightly and reached 329,856 to
// 372,480 bytes over 18 runs, inside the band. The band keeps 6.1's values: the same rule applied
// to 7.2 would put the lower edge below wgstack's 256 KiB floor, where it no longer catches a
// receiver that never raises its window limit.
const (
	pacingLinuxLow  = 401_000
	pacingLinuxHigh = 737_000
	pacingBandLow   = pacingLinuxLow * 3 / 4
	pacingBandHigh  = pacingLinuxHigh * 3 / 2
)

// pacer drives one rcv-window-pacing connection: it sends each round's segments on time, has
// the application read at once, and checks every ACK's window as it comes.
type pacer struct {
	*ovfFlow
	sinceAck int  // data segments sent since the latest ACK
	baseline bool // an ACK of data has set maxWin
	maxWin   int  // the largest window an ACK has advertised
	roundWin int  // the largest window an ACK has advertised in this round
	stepBad  int
	worst    string
	clocked  bool
	buf      []byte
	// ecr is the TSecr the round's segments carry: the latest TSval the testbench had when the
	// round began, as a sender on the path sends a round on the ACKs of the round before. The DUT's
	// receiver RTT estimate then sees the path's RTT.
	ecr uint32

	mu   sync.Mutex
	read int // bytes the application has read
}

// next is ovfFlow.next that checks every ACK's window: it may exceed the largest window
// advertised before by at most twice the DUT's MSS for each segment sent since the previous ACK,
// or for one segment if none was, and one scale unit for the rounding of the window field. Linux
// grows rcv_ssthresh by at most twice its MSS for each segment it takes, and only while it lies
// below the free space (tcp_grow_window), so a window larger than any before comes only from
// that step. The ACK of a segment can show less of the step while the segment still waits to be
// read; the update after the read then shows the rest, which Linux did by up to 2,816 bytes. The
// first ACK of data sets the base: the SYN-ACK's window field is not scaled.
func (pc *pacer) next(d time.Duration) (Segment, bool) {
	s, ok := pc.ovfFlow.next(d)
	if !ok || !s.Has(FlagACK) || s.Has(FlagSYN) || s.Has(FlagRST) {
		return s, ok
	}
	n := pc.sinceAck
	pc.sinceAck = 0
	w := int(s.Window) << pc.p.DutWS
	pc.roundWin = max(pc.roundWin, w)
	if !pc.baseline {
		if s.Ack != pc.start {
			pc.baseline, pc.maxWin = true, w
		}
		return s, ok
	}
	if limit := pc.maxWin + 2*pc.mss*max(n, 1) + int(pc.unit()); w > limit {
		pc.stepBad++
		pc.h.T.Logf("window %d bytes, above the largest before by %d after %d segments", w, w-pc.maxWin, n)
		if pc.worst == "" {
			pc.worst = fmt.Sprintf("a window %d bytes above the largest before after %d segments", w-pc.maxWin, n)
		}
	}
	pc.maxWin = max(pc.maxWin, w)
	return s, ok
}

// await is ovfFlow.await through pacer.next.
func (pc *pacer) await(d time.Duration, match func(Segment) bool) (Segment, bool) {
	deadline := pc.h.Now().Add(d)
	for {
		s, ok := pc.next(max(deadline.Sub(pc.h.Now()), 0))
		if !ok {
			return Segment{}, false
		}
		if match(s) {
			return s, true
		}
	}
}

// until handles the DUT's segments until the scenario's clock reaches t. On a DUT on the
// harness's clock it moves the clock straight to t, so the gaps between segments are as sent.
func (pc *pacer) until(t time.Time) {
	for {
		now := pc.h.Now()
		if !now.Before(t) {
			return
		}
		if c, ok := pc.h.DUT.(ClockedDUT); ok {
			for {
				if _, ok := pc.next(0); !ok {
					break
				}
			}
			c.Advance(t.Sub(now))
			continue
		}
		pc.next(t.Sub(now))
	}
}

func (pc *pacer) readBytes() int {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return pc.read
}

// caughtUp waits, on a DUT on the harness's clock, until the application has read every byte up
// to seq. The reader goroutine's read cannot time out while data waits, but it runs on real time;
// waiting here keeps the engine's clock still while it reads, so a run does not turn on how the
// goroutines were scheduled. On real time the reader runs beside the testbench and nothing waits.
func (pc *pacer) caughtUp(seq uint32) {
	if !pc.clocked {
		return
	}
	want := int(seq - pc.start)
	for deadline := time.Now().Add(5 * time.Second); pc.readBytes() < want && time.Now().Before(deadline); {
		time.Sleep(20 * time.Microsecond)
	}
}

// send sends n stream bytes at seq with the round's TSecr. inOrder is how far the stream is in
// order once the DUT has it; caughtUp waits for the application to read up to there.
func (pc *pacer) send(seq uint32, n int, inOrder uint32) {
	s := pc.p.Segment(FlagACK|FlagPSH, seq, pc.at(seq, n))
	if s.Opts.TS != nil && pc.ecr != 0 {
		s.Opts.TS.Ecr = pc.ecr
	}
	pc.p.Send(s)
	pc.sinceAck++
	pc.caughtUp(inOrder)
}

// rcvWindowPacing acts out a 100 ms path: rounds of 10, 20, 40 and then 80 segments 0.5 ms apart,
// read at once by the application, and checks that no ACK advertises a window larger than every
// earlier one by more than two segments for each segment that arrived since the previous ACK
// (wgstack-performance.md, Linux's receiver after a queue overflow: the window opens per arriving
// segment, by rcv_ssthresh's step). With band, the window the reads lead to must lie in a band
// around the reference Linux's. The last round loses its first segment and the eleventh.
// Filling the first hole while the second stays must not open the window by more than the
// in-order data it frees less half the out-of-order data still held: Linux's free space counts
// that data at its allocation size, at least its length, and halves it. Filling the second hole
// acknowledges everything at once.
func rcvWindowPacing(band bool) func(h *H) {
	return func(h *H) { rcvWindowPacingOn(h, band) }
}

func rcvWindowPacingOn(h *H, band bool) {
	const port = 8404
	pc := &pacer{ovfFlow: ovfOpen(h, port), buf: make([]byte, 256<<10)}
	_, pc.clocked = h.DUT.(ClockedDUT)
	p := pc.p
	mss := pc.mss
	go func() {
		// A read that cannot time out while data waits: the deadline is far off.
		pc.c.SetReadDeadline(time.Now().Add(30 * time.Second))
		for {
			n, err := pc.c.Read(pc.buf)
			pc.mu.Lock()
			pc.read += n
			pc.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	start := h.Now()
	var hole1, hole2, mid, end uint32
	limited := 0
	roundMax := make([]int, len(pacingRounds))
	loss := len(pacingRounds) - 1
	var lossEdge uint32 // the right edge when the loss round began
	for r, n := range pacingRounds {
		pc.until(start.Add(time.Duration(r) * pacingRTT))
		roundStart := h.Now()
		pc.ecr = p.TSRecent
		pc.roundWin = 0
		lossEdge = pc.right
		for i := range n {
			pc.until(roundStart.Add(time.Duration(i) * pacingGap))
			if int(int32(pc.last-p.SndNxt)) < mss {
				limited++
				break
			}
			seq := p.SndNxt
			p.SndNxt += uint32(mss)
			switch {
			case r == loss && i == 0:
				hole1 = seq
			case r == loss && i == pacingSecondHole:
				hole2 = seq
			case r == loss:
				pc.send(seq, mss, hole1)
			default:
				pc.send(seq, mss, p.SndNxt)
			}
		}
		if r < loss {
			pc.until(roundStart.Add(pacingRTT - time.Millisecond))
		}
		roundMax[r] = pc.roundWin
		h.Measure(fmt.Sprintf("round%d.largest-window", r+1), roundMax[r])
	}
	end = p.SndNxt
	mid = hole2 + uint32(mss)
	pc.until(h.Now().Add(pacingRTT / 2))
	h.Measure("rounds.window-limited", limited)

	// The window stopped growing before the loss round, so the window limit binds there.
	steady := true
	for r := loss - pacingSteadyRounds; r < loss; r++ {
		steady = steady && roundMax[r] <= roundMax[r-1]+int(pc.unit())
	}
	h.Require("steady", steady, fmt.Sprintf("the largest window of the %d rounds before the loss round grows no more", pacingSteadyRounds),
		yesNo(steady, "it does not", "it still grows"))
	if band {
		w := roundMax[loss-1]
		in := w >= pacingBandLow && w <= pacingBandHigh
		h.Check("window.band", in, fmt.Sprintf("the window the reads lead to lies between %d and %d bytes", pacingBandLow, pacingBandHigh),
			yesNo(in, "within the band", yesNo(w < pacingBandLow, "below the band", "above the band")))
	}

	// While the first hole stays, the out-of-order data only takes free space: once the window has
	// reached the window limit, the right edge stays where the loss round found it.
	kept := !after(pc.right, lossEdge+pc.unit())
	h.Measure("loss.edge-growth", int32(pc.right-lossEdge))
	h.Check("loss.edge-kept", kept, "while the first hole stays, the right edge stays where it was when the loss round began",
		yesNo(kept, "it stays", "it grows"))

	// The first hole: RCV.NXT moves to the second hole, the application reads what it frees.
	before := pc.right
	pc.send(hole1, mss, hole2)
	a, ok := pc.await(h.Prompt(), func(s Segment) bool { return isPureAck(s) && after(s.Ack, hole1) })
	h.Check("partial.ack", ok && a.Ack == hole2 && covers(a, mid, end), "filling the first hole acknowledges at once up to the second, which the SACK still reports",
		yesNo(ok && a.Ack == hole2 && covers(a, mid, end), "it does", "it does not"))
	pc.until(h.Now().Add(20 * time.Millisecond))
	freed := int(hole2 - hole1)
	heldOOO := int(end - mid)
	// The window after the partial fill: one more segment past the held span draws an ACK with it.
	if k := min(mss, int(int32(pc.last-end))); k > 0 {
		pc.send(end, k, hole2)
		end += uint32(k)
		p.SndNxt = max32(p.SndNxt, end)
		pc.await(h.Prompt(), func(s Segment) bool { return isPureAck(s) && s.Ack == hole2 && covers(s, mid, end) })
	}
	opened := int(int32(pc.right - before))
	// One segment of slack covers the rounding of the window field and a receiver's SWS
	// avoidance, which opens the window in steps of up to a segment.
	bound := max(0, freed-heldOOO/2) + mss
	h.Measure("partial.freed-bytes", freed)
	h.Measure("partial.held-bytes", heldOOO)
	h.Measure("partial.opened-bytes", opened)
	h.Check("partial.window", opened <= bound,
		"filling the first hole opens the window by at most what it frees less half the out-of-order data still held",
		yesNo(opened <= bound, "within that", "beyond that"))

	pc.send(hole2, mss, end)
	a, ok = pc.await(h.Prompt(), func(s Segment) bool { return isPureAck(s) && !after(hole2+uint32(mss), s.Ack) })
	h.Check("hole.ack", ok && a.Ack == end && len(a.Opts.SACK) == 0, "filling the second hole acknowledges everything at once, with no SACK block",
		yesNo(ok && a.Ack == end && len(a.Opts.SACK) == 0, "it does", "it does not"))
	pc.until(h.Now().Add(20 * time.Millisecond))

	if pc.worst != "" {
		h.T.Logf("first window beyond the step: %s", pc.worst)
	}
	h.Measure("largest-window", pc.maxWin)
	h.Check("window.step", pc.stepBad == 0,
		"no ACK advertises a window above every earlier one by more than two segments for each segment since the previous ACK",
		yesNo(pc.stepBad == 0, "none does", "some do"))
	h.Measure("right-edge.rounded-below", pc.rounded)
	h.Check("right-edge.kept", pc.retracted == 0, "no ACK moves the right edge of the window back by a scale unit or more",
		yesNo(pc.retracted == 0, "none did", fmt.Sprintf("%d did; %s", pc.retracted, pc.firstRetract)))
	want := int(end - pc.start)
	deadline := time.Now().Add(2 * time.Second)
	for pc.readBytes() < want && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	got := pc.readBytes()
	h.Check("delivered", got == want, "the application reads every byte", fmt.Sprintf("%d of %d bytes", got, want))
}

const pacingRefs = "RFC 9293 3.8.6, RFC 7323 2.4, RFC 2018 4, RFC 5681 4.2; wgstack-performance.md, Linux's receiver after a queue overflow, rcv-window-pacing"
