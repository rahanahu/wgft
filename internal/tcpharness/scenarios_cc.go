package tcpharness

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// CongestionScenarios check a sender's congestion window against the formulas of RFC 9438,
// CUBIC, and RFC 9406, HyStart++. wgstack-performance.md does not compare these with Linux,
// which ends slow start with its own HyStart and whose CUBIC differs in detail, so they run on a
// ClockedDUT only: the testbench is the path, it holds every ACK for exactly the round-trip time
// it emulates, and it reads the window as the data the DUT sends in one round.
var CongestionScenarios = []Scenario{
	{Name: "cubic-after-loss", Refs: "RFC 9438 4.2, 4.3, 4.6 and 4.8", Run: cubicAfterLoss},
	{Name: "cubic-fast-convergence", Refs: "RFC 9438 4.7", Run: cubicFastConvergence},
	{Name: "hystart-css", Refs: "RFC 9406 4.2 and 4.3", Run: hystartCSS},
	{Name: "hystart-css-back", Refs: "RFC 9406 4.3", Run: hystartBack},
	{Name: "hystart-css-ack-burst", Refs: "RFC 9406 4.2 and 4.3; wireguard-go writes a received batch to the Device before it reads", Run: hystartCSSBurst},
	{Name: "cubic-ack-burst", Refs: "RFC 9438 4.2 and 4.3; wireguard-go writes a received batch to the Device before it reads", Run: cubicBurst},
}

// The constants of RFC 9438 and RFC 9406 the scenarios compute with.
const (
	cubicC    = 0.4
	cubicBeta = 0.7

	hsMinThresh   = 4 * time.Millisecond
	hsMaxThresh   = 16 * time.Millisecond
	hsGrowthDiv   = 4
	hsCSSRounds   = 5
	ccRTT         = 100 * time.Millisecond
	ccWriteChunk  = 64 << 10
	ccWriteFilled = 3 // chunks written before the first round, about 192 KiB
)

// ccFlow is one connection whose application always has data to send, read round by round.
type ccFlow struct {
	h    *H
	clk  ClockedDUT
	p    *Peer
	r    *receiver
	smss float64
	// burst hands a round's ACKs to the DUT before reading anything it sends, as wireguard-go
	// writes a batch it received to the Device before its reader pulls; otherwise the tunnel
	// reads after each ACK.
	burst bool
}

func ccOpen(h *H, port uint16) *ccFlow {
	h.T.Helper()
	clk, ok := h.DUT.(ClockedDUT)
	if !ok {
		h.T.Skipf("the congestion scenarios need a DUT on a clock the harness drives")
	}
	l := h.Listen(port)
	p, _, c := h.ConnectWith(l, port, Dial{SYN: StandardSYN(), AckDelay: ccRTT})
	h.Require("options", p.SACK && p.TS && p.DutWS >= 0, "SACK, timestamps and window scaling negotiated",
		fmt.Sprintf("SACK %v, timestamps %v, scale %d", p.SACK, p.TS, p.DutWS))
	filled := make(chan struct{})
	go func() {
		buf := pattern(ccWriteChunk, 0xc1)
		for i := 0; ; i++ {
			if i == ccWriteFilled {
				close(filled)
			}
			if _, err := c.Write(buf); err != nil {
				if i < ccWriteFilled {
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
	return &ccFlow{h: h, clk: clk, p: p, r: newReceiver(p), smss: float64(segSize(p))}
}

// sent takes every data segment the DUT sends now, without moving the clock.
func (f *ccFlow) sent() []Segment {
	var out []Segment
	for {
		s, ok := f.p.Next(0)
		if !ok {
			return out
		}
		if isData(s) {
			out = append(out, s)
		}
	}
}

// segs is the length of a flight in full segments.
func (f *ccFlow) segs(flight []Segment) float64 {
	n := 0
	for _, s := range flight {
		n += len(s.Payload)
	}
	return float64(n) / f.smss
}

// round holds flight for rtt, collecting what the DUT sends meanwhile, such as a RACK
// retransmission, then acknowledges every segment but the lost ones one by one, each ACK echoing
// the segment's own TSval as a receiver does. It returns the next flight: everything the DUT
// sends at once in answer, with what came during the wait.
func (f *ccFlow) round(flight []Segment, rtt time.Duration, lost func(i int) bool) []Segment {
	var late []Segment
	deadline := f.h.Now().Add(rtt)
	for {
		s, ok := f.p.Next(max(deadline.Sub(f.h.Now()), 0))
		if !ok {
			break
		}
		if isData(s) {
			late = append(late, s)
		}
	}
	// The tunnel reads what the DUT sends after each ACK, as wgft's agent pulls packets from a
	// Device that is ready: a sender that builds its segments when they are pulled advances
	// SND.NXT between the ACKs, as one that sends at once does.
	var next []Segment
	for i, s := range append(flight, late...) {
		if i < len(flight) && lost != nil && lost(i) {
			continue
		}
		f.r.take(s)
		f.p.Send(f.r.ack(s.Opts.TS.Val))
		if !f.burst {
			next = append(next, f.sent()...)
		}
	}
	// the application refills the send buffer on its own goroutine
	time.Sleep(2 * time.Millisecond)
	return append(next, f.sent()...)
}

// slowStartTo runs loss-free rounds until a flight reaches n segments.
func (f *ccFlow) slowStartTo(flight []Segment, n float64) []Segment {
	for i := 0; f.segs(flight) < n && i < 12; i++ {
		flight = f.round(flight, ccRTT, nil)
	}
	f.h.Require("slow-start", f.segs(flight) >= n, fmt.Sprintf("slow start reaches %.0f segments in a round", n),
		fmt.Sprintf("%.1f segments", f.segs(flight)))
	return flight
}

// lose drops the first segment of flight and acknowledges the rest with SACK blocks, then runs
// rounds until the cumulative ACK passes what was sent before the loss. It returns the flight
// after the round that ended recovery and the time of that round's ACKs, where RFC 9438's new
// congestion avoidance epoch starts.
func (f *ccFlow) lose(flight []Segment) ([]Segment, time.Time, bool) {
	last := flight[len(flight)-1]
	recover := last.Seq + uint32(len(last.Payload))
	flight = f.round(flight, ccRTT, func(i int) bool { return i == 0 })
	for i := 0; i < 6; i++ {
		flight = f.round(flight, ccRTT, nil)
		if !after(recover, f.r.cum) {
			return flight, f.h.Now(), true
		}
	}
	return flight, time.Time{}, false
}

// cubicModel is RFC 9438's window in segments over one congestion avoidance epoch, updated per
// ACK of one segment: W_cubic of 4.2 aimed one RTT ahead and kept within [cwnd, 1.5 cwnd], and
// W_est of 4.3, which the window follows while W_cubic is below it. W_est grows by alpha_cubic
// until it reaches cwnd_prior, the window when ssthresh was last set, and by 1 after that.
type cubicModel struct {
	wmax, k, cwnd, west, prior float64
}

func newCubicModel(wmax, cwndEpoch, prior float64) *cubicModel {
	k := 0.0
	if wmax > cwndEpoch {
		k = math.Cbrt((wmax - cwndEpoch) / cubicC)
	}
	return &cubicModel{wmax: wmax, k: k, cwnd: cwndEpoch, west: cwndEpoch, prior: prior}
}

func (m *cubicModel) wcubic(t float64) float64 { return cubicC*math.Pow(t-m.k, 3) + m.wmax }

// acks applies n ACKs, each of one segment, at t seconds into the epoch.
func (m *cubicModel) acks(n int, t, rtt float64) {
	for range n {
		alpha := 3 * (1 - cubicBeta) / (1 + cubicBeta)
		if m.west >= m.prior {
			alpha = 1
		}
		m.west += alpha / m.cwnd
		if m.wcubic(t) < m.west {
			m.cwnd = m.west
			continue
		}
		target := min(max(m.wcubic(t+rtt), m.cwnd), 1.5*m.cwnd)
		m.cwnd += (target - m.cwnd) / m.cwnd
	}
}

// ccTolerance is how far a measured window may stand from the model: one segment, because the
// DUT sends whole segments, and 5% for a sender that counts in bytes, not segments.
func ccTolerance(w float64) float64 { return 1 + 0.05*w }

// epoch runs n loss-free rounds from flight, starting at the epoch's start t0, and compares each
// round's flight with the model. It returns the last flight, the largest deviation from the
// model and the trajectory for the log.
func (f *ccFlow) epoch(flight []Segment, t0 time.Time, m *cubicModel, n int) ([]Segment, float64, string) {
	worst := 0.0
	var traj []string
	for range n {
		acked := int(math.Round(f.segs(flight)))
		t := f.h.Now().Add(ccRTT).Sub(t0).Seconds()
		flight = f.round(flight, ccRTT, nil)
		m.acks(acked, t, ccRTT.Seconds())
		got := f.segs(flight)
		dev := math.Abs(got - m.cwnd)
		if dev/ccTolerance(m.cwnd) > worst/ccTolerance(m.cwnd) {
			worst = dev
		}
		traj = append(traj, fmt.Sprintf("%.1fs:%.0f/%.1f", t, got, m.cwnd))
	}
	return flight, worst, strings.Join(traj, " ")
}

// cubicAfterLoss grows the window to 40 segments in slow start, loses one segment and follows
// the congestion avoidance epoch past K, where the window returns to W_max.
func cubicAfterLoss(h *H) { cubicAfterLossOn(ccOpen(h, 8201)) }

// cubicBurst is cubicAfterLoss with each round's ACKs in one burst.
func cubicBurst(h *H) {
	f := ccOpen(h, 8205)
	f.burst = true
	cubicAfterLossOn(f)
}

func cubicAfterLossOn(f *ccFlow) {
	h := f.h
	flight := f.slowStartTo(f.sent(), 40)
	w := f.segs(flight)
	flight, t0, ok := f.lose(flight)
	h.Require("recovers", ok, "recovery ends within six rounds", yesNo(ok, "ended", "still in recovery"))
	got := f.segs(flight)
	ss := cubicBeta * w
	h.Check("ssthresh", got >= ss-1.5 && got <= ss+2.5, fmt.Sprintf("4.6: the window after recovery is beta x %.0f = %.1f segments, give or take the epoch's first ACKs", w, ss),
		fmt.Sprintf("%.0f segments", got))
	m := newCubicModel(w, ss, w)
	m.cwnd = got
	h.Measure("k-seconds", fmt.Sprintf("%.2f", m.k))
	rounds := int(math.Ceil(m.k/ccRTT.Seconds())) + 8
	_, worst, traj := f.epoch(flight, t0, m, rounds)
	h.Measure("trajectory", traj)
	h.Check("trajectory", worst <= ccTolerance(w), "4.2 and 4.3: every round's window is within one segment and 5% of the RFC's",
		fmt.Sprintf("largest deviation %.1f segments", worst))
}

// cubicFastConvergence loses a segment at 40, then again before the window is back at W_max.
// 4.7: the second W_max is the window at the loss times (1 + beta) / 2, so the window levels off
// lower than the first.
func cubicFastConvergence(h *H) {
	f := ccOpen(h, 8202)
	flight := f.slowStartTo(f.sent(), 40)
	w1 := f.segs(flight)
	flight, t0, ok := f.lose(flight)
	h.Require("recovers", ok, "the first recovery ends within six rounds", yesNo(ok, "ended", "still in recovery"))
	m := newCubicModel(w1, cubicBeta*w1, w1)
	m.cwnd = f.segs(flight)
	flight, _, _ = f.epoch(flight, t0, m, 6)
	w2 := f.segs(flight)
	h.Require("below-wmax", w2 < w1, "the second loss comes below the first W_max", fmt.Sprintf("%.0f and %.0f segments", w2, w1))
	flight, t0, ok = f.lose(flight)
	h.Require("recovers-again", ok, "the second recovery ends within six rounds", yesNo(ok, "ended", "still in recovery"))
	wmax := w2 * (1 + cubicBeta) / 2
	m = newCubicModel(wmax, cubicBeta*w2, w2)
	m.cwnd = f.segs(flight)
	rounds := int(math.Ceil(m.k/ccRTT.Seconds())) + 4
	flight, worst, traj := f.epoch(flight, t0, m, rounds)
	h.Measure("trajectory", traj)
	h.Check("trajectory", worst <= ccTolerance(w2), fmt.Sprintf("4.7: the epoch follows W_max = %.1f, the window at the loss times 0.85, within one segment and 5%% of the RFC's", wmax),
		fmt.Sprintf("largest deviation %.1f segments", worst))
	h.Measure("final-window", fmt.Sprintf("%.0f", f.segs(flight)))
}

// hsThresh is RFC 9406's RTT threshold: the last round's minimum RTT over 8, clamped to
// [4 ms, 16 ms].
func hsThresh(last time.Duration) time.Duration { return min(max(last/8, hsMinThresh), hsMaxThresh) }

// growth runs a round of rtt and returns the next flight with its size over this one's.
func (f *ccFlow) growth(flight []Segment, rtt time.Duration) ([]Segment, float64) {
	before := f.segs(flight)
	next := f.round(flight, rtt, nil)
	return next, f.segs(next) / before
}

func ratios(r []float64) string {
	var b []string
	for _, x := range r {
		b = append(b, fmt.Sprintf("%.2f", x))
	}
	return strings.Join(b, " ")
}

// hystartCSS doubles the window in slow start at a steady RTT, then raises the RTT by more
// than the threshold. RFC 9406 4.2: the sender enters Conservative Slow Start, where the window
// grows by a quarter of slow start's rate, 1.25 times a round with an ACK per segment; after
// CSS_ROUNDS of it, it leaves slow start for congestion avoidance.
func hystartCSS(h *H) { hystartCSSOn(ccOpen(h, 8203)) }

// hystartCSSBurst is hystartCSS with each round's ACKs in one burst. The rounds of RFC 9406 end at
// the SND.NXT of the round's start, so a sender that builds segments as they are pulled must
// count what the ACKs let it send, not what it had pulled when they came.
func hystartCSSBurst(h *H) {
	f := ccOpen(h, 8206)
	f.burst = true
	hystartCSSOn(f)
}

func hystartCSSOn(f *ccFlow) {
	h := f.h
	flight := f.sent()
	var ss []float64
	// two rounds at the base RTT, so the round before the rise has its minimum whatever the
	// sender counts as its first round
	for f.segs(flight) < 40 && len(ss) < 4 {
		var g float64
		flight, g = f.growth(flight, ccRTT)
		ss = append(ss, g)
	}
	h.Check("slow-start-doubles", minOf(ss) >= 1.8, "4.1: with an ACK per segment, slow start doubles the window each round", ratios(ss))
	slow := ccRTT + hsThresh(ccRTT) + 8*time.Millisecond
	h.Measure("rtt-step", slow-ccRTT)
	var css []float64
	for range hsCSSRounds + 4 {
		var g float64
		flight, g = f.growth(flight, slow)
		css = append(css, g)
	}
	h.Measure("growth-after-step", ratios(css))
	in := 0
	first := -1
	for i, g := range css {
		if g >= 1.15 && g <= 1.35 {
			in++
			if first < 0 {
				first = i
			}
		}
	}
	h.Check("css-entered", first >= 0 && first <= 1, "4.2: within a round of the RTT rise, the window grows by about 1.25 a round",
		fmt.Sprintf("first such round %d", first))
	h.Check("css-rounds", in >= hsCSSRounds-1 && in <= hsCSSRounds+1, fmt.Sprintf("4.3: CSS lasts CSS_ROUNDS = %d rounds", hsCSSRounds),
		fmt.Sprintf("%d rounds", in))
	tail := css[len(css)-2:]
	h.Check("avoidance-after", maxOf(tail) < 1.1, "4.3: after CSS the window grows as in congestion avoidance, well under 1.1 a round", ratios(tail))
}

// hystartBack enters CSS as hystartCSS does, then brings the RTT back. RFC 9406 4.3: a round
// whose minimum RTT is below the one that started CSS returns the sender to slow start.
func hystartBack(h *H) {
	f := ccOpen(h, 8204)
	flight := f.sent()
	for i := 0; f.segs(flight) < 40 && i < 4; i++ {
		flight = f.round(flight, ccRTT, nil)
	}
	slow := ccRTT + hsThresh(ccRTT) + 8*time.Millisecond
	var g1, g2 float64
	flight, g1 = f.growth(flight, slow)
	flight, g2 = f.growth(flight, slow)
	h.Measure("growth-in-css", ratios([]float64{g1, g2}))
	h.Require("css", min(g1, g2) <= 1.35, "the RTT rise starts CSS", ratios([]float64{g1, g2}))
	var back []float64
	for range 2 {
		var g float64
		flight, g = f.growth(flight, ccRTT)
		back = append(back, g)
	}
	h.Check("back-to-slow-start", maxOf(back) >= 1.8, "4.3: once the RTT is back below CSS's baseline, the window doubles again", ratios(back))
}

func minOf(v []float64) float64 {
	m := math.Inf(1)
	for _, x := range v {
		m = math.Min(m, x)
	}
	return m
}

func maxOf(v []float64) float64 {
	m := math.Inf(-1)
	for _, x := range v {
		m = math.Max(m, x)
	}
	return m
}
