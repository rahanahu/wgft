//go:build qbench

package qbench

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// This file is the measurement plan of docs/design/userspace/wgstack-performance.md, 計測の計画
// and 判定の規則: time-bounded runs of the same length for every engine, a thin stream, the
// reference Linux through linuxdut, a routine mode that measures wgstack alone against stored
// medians and a gate mode that measures all three engines and judges.
//
//	go test -tags qbench -run TestQBenchRoutine -v ./internal/tcpharness/qbench
//	go test -c -tags qbench -o bin/qbench.test ./internal/tcpharness/qbench
//	lab VM, as root: QBENCH_WRITE_REF=/tmp/reference.json /wgft/bin/qbench.test -test.run TestQBenchGate -test.v -test.timeout 4h
//
// The linux engine needs a network namespace it can configure, so a test that asks for it re-runs
// itself in a new user and network namespace with the performance sysctls pinned.

// Cell is one case of the matrix.
type Cell struct {
	Name    string
	Thin    bool    // 200-byte writes every 20 ms instead of a bulk transfer
	DUTSend bool    // the DUT is the data sender
	Loss    float64 // random loss per packet, each direction
	Outage  bool    // a 2 s cut from 2 s after the first data byte
	Reorder bool    // 1% of packets held back long enough for three duplicate ACKs
	Len     time.Duration
	// NotJudged, when set, says why the cell is measured but not judged.
	NotJudged string
}

// The run lengths. A thin-stream run is longer than a bulk one, so 5 routine runs pool at least
// 1,000 samples: 8 s at 50 messages a second is 400 per run.
const (
	bulkLen   = 6 * time.Second
	outageLen = 8 * time.Second
	thinLen   = 8 * time.Second
)

func bulk(name string, send bool, loss float64) Cell {
	return Cell{Name: name, DUTSend: send, Loss: loss, Len: bulkLen}
}

func thin(name string, send bool, loss float64, outage bool) Cell {
	return Cell{Name: name, Thin: true, DUTSend: send, Loss: loss, Outage: outage, Len: thinLen}
}

// routineCells is the routine matrix: the DUT-send direction at loss 0, 1 and 5%, a reordering
// path and a 2 s outage, the DUT-receive direction at loss 0 and 1%, and the thin stream from the
// DUT at loss 1%.
func routineCells() []Cell {
	return []Cell{
		bulk("send/loss0%", true, 0),
		bulk("send/loss1%", true, 0.01),
		bulk("send/loss5%", true, 0.05),
		{Name: "send/reorder", DUTSend: true, Reorder: true, Len: bulkLen},
		{Name: "send/outage2s", DUTSend: true, Outage: true, Len: outageLen},
		bulk("recv/loss0%", false, 0),
		bulk("recv/loss1%", false, 0.01),
		thin("thin-send/loss1%", true, 0.01, false),
	}
}

// gateCells adds both directions of the rest: loss 5%, reordering and the outage for the
// receiving DUT, and the thin stream at loss 0, 1 and 5% and with an outage in both directions.
func gateCells() []Cell {
	cells := routineCells()
	cells = append(cells,
		bulk("recv/loss5%", false, 0.05),
		Cell{Name: "recv/reorder", Reorder: true, Len: bulkLen},
		Cell{Name: "recv/outage2s", Outage: true, Len: outageLen, NotJudged: clientSends},
		thin("thin-send/loss0%", true, 0, false),
		thin("thin-send/loss5%", true, 0.05, false),
		thin("thin-send/outage2s", true, 0, true),
		thin("thin-recv/loss0%", false, 0, false),
		thin("thin-recv/loss1%", false, 0.01, false),
		thin("thin-recv/loss5%", false, 0.05, false),
		withNotJudged(thin("thin-recv/outage2s", false, 0, true), clientSends),
	)
	return cells
}

// clientSends is why the outage cells in which the DUT receives are not judged: the sender is
// the gVisor client, whose RTO the bench cannot read and which, sending a thin stream, stalls
// for seconds after an outage whatever the DUT, so the cell measures the client.
const clientSends = "the gVisor client sends; it stalls after an outage and its RTO is unknown"

func withNotJudged(c Cell, why string) Cell {
	c.NotJudged = why
	return c
}

// Run is one measured run.
type Run struct {
	Engine, Cell string
	Seed         int64
	Err          string
	Bytes        int64
	Mbps         float64
	Verified     bool          // every byte read matched the sender's seeded stream
	Recovery     time.Duration // from the outage's end to the next read; -1 without one
	RTO          time.Duration // the sender's RTO in use at the outage's end; -1 if unknown
	Stall        time.Duration // the longest gap between reads outside the outage
	Lat          []time.Duration
	Lost         int // thin messages written but never delivered
	Retrans      int
	DataPkts     int
	QDrops       int
	Stats        string
}

// open builds the rig, connects and accepts.
func open(engine string, imp Impair, seed int64) (*Rig, net.Conn, net.Conn, error) {
	rig, err := newRig(engine, imp, seed)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("setup: %w", err)
	}
	ln, err := rig.D.Listen(port)
	if err != nil {
		rig.Close()
		return nil, nil, nil, fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()
	type acc struct {
		c   net.Conn
		err error
	}
	accCh := make(chan acc, 1)
	go func() { c, err := ln.Accept(); accCh <- acc{c, err} }()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cc, err := rig.C.Dial(ctx)
	if err != nil {
		rig.Close()
		return nil, nil, nil, fmt.Errorf("dial: %w", err)
	}
	select {
	case a := <-accCh:
		if a.err != nil {
			cc.Close()
			rig.Close()
			return nil, nil, nil, fmt.Errorf("accept: %w", a.err)
		}
		if rig.D.OnAccept != nil {
			rig.D.OnAccept(a.c)
		}
		return rig, cc, a.c, nil
	case <-ctx.Done():
		cc.Close()
		rig.Close()
		return nil, nil, nil, fmt.Errorf("accept: timeout")
	}
}

func impair(c Cell) Impair {
	imp := Impair{Delay: 25 * time.Millisecond, Loss: c.Loss, RateBps: int64(envInt("QBENCH_RATE_MBIT", 20)) * 1_000_000, QueuePkts: envInt("QBENCH_QUEUE_PKTS", 200)}
	if c.DUTSend {
		imp.DataDir = 1
	}
	if c.Outage {
		imp.OutageAt, imp.OutageLen = 2*time.Second, 2*time.Second
	}
	if c.Reorder {
		// 3 ms is the time of five full packets at 20 Mbit/s: enough for three duplicate ACKs
		imp.Reorder, imp.ReorderGap = 0.01, 3*time.Millisecond
	}
	return imp
}

// runCell measures one run of c on engine.
func runCell(engine string, c Cell, seed int64) (r Run) {
	r = Run{Engine: engine, Cell: c.Name, Seed: seed, Recovery: -1, RTO: -1}
	rig, cc, dc, err := open(engine, impair(c), seed)
	if err != nil {
		r.Err = err.Error()
		return
	}
	defer rig.Close()
	defer cc.Close()
	defer dc.Close()
	snd, rcv := cc, dc
	if c.DUTSend {
		snd, rcv = dc, cc
	}
	var reads []time.Time
	if c.Thin {
		reads = runThin(&r, c, seed, snd, rcv)
	} else {
		reads = runBulk(&r, c, seed, snd, rcv)
	}
	ostart, oe := rig.L.Outage()
	for i := 1; i < len(reads); i++ {
		a, b := reads[i-1], reads[i]
		if !ostart.IsZero() && a.Before(oe) && b.After(ostart) {
			if b.After(oe) && r.Recovery < 0 {
				r.Recovery = b.Sub(oe)
			}
			continue
		}
		r.Stall = max(r.Stall, b.Sub(a))
	}
	if c.DUTSend && !oe.IsZero() && rig.D.RTOAt != nil {
		r.RTO = rig.D.RTOAt(oe)
	}
	st := rig.L.Stats(impair(c).DataDir)
	r.Retrans, r.DataPkts, r.QDrops = st.Retrans, st.DataPkts, st.QDrops
	r.Stats = "-"
	if rig.D.Stats != nil {
		r.Stats = rig.D.Stats(oe)
	}
	return
}

// runBulk sends the seeded stream for c.Len after the handshake and counts what the receiver
// reads in that time, from its first byte, checking every byte against the stream.
func runBulk(r *Run, c Cell, seed int64, snd, rcv net.Conn) []time.Time {
	end := time.Now().Add(c.Len)
	snd.SetDeadline(end.Add(5 * time.Second))
	rcv.SetReadDeadline(end)
	go func() {
		g := gen(seed)
		buf := make([]byte, 32<<10)
		for time.Now().Before(end.Add(5 * time.Second)) {
			g.Read(buf)
			if _, err := snd.Write(buf); err != nil {
				return
			}
		}
	}()
	exp := gen(seed)
	buf := make([]byte, 64<<10)
	want := make([]byte, 64<<10)
	var reads []time.Time
	var first time.Time
	r.Verified = true
	for {
		n, err := rcv.Read(buf)
		now := time.Now()
		if n > 0 {
			exp.Read(want[:n])
			if !bytes.Equal(buf[:n], want[:n]) {
				r.Verified = false
			}
			if first.IsZero() {
				first = now
			}
			r.Bytes += int64(n)
			reads = append(reads, now)
		}
		if err != nil {
			break
		}
	}
	if r.Bytes > 0 && end.After(first) {
		r.Mbps = float64(r.Bytes) * 8 / end.Sub(first).Seconds() / 1e6
	}
	if !r.Verified {
		r.Err = "STREAM MISMATCH"
	}
	return reads
}

const (
	thinSize  = 200
	thinEvery = 20 * time.Millisecond
)

// runThin writes 200 seeded bytes every 20 ms for c.Len and measures, per message, the time from
// the write to the read that completes it.
func runThin(r *Run, c Cell, seed int64, snd, rcv net.Conn) []time.Time {
	end := time.Now().Add(c.Len)
	var mu sync.Mutex
	var written []time.Time
	go func() {
		g := gen(seed)
		msg := make([]byte, thinSize)
		t := time.NewTicker(thinEvery)
		defer t.Stop()
		for time.Now().Before(end) {
			g.Read(msg)
			mu.Lock()
			written = append(written, time.Now())
			mu.Unlock()
			if _, err := snd.Write(msg); err != nil {
				return
			}
			<-t.C
		}
	}()
	// read until every message written by end has arrived, or 5 s after end
	rcv.SetReadDeadline(end.Add(5 * time.Second))
	exp := gen(seed)
	buf := make([]byte, 64<<10)
	want := make([]byte, 64<<10)
	var reads []time.Time
	var got int64
	done := 0
	r.Verified = true
	for {
		n, err := rcv.Read(buf)
		now := time.Now()
		if n > 0 {
			exp.Read(want[:n])
			if !bytes.Equal(buf[:n], want[:n]) {
				r.Verified = false
			}
			got += int64(n)
			reads = append(reads, now)
			mu.Lock()
			for done < len(written) && int64(done+1)*thinSize <= got {
				r.Lat = append(r.Lat, now.Sub(written[done]))
				done++
			}
			all := !now.Before(end) && done == len(written)
			mu.Unlock()
			if all {
				break
			}
		}
		if err != nil {
			break
		}
	}
	mu.Lock()
	r.Lost = len(written) - done
	mu.Unlock()
	r.Bytes = got
	if !r.Verified {
		r.Err = "STREAM MISMATCH"
	}
	return reads
}

// Summary is the medians of one engine in one cell, the values the judgment compares.
type Summary struct {
	Runs       int     `json:"runs"`
	OK         int     `json:"ok"`
	Mbps       float64 `json:"mbps"`
	RecoveryMS float64 `json:"recovery_ms"` // -1 without an outage
	RTOMS      float64 `json:"rto_ms"`      // -1 if unknown
	P50MS      float64 `json:"p50_ms"`      // thin stream, all runs pooled
	P99MS      float64 `json:"p99_ms"`
	MaxMS      float64 `json:"max_ms"`
	Samples    int     `json:"samples"`
	Spread     float64 `json:"spread"` // max over min of the judged value across runs
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func medianF(v []float64) float64 {
	if len(v) == 0 {
		return -1
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	return s[len(s)/2]
}

func quantile(s []time.Duration, q float64) time.Duration {
	if len(s) == 0 {
		return -1
	}
	i := int(math.Ceil(q*float64(len(s)))) - 1
	return s[max(0, min(i, len(s)-1))]
}

func spread(v []float64) float64 {
	lo, hi := math.Inf(1), 0.0
	for _, x := range v {
		if x <= 0 {
			continue
		}
		lo, hi = math.Min(lo, x), math.Max(hi, x)
	}
	if hi == 0 || math.IsInf(lo, 1) {
		return 0
	}
	return hi / lo
}

func summarize(c Cell, runs []Run) Summary {
	s := Summary{Runs: len(runs), RecoveryMS: -1, RTOMS: -1, P50MS: -1, P99MS: -1, MaxMS: -1}
	var mb, rec, rto, judged []float64
	var lat []time.Duration
	for _, r := range runs {
		if r.Err == "" {
			s.OK++
		}
		mb = append(mb, r.Mbps)
		if r.Recovery >= 0 {
			rec = append(rec, ms(r.Recovery))
		}
		if r.RTO >= 0 {
			rto = append(rto, ms(r.RTO))
		}
		lat = append(lat, r.Lat...)
		switch {
		case c.Thin:
			l := append([]time.Duration(nil), r.Lat...)
			sort.Slice(l, func(i, j int) bool { return l[i] < l[j] })
			judged = append(judged, ms(quantile(l, 0.99)))
		case c.Outage:
			if r.Recovery >= 0 {
				judged = append(judged, ms(r.Recovery))
			}
		default:
			judged = append(judged, r.Mbps)
		}
	}
	s.Mbps = medianF(mb)
	if len(rec) > 0 {
		s.RecoveryMS = medianF(rec)
	}
	if len(rto) > 0 {
		s.RTOMS = medianF(rto)
	}
	if len(lat) > 0 {
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		s.P50MS, s.P99MS, s.MaxMS = ms(quantile(lat, 0.5)), ms(quantile(lat, 0.99)), ms(lat[len(lat)-1])
		s.Samples = len(lat)
	}
	s.Spread = spread(judged)
	return s
}

// Reference is the stored medians the routine mode compares wgstack with.
type Reference struct {
	Measured string                        `json:"measured"`
	Where    string                        `json:"where"`
	Runs     int                           `json:"runs"`
	Cells    map[string]map[string]Summary `json:"cells"`
}

// Verdict is the judgment of one cell by 判定の規則.
type Verdict struct {
	Rule, Result string
	Value, Line  float64
}

// judge applies the rule of c's kind to wgstack's summary against gVisor's and Linux's.
func judge(c Cell, wg, gv, lx Summary, haveG, haveL bool) Verdict {
	if c.NotJudged != "" {
		return Verdict{Rule: "-", Result: "NOT JUDGED: " + c.NotJudged}
	}
	if !haveL {
		return Verdict{Rule: "-", Result: "no Linux reference"}
	}
	var v Verdict
	switch {
	case c.Thin:
		v = Verdict{Rule: "p99 <= 1.5 x Linux", Value: wg.P99MS, Line: 1.5 * lx.P99MS}
		v.Result = yes(v.Value <= v.Line)
	case c.Outage:
		if lx.RTOMS < 0 {
			return Verdict{Rule: "recovery <= Linux + Linux RTO", Result: "no Linux RTO"}
		}
		v = Verdict{Rule: "recovery <= Linux + Linux RTO", Value: wg.RecoveryMS, Line: lx.RecoveryMS + lx.RTOMS}
		v.Result = yes(v.Value >= 0 && v.Value <= v.Line)
	default:
		// 0.8 x Linux, or gVisor's value where gVisor is above it
		line, rule := 0.8*lx.Mbps, "Mbit/s >= 0.8 x Linux; gVisor is below"
		if haveG && gv.Mbps > line {
			line, rule = gv.Mbps, "Mbit/s >= gVisor; gVisor is above 0.8 x Linux"
		}
		v = Verdict{Rule: rule, Value: wg.Mbps, Line: line}
		v.Result = yes(v.Value >= v.Line)
	}
	for _, s := range []Summary{wg, gv, lx} {
		if s.Spread > 2 {
			v.Result = "UNDETERMINED: max/min above 2, diagnose and rerun"
			return v
		}
	}
	return v
}

func yes(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

// near reports whether a verdict's value is within 5% of its line, where the plan doubles the
// runs and judges again.
func near(v Verdict) bool {
	return v.Line > 0 && v.Value >= 0 && math.Abs(v.Value/v.Line-1) <= 0.05
}

func dur(d time.Duration) string {
	if d < 0 {
		return "-"
	}
	return d.Round(time.Millisecond).String()
}

func printRun(r Run) {
	fmt.Printf("QBENCH-RUN engine=%s cell=%s seed=%d bytes=%d mbps=%.2f verified=%v recovery=%s rto=%s stall=%s samples=%d lost=%d retrans=%d/%d qdrop=%d err=%q\n",
		r.Engine, r.Cell, r.Seed, r.Bytes, r.Mbps, r.Verified, dur(r.Recovery), dur(r.RTO),
		r.Stall.Round(time.Millisecond), len(r.Lat), r.Lost, r.Retrans, r.DataPkts, r.QDrops, r.Err)
	if r.Stats != "-" {
		fmt.Printf("QBENCH-STATS engine=%s cell=%s seed=%d %s\n", r.Engine, r.Cell, r.Seed, r.Stats)
	}
}

// measure runs every engine runs times in c, with the same seeds for every engine.
func measure(t *testing.T, c Cell, ci int, engines []string, runs, from int) map[string][]Run {
	out := map[string][]Run{}
	for _, eng := range engines {
		for i := from; i < from+runs; i++ {
			seed := int64(i+1)*7919 + int64(ci)*131
			r := runCell(eng, c, seed)
			printRun(r)
			if r.Err != "" {
				t.Errorf("%s %s seed %d: %s", eng, c.Name, seed, r.Err)
			}
			out[eng] = append(out[eng], r)
		}
	}
	return out
}

func printSummary(c Cell, eng string, s Summary) {
	fmt.Printf("QBENCH-SUMMARY engine=%s cell=%s runs=%d ok=%d mbps=%.2f recovery_ms=%.0f rto_ms=%.0f p50_ms=%.1f p99_ms=%.1f max_ms=%.1f samples=%d spread=%.2f\n",
		eng, c.Name, s.Runs, s.OK, s.Mbps, s.RecoveryMS, s.RTOMS, s.P50MS, s.P99MS, s.MaxMS, s.Samples, s.Spread)
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func cellFilter(cells []Cell) []Cell {
	only := os.Getenv("QBENCH_CELLS")
	if only == "" {
		return cells
	}
	var out []Cell
	for _, c := range cells {
		for _, o := range strings.Split(only, ",") {
			if strings.Contains(c.Name, o) {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

func loadReference(t *testing.T) *Reference {
	path := os.Getenv("QBENCH_REF")
	if path == "" {
		path = "testdata/reference.json"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Logf("no stored reference at %s: %v", path, err)
		return &Reference{Cells: map[string]map[string]Summary{}}
	}
	var ref Reference
	if err := json.Unmarshal(b, &ref); err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return &ref
}

// TestQBenchRoutine is the routine matrix: wgstack alone, 5 runs per cell, judged against the
// stored gVisor and Linux medians in testdata/reference.json. A cell within 5% of its line is
// measured again with twice the runs. It takes about 5 minutes; verdicts are printed, not failed.
func TestQBenchRoutine(t *testing.T) {
	engines := []string{"wgstack"}
	if v := os.Getenv("QBENCH_ENGINES"); v != "" {
		engines = strings.Split(v, ",")
	}
	if has(engines, "linux") && !inNetns(t) {
		return
	}
	pinLinux(t, engines)
	ref := loadReference(t)
	fmt.Printf("QBENCH-META mode=routine reference=%q measured=%q runs_ref=%d\n", ref.Where, ref.Measured, ref.Runs)
	runs := envInt("QBENCH_RUNS", 5)
	cells := cellFilter(routineCells())
	var table []string
	for ci, c := range cells {
		res := measure(t, c, ci, engines, runs, 0)
		wg := summarize(c, res["wgstack"])
		printSummary(c, "wgstack", wg)
		gv, haveG := ref.Cells[c.Name]["gvisor"]
		lx, haveL := ref.Cells[c.Name]["linux"]
		v := judge(c, wg, gv, lx, haveG, haveL)
		if near(v) {
			more := measure(t, c, ci, []string{"wgstack"}, runs, runs)
			wg = summarize(c, append(res["wgstack"], more["wgstack"]...))
			printSummary(c, "wgstack", wg)
			v = judge(c, wg, gv, lx, haveG, haveL)
			v.Result += " after doubling"
		}
		table = append(table, row(c, wg, gv, lx, v))
	}
	printTable(table)
}

// TestQBenchGate is the gate matrix: wgstack, gVisor and Linux in the same process and VM, 9 runs
// per cell, judged by 判定の規則, with the runs doubled for a cell within 5% of its line.
// QBENCH_WRITE_REF names a file to store the gVisor and Linux medians in, for the routine mode.
func TestQBenchGate(t *testing.T) {
	engines := []string{"wgstack", "gvisor", "linux"}
	if v := os.Getenv("QBENCH_ENGINES"); v != "" {
		engines = strings.Split(v, ",")
	}
	if has(engines, "linux") && !inNetns(t) {
		return
	}
	where := pinLinux(t, engines)
	runs := envInt("QBENCH_RUNS", 9)
	cells := cellFilter(gateCells())
	ref := &Reference{Measured: time.Now().UTC().Format(time.RFC3339), Where: where, Runs: runs, Cells: map[string]map[string]Summary{}}
	var table []string
	for ci, c := range cells {
		res := measure(t, c, ci, engines, runs, 0)
		sum := func() map[string]Summary {
			m := map[string]Summary{}
			for _, e := range engines {
				m[e] = summarize(c, res[e])
				printSummary(c, e, m[e])
			}
			return m
		}
		m := sum()
		gv, haveG := m["gvisor"]
		lx, haveL := m["linux"]
		v := judge(c, m["wgstack"], gv, lx, haveG, haveL)
		if near(v) {
			more := measure(t, c, ci, engines, runs, runs)
			for e, rs := range more {
				res[e] = append(res[e], rs...)
			}
			m = sum()
			gv, lx = m["gvisor"], m["linux"]
			v = judge(c, m["wgstack"], gv, lx, haveG, haveL)
			v.Result += " after doubling"
		}
		ref.Cells[c.Name] = map[string]Summary{}
		for _, e := range engines {
			if e != "wgstack" {
				ref.Cells[c.Name][e] = m[e]
			}
		}
		table = append(table, row(c, m["wgstack"], gv, lx, v))
	}
	printTable(table)
	if path := os.Getenv("QBENCH_WRITE_REF"); path != "" {
		b, _ := json.MarshalIndent(ref, "", "  ")
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Errorf("writing %s: %v", path, err)
		}
		fmt.Printf("QBENCH-REF written to %s\n", path)
	}
}

func row(c Cell, wg, gv, lx Summary, v Verdict) string {
	val := func(s Summary) string {
		switch {
		case s.Runs == 0:
			return "-"
		case c.Thin:
			return fmt.Sprintf("%.0f / %.0f / %.0f ms", s.P50MS, s.P99MS, s.MaxMS)
		case c.Outage:
			return fmt.Sprintf("%.0f ms, RTO %.0f ms, %.2f Mbit/s", s.RecoveryMS, s.RTOMS, s.Mbps)
		}
		return fmt.Sprintf("%.2f Mbit/s", s.Mbps)
	}
	return fmt.Sprintf("| %s | %s | %s | %s | %s: %.1f vs %.1f | %s |", c.Name, val(wg), val(gv), val(lx), v.Rule, v.Value, v.Line, v.Result)
}

func printTable(rows []string) {
	fmt.Println("QBENCH-TABLE")
	fmt.Println("| cell | wgstack | gVisor | Linux | rule: value vs line | verdict |")
	fmt.Println("|---|---|---|---|---|---|")
	for _, r := range rows {
		fmt.Println(r)
	}
	fmt.Println("QBENCH-DONE")
}
