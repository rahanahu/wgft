//go:build qbench

package qbench

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
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
//	lab VM, as root: QBENCH_COMMIT=<commit> QBENCH_WRITE_REF=/var/tmp/qref/reference.json /wgft/bin/qbench.test -test.run TestQBenchGate -test.v -test.timeout 4h
//
// QBENCH_CLIENT=linux has a Linux client send in the cells where the DUT receives, from a network
// namespace of its own, so the lab VM only. QBENCH_TRACE=<dir> writes each run's packet log there,
// one line per TCP packet the link carries: times, direction, fate, flags, numbers, window, SACK
// blocks and timestamps.
//
// Writing the reference needs the commit: the test reads it with git, which a lab VM's share of a
// worktree does not have, so pass QBENCH_COMMIT from the host, for example
// "$(git rev-parse HEAD)$(git diff --quiet HEAD || echo -dirty)".
//
// The reference file is written from inside the user namespace, so it needs a directory without
// the sticky bit that the namespace's user can write, such as one made with mkdir -m 777.
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
	// Client is the dialing side's engine: "" for gVisor's netstack, or "linux".
	Client string
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
//
// In the gate, every cell where the DUT receives runs twice: with the Linux client, judged, and
// with the gVisor client, measured for information only. The gVisor client wedges and then
// measures itself, and its RTO cannot be read (the supervisor's decision; the owner can revise
// it). The routine mode, on the host, keeps the gVisor client as a quick indicator.
func gateCells() []Cell {
	cells := append(routineCells(),
		bulk("recv/loss5%", false, 0.05),
		Cell{Name: "recv/reorder", Reorder: true, Len: bulkLen},
		Cell{Name: "recv/outage2s", Outage: true, Len: outageLen},
		thin("thin-send/loss0%", true, 0, false),
		thin("thin-send/loss5%", true, 0.05, false),
		thin("thin-send/outage2s", true, 0, true),
		thin("thin-recv/loss0%", false, 0, false),
		thin("thin-recv/loss1%", false, 0.01, false),
		thin("thin-recv/loss5%", false, 0.05, false),
		thin("thin-recv/outage2s", false, 0, true),
	)
	var out []Cell
	for _, c := range cells {
		if c.DUTSend {
			out = append(out, c)
			continue
		}
		out = append(out, withNotJudged(c, clientSends), withClient([]Cell{c}, "linux")[0])
	}
	return out
}

// clientSends is why a cell in which the gVisor client sends is not judged in the gate: the
// client wedges after losses and outages whatever the DUT, so the cell measures the client, and
// its RTO cannot be read. The same cell with the Linux client is judged.
const clientSends = "informational; the gVisor client sends and can wedge; the gate judges the /linux-client cell"

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
	Verified     bool            // every byte read matched the sender's seeded stream
	Recovery     time.Duration   // from the outage's end to the next read; -1 without one
	RTO          time.Duration   // the sender's RTO in use at the outage's end; -1 if unknown
	Stall        time.Duration   // the longest gap between reads outside the outage
	Lat          []time.Duration // per thin message; an undelivered one counts until the receiver gave up
	Lost         int             // thin messages never delivered, written or not
	Retrans      int
	DataPkts     int
	QDrops       int
	Stats        string
}

// open builds the rig, connects and accepts.
func open(engine, client string, imp Impair, seed int64) (*Rig, net.Conn, net.Conn, error) {
	rig, err := newRig(engine, client, imp, seed)
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
			if err := rig.D.OnAccept(a.c); err != nil {
				a.c.Close()
				cc.Close()
				rig.Close()
				return nil, nil, nil, err
			}
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
	tracePath = ""
	if dir := os.Getenv("QBENCH_TRACE"); dir != "" {
		tracePath = filepath.Join(dir, fmt.Sprintf("%s_%s_%d.tsv", engine, strings.NewReplacer("/", "_", "%", "pct").Replace(c.Name), seed))
	}
	rig, cc, dc, err := open(engine, c.Client, impair(c), seed)
	if err != nil {
		r.Err = err.Error()
		return
	}
	defer rig.Close()
	// a kernel socket closed with data left keeps sending, into the next run's rig
	defer abort(cc)
	defer abort(dc)
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
	// the sender's RTO at the outage's end: the DUT's where it sends, the client's where it receives
	rtoAt, rtoErr, kernel := rig.D.RTOAt, rig.D.RTOErr, engine == "linux"
	if !c.DUTSend {
		rtoAt, rtoErr, kernel = rig.C.RTOAt, rig.C.RTOErr, rig.C.Name == "linux"
	}
	if !oe.IsZero() && rtoAt != nil {
		r.RTO = rtoAt(oe)
		if r.RTO <= 0 && kernel && r.Err == "" {
			// the judgment needs the kernel sender's RTO; a run without it must not pass as measured
			r.Err = "no TCP_INFO RTO sample before the outage's end"
			if rtoErr != nil && rtoErr() != nil {
				r.Err += "; the last TCP_INFO read: " + rtoErr().Error()
			}
		}
	}
	st := rig.L.Stats(impair(c).DataDir)
	r.Retrans, r.DataPkts, r.QDrops = st.Retrans, st.DataPkts, st.QDrops
	r.Stats = "-"
	if rig.D.Stats != nil {
		r.Stats = rig.D.Stats(oe)
	}
	return
}

// abort closes c with a RST where the engine offers it, and closes it otherwise.
func abort(c net.Conn) {
	switch a := c.(type) {
	case interface{ Abort() error }:
		a.Abort()
	case interface{ Abort() }:
		a.Abort()
	case *net.TCPConn:
		a.SetLinger(0)
	}
	c.Close()
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
	// Each message has a slot every thinEvery and is timed from its slot, not from its write: a
	// write that blocks delays the messages behind it, and their latency includes the wait.
	start := time.Now()
	end := start.Add(c.Len)
	slots := int((c.Len + thinEvery - 1) / thinEvery)
	slot := func(i int) time.Time { return start.Add(time.Duration(i) * thinEvery) }
	var mu sync.Mutex
	written := 0
	go func() {
		g := gen(seed)
		msg := make([]byte, thinSize)
		for i := 0; i < slots; i++ {
			time.Sleep(time.Until(slot(i)))
			g.Read(msg)
			mu.Lock()
			written++
			mu.Unlock()
			if _, err := snd.Write(msg); err != nil {
				return
			}
		}
	}()
	// read until every slot's message has arrived, or 5 s after end
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
			for done < written && int64(done+1)*thinSize <= got {
				r.Lat = append(r.Lat, now.Sub(slot(done)))
				done++
			}
			all := done == slots
			mu.Unlock()
			if all {
				break
			}
		}
		if err != nil {
			break
		}
	}
	// A message that never arrives, written or still waiting for a blocked write, counts in the
	// pool at the latency it had reached when the receiver gave up, so the percentiles show the
	// stall instead of leaving it out.
	giveUp := end.Add(5 * time.Second)
	r.Lost = slots - done
	for i := done; i < slots; i++ {
		r.Lat = append(r.Lat, giveUp.Sub(slot(i)))
	}
	r.Bytes = got
	if !r.Verified {
		r.Err = "STREAM MISMATCH"
	}
	return reads
}

// Summary is the medians of one engine in one cell, the values the judgment compares.
type Summary struct {
	Runs        int     `json:"runs"`
	OK          int     `json:"ok"`
	Mbps        float64 `json:"mbps"`
	RecoveryMS  float64 `json:"recovery_ms"` // -1 without an outage
	RTOMS       float64 `json:"rto_ms"`      // -1 if unknown
	P50MS       float64 `json:"p50_ms"`      // thin stream, all runs pooled
	P99MS       float64 `json:"p99_ms"`
	P99LoMS     float64 `json:"p99_lo_ms,omitempty"` // thin stream: the bootstrap 95% interval of the pooled p99
	P99HiMS     float64 `json:"p99_hi_ms,omitempty"`
	MaxMS       float64 `json:"max_ms"`
	Samples     int     `json:"samples"`
	Lost        int     `json:"lost"`        // thin messages never delivered, all runs
	Unrecovered int     `json:"unrecovered"` // outage runs with no read after the outage
	Spread      float64 `json:"spread"`      // max over min of the judged value across runs; spreadInf for a missing value; 0 for a thin stream
}

// spreadInf stands for an infinite spread, which JSON cannot carry: a run without a judged value,
// such as one that never recovered from the outage.
const spreadInf = 1e9

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

// spread is the max over the min of v. A value of zero or below, a run without a usable value,
// makes it spreadInf, so a stuck run cannot hide.
func spread(v []float64) float64 {
	lo, hi := math.Inf(1), 0.0
	for _, x := range v {
		if x <= 0 {
			return spreadInf
		}
		lo, hi = math.Min(lo, x), math.Max(hi, x)
	}
	if hi == 0 {
		return 0
	}
	return hi / lo
}

func summarize(c Cell, runs []Run) Summary {
	s := Summary{Runs: len(runs), RecoveryMS: -1, RTOMS: -1, P50MS: -1, P99MS: -1, MaxMS: -1}
	var mb, rec, rto, judged []float64
	var lat []time.Duration
	for _, r := range runs {
		if r.Err != "" {
			continue // a failed run stays out of every median
		}
		s.OK++
		mb = append(mb, r.Mbps)
		if r.Recovery >= 0 {
			rec = append(rec, ms(r.Recovery))
		} else if c.Outage {
			s.Unrecovered++
		}
		if r.RTO >= 0 {
			rto = append(rto, ms(r.RTO))
		}
		lat = append(lat, r.Lat...)
		s.Lost += r.Lost
		switch {
		case c.Thin:
			// judged on the pooled p99 and its interval, not on the per-run spread
		case c.Outage:
			judged = append(judged, ms(r.Recovery)) // -1 for a run that never recovered
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
		if c.Thin {
			s.P99LoMS, s.P99HiMS = p99Interval(lat)
		}
	}
	s.Spread = spread(judged)
	if s.OK < s.Runs {
		s.Spread = spreadInf // a failed run makes the cell undetermined
	}
	return s
}

// bootstrapResamples is how many resamples p99Interval draws.
const bootstrapResamples = 1000

// p99Interval is the bootstrap 95% interval of the p99 of the sorted pool, in ms: the 2.5th and
// 97.5th percentiles of the p99 over resamples of the pool's size drawn with replacement. The
// seed is fixed, so the same pool gives the same interval.
func p99Interval(sorted []time.Duration) (lo, hi float64) {
	r := rand.New(rand.NewSource(1))
	n := len(sorted)
	idx := make([]int, n)
	est := make([]float64, bootstrapResamples)
	for i := range est {
		for j := range idx {
			idx[j] = r.Intn(n)
		}
		sort.Ints(idx) // a resample of indices into the sorted pool is sorted by value
		k := int(math.Ceil(0.99*float64(n))) - 1
		est[i] = ms(sorted[idx[max(k, 0)]])
	}
	sort.Float64s(est)
	return est[int(0.025*float64(len(est)))], est[int(0.975*float64(len(est)))-1]
}

// Reference is the stored medians the routine mode compares wgstack with. Each cell carries the
// provenance of the run that measured it, so a partial re-run can replace some cells.
type Reference struct {
	Measured string                        `json:"measured"`
	Where    string                        `json:"where"`
	BaseRuns int                           `json:"base_runs"` // per cell before doubling; each summary has its own runs
	Cells    map[string]map[string]Summary `json:"cells"`
	CellMeta map[string]Provenance         `json:"cell_meta"`
}

// Provenance says what measured a cell.
type Provenance struct {
	Measured string `json:"measured"`
	Commit   string `json:"commit"`
	Go       string `json:"go"`
	GVisor   string `json:"gvisor"`
	Where    string `json:"where"`
}

func provenance(where string) Provenance {
	p := Provenance{Measured: time.Now().UTC().Format(time.RFC3339), Commit: os.Getenv("QBENCH_COMMIT"), Go: runtime.Version(), Where: where}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "gvisor.dev/gvisor" {
				p.GVisor = d.Version
			}
		}
		for _, st := range bi.Settings {
			if st.Key == "vcs.revision" && p.Commit == "" {
				p.Commit = st.Value
			}
		}
	}
	if p.Commit == "" {
		p.Commit = gitCommit()
	}
	return p
}

// gitCommit is the checked-out commit of the tree the test runs in, with "-dirty" when the tree
// has changes, or "" when git cannot tell.
func gitCommit() string {
	out, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return ""
	}
	c := strings.TrimSpace(string(out))
	st, err := exec.Command("git", "status", "--porcelain", "--untracked-files=no").Output()
	if err != nil {
		return ""
	}
	if len(bytes.TrimSpace(st)) > 0 {
		c += "-dirty"
	}
	return c
}

// Verdict is the judgment of one cell by 判定の規則.
type Verdict struct {
	Rule, Result string
	Value, Line  float64
	// Straddles is set for a thin stream whose p99 interval contains the line, where the plan
	// doubles the runs as it does for a value near the line.
	Straddles bool
}

// throughputTolerance is the measurement tolerance of the throughput rule: wgstack passes at
// 0.99 of the binding line, so a cell where every engine fills the link does not fail on noise.
const throughputTolerance = 0.99

// judge applies the rule of c's kind to wgstack's summary against gVisor's and Linux's.
func judge(c Cell, wg, gv, lx Summary, haveG, haveL bool) Verdict {
	if c.NotJudged != "" {
		return Verdict{Rule: "-", Result: "NOT JUDGED: " + c.NotJudged}
	}
	if !haveL {
		return Verdict{Rule: "-", Result: "no Linux reference"}
	}
	// wgstack's own failures decide the cell whatever the spread
	switch {
	case wg.OK == 0:
		return Verdict{Rule: "-", Result: fmt.Sprintf("FAIL: none of %d wgstack runs finished", wg.Runs)}
	case !c.Thin && !c.Outage && wg.Mbps <= 0:
		return Verdict{Rule: "-", Result: "FAIL: wgstack's median is 0 Mbit/s"}
	case c.Thin && !c.Outage && wg.Lost > 0:
		return Verdict{Rule: "-", Result: fmt.Sprintf("FAIL: wgstack lost %d thin messages without an outage", wg.Lost)}
	}
	var v Verdict
	switch {
	case c.Thin:
		v = Verdict{Rule: "p99 95% interval vs 1.5 x Linux", Value: wg.P99MS, Line: 1.5 * lx.P99MS}
		switch {
		case wg.P99HiMS <= v.Line:
			v.Result = "PASS"
		case wg.P99LoMS > v.Line:
			v.Result = "FAIL"
		default:
			v.Straddles = true
			v.Result = fmt.Sprintf("UNDETERMINED: the 95%% interval %.0f to %.0f ms contains the line", wg.P99LoMS, wg.P99HiMS)
		}
		return v
	case c.Outage:
		if wg.Unrecovered > 0 {
			return Verdict{Rule: "recovery <= Linux + Linux RTO", Result: fmt.Sprintf("FAIL: %d runs never recovered", wg.Unrecovered)}
		}
		if lx.RTOMS < 0 {
			return Verdict{Rule: "recovery <= Linux + Linux RTO", Result: "no Linux RTO"}
		}
		v = Verdict{Rule: "recovery <= Linux + Linux RTO", Value: wg.RecoveryMS, Line: lx.RecoveryMS + lx.RTOMS}
		v.Result = yes(v.Value >= 0 && v.Value <= v.Line)
	default:
		// 0.8 x Linux, or gVisor's value where gVisor is above it
		line, rule := 0.8*lx.Mbps, "Mbit/s >= 0.99 x 0.8 x Linux; gVisor is below"
		if haveG && gv.Mbps > line {
			line, rule = gv.Mbps, "Mbit/s >= 0.99 x gVisor; gVisor is above 0.8 x Linux"
		}
		v = Verdict{Rule: rule, Value: wg.Mbps, Line: line}
		v.Result = yes(v.Value >= throughputTolerance*v.Line)
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
	return v.Straddles || (v.Line > 0 && v.Value >= 0 && math.Abs(v.Value/v.Line-1) <= 0.05)
}

func dur(d time.Duration) string {
	if d < 0 {
		return "-"
	}
	return d.Round(time.Millisecond).String()
}

func printRun(r Run) {
	p99 := "-"
	if len(r.Lat) > 0 {
		l := append([]time.Duration(nil), r.Lat...)
		sort.Slice(l, func(i, j int) bool { return l[i] < l[j] })
		p99 = dur(quantile(l, 0.99))
	}
	fmt.Printf("QBENCH-RUN engine=%s cell=%s seed=%d bytes=%d mbps=%.2f verified=%v recovery=%s rto=%s stall=%s samples=%d p99=%s lost=%d retrans=%d/%d qdrop=%d err=%q\n",
		r.Engine, r.Cell, r.Seed, r.Bytes, r.Mbps, r.Verified, dur(r.Recovery), dur(r.RTO),
		r.Stall.Round(time.Millisecond), len(r.Lat), p99, r.Lost, r.Retrans, r.DataPkts, r.QDrops, r.Err)
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
	fmt.Printf("QBENCH-SUMMARY engine=%s cell=%s runs=%d ok=%d mbps=%.2f recovery_ms=%.0f rto_ms=%.0f unrecovered=%d p50_ms=%.1f p99_ms=%.1f p99_ci_ms=%.1f-%.1f max_ms=%.1f samples=%d lost=%d spread=%.2f\n",
		eng, c.Name, s.Runs, s.OK, s.Mbps, s.RecoveryMS, s.RTOMS, s.Unrecovered, s.P50MS, s.P99MS, s.P99LoMS, s.P99HiMS, s.MaxMS, s.Samples, s.Lost, s.Spread)
}

// checkPool fails the test when a thin cell's pool is below the plan's 1,000 samples.
func checkPool(t *testing.T, c Cell, eng string, s Summary) {
	if c.Thin && s.Samples < 1000 {
		t.Errorf("%s %s: %d thin-stream samples pooled, below the plan's 1,000", eng, c.Name, s.Samples)
	}
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
	return withClient(nameFilter(cells), os.Getenv("QBENCH_CLIENT"))
}

// withClient gives the cells in which the DUT receives the client named by QBENCH_CLIENT. With the
// Linux client the sender's RTO is the kernel's and can be read, so the receiving outage cells are
// judged. The cells' names say the client, since their values differ from the gVisor client's.
func withClient(cells []Cell, client string) []Cell {
	if client == "" || client == "gvisor" {
		return cells
	}
	out := append([]Cell(nil), cells...)
	for i := range out {
		if !out[i].DUTSend {
			out[i].Client = client
			out[i].Name += "/" + client + "-client"
			out[i].NotJudged = ""
		}
	}
	return out
}

func nameFilter(cells []Cell) []Cell {
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
		return &Reference{Cells: map[string]map[string]Summary{}, CellMeta: map[string]Provenance{}}
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
	if (has(engines, "linux") || os.Getenv("QBENCH_CLIENT") == "linux") && !inNetns(t) {
		return
	}
	pinLinux(t, engines)
	ref := loadReference(t)
	fmt.Printf("QBENCH-META mode=routine reference=%q measured=%q base_runs=%d\n", ref.Where, ref.Measured, ref.BaseRuns)
	runs := envInt("QBENCH_RUNS", 5)
	cells := cellFilter(routineCells())
	var table []string
	for ci, c := range cells {
		res := measure(t, c, ci, engines, runs, 0)
		wg := summarize(c, res["wgstack"])
		printSummary(c, "wgstack", wg)
		checkPool(t, c, "wgstack", wg)
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
// per cell, judged by 判定の規則, with the runs doubled for a cell within 5% of its line or, for a
// thin stream, with a p99 interval that contains the line.
// QBENCH_WRITE_REF names a file to store the gVisor and Linux medians in, for the routine mode.
func TestQBenchGate(t *testing.T) {
	engines := []string{"wgstack", "gvisor", "linux"}
	if v := os.Getenv("QBENCH_ENGINES"); v != "" {
		engines = strings.Split(v, ",")
	}
	// the gate fixes each cell's client itself, so QBENCH_CLIENT does not apply
	cells := nameFilter(gateCells())
	linuxClient := false
	for _, c := range cells {
		linuxClient = linuxClient || c.Client == "linux"
	}
	if (has(engines, "linux") || linuxClient) && !inNetns(t) {
		return
	}
	where := pinLinux(t, engines)
	runs := envInt("QBENCH_RUNS", 9)
	prov := provenance(where)
	if os.Getenv("QBENCH_WRITE_REF") != "" {
		if prov.Commit == "" {
			t.Fatalf("the commit is unknown: run in the git tree or set QBENCH_COMMIT")
		}
		if strings.HasSuffix(prov.Commit, "-dirty") {
			t.Logf("WARNING: the tree has uncommitted changes; the reference records %s", prov.Commit)
		}
	}
	ref := &Reference{Cells: map[string]map[string]Summary{}, CellMeta: map[string]Provenance{}}
	if path := os.Getenv("QBENCH_WRITE_REF"); path != "" {
		// fail now rather than after the runs if the file cannot be written
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			t.Fatalf("the reference file is not writable: %v", err)
		}
		f.Close()
		// a partial run replaces its own cells and keeps the others
		if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
			if err := json.Unmarshal(b, ref); err != nil {
				t.Fatalf("reading %s: %v", path, err)
			}
			if ref.CellMeta == nil {
				ref.CellMeta = map[string]Provenance{}
			}
			// the cells this run keeps carry the provenance they were measured with
			for name := range ref.Cells {
				if _, ok := ref.CellMeta[name]; !ok {
					ref.CellMeta[name] = Provenance{Measured: ref.Measured, Where: ref.Where, Commit: "not recorded", Go: "not recorded", GVisor: "not recorded"}
				}
			}
		}
	}
	ref.Measured, ref.Where, ref.BaseRuns = prov.Measured, where, runs
	var table []string
	for ci, c := range cells {
		res := measure(t, c, ci, engines, runs, 0)
		sum := func() map[string]Summary {
			m := map[string]Summary{}
			for _, e := range engines {
				m[e] = summarize(c, res[e])
				printSummary(c, e, m[e])
				checkPool(t, c, e, m[e])
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
		// a reference that failed or spreads too far is not stored; the cell keeps what it had
		if bad := unstorable(engines, m); bad != "" {
			fmt.Printf("QBENCH-WARN cell=%s reference not stored: %s\n", c.Name, bad)
			t.Logf("WARNING: %s: reference not stored: %s", c.Name, bad)
		} else {
			ref.Cells[c.Name] = map[string]Summary{}
			ref.CellMeta[c.Name] = prov
			for _, e := range engines {
				if e != "wgstack" {
					ref.Cells[c.Name][e] = m[e]
				}
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

// unstorable says why the gVisor and Linux summaries of a cell must not become the reference, or
// returns "" when they may.
func unstorable(engines []string, m map[string]Summary) string {
	for _, e := range engines {
		if e == "wgstack" {
			continue
		}
		s := m[e]
		switch {
		case s.OK < s.Runs:
			return fmt.Sprintf("%s: %d of %d runs failed", e, s.Runs-s.OK, s.Runs)
		case s.Spread > 2:
			return fmt.Sprintf("%s: max/min %.2f is above 2", e, s.Spread)
		}
	}
	return ""
}

func row(c Cell, wg, gv, lx Summary, v Verdict) string {
	val := func(s Summary) string {
		switch {
		case s.Runs == 0:
			return "-"
		case c.Thin:
			return fmt.Sprintf("%.0f / %.0f (%.0f to %.0f) / %.0f ms, %d lost", s.P50MS, s.P99MS, s.P99LoMS, s.P99HiMS, s.MaxMS, s.Lost)
		case c.Outage:
			return fmt.Sprintf("%.0f ms, RTO %.0f ms, %.2f Mbit/s", s.RecoveryMS, s.RTOMS, s.Mbps)
		}
		return fmt.Sprintf("%.2f Mbit/s", s.Mbps)
	}
	rule := fmt.Sprintf("%s: %.1f vs %.1f", v.Rule, v.Value, v.Line)
	if c.NotJudged != "" {
		rule = "-"
	}
	return fmt.Sprintf("| %s | %s | %s | %s | %s | %s |", c.Name, val(wg), val(gv), val(lx), rule, v.Result)
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

// TestJudgeRules checks the summary and judgment rules on made-up runs, without a network.
func TestJudgeRules(t *testing.T) {
	out := Cell{Name: "send/outage2s", DUTSend: true, Outage: true}
	rec := func(d time.Duration) Run { return Run{Recovery: d, RTO: time.Second} }

	stuck := summarize(out, []Run{rec(time.Second), rec(time.Second), rec(-1)})
	if stuck.Unrecovered != 1 || stuck.Spread != spreadInf {
		t.Errorf("a run that never recovered: unrecovered %d, spread %v; want 1 and infinite", stuck.Unrecovered, stuck.Spread)
	}
	lx := summarize(out, []Run{rec(time.Second)})
	if v := judge(out, stuck, Summary{}, lx, false, true); !strings.HasPrefix(v.Result, "FAIL") {
		t.Errorf("wgstack with an unrecovered run: %q, want FAIL", v.Result)
	}

	failed := summarize(out, []Run{rec(time.Second), {Err: "boom", Recovery: 10 * time.Second}})
	if failed.OK != 1 || failed.RecoveryMS != 1000 || failed.Spread != spreadInf {
		t.Errorf("a failed run: ok %d, recovery %v ms, spread %v; want 1, 1000 and infinite", failed.OK, failed.RecoveryMS, failed.Spread)
	}

	thin := Cell{Name: "thin-send/loss0%", DUTSend: true, Thin: true}
	lat := make([]time.Duration, 100)
	for i := range lat {
		lat[i] = 10 * time.Millisecond
	}
	lat[99] = 5 * time.Second // what runThin appends for an undelivered message
	s := summarize(thin, []Run{{Lat: lat, Lost: 1}})
	if s.Lost != 1 || s.MaxMS != 5000 {
		t.Errorf("an undelivered message: lost %d, max %v ms; want 1 and 5000", s.Lost, s.MaxMS)
	}

	bulkC := Cell{Name: "send/loss0%", DUTSend: true}
	lxBulk := Summary{Runs: 1, OK: 1, Mbps: 10}
	if v := judge(bulkC, Summary{Runs: 5}, Summary{}, lxBulk, false, true); !strings.HasPrefix(v.Result, "FAIL") {
		t.Errorf("no wgstack run finished: %q, want FAIL", v.Result)
	}
	if v := judge(bulkC, Summary{Runs: 5, OK: 5, Spread: spreadInf}, Summary{}, lxBulk, false, true); !strings.HasPrefix(v.Result, "FAIL") {
		t.Errorf("wgstack at 0 Mbit/s: %q, want FAIL", v.Result)
	}
	lossy := Summary{Runs: 5, OK: 5, P99MS: 10, Lost: 1, Spread: 1}
	if v := judge(thin, lossy, Summary{}, Summary{Runs: 5, OK: 5, P99MS: 100, Spread: 1}, false, true); !strings.HasPrefix(v.Result, "FAIL") {
		t.Errorf("a lost thin message without an outage: %q, want FAIL", v.Result)
	}
	if bad := unstorable([]string{"wgstack", "linux"}, map[string]Summary{"linux": {Runs: 9, OK: 8}}); bad == "" {
		t.Error("a Linux summary with a failed run would be stored")
	}
	if bad := unstorable([]string{"gvisor"}, map[string]Summary{"gvisor": {Runs: 9, OK: 9, Spread: 2.5}}); bad == "" {
		t.Error("a gVisor summary spreading above 2 would be stored")
	}

	// thin streams: the pooled p99's interval against 1.5 x Linux
	lxThin := Summary{Runs: 5, OK: 5, P99MS: 100}
	for _, tc := range []struct {
		lo, hi float64
		want   string
	}{{100, 140, "PASS"}, {160, 200, "FAIL"}, {140, 160, "UNDETERMINED"}} {
		wgThin := Summary{Runs: 5, OK: 5, P99MS: (tc.lo + tc.hi) / 2, P99LoMS: tc.lo, P99HiMS: tc.hi}
		v := judge(thin, wgThin, Summary{}, lxThin, false, true)
		if !strings.HasPrefix(v.Result, tc.want) || (tc.want == "UNDETERMINED") != near(v) {
			t.Errorf("interval %v to %v against 150: %q, doubling %v; want %s", tc.lo, tc.hi, v.Result, near(v), tc.want)
		}
	}
	pool := make([]time.Duration, 2000)
	for i := range pool {
		pool[i] = time.Duration(i) * time.Millisecond
	}
	if lo, hi := p99Interval(pool); !(lo < 1980 && hi > 1980 && lo > 1960 && hi < 2000) {
		t.Errorf("the p99 interval of 0 to 1999 ms is %v to %v; want about 1980 inside it", lo, hi)
	}

	// throughput: 1% measurement tolerance under the binding line
	gvBulk := Summary{Runs: 5, OK: 5, Mbps: 18.87, Spread: 1}
	lx19 := Summary{Runs: 5, OK: 5, Mbps: 18.87, Spread: 1}
	if v := judge(bulkC, Summary{Runs: 5, OK: 5, Mbps: 18.86, Spread: 1}, gvBulk, lx19, true, true); v.Result != "PASS" {
		t.Errorf("18.86 against gVisor's 18.87: %q, want PASS", v.Result)
	}
	if v := judge(bulkC, Summary{Runs: 5, OK: 5, Mbps: 18.6, Spread: 1}, gvBulk, lx19, true, true); v.Result != "FAIL" {
		t.Errorf("18.6 against gVisor's 18.87: %q, want FAIL", v.Result)
	}

	// the gate judges every receiving cell with the Linux client and keeps the gVisor one aside
	for _, c := range gateCells() {
		switch {
		case c.DUTSend:
		case c.Client == "linux" && c.NotJudged != "":
			t.Errorf("%s: the Linux-client cell is not judged", c.Name)
		case c.Client == "" && c.NotJudged == "":
			t.Errorf("%s: the gVisor-client cell is judged", c.Name)
		}
	}

	nj := Cell{Name: "recv/outage2s", Outage: true, NotJudged: clientSends}
	if v := judge(nj, stuck, Summary{}, lx, false, true); !strings.HasPrefix(v.Result, "NOT JUDGED") {
		t.Errorf("recv/outage2s: %q, want NOT JUDGED", v.Result)
	}
}
