//go:build qbench

package qbench

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Case is one cell of the matrix.
type Case struct {
	Name    string
	Loss    float64
	DUTSend bool // the DUT is the data sender
	Outage  bool
}

// Result is one run.
type Result struct {
	Engine, Case string
	Seed         int64
	Bytes, Want  int64
	Dur          time.Duration
	HashOK       bool
	Err          string
	Mbps         float64
	Recovery     time.Duration // outage end to the next byte at the receiver; -1 if none
	Stall        time.Duration // longest gap between receiver reads outside the outage
	Retrans      int
	DataPkts     int
	QDrops       int
	RandDrops    int
}

type gap struct{ from, to time.Time }

func gen(seed int64) *rand.Rand { return rand.New(rand.NewSource(seed)) }

func runOne(engine string, c Case, seed int64, size int64, limit time.Duration) (res Result) {
	res = Result{Engine: engine, Case: c.Name, Seed: seed, Want: size, Recovery: -1}
	imp := Impair{Delay: 25 * time.Millisecond, Loss: c.Loss, RateBps: int64(envInt("QBENCH_RATE_MBIT", 20)) * 1_000_000, QueuePkts: envInt("QBENCH_QUEUE_PKTS", 200)}
	dataDir := 0
	if c.DUTSend {
		dataDir = 1
	}
	if c.Outage {
		imp.OutageAfter, imp.OutageLen, imp.DataDir = 2<<20, 2*time.Second, dataDir
	}
	rig, err := newRig(engine, imp, seed)
	if err != nil {
		res.Err = "setup: " + err.Error()
		return
	}
	defer rig.Close()
	ln, err := rig.D.Listen(port)
	if err != nil {
		res.Err = "listen: " + err.Error()
		return
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	type acc struct {
		c   net.Conn
		err error
	}
	accCh := make(chan acc, 1)
	go func() { cn, err := ln.Accept(); accCh <- acc{cn, err} }()
	dctx, dcancel := context.WithTimeout(ctx, 40*time.Second)
	cc, err := rig.C.Dial(dctx)
	dcancel()
	if err != nil {
		res.Err = "dial: " + err.Error()
		return
	}
	defer cc.Close()
	var dc net.Conn
	select {
	case a := <-accCh:
		if a.err != nil {
			res.Err = "accept: " + a.err.Error()
			return
		}
		dc = a.c
	case <-ctx.Done():
		res.Err = "accept: timeout"
		return
	}
	defer dc.Close()

	snd, rcv := cc, dc
	if c.DUTSend {
		snd, rcv = dc, cc
	}
	deadline := time.Now().Add(limit)
	snd.SetDeadline(deadline)
	rcv.SetDeadline(deadline)

	start := time.Now()
	sendHash := make(chan [32]byte, 1)
	sendErr := make(chan error, 1)
	go func() {
		h := sha256.New()
		r := gen(seed)
		buf := make([]byte, 32<<10)
		left := size
		for left > 0 {
			n := int64(len(buf))
			if n > left {
				n = left
			}
			r.Read(buf[:n])
			h.Write(buf[:n])
			if _, err := snd.Write(buf[:n]); err != nil {
				sendErr <- err
				return
			}
			left -= n
		}
		var s [32]byte
		copy(s[:], h.Sum(nil))
		if cw, ok := snd.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		sendHash <- s
		sendErr <- nil
	}()

	// receiver
	h := sha256.New()
	buf := make([]byte, 64<<10)
	var got int64
	var last time.Time
	var gaps []gap
	var rerr error
	for {
		n, err := rcv.Read(buf)
		now := time.Now()
		if n > 0 {
			h.Write(buf[:n])
			got += int64(n)
			if !last.IsZero() && now.Sub(last) >= 30*time.Millisecond {
				gaps = append(gaps, gap{last, now})
			}
			last = now
		}
		if err != nil {
			if err != io.EOF {
				rerr = err
			}
			break
		}
	}
	end := time.Now()
	res.Bytes, res.Dur = got, end.Sub(start)
	if got > 0 {
		res.Mbps = float64(got) * 8 / res.Dur.Seconds() / 1e6
	}
	var want [32]byte
	select {
	case want = <-sendHash:
		res.HashOK = got == size && string(h.Sum(nil)) == string(want[:])
	default:
		res.HashOK = false
	}
	switch {
	case rerr != nil:
		res.Err = "recv: " + rerr.Error()
	case got != size:
		res.Err = fmt.Sprintf("short: %d of %d bytes", got, size)
	case !res.HashOK:
		res.Err = "HASH MISMATCH"
	}
	select {
	case e := <-sendErr:
		if e != nil && res.Err == "" {
			res.Err = "send: " + e.Error()
		}
	default:
	}

	os, oe := rig.L.Outage()
	for _, g := range gaps {
		if !os.IsZero() && g.from.Before(oe) && g.to.After(os) {
			if g.to.After(oe) {
				res.Recovery = g.to.Sub(oe)
			}
			continue
		}
		if d := g.to.Sub(g.from); d > res.Stall {
			res.Stall = d
		}
	}
	if c.Outage && !os.IsZero() && res.Recovery < 0 && got < size {
		res.Recovery = -1 // never recovered
	}
	st := rig.L.Stats(dataDir)
	res.Retrans, res.DataPkts, res.QDrops, res.RandDrops = st.Retrans, st.DataPkts, st.QDrops, st.Dropped
	return
}

func median[T int | float64 | time.Duration](v []T) T {
	s := append([]T(nil), v...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}

func envInt(k string, d int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return v
	}
	return d
}

func TestQBench(t *testing.T) {
	runs := envInt("QBENCH_RUNS", 3)
	size := int64(envInt("QBENCH_MIB", 8)) << 20
	limit := time.Duration(envInt("QBENCH_LIMIT_S", 150)) * time.Second
	only := os.Getenv("QBENCH_ONLY")
	var cases []Case
	for _, dir := range []bool{false, true} {
		dn := "dut-recv"
		if dir {
			dn = "dut-send"
		}
		for _, l := range []float64{0, 0.01, 0.05} {
			cases = append(cases, Case{Name: fmt.Sprintf("loss%g%%/%s", l*100, dn), Loss: l, DUTSend: dir})
		}
		cases = append(cases, Case{Name: "outage2s/" + dn, DUTSend: dir, Outage: true})
	}
	var all []Result
	byKey := map[string][]Result{}
	for _, c := range cases {
		if only != "" && !strings.Contains(c.Name, only) {
			continue
		}
		for _, eng := range []string{"wgstack", "gvisor"} {
			for run := 0; run < runs; run++ {
				seed := int64(run+1)*7919 + int64(len(c.Name))*131 + int64(c.Loss*1000)
				fmt.Printf("QBENCH-START engine=%s case=%s run=%d seed=%d\n", eng, c.Name, run, seed)
				r := runOne(eng, c, seed, size, limit)
				fmt.Printf("QBENCH-RUN engine=%s case=%s run=%d seed=%d bytes=%d/%d dur=%s mbps=%.2f hash_ok=%v recovery=%s stall=%s retrans=%d/%d qdrop=%d randdrop=%d err=%q\n",
					eng, c.Name, run, seed, r.Bytes, r.Want, r.Dur.Round(time.Millisecond), r.Mbps, r.HashOK, r.Recovery.Round(time.Millisecond), r.Stall.Round(time.Millisecond), r.Retrans, r.DataPkts, r.QDrops, r.RandDrops, r.Err)
				all = append(all, r)
				k := eng + "|" + c.Name
				byKey[k] = append(byKey[k], r)
				if r.Err != "" {
					t.Errorf("%s %s run %d seed %d: %s", eng, c.Name, run, seed, r.Err)
				}
			}
		}
	}
	fmt.Println("QBENCH-TABLE")
	fmt.Println("| case | engine | ok/runs | Mbit/s (median) | duration | recovery after outage | longest stall | retransmits (data pkts) | queue drops |")
	fmt.Println("|---|---|---|---|---|---|---|---|---|")
	for _, c := range cases {
		for _, eng := range []string{"wgstack", "gvisor"} {
			rs := byKey[eng+"|"+c.Name]
			if len(rs) == 0 {
				continue
			}
			var ok int
			var mb []float64
			var du, rec, st []time.Duration
			var rt, dp, qd []int
			for _, r := range rs {
				if r.Err == "" {
					ok++
				}
				mb = append(mb, r.Mbps)
				du = append(du, r.Dur)
				rec = append(rec, r.Recovery)
				st = append(st, r.Stall)
				rt = append(rt, r.Retrans)
				dp = append(dp, r.DataPkts)
				qd = append(qd, r.QDrops)
			}
			recs := "-"
			if c.Outage {
				recs = median(rec).Round(time.Millisecond).String()
			}
			fmt.Printf("| %s | %s | %d/%d | %.2f | %s | %s | %s | %d (%d) | %d |\n", c.Name, eng, ok, len(rs), median(mb),
				median(du).Round(10*time.Millisecond), recs, median(st).Round(10*time.Millisecond), median(rt), median(dp), median(qd))
		}
	}
	fmt.Println("QBENCH-DONE")
}

// TestQBenchSmoke is a short unclean-link transfer that checks the rig itself.
func TestQBenchSmoke(t *testing.T) {
	for _, eng := range []string{"wgstack", "gvisor"} {
		for _, send := range []bool{false, true} {
			r := runOne(eng, Case{Name: "smoke", Loss: 0.01, DUTSend: send}, 42, 1<<20, 60*time.Second)
			t.Logf("%s send=%v: %+v", eng, send, r)
			if r.Err != "" {
				t.Errorf("%s send=%v: %s", eng, send, r.Err)
			}
		}
	}
}
