package wgstack

import (
	"testing"
	"time"
)

// 観測(wgstack-performance.md の「安く確かめる手順」)の数と関数を確かめる。観測は挙動を変えない。

func traceInto(n *testNet) *[]TraceEvent {
	var evs []TraceEvent
	n.d.s.trace = func(e TraceEvent) { evs = append(evs, e) }
	return &evs
}

func TestStatsCountFastRecoveryAndPartialAck(t *testing.T) {
	n := newTestNet(t, smallLimits())
	evs := traceInto(n)
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	mss := testMTU - 40 - 12
	c.Write(make([]byte, 10*mss))
	outs := n.drain()
	p.rcv = outs[0].seg.seq + uint32(mss)
	p.ack(nil)
	n.drain()
	for range 3 {
		p.ack(nil)
	}
	n.drain()
	p.rcv = outs[2].seg.seq
	p.ack(nil)
	n.drain()
	st := n.d.Stats()
	if st.DupAcksIn != 3 || st.FastRecoveries != 1 || st.RetransFast != 1 || st.PartialAcks != 1 || st.RetransPartial != 1 || st.RTOs != 0 || st.RetransRTO != 0 {
		t.Fatalf("stats %+v", st)
	}
	last := (*evs)[len(*evs)-1]
	if last.Kind != TraceAck || !last.InRecovery || last.SndUna != outs[2].seg.seq || last.Flight != last.SndMax-last.SndUna ||
		last.Remote.Port() != 40000 || last.Local.Port() != 80 || last.PeerWnd == 0 || last.RTO < rtoMin {
		t.Fatalf("last trace %+v", last)
	}
	if len(*evs) != 5 { // 1 つ目の確認、3 つの重複、部分の確認。握手の最後の ACK は握手の行が処理する
		t.Fatalf("%d trace events", len(*evs))
	}
}

func TestStatsCountRTOsAndBackoff(t *testing.T) {
	n := newTestNet(t, smallLimits())
	evs := traceInto(n)
	l := listen(t, n, 80)
	n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	c.Write([]byte("data"))
	n.drain()
	for countKind(*evs, TraceRTO) < 2 {
		n.advance(time.Millisecond)
		n.drain()
	}
	var rtos []time.Duration // TraceRTO は後退を含めた次の RTO を渡す
	for _, e := range *evs {
		if e.Kind == TraceRTO {
			rtos = append(rtos, e.RTO)
		}
	}
	st := n.d.Stats()
	if st.RTOs != 2 || st.RTOsBackedOff != 1 || st.RetransRTO != 2 || st.RTOsShortOfDupThresh != 0 || st.FastRecoveries != 0 {
		t.Fatalf("stats %+v", st)
	}
	if rtos[1] != 2*rtos[0] {
		t.Fatalf("RTO in the trace %v", rtos)
	}
}

func countKind(evs []TraceEvent, k TraceKind) int {
	m := 0
	for _, e := range evs {
		if e.Kind == k {
			m++
		}
	}
	return m
}

func TestStatsCountRTOShortOfDupThresh(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	mss := testMTU - 40 - 12
	c.Write(make([]byte, 3*mss))
	outs := n.drain()
	p.rcv = outs[0].seg.seq + uint32(mss)
	p.ack(nil)
	p.ack(nil) // 重複した ACK を 1 つだけ受ける
	n.drain()
	for n.d.Stats().RTOs == 0 {
		n.advance(time.Millisecond)
		n.drain()
	}
	st := n.d.Stats()
	if st.DupAcksIn != 1 || st.RTOsShortOfDupThresh != 1 || st.FastRecoveries != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestStatsCountDelayedAndImmediateAcks(t *testing.T) {
	n := newTestNet(t, smallLimits())
	listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	n.drain()
	skipQuickack(n)
	base := n.d.Stats()
	p.ack(make([]byte, 100))
	n.advance(delackTimeout)
	n.drain()
	full := make([]byte, testMTU-40-12)
	p.ack(full)
	p.ack(full)
	n.drain()
	st := n.d.Stats()
	if st.AcksDelayed-base.AcksDelayed != 1 || st.AcksImmediate-base.AcksImmediate != 1 {
		t.Fatalf("delayed %d immediate %d", st.AcksDelayed-base.AcksDelayed, st.AcksImmediate-base.AcksImmediate)
	}
}

func TestStatsCountPMTUResend(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	c.Write(make([]byte, 3000))
	outs := n.drain()
	cs := c.c
	cs.mu.Lock()
	cs.pmtuDrop(outs[0].seg.seq, 1000, int64(n.clk.Now()))
	cs.mu.Unlock()
	resent := n.drain()
	if st := n.d.Stats(); st.RetransPMTU == 0 || st.RetransPMTU != uint64(len(resent)) || st.RetransRTO != 0 {
		t.Fatalf("stats %+v after %d resent segments", st, len(resent))
	}
}

func TestTestBoostPolicy(t *testing.T) {
	t.Run("at accept", func(t *testing.T) {
		n := newTestNet(t, smallLimits())
		n.d.s.boostPolicy = BoostAtAccept
		l := listen(t, n, 80)
		n.handshake(40000, 80, true, false, true)
		c := acceptOne(t, l)
		if !c.c.boosted || !c.c.rcvBoost || c.c.rcvCap != boostSize || n.d.Stats().BoostGranted != 1 {
			t.Fatalf("boosted %v rcvBoost %v", c.c.boosted, c.c.rcvBoost)
		}
		checkHeld(t, n)
	})
	t.Run("never", func(t *testing.T) {
		n := newTestNet(t, smallLimits())
		n.d.s.boostPolicy = BoostNever
		l := listen(t, n, 80)
		p := n.handshake(40000, 80, true, false, true)
		c := acceptOne(t, l)
		p.sendBulk(demandBytes)
		readN(t, c, demandBytes)
		if _, err := c.Write(make([]byte, demandBytes)); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 10000 && c.c.unaOff != c.c.tailOff; i++ {
			p.absorb(n.drain())
			p.ack(nil)
		}
		if c.c.boosted || n.d.Stats().BoostGranted != 0 {
			t.Fatal("boosted under BoostNever")
		}
	})
}

func TestConfigSetsTraceAndTestBoost(t *testing.T) {
	called := false
	d, err := New(Config{Addr: dutAddr, MTU: testMTU, Clock: NewManualClock(), Trace: func(TraceEvent) { called = true }, TestBoost: BoostNever})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if d.s.trace == nil || d.s.boostPolicy != BoostNever || called {
		t.Fatal("Config.Trace or Config.TestBoost not applied")
	}
}

// TestTraceDoesNotChangeOutput は、観測の関数を設定しても Device の出力が 1 byte も変わらないことを確かめる。
func TestTraceDoesNotChangeOutput(t *testing.T) {
	var evs *[]TraceEvent
	run := func(trace bool) [][]byte {
		n := newTestNet(t, smallLimits())
		if trace {
			evs = traceInto(n)
		}
		l := listen(t, n, 80)
		p := n.handshake(40000, 80, true, true, true)
		c := acceptOne(t, l)
		var got [][]byte
		mss := testMTU - 40 - 12
		c.Write(make([]byte, 20*mss))
		outs := n.drainRaw()
		got = append(got, outs...)
		first := n.d.s.conns[c.c.id].sndUna
		p.rcv = first + uint32(mss)
		for range 4 {
			p.ack(nil)
			got = append(got, n.drainRaw()...)
		}
		for range 3 {
			n.advance(300 * time.Millisecond)
			got = append(got, n.drainRaw()...)
		}
		return got
	}
	a, b := run(false), run(true)
	if len(*evs) == 0 || countKind(*evs, TraceRTO) == 0 {
		t.Fatalf("the traced run produced %d events, %d of them RTOs", len(*evs), countKind(*evs, TraceRTO))
	}
	if len(a) < 12 || len(a) != len(b) {
		t.Fatalf("%d packets without the trace, %d with it", len(a), len(b))
	}
	for i := range a {
		if string(a[i]) != string(b[i]) {
			t.Fatalf("packet %d differs", i)
		}
	}
}
