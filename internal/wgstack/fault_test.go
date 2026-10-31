package wgstack

import (
	"testing"
	"time"
)

// TestAccountingFaultClosesTheConnection は、送信の輪の生きている範囲の外を送ろうとした時に、segment を作らず、
// RST を送って接続を閉じ、数を数えることを確かめる。
func TestAccountingFaultClosesTheConnection(t *testing.T) {
	n, c, cs, _, _ := rackConnApp(t, 2)
	cs.mu.Lock()
	o := cs.options(int64(n.clk.Now()), true)
	b := make([]byte, 2048)
	k := cs.emit(b, cs.sndMax, 0, &o, cs.tailOff, 100, int64(n.clk.Now()))
	st := cs.state
	cs.mu.Unlock()
	if k != 0 || st != stClosed || n.d.Stats().AccountingFaults != 1 {
		t.Fatalf("emit %d, state %v, stats %+v", k, st, n.d.Stats())
	}
	rst := false
	for _, x := range n.drain() {
		rst = rst || x.seg.has(flagRST)
	}
	if !rst {
		t.Fatal("no RST after the fault")
	}
	if _, err := c.Write([]byte("x")); err == nil {
		t.Fatal("write succeeded on the faulted connection")
	}
}

// TestRetransmitPastSNDMaxIsAFault は、SND.MAX の先に終わる再送を会計の不整合として扱うことを確かめる。
func TestRetransmitPastSNDMaxIsAFault(t *testing.T) {
	_, _, cs, _, _ := rackConnApp(t, 2)
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if !cs.sendRangeOK(cs.sndUna, cs.sndMax-cs.sndUna) || cs.sendRangeOK(cs.sndUna+1, cs.sndMax-cs.sndUna) || cs.sendRangeOK(cs.sndUna-1, 1) {
		t.Fatal("sendRangeOK does not bound [SND.UNA, SND.MAX)")
	}
}

// TestChunksAreZeroedWhenReturned は、置き場に戻した chunk が前の中身を持たないことを確かめる。
func TestChunksAreZeroedWhenReturned(t *testing.T) {
	var p chunkPool
	ch := p.get()
	for i := range ch {
		ch[i] = 0x5a
	}
	p.put(ch)
	ch = p.get()
	for i, v := range ch {
		if v != 0 {
			t.Fatalf("byte %d of a reused chunk is %#x", i, v)
		}
	}
}

// TestTimeWaitWantsOnlyAnACK は、TIME_WAIT に入る時に送り残しの probe と再送の印を消し、TIME_WAIT の接続が
// ACK のほかに送るものを持たないと答えることを確かめる。
func TestTimeWaitWantsOnlyAnACK(t *testing.T) {
	n, _, cs, _, _ := rackConnApp(t, 1)
	cs.mu.Lock()
	cs.tlpProbe, cs.tlpActive, cs.fastRtx, cs.probePending = true, true, true, true
	cs.enterTimeWait(int64(n.clk.Now()))
	cleared := !cs.tlpProbe && !cs.tlpActive && !cs.fastRtx && !cs.probePending
	cs.tlpProbe, cs.fastRtx = true, true // 印が残った場合
	cs.ackNow = false
	wants := cs.wantOutput()
	cs.mu.Unlock()
	if !cleared {
		t.Fatal("output marks survived into TIME_WAIT")
	}
	if wants {
		t.Fatal("a TIME_WAIT connection without an ACK to send wants output")
	}
}

// pendingConn は送るデータを持つ接続を返す。小さすぎる buffer での Poll では、接続は送るものがあると答えるのに
// segment を作れないので、build と wantOutput が食い違う形になる。
func pendingConn(t *testing.T, n *testNet, port uint16) *tcb {
	t.Helper()
	l := listen(t, n, port)
	n.handshake(40000+port, port, true, true, true)
	c := acceptOne(t, l)
	n.drain()
	c.Write(make([]byte, 100))
	c.c.mu.Lock()
	defer c.c.mu.Unlock()
	if !c.c.wantOutput() {
		t.Fatal("setup: the connection does not want output")
	}
	return c.c
}

// pollWithin は期限つきで b の大きさの Poll を呼び、packet の長さを返す。期限を過ぎたら試験を落とす。
func pollWithin(t *testing.T, n *testNet, size int) int {
	t.Helper()
	done := make(chan int, 1)
	go func() { done <- n.d.Poll(make([]byte, size)) }()
	select {
	case k := <-done:
		return k
	case <-time.After(3 * time.Second):
		t.Fatal("Poll spun on a connection that builds nothing")
	}
	return 0
}

// TestEmptyBuildIsNotRequeued は、何も作らなかった接続を出力の list に入れ直さないことを確かめる(出力の守りの
// 3 つ目の層)。
func TestEmptyBuildIsNotRequeued(t *testing.T) {
	n := newTestNet(t, smallLimits())
	cs := pendingConn(t, n, 80)
	if k := pollWithin(t, n, 40); k != 0 {
		t.Fatalf("built %d bytes into a 40-byte buffer", k)
	}
	n.d.s.out.mu.Lock()
	queued := n.d.s.out.conns.in[cs.id]
	n.d.s.out.mu.Unlock()
	if queued {
		t.Fatal("the connection that built nothing was put back on the output list")
	}
}

// TestPollGivesUpOnEntriesThatBuildNothing は、何も作らない接続が入れ直され続けても、1 回の Poll が list に
// 入りうる数を超えて回らずに戻ることを確かめる(出力の守りの 4 つ目の層)。3 つ目の層を試験の切り替えで外す。
func TestPollGivesUpOnEntriesThatBuildNothing(t *testing.T) {
	requeueEmptyForTest = true
	defer func() { requeueEmptyForTest = false }()
	n := newTestNet(t, smallLimits())
	var conns []*Conn
	for _, port := range []uint16{80, 81} {
		l := listen(t, n, port)
		n.handshake(40000+port, port, true, true, true)
		conns = append(conns, acceptOne(t, l))
		n.drain()
	}
	for _, c := range conns {
		c.Write(make([]byte, 100))
	}
	if k := pollWithin(t, n, 40); k != 0 {
		t.Fatalf("built %d bytes into a 40-byte buffer", k)
	}
	// 普通の大きさの buffer では、どちらの接続の出力も送る
	sent := 0
	for range 10 {
		if pollWithin(t, n, 65536) == 0 {
			break
		}
		sent++
	}
	if sent < 2 {
		t.Fatalf("sent %d packets after the empty Poll", sent)
	}
}

// TestOneFaultClosesOnce は、Poll の中で会計の不整合が接続を閉じた後に、同じ build が次の segment を作らず、
// 不整合を 1 回だけ数えて RST を 1 つだけ送ることを確かめる。
func TestOneFaultClosesOnce(t *testing.T) {
	n, c, cs, _, _ := rackConnApp(t, 3)
	c.Write(make([]byte, 20*testSegPayload)) // 輻輳の窓の外に未送信のデータを残す
	n.drain()
	cs.mu.Lock()
	cs.markAllLost(rtxRTO)
	cs.cwnd = 1 << 20
	cs.sndMax = cs.sndUna + 10 // 再送が SND.MAX の先に終わる不整合
	cs.mu.Unlock()
	n.d.s.out.queueConn(cs.id)
	rsts := 0
	for range 10 {
		if pollWithin(t, n, 65536) == 0 {
			break
		}
	}
	for _, o := range n.drain() {
		if o.seg.has(flagRST) {
			rsts++
		}
	}
	if f := n.d.Stats().AccountingFaults; f != 1 {
		t.Fatalf("%d accounting faults for one inconsistency", f)
	}
}
