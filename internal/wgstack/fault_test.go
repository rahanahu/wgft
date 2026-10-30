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

// TestTimeWaitWantsOnlyAnACK は、TIME_WAIT の接続が ACK のほかに送るものを持たないと答え、何も作らなかった
// 接続を出力の list に入れ直さないことを確かめる。
func TestTimeWaitWantsOnlyAnACK(t *testing.T) {
	n, _, cs, _, _ := rackConnApp(t, 1)
	cs.mu.Lock()
	cs.enterTimeWait(int64(n.clk.Now()))
	if cs.tlpProbe || cs.tlpActive || cs.fastRtx || cs.probePending {
		t.Fatal("output marks survived into TIME_WAIT")
	}
	cs.tlpProbe, cs.fastRtx = true, true // 印が残った場合
	cs.ackNow = false
	if cs.wantOutput() {
		t.Fatal("a TIME_WAIT connection without an ACK to send wants output")
	}
	cs.mu.Unlock()
	n.d.s.out.mu.Lock()
	n.d.s.out.conns.popFront()
	n.d.s.out.mu.Unlock()
	n.d.s.out.queueConn(cs.id)
	done := make(chan int, 1)
	go func() { done <- n.d.Poll(make([]byte, 65536)) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Poll spun on a connection that builds nothing")
	}
}
