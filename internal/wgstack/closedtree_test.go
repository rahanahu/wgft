package wgstack

import "testing"

// TestClosedConnectionDropsTheIntervalTree は、CLOSED になった boost の接続が順序外の区間の木を捨て、
// 窓の右端近くの順序外の byte のために floor に戻れなくならないことを確かめる。
func TestClosedConnectionDropsTheIntervalTree(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, true, true)
	c := acceptOne(t, l)
	p.sendBulk(demandBytes)
	readN(t, c, demandBytes)
	cs := c.c
	if !cs.rcvBoost {
		t.Fatal("no receive boost")
	}
	for k := 0; k < 8; k++ {
		p.sendBulk(demandBytes)
		readN(t, c, demandBytes)
	}
	cs.mu.Lock()
	w := cs.rcvWindow()
	cs.mu.Unlock()
	t.Logf("window %d", w)
	s := p.seg(flagACK, []byte{1})
	s.seq = p.snd + w - 10
	n.inject(s)
	n.drain()
	cs.mu.Lock()
	t.Logf("before RST: n=%d root=%d rightmost-readOff=%d", cs.rcv.n, cs.rcv.root, cs.rcv.rightmost()-cs.rcv.readOff)
	cs.mu.Unlock()
	r := p.seg(flagRST|flagACK, nil)
	n.inject(r)
	n.drain()
	cs.mu.Lock()
	t.Logf("after RST: state=%d boosted=%v n=%d root=%d used=%d rightmost-readOff=%d written=%v floor=%d",
		cs.state, cs.boosted, cs.rcv.n, cs.rcv.root, cs.rcv.used, cs.rcv.rightmost()-cs.rcv.readOff, cs.rcv.written(), recvFloor)
	cs.mu.Unlock()
	ok := demoteIdle(n, cs)
	t.Logf("demote of the closed boosted connection: %v", ok)
	if cs.rcv.root != 0 || cs.rcv.n != 0 || !ok {
		t.Errorf("toClosed left the interval tree: n=%d root=%d; demote=%v", cs.rcv.n, cs.rcv.root, ok)
	}
}

// TestClosedConnectionDemoteHoldsNoChunks は、floor の内側に順序外のデータを持って CLOSED になった接続を
// floor に戻すときに、捨てた区間を写すために chunk を確保しないことを確かめる。
func TestClosedConnectionDemoteHoldsNoChunks(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, true, true)
	c := acceptOne(t, l)
	p.sendBulk(demandBytes)
	readN(t, c, demandBytes)
	cs := c.c
	for i := 0; i < 40; i++ {
		s := p.seg(flagACK, make([]byte, 500))
		s.seq = p.snd + 1 + uint32(i)*20000
		n.inject(s)
	}
	n.drain()
	n.inject(p.seg(flagRST|flagACK, nil))
	n.drain()
	cs.mu.Lock()
	before := cs.rcv.r.heldChunks()
	cs.mu.Unlock()
	ok := demoteIdle(n, cs)
	cs.mu.Lock()
	after := cs.rcv.r.heldChunks()
	t.Logf("closed: demote=%v held chunks before=%d after=%d n=%d root=%d", ok, before, after, cs.rcv.n, cs.rcv.root)
	cs.mu.Unlock()
	if after > before {
		t.Errorf("demote of a closed connection allocated %d chunks for discarded out-of-order data", after-before)
	}
}
