package wgstack

import "testing"

// TestDemoteRefusedWhileIntervalsExceedTheFloor は、受信の向きの boost を持つ接続が floor の区間の表より多い
// 順序外の区間を持つ間は floor に戻らないことを確かめる。戻ると区間を floor の表に移せず、相手の次の segment が
// 表の外を指して Device が止まる。
func TestDemoteRefusedWhileIntervalsExceedTheFloor(t *testing.T) {
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
	// floor の内側に 1 byte の順序外の区間を 300 個作る
	for i := 0; i < 300; i++ {
		s := p.seg(flagACK, []byte{byte(i)})
		s.seq = p.snd + 1 + uint32(2*i)
		n.inject(s)
	}
	n.drain()
	if cs.rcv.n != 300 || cs.rcv.rightmost()-cs.rcv.readOff > recvFloor {
		t.Fatalf("setup: %d intervals, span %d", cs.rcv.n, cs.rcv.rightmost()-cs.rcv.readOff)
	}
	if demoteIdle(n, cs) {
		t.Fatal("demoted a holder with more intervals than the floor table holds")
	}
	// 相手の次の segment も受け入れられる
	s := p.seg(flagACK, []byte{1})
	s.seq = p.snd + 1 + 2*300
	n.inject(s)
	n.drain()
	if cs.rcv.n != 301 {
		t.Fatalf("intervals %d after one more segment", cs.rcv.n)
	}
}

// TestSetIntervalsRefusesToTruncate は、使っている区間が入らない表には移さず、今の表を持ち続けることを確かめる。
func TestSetIntervalsRefusesToTruncate(t *testing.T) {
	var p chunkPool
	b := recvBuf{r: ring{pool: &p, cap: boostSize}, iv: make([]interval, boostIntervals)}
	for i := 0; i < floorIntervals+10; i++ {
		b.insert(uint64(1+2*i), []byte{1}, boostSize)
	}
	if b.setIntervals(make([]interval, floorIntervals)) || len(b.iv) != boostIntervals || b.n != floorIntervals+10 {
		t.Fatalf("setIntervals truncated: len %d n %d", len(b.iv), b.n)
	}
	b.insert(uint64(1+2*(floorIntervals+10)), []byte{1}, boostSize)
	b.r.release()
}
