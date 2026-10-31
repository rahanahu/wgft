package wgstack

import "testing"

// TestDemoteRenegesIntervalsBeyondTheFloorTable は、受信の向きの boost を持つ接続が floor の区間の表より多い
// 順序外の区間を持つときは、floor に戻る時に表に入らない右の区間を取り消すことを確かめる。区間を残したまま
// 戻ると区間を floor の表に移せず、相手の次の segment が表の外を指して Device が止まる。
func TestDemoteRenegesIntervalsBeyondTheFloorTable(t *testing.T) {
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
	if !demoteIdle(n, cs) {
		t.Fatal("holder with more intervals than the floor table holds not demoted")
	}
	ivs := cs.rcv.intervals(nil)
	if cs.rcv.n != floorIntervals || len(ivs) != floorIntervals || cs.rcv.ooo != floorIntervals {
		t.Fatalf("after demotion: %d intervals, %d in the tree, %d out-of-order bytes", cs.rcv.n, len(ivs), cs.rcv.ooo)
	}
	// 残すのは左の区間である
	if last := ivs[len(ivs)-1]; last[0] != cs.rcv.nxtOff+1+2*(floorIntervals-1) {
		t.Fatalf("last kept interval %v", last)
	}
	// 相手の次の segment も表の内側で扱う。新しい区間を要する segment は捨て、穴を埋める segment は受け入れる
	s := p.seg(flagACK, []byte{1})
	s.seq = p.snd + 1 + 2*300
	n.inject(s)
	n.inject(p.seg(flagACK, []byte{1}))
	n.drain()
	if cs.rcv.n != floorIntervals-1 || cs.rcv.nxtOff != cs.rcv.readOff+2 {
		t.Fatalf("%d intervals, nxt %d from %d after two more segments", cs.rcv.n, cs.rcv.nxtOff, cs.rcv.readOff)
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
