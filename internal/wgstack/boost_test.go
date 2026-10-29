package wgstack

import (
	"io"
	"testing"
	"time"
)

// sendBulk は相手から n byte を MSS ごとに送り、Device の ACK を読み捨てる。
func (p *peerConn) sendBulk(n int) {
	mss := testMTU - 40 - 12
	for n > 0 {
		k := min(n, mss)
		p.ack(make([]byte, k))
		n -= k
		p.n.drain()
	}
}

func readN(t testing.TB, c *Conn, n int) {
	t.Helper()
	if _, err := io.ReadFull(c, make([]byte, n)); err != nil {
		t.Fatal(err)
	}
}

func TestBoostOnReceiveDemand(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	var calls []bool
	c.OnBoost(func(b bool) bool { calls = append(calls, b); return true })
	p.sendBulk(demandBytes)
	readN(t, c, demandBytes)
	cs := &n.d.s.conns[c.c.id]
	if !cs.boosted || !cs.rcvBoost || cs.rcvCap != boostSize || cs.sndCap != boostSize {
		t.Fatalf("boosted %v rcvBoost %v caps %d %d", cs.boosted, cs.rcvBoost, cs.rcvCap, cs.sndCap)
	}
	if len(calls) != 2 || calls[0] || !calls[1] {
		t.Fatalf("OnBoost calls %v", calls)
	}
	// 広げた窓を知らせる
	outs := n.drain()
	if len(outs) == 0 || uint64(outs[len(outs)-1].seg.wnd)<<rcvWindowShft <= recvFloor {
		t.Fatalf("window not opened beyond the floor: %v", outs)
	}
}

func TestBoostOnSendDemandKeepsReceiveFloor(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	p.wnd = 65535
	c := acceptOne(t, l)
	n.drain()
	if _, err := c.Write(make([]byte, demandBytes)); err != nil {
		t.Fatal(err)
	}
	cs := &n.d.s.conns[c.c.id]
	if !cs.boosted || cs.rcvBoost || cs.rcvCap != recvFloor || cs.sndCap != boostSize {
		t.Fatalf("boosted %v rcvBoost %v caps %d %d", cs.boosted, cs.rcvBoost, cs.rcvCap, cs.sndCap)
	}
	if len(cs.recs.recs) != boostRecords {
		t.Fatalf("record ring %d", len(cs.recs.recs))
	}
	// 後から受信の向きの需要が生じたら同じ枠のまま受信の窓を広げる
	p.absorb(n.drain())
	p.sendBulk(demandBytes)
	readN(t, c, demandBytes)
	if !cs.rcvBoost || cs.rcvCap != boostSize {
		t.Fatal("receive window not opened on receive demand")
	}
	if got := n.d.s.pool.held(); got != 1 {
		t.Fatalf("pool holds %d slots", got)
	}
}

// boostTwo は枠 1 つの集まりで、1 本目に枠を持たせた 2 本の接続を作る。
func boostTwo(t *testing.T) (*testNet, *Conn, *peerConn, *Conn, *peerConn) {
	n := newTestNetPool(t, smallLimits(), newBoostPool(1))
	l := listen(t, n, 80)
	p1 := n.handshake(40000, 80, true, false, true)
	c1 := acceptOne(t, l)
	p2 := n.handshake(40001, 80, true, false, true)
	c2 := acceptOne(t, l)
	p1.sendBulk(demandBytes)
	readN(t, c1, demandBytes)
	n.drain()
	if !n.d.s.conns[c1.c.id].boosted {
		t.Fatal("first connection not boosted")
	}
	return n, c1, p1, c2, p2
}

func TestBoostReclaimFromIdleHolder(t *testing.T) {
	n, c1, p1, c2, p2 := boostTwo(t)
	// 1 秒より前の需要では回収しない
	n.advance(500 * time.Millisecond)
	p2.sendBulk(demandBytes)
	readN(t, c2, demandBytes)
	if n.d.s.conns[c2.c.id].boosted {
		t.Fatal("reclaimed from a holder idle for less than a second")
	}
	n.advance(time.Second)
	p2.sendBulk(demandBytes)
	readN(t, c2, demandBytes)
	cs1, cs2 := &n.d.s.conns[c1.c.id], &n.d.s.conns[c2.c.id]
	if cs1.boosted || !cs2.boosted {
		t.Fatalf("after reclaim: holder %v requester %v", cs1.boosted, cs2.boosted)
	}
	if cs1.rcvCap != recvFloor || cs1.sndCap != sendFloor || len(cs1.recs.recs) != floorRecords {
		t.Fatal("holder not back at the floor")
	}
	// 戻した後も広告した右端は縮めず、floor の外のデータは ACK せずに捨てて重複した ACK を返す
	n.drain()
	adv := cs1.advRight
	if adv <= cs1.rcv.readOff+recvFloor {
		t.Fatalf("advertised edge %d did not extend beyond the floor %d", adv, cs1.rcv.readOff+recvFloor)
	}
	before := p1.snd
	s := p1.seg(flagACK, make([]byte, 1000))
	s.seq = cs1.irs + 1 + uint32(cs1.rcv.readOff+recvFloor+100) // floor の外、広告した右端の内側
	n.inject(s)
	outs := n.drain()
	if len(outs) != 1 || outs[0].seg.ack != before {
		t.Fatalf("data beyond the floor: %v", outs)
	}
	if cs1.rcv.n != 0 {
		t.Fatal("data beyond the floor was kept")
	}
	if n.d.Stats().BoostReclaimed != 1 {
		t.Fatal("reclaim not counted")
	}
}

func TestBoostDemotionRefusedByOnBoost(t *testing.T) {
	n, c1, _, c2, p2 := boostTwo(t)
	c1.OnBoost(func(b bool) bool { return b })
	n.advance(2 * time.Second)
	p2.sendBulk(demandBytes)
	readN(t, c2, demandBytes)
	if !n.d.s.conns[c1.c.id].boosted || n.d.s.conns[c2.c.id].boosted {
		t.Fatal("OnBoost(false) returning false did not keep the slot")
	}
}

func TestBoostDemotionRefusedByFarOutOfOrderData(t *testing.T) {
	n, c1, p1, c2, p2 := boostTwo(t)
	cs1 := &n.d.s.conns[c1.c.id]
	// 3 MiB 先の 10 KiB の順序外のデータ
	s := p1.seg(flagACK, make([]byte, 1000))
	s.seq = p1.snd + 3<<20
	n.inject(s)
	n.drain()
	if cs1.rcv.n != 1 {
		t.Fatal("out-of-order data not held")
	}
	n.advance(2 * time.Second)
	p2.sendBulk(demandBytes)
	readN(t, c2, demandBytes)
	if !cs1.boosted {
		t.Fatal("demoted a holder whose rightmost byte is beyond the floor")
	}
}

func TestBoostReturnedWhenSlotFreed(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	p.sendBulk(demandBytes)
	readN(t, c, demandBytes)
	if n.d.s.pool.held() != 1 {
		t.Fatal("not boosted")
	}
	c.Abort()
	if n.d.s.pool.held() != 0 {
		t.Fatal("slot not returned on Abort")
	}
}
