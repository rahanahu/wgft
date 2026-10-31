package wgstack

import (
	"bytes"
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
	// 予約は 4 MiB にするが、測定が窓の上限を上げるまで広告する窓は floor を超えない(rcvwin.go)
	for _, o := range n.drain() {
		if uint64(o.seg.wnd)<<rcvWindowShft > recvFloor {
			t.Fatalf("window jumped beyond the floor on boost: %v", o)
		}
	}
	if cs.rcvClamp() != recvFloor || cs.advRight > cs.rcv.readOff+recvFloor {
		t.Fatalf("window clamp %d, edge %d past the floor from %d", cs.rcvClamp(), cs.advRight, cs.rcv.readOff)
	}
}

// openWindow は boost の接続の窓の上限と歩みの上限を予約まで上げ、広げた窓を知らせる。窓の広げ方の外を
// 確かめる試験が使う。
func openWindow(n *testNet, cs *tcb) {
	cs.mu.Lock()
	cs.rcvWant, cs.rcvSsthresh = cs.rcvCap, cs.rcvCap
	cs.ackNow = true
	cs.afterInput(int64(n.clk.Now()))
	cs.mu.Unlock()
	n.drain()
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
	return boostTwoWith(t, false)
}

// boostTwoWith は boostTwo と同じ接続を、sack で SACK を交渉するかを選んで作る。
func boostTwoWith(t *testing.T, sack bool) (*testNet, *Conn, *peerConn, *Conn, *peerConn) {
	n := newTestNetPool(t, smallLimits(), newBoostPool(1))
	l := listen(t, n, 80)
	p1 := n.handshake(40000, 80, true, sack, true)
	c1 := acceptOne(t, l)
	p2 := n.handshake(40001, 80, true, sack, true)
	c2 := acceptOne(t, l)
	p1.sendBulk(demandBytes)
	readN(t, c1, demandBytes)
	n.drain()
	if !n.d.s.conns[c1.c.id].boosted {
		t.Fatal("first connection not boosted")
	}
	openWindow(n, &n.d.s.conns[c1.c.id])
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

// injectAt は相手から受信の offset off に data を送る。
func injectAt(n *testNet, p *peerConn, cs *tcb, off uint64, data []byte) {
	s := p.seg(flagACK, data)
	s.seq = cs.irs + 1 + uint32(off)
	n.inject(s)
}

// TestBoostRenegeOnlyOnContentionAfterIdle は、floor の外に SACK 済みの順序外のデータを持つ保有者が、枠の取り合い
// があり 1 秒の間需要が無いときだけ、floor の外の分を取り消して枠を渡すことを確かめる(設計文書の「boost の取得と
// floor への戻り」)。取り消した範囲は後の SACK の block に現れず、広告した右端は縮めない。
func TestBoostRenegeOnlyOnContentionAfterIdle(t *testing.T) {
	n, c1, p1, c2, p2 := boostTwoWith(t, true)
	cs1, cs2 := &n.d.s.conns[c1.c.id], &n.d.s.conns[c2.c.id]
	nxt := cs1.rcv.nxtOff
	edge := cs1.rcv.readOff + recvFloor
	injectAt(n, p1, cs1, nxt+1000, make([]byte, 1000))  // floor の内側
	injectAt(n, p1, cs1, edge-500, make([]byte, 1000))  // floor の境をまたぐ
	injectAt(n, p1, cs1, nxt+3<<20, make([]byte, 1000)) // 3 MiB 先
	n.drain()
	if cs1.rcv.n != 3 || cs1.rcv.ooo != 3000 {
		t.Fatalf("setup: %d intervals, %d out-of-order bytes", cs1.rcv.n, cs1.rcv.ooo)
	}
	adv := cs1.advRight
	// 需要が 1 秒より新しい保有者からは、取り合いがあっても取り消さない
	n.advance(500 * time.Millisecond)
	p2.sendBulk(demandBytes)
	readN(t, c2, demandBytes)
	if !cs1.boosted || cs2.boosted || cs1.rcv.n != 3 {
		t.Fatalf("holder idle for less than a second: boosted %v, requester %v, %d intervals", cs1.boosted, cs2.boosted, cs1.rcv.n)
	}
	// 取り合いが無ければ、長く黙っても取り消さない
	n.advance(30 * time.Second)
	n.drain()
	if !cs1.boosted || cs1.rcv.n != 3 || cs1.rcv.ooo != 3000 {
		t.Fatalf("without contention: boosted %v, %d intervals, %d out-of-order bytes", cs1.boosted, cs1.rcv.n, cs1.rcv.ooo)
	}
	// 取り合いがあり、1 秒より長く黙った保有者は floor の外を取り消して枠を渡す
	p2.sendBulk(demandBytes)
	readN(t, c2, demandBytes)
	if cs1.boosted || !cs2.boosted {
		t.Fatalf("after contention: holder %v, requester %v", cs1.boosted, cs2.boosted)
	}
	got := cs1.rcv.intervals(nil)
	want := [][2]uint64{{nxt + 1000, nxt + 2000}, {edge - 500, edge}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || cs1.rcv.ooo != 1500 {
		t.Fatalf("kept intervals %v, %d out-of-order bytes; want %v, 1500", got, cs1.rcv.ooo, want)
	}
	if cs1.advRight != adv {
		t.Fatalf("advertised edge moved from %d to %d", adv, cs1.advRight)
	}
	if got := n.d.Stats().BoostRenegedBytes; got != 1500 {
		t.Fatalf("reneged bytes counted %d, want 1500", got)
	}
	// 最近の区間の印は残した区間の始まりだけを指す。取り消した区間の印が残ると、後でその位置に作る区間の
	// block を先頭に置いてしまう
	if cs1.rcv.nrecent != 2 {
		t.Fatalf("%d recent-interval marks after the renege, want 2", cs1.rcv.nrecent)
	}
	for _, x := range cs1.rcv.recent[:cs1.rcv.nrecent] {
		if k := cs1.rcv.containing(cs1.rcv.full(x)); k == 0 || cs1.rcv.kStart(k) != cs1.rcv.full(x) {
			t.Fatalf("recent-interval mark %d is not the start of a kept interval", x)
		}
	}
	// 次の ACK の SACK の block は floor の内側だけを知らせる
	injectAt(n, p1, cs1, nxt+5000, make([]byte, 10))
	outs := n.drain()
	if len(outs) != 1 || outs[0].seg.opt.nsack != 3 {
		t.Fatalf("ACK after the renege: %v", outs)
	}
	base := cs1.irs + 1
	for _, b := range outs[0].seg.opt.sack[:outs[0].seg.opt.nsack] {
		if seqGT(b.right, base+uint32(edge)) {
			t.Fatalf("SACK block %v reports reneged data beyond %d", b, base+uint32(edge))
		}
	}
}

// TestBoostPinnedByOneOutOfOrderByteIsReclaimed は、相手が枠を得た接続に floor の外の 1 byte を送って穴を埋めずに
// 黙っても、枠を持ち続けられないことを確かめる。取り消しの前は、枠の数だけの接続で、ほかのすべての接続を floor の
// 窓に留められた。
func TestBoostPinnedByOneOutOfOrderByteIsReclaimed(t *testing.T) {
	const slots = 2
	n := newTestNetPool(t, smallLimits(), newBoostPool(slots))
	l := listen(t, n, 80)
	var pinned []*tcb
	for i := 0; i < slots; i++ {
		p := n.handshake(uint16(40000+i), 80, true, true, true)
		c := acceptOne(t, l)
		cs := &n.d.s.conns[c.c.id]
		for rounds := 0; ; rounds++ {
			if rounds == 40 {
				t.Fatal("the window did not open past the floor")
			}
			p.sendBulk(demandBytes)
			readN(t, c, demandBytes)
			n.advance(10 * time.Millisecond)
			n.drain()
			if cs.boosted && cs.advRight > cs.rcv.readOff+recvFloor+2000 {
				break
			}
		}
		injectAt(n, p, cs, cs.rcv.readOff+recvFloor+1000, []byte{0x41})
		n.drain()
		if cs.rcv.n != 1 {
			t.Fatal("out-of-order byte beyond the floor not held")
		}
		pinned = append(pinned, cs)
	}
	n.advance(30 * time.Second)
	p3 := n.handshake(40100, 80, true, true, true)
	c3 := acceptOne(t, l)
	p3.sendBulk(demandBytes)
	readN(t, c3, demandBytes)
	if !n.d.s.conns[c3.c.id].boosted {
		t.Fatal("a connection with demand got no slot from holders pinned by one out-of-order byte")
	}
	reneged := 0
	for _, cs := range pinned {
		if !cs.boosted {
			reneged++
			if cs.rcv.n != 0 || cs.rcv.ooo != 0 {
				t.Fatalf("demoted holder kept %d intervals, %d bytes", cs.rcv.n, cs.rcv.ooo)
			}
		}
	}
	if reneged != 1 || n.d.s.pool.held() != slots {
		t.Fatalf("%d holders demoted, pool holds %d", reneged, n.d.s.pool.held())
	}
}

// TestBoostRenegeThenRetransmitDeliversInOrder は、取り消しの後に相手が累積の確認から送り直すと、取り消さずに
// 残した順序外のデータと送り直したデータが、壊れずに順に届くことを確かめる。
func TestBoostRenegeThenRetransmitDeliversInOrder(t *testing.T) {
	n, c1, p1, c2, p2 := boostTwoWith(t, true)
	cs1 := &n.d.s.conns[c1.c.id]
	start := cs1.rcv.nxtOff
	const total = 600 << 10
	const mss = 1380
	data := make([]byte, total)
	for i := range data {
		data[i] = byte(splitmix64(uint64(i)))
	}
	send := func(lo, hi int) {
		for o := lo; o < hi; o += mss {
			injectAt(n, p1, cs1, start+uint64(o), data[o:min(o+mss, hi)])
		}
	}
	// 先頭の segment を欠いて残りを送る。残りは 1 つの区間になり、SACK で知らせる
	send(mss, total)
	n.drain()
	if cs1.rcv.n != 1 || cs1.rcv.ooo != total-mss {
		t.Fatalf("setup: %d intervals, %d out-of-order bytes", cs1.rcv.n, cs1.rcv.ooo)
	}
	n.advance(2 * time.Second)
	p2.sendBulk(demandBytes)
	readN(t, c2, demandBytes)
	if cs1.boosted {
		t.Fatal("holder not demoted")
	}
	if kept := cs1.rcv.readOff + recvFloor - start - mss; cs1.rcv.ooo != kept {
		t.Fatalf("kept %d out-of-order bytes, want %d", cs1.rcv.ooo, kept)
	}
	// 穴だけを送り直すと、残した区間までが順序どおりになる
	send(0, mss)
	n.drain()
	var got []byte
	readAll := func() {
		if k := int(cs1.rcv.unread()); k > 0 {
			buf := make([]byte, k)
			if _, err := io.ReadFull(c1, buf); err != nil {
				t.Fatal(err)
			}
			got = append(got, buf...)
		}
	}
	readAll()
	if len(got) != recvFloor {
		t.Fatalf("read %d bytes after the hole was filled, want %d", len(got), recvFloor)
	}
	// 相手は累積の確認から送り直す。floor の外のデータは読んで空くまで捨てられる
	for rounds := 0; len(got) < total; rounds++ {
		if rounds == 100 {
			t.Fatalf("stalled at %d of %d bytes", len(got), total)
		}
		send(int(cs1.rcv.nxtOff-start), total)
		n.drain()
		readAll()
	}
	if !bytes.Equal(got, data) {
		t.Fatal("bytes delivered after the renege differ from the bytes sent")
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
