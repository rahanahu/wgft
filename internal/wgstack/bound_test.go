package wgstack

import (
	"net/netip"
	"runtime"
	"runtime/metrics"
	"testing"
	"time"
)

// 敵対的な保持の試験(wgstack-verification.md)。どの試験も会計が数える保持を、構造の上限と上界の式の値と
// 比べ、入力が止まった後に元の値へ戻ることを確かめる。

// checkHeld は Device が今持つ量を数え直し、上界の式の項と比べる。
func checkHeld(t *testing.T, n *testNet) Stats {
	t.Helper()
	s := n.d.s
	st := n.d.Stats()
	b := n.d.Bound()
	lim := s.lim
	if st.SynRows > lim.synRows || st.TWRows > lim.twRows || st.AcceptQueued > lim.acceptQ || st.CtlQueued > lim.ctlSlots || st.Conns > lim.conns() {
		t.Fatalf("a table exceeds its size: %+v", st)
	}
	if held := st.ChunkBytes + st.RecordBytes; held > b.FloorConn+b.Boost {
		t.Fatalf("held buffers %d exceed the bound %d", held, b.FloorConn+b.Boost)
	}
	if st.HeldChunksInPool*chunkSize != st.ChunkBytes {
		t.Fatalf("chunk accounting: pool says %d chunks, rings hold %d bytes", st.HeldChunksInPool, st.ChunkBytes)
	}
	for i := range s.conns {
		c := &s.conns[i]
		c.mu.Lock()
		if c.state != stFree {
			if got := uint64(c.snd.heldChunks()) * chunkSize; got > c.sndCap {
				t.Errorf("conn %d send ring holds %d > %d", i, got, c.sndCap)
			}
			if got := uint64(c.rcv.r.heldChunks()) * chunkSize; got > c.rcvCap {
				t.Errorf("conn %d receive ring holds %d > %d", i, got, c.rcvCap)
			}
			if c.tailOff-c.unaOff > c.sndCap || c.rcv.rightmost()-c.rcv.readOff > max(c.rcvCap, c.advRight-c.rcv.readOff) {
				t.Errorf("conn %d holds bytes beyond its reservation", i)
			}
			if c.rcv.n > oooIntervals || c.recs.n > len(c.recs.recs) {
				t.Errorf("conn %d intervals %d records %d", i, c.rcv.n, c.recs.n)
			}
		}
		c.mu.Unlock()
	}
	return st
}

func spoofed(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{10, 8, byte(i >> 8), byte(i)})
}

func TestBoundSYNFlood(t *testing.T) {
	n := newTestNet(t, smallLimits())
	listen(t, n, 80)
	listen(t, n, 81)
	for i := 0; i < 1000; i++ {
		n.inject(tseg{src: spoofed(i), sport: uint16(i), dport: 80 + uint16(i%2), seq: uint32(i), flags: flagSYN, wnd: 1000, mss: 1380, ws: 7, sackOK: true, ts: true})
		if i%50 == 0 {
			n.drain()
		}
	}
	n.drain()
	st := checkHeld(t, n)
	if st.SynRows != n.d.s.lim.synRows || st.Conns != 0 || st.ChunkBytes != 0 || st.SynTableFull == 0 {
		t.Fatalf("after the flood %+v", st)
	}
	for _, l := range n.d.s.listeners {
		if l.synCount > n.d.s.lim.synRows/2 {
			t.Fatalf("listener holds %d rows", l.synCount)
		}
	}
	for range 64 {
		n.advance(time.Second)
		n.drain()
	}
	if st := checkHeld(t, n); st.SynRows != 0 {
		t.Fatalf("rows left after the retries %+v", st)
	}
}

func TestBoundAcceptQueue(t *testing.T) {
	n := newTestNet(t, smallLimits())
	listen(t, n, 80)
	listen(t, n, 81)
	for i := 0; i < 12; i++ {
		n.handshake(uint16(1000+i), 80+uint16(i%2), true, false, true)
	}
	st := checkHeld(t, n)
	q := n.d.s.lim.acceptQ
	if st.AcceptQueued != q || st.Conns != q || st.AcceptOverflow == 0 {
		t.Fatalf("after the handshakes %+v", st)
	}
	for _, l := range n.d.s.listeners {
		if l.qLen > q/2 {
			t.Fatalf("listener queue %d", l.qLen)
		}
	}
	// 捨てた最後の ACK の行は SYN-ACK の再送を使い切って消える
	for range 64 {
		n.advance(time.Second)
		n.drain()
	}
	if st := checkHeld(t, n); st.SynRows != 0 || st.Conns != q {
		t.Fatalf("after the retries %+v", st)
	}
}

func TestBoundOutOfOrderFlood(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, true, true)
	acceptOne(t, l)
	n.drain()
	for i := 0; i < 5000; i++ {
		s := p.seg(flagACK, []byte{1, 2})
		s.seq = p.snd + uint32(1+(i*7919)%250000)
		n.inject(s)
		if i%100 == 0 {
			n.drain()
		}
	}
	n.drain()
	st := checkHeld(t, n)
	if st.ChunkBytes > recvFloor || st.OOODropped == 0 {
		t.Fatalf("after the flood %+v", st)
	}
	c := &n.d.s.conns[0]
	if c.rcv.n != oooIntervals {
		t.Fatalf("intervals %d", c.rcv.n)
	}
}

func TestBoundNeverReadingPeer(t *testing.T) {
	for _, tc := range []struct {
		name  string
		slots int
		want  int64
	}{{"floor", 0, sendFloor}, {"boost", 1, boostSize}} {
		t.Run(tc.name, func(t *testing.T) {
			n := newTestNetPool(t, smallLimits(), newBoostPool(tc.slots))
			l := listen(t, n, 80)
			p := n.handshake(40000, 80, true, false, true)
			c := acceptOne(t, l)
			n.drain()
			p.wnd = 0
			p.ack(nil)
			c.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
			if _, err := c.Write(make([]byte, 2*boostSize)); !isTimeout(err) {
				t.Fatalf("Write to a never-reading peer: %v", err)
			}
			first := checkHeld(t, n)
			if first.ChunkBytes != tc.want {
				t.Fatalf("send ring holds %d, want %d", first.ChunkBytes, tc.want)
			}
			// probe が続く間も保持は増えない
			for i := 0; i < 200; i++ {
				n.advance(time.Second)
				for range n.drain() {
					p.ack(nil)
				}
			}
			st := checkHeld(t, n)
			if st.ChunkBytes != first.ChunkBytes || st.Conns != 1 || st.ProbeAborts != 0 {
				t.Fatalf("after probing %+v", st)
			}
		})
	}
}

func TestBoundEmptyACKFlood(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, true, true)
	c := acceptOne(t, l)
	n.drain()
	p.wnd = 65535
	c.Write(make([]byte, sendFloor))
	outs := n.drain()
	una := p.rcv
	start := time.Now()
	for i := 0; i < 30000; i++ {
		s := p.seg(flagACK, nil)
		switch i % 3 {
		case 0: // 重複した ACK
			s.ack = una
		case 1: // SACK の block を持つ ACK
			s.ack = una
			s.sack = []sackBlock{{una + 1000, una + 2000}}
		case 2: // 累積の確認を 1 byte ずつ進める ACK
			una++
			s.ack = una
		}
		n.inject(s)
		if i%500 == 0 {
			n.drain()
		}
	}
	n.drain()
	st := checkHeld(t, n)
	if st.ChunkBytes > sendFloor || st.CtlQueued != 0 {
		t.Fatalf("after the flood %+v", st)
	}
	t.Logf("%d segments sent, 30000 empty ACKs processed in %v", len(outs), time.Since(start))
}

func TestBoundTimeWaitChurn(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	for i := 0; i < 200; i++ {
		p := n.handshake(uint16(2000+i), 80, true, false, true)
		c := acceptOne(t, l)
		n.drain()
		c.Close()
		p.absorb(n.drain())
		p.fin()
		n.drain()
		if i%20 == 0 {
			checkHeld(t, n)
		}
	}
	st := checkHeld(t, n)
	if st.TWRows != n.d.s.lim.twRows || st.Conns != 0 || st.TWEvicted != uint64(200-n.d.s.lim.twRows) {
		t.Fatalf("after the churn %+v", st)
	}
	n.advance(61 * time.Second)
	if st := checkHeld(t, n); st.TWRows != 0 {
		t.Fatalf("rows left after the timeout %+v", st)
	}
}

func TestBoundSmallWritesSlowReader(t *testing.T) {
	n := newTestNetPool(t, smallLimits(), newBoostPool(0))
	l := listen(t, n, 80)
	n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	// 1 byte の書き込みを 1 つずつ送らせ、相手は確認しない。記録の輪が満ちたら送らない
	sent := 0
	for i := 0; i < 3*floorRecords; i++ {
		if _, err := c.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		sent += len(n.drain())
	}
	cs := &n.d.s.conns[c.c.id]
	checkHeld(t, n)
	if sent != floorRecords || cs.recs.n != floorRecords {
		t.Fatalf("sent %d segments, %d records; want %d", sent, cs.recs.n, floorRecords)
	}
	if got := cs.tailOff - cs.unaOff; got != 3*floorRecords {
		t.Fatalf("send ring holds %d bytes", got)
	}
}

func TestBoundUnmatchedFloodKeepsOtherClasses(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	p.wnd = 65535
	c.Write(make([]byte, 20000))
	// どの接続にも当たらない segment の洪水が制御の輪を埋める
	for i := 0; i < 100; i++ {
		n.inject(tseg{src: spoofed(i), sport: 1, dport: 9, seq: 1, ack: 1, flags: flagACK, ws: -1})
	}
	n.inject(tseg{sport: 50000, dport: 80, seq: 1, flags: flagSYN, wnd: 1000, mss: 1380, ws: -1})
	st := checkHeld(t, n)
	if st.CtlQueued != n.d.s.lim.ctlSlots || st.CtlDropped == 0 {
		t.Fatalf("control ring %+v", st)
	}
	// MTU 1 つ分ずつの deficit round robin なので、制御の輪の小さな RST が 1 回の番で数十個出た後に、
	// 接続の data と行の SYN-ACK が出る
	var data, synack, rst int
	for i := 0; i < 2*n.d.s.mtu/40; i++ {
		k := n.d.Poll(n.buf)
		if k == 0 {
			break
		}
		ip, _ := parseIPv4(n.buf[:k])
		seg, _ := parseTCP(&ip)
		switch {
		case seg.has(flagRST):
			rst++
		case seg.has(flagSYN):
			synack++
		case len(seg.payload) > 0:
			data++
		}
	}
	if data == 0 || synack == 0 || rst == 0 {
		t.Fatalf("classes starved: data %d syn-ack %d rst %d", data, synack, rst)
	}
}

func TestBoundOutputStall(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	var ps []*peerConn
	var cs []*Conn
	for i := 0; i < 4; i++ {
		ps = append(ps, n.handshake(uint16(3000+i), 80, true, false, true))
		cs = append(cs, acceptOne(t, l))
	}
	n.drain()
	// Read を呼ばない間に入力と書き込みを続けても、出力の保持は接続と行の数で止まる
	for r := 0; r < 50; r++ {
		for i, p := range ps {
			p.ack(make([]byte, 100))
			cs[i].Write(make([]byte, 1000))
		}
		n.advance(10 * time.Millisecond)
	}
	s := n.d.s
	s.out.mu.Lock()
	queued := s.out.conns.n
	s.out.mu.Unlock()
	if queued > len(ps) {
		t.Fatalf("%d output entries for %d connections", queued, len(ps))
	}
	checkHeld(t, n)
	// 詰まりが解けると送り直しで進む
	for _, o := range n.drain() {
		_ = o
	}
	for i, p := range ps {
		p.rcv = n.d.s.conns[cs[i].c.id].sndNxt
		p.ack(nil)
	}
	n.drain()
}

func TestCloseReturnsEverything(t *testing.T) {
	pool := newBoostPool(boostSlots)
	n := newTestNetPool(t, smallLimits(), pool)
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.handshake(40001, 80, true, false, true)
	p.sendBulk(demandBytes)
	readN(t, c, demandBytes)
	c.Write(make([]byte, 100000))
	n.inject(tseg{sport: 9, dport: 80, seq: 1, flags: flagSYN, wnd: 1000, ws: -1})
	if pool.held() != 1 {
		t.Fatal("not boosted")
	}
	n.d.Close()
	st := n.d.s.stats()
	if st.Conns != 0 || st.SynRows != 0 || st.TWRows != 0 || st.AcceptQueued != 0 || st.ChunkBytes != 0 || st.HeldChunksInPool != 0 || st.RecordBytes != 0 || pool.held() != 0 {
		t.Fatalf("after Close %+v pool %d", st, pool.held())
	}
}

// TestHeapWithinBound は、本番の大きさの表を持つ Device に接続を満たしたときの生きているヒープを
// runtime/metrics で測り、上界の式の値と比べる。差は Go のランタイムの費用で、記録であり保証ではない。
func TestHeapWithinBound(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates the production-sized tables")
	}
	heap := func() int64 {
		runtime.GC()
		s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
		metrics.Read(s)
		return int64(s[0].Value.Uint64())
	}
	before := heap()
	lim := defaultLimits(256)
	clk := NewManualClock()
	d, err := newDevice(Config{Addr: dutAddr, MTU: testMTU, Clock: clk, Rand: seededRand()}, lim, newBoostPool(boostSlots))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	n := &testNet{t: t, d: d, clk: clk, buf: make([]byte, 65536)}
	l := listen(t, n, 80)
	// 待ち行列の上限まで接続を作り、それぞれに floor いっぱいのデータを送る(読まない)
	for i := 0; i < lim.acceptQ/2; i++ {
		p := n.handshake(uint16(10000+i), 80, true, false, true)
		for k := 0; k < recvFloor/(testMTU-52); k++ {
			p.ack(make([]byte, testMTU-52))
			if k%8 == 0 {
				n.drain()
			}
		}
		n.drain()
	}
	_ = l
	after := heap()
	st := d.Stats()
	b := d.Bound()
	t.Logf("live heap grew by %d bytes; counted chunks %d, records %d; bound %d (fixed %d)", after-before, st.ChunkBytes, st.RecordBytes, b.Total, b.Fix)
	if after-before > b.Total {
		t.Errorf("live heap %d exceeds the bound %d", after-before, b.Total)
	}
	if st.ChunkBytes > int64(st.Conns)*recvFloor {
		t.Errorf("chunks %d exceed %d connections at the floor", st.ChunkBytes, st.Conns)
	}
}
