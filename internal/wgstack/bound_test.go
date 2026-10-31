package wgstack

import (
	"net"
	"net/netip"
	"runtime"
	"runtime/metrics"
	"strconv"
	"testing"
	"time"
)

// 敵対的な保持の試験(wgstack-verification.md)。どの試験も会計が数える保持を、構造の上限と上界の式の値と
// 比べ、入力が止まった後に元の値へ戻ることを確かめる。

// checkHeld は Device が今持つ量を数え直し、上界の式の項と比べる。空きの枠と 4 つ組の hash の表の照合は、開いた
// Device でだけ行う。閉じた Device では、tryRetire が inIndex を真のまま枠を返すことがある(tcb.go の枠の資源の
// 返し方)。
func checkHeld(t testing.TB, n *testNet) Stats {
	t.Helper()
	s := n.d.s
	st := n.d.Stats()
	b := n.d.Bound()
	lim := s.lim
	if st.SynRows > lim.synRows || st.TWRows > lim.twRows || st.AcceptQueued > lim.acceptQ || st.CtlQueued > lim.ctlSlots || st.Conns > lim.conns() {
		t.Fatalf("a table exceeds its size: %+v", st)
	}
	if held := st.ChunkBytes + st.RecordBytes + st.IntervalBytes; held > b.FloorConn+b.Boost {
		t.Fatalf("held buffers %d exceed the bound %d", held, b.FloorConn+b.Boost)
	}
	tm := terms()
	if b.FloorConn != int64(len(s.conns))*tm.floor() || b.Boost != int64(len(s.pool.slots))*tm.boost() {
		t.Fatalf("Bound does not use the slot terms: floor %d boost %d, terms %+v", b.FloorConn, b.Boost, tm)
	}
	if st.Boosted > len(s.pool.slots) {
		t.Fatalf("%d boosted connections with %d boost slots", st.Boosted, len(s.pool.slots))
	}
	if st.UDPRxBytes > udpRxBytes || st.UDPRxDatagrams > udpRxDatagrams || st.UDPTxBytes > udpTxBytes || st.UDPTxDatagrams > udpTxDatagrams ||
		int64(st.FragBytes) > b.Frag || st.PingEndpoints > pingEndpoints {
		t.Fatalf("UDP, reassembly or ping beyond the bound: %+v", st)
	}
	if st.HeldChunksInPool*chunkSize != st.ChunkBytes+st.UDPRxBytes+st.UDPTxBytes {
		t.Fatalf("chunk accounting: pool says %d chunks, rings hold %d bytes", st.HeldChunksInPool, st.ChunkBytes)
	}
	s.tmu.Lock()
	closed := s.closed
	s.tmu.Unlock()
	indexed := 0
	for i := range s.conns {
		c := &s.conns[i]
		c.mu.Lock()
		// 空きの枠の輪は chunk を持たない(持てば置き場の会計の比べで分かる)
		var sndHeld, rcvHeld int64
		if c.state != stFree {
			sndHeld, rcvHeld = int64(c.snd.heldChunks()), int64(c.rcv.r.heldChunks())
			if got := uint64(sndHeld) * chunkSize; got > c.sndCap {
				t.Errorf("conn %d send ring holds %d > %d", i, got, c.sndCap)
			}
			if got := uint64(rcvHeld) * chunkSize; got > c.rcvCap {
				t.Errorf("conn %d receive ring holds %d > %d", i, got, c.rcvCap)
			}
			if c.tailOff-c.unaOff > c.sndCap || c.rcv.rightmost()-c.rcv.readOff > max(c.rcvCap, c.advRight-c.rcv.readOff) {
				t.Errorf("conn %d holds bytes beyond its reservation", i)
			}
			if c.rcv.n > len(c.rcv.iv) || c.recs.n > len(c.recs.recs) {
				t.Errorf("conn %d intervals %d records %d", i, c.rcv.n, c.recs.n)
			}
		}
		// 枠ごとに、向きごとの予約(か持つ chunk)と配列を、その枠の項と比べる。floor の配列は空きの枠も持つ
		recs, ivs := c.arrayBytes()
		snd := max(ringBytes(int64(c.sndCap)), sndHeld*chunkHeap()) + recs
		rcv := max(ringBytes(int64(c.rcvCap)), rcvHeld*chunkHeap()) + ivs
		sndLim, rcvLim := tm.fs+tm.rf, tm.fr+tm.hf
		if c.boosted && c.state != stFree {
			sndLim += tm.ds + tm.drec
		}
		if c.rcvBoost && c.state != stFree {
			rcvLim += tm.dr + tm.dh
		}
		if snd > sndLim || rcv > rcvLim {
			t.Errorf("slot %d holds send %d of %d, receive %d of %d (boosted %v %v)", i, snd, sndLim, rcv, rcvLim, c.boosted, c.rcvBoost)
		}
		if c.inIndex {
			indexed++
		}
		// 空きの枠はタイマーの節、接続の組の出力の list の節、4 つ組の hash の表の項を持たない
		if c.state == stFree && !closed {
			s.wheel.mu.Lock()
			for k := range numTimers {
				if s.wheel.where[c.timerNode(k)] != -1 {
					t.Errorf("free slot %d still has timer %d in the wheel", i, k)
				}
			}
			s.wheel.mu.Unlock()
			s.out.mu.Lock()
			queued := s.out.conns.in[i]
			s.out.mu.Unlock()
			if queued {
				t.Errorf("free slot %d is still on the connection output list", i)
			}
			if c.inIndex {
				t.Errorf("free slot %d is still in the connection index", i)
			}
		}
		c.mu.Unlock()
	}
	if closed {
		return st
	}
	// 4 つ組の hash の表の項は、inIndex の枠と 1 対 1 で、項の世代と 4 つ組がその枠の今の接続と合う
	s.tmu.Lock()
	ents := make([]indexEnt, 0, len(s.conns))
	for _, e := range s.connIdx.ents {
		if e.id != 0 {
			ents = append(ents, e)
		}
	}
	s.tmu.Unlock()
	if len(ents) != indexed {
		t.Errorf("the connection index has %d entries, %d slots are marked inIndex", len(ents), indexed)
	}
	for _, e := range ents {
		c := &s.conns[e.id-1]
		c.mu.Lock()
		if !c.inIndex || c.state == stFree || c.gen != e.gen || c.tup != e.tup {
			t.Errorf("index entry for slot %d does not match it: inIndex %v state %v gen %d/%d", e.id-1, c.inIndex, c.state, c.gen, e.gen)
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
	_, p := n.accepted(true, true)
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
	if c.rcv.n != floorIntervals {
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
			c, p := n.accepted(true, false)
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
	c, p := n.accepted(true, true)
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
	c, _ := n.accepted(true, false)
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
	c, p := n.accepted(true, false)
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

// TestBoundCountsBoostedSlot は、両方の向きの boost を持つ接続 1 本の予約、記録の輪、区間の表を、枠 1 つの
// floor の項と枠 1 つの集まりの boost の項の和と比べる。boost の間も floor の記録の輪と区間の表は枠に残るので、
// boost の項が floor との差で数えると、この和を超える。
func TestBoundCountsBoostedSlot(t *testing.T) {
	n := newTestNetPool(t, smallLimits(), newBoostPool(1))
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	p.sendBulk(demandBytes)
	readN(t, c, demandBytes)
	cs := &n.d.s.conns[c.c.id]
	if !cs.boosted || !cs.rcvBoost || len(cs.recs.recs) != boostRecords || len(cs.rcv.iv) != boostIntervals {
		t.Fatalf("not boosted in both directions: boosted %v rcvBoost %v records %d intervals %d", cs.boosted, cs.rcvBoost, len(cs.recs.recs), len(cs.rcv.iv))
	}
	st := n.d.Stats()
	b := n.d.Bound()
	if st.Conns != 1 || st.Boosted != 1 {
		t.Fatalf("conns %d boosted %d", st.Conns, st.Boosted)
	}
	slot := b.FloorConn / int64(n.d.s.lim.conns())
	held := st.Reserved + st.RecordBytes + st.IntervalBytes
	if held > slot+b.Boost {
		t.Fatalf("a boosted slot holds %d bytes of reservation, records and intervals; the bound counts %d (floor %d, boost %d)", held, slot+b.Boost, slot, b.Boost)
	}
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
	if st.Conns != 0 || st.SynRows != 0 || st.TWRows != 0 || st.AcceptQueued != 0 || st.ChunkBytes != 0 || st.HeldChunksInPool != 0 || st.RecordBytes != 0 || st.IntervalBytes != 0 || pool.held() != 0 {
		t.Fatalf("after Close %+v pool %d", st, pool.held())
	}
}

// liveHeap は GC の後の生きているヒープの byte を返す。
func liveHeap() int64 {
	runtime.GC()
	s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(s)
	return int64(s[0].Value.Uint64())
}

// quietHeap は liveHeap を数回測った最小を返す。finalizer を持つ object は 2 回目の GC で消えるので、
// 1 回の GC の後には前の試験の残りが含まれる。
func quietHeap() int64 {
	m := liveHeap()
	for range 3 {
		m = min(m, liveHeap())
	}
	return m
}

// boostFull は接続を 1 本作り、両方の向きの boost を持たせて送信と受信の輪を満たす。
func boostFull(t *testing.T, n *testNet, l *TCPListener, port uint16) (*Conn, *peerConn) {
	t.Helper()
	p := n.handshake(port, 80, true, false, true)
	// 待ち行列に接続があるので Accept は待たない。acceptOne の goroutine とタイマーを測る範囲に入れない
	nc, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	c := nc.(*Conn)
	p.sendBulk(demandBytes)
	readN(t, c, demandBytes)
	openWindow(n, &n.d.s.conns[c.c.id])
	p.absorb(n.drain())
	p.wnd = 0
	p.ack(nil)
	// 窓が閉じているので、送信の輪をちょうど満たす書き込みは送らずに戻る
	if k, err := c.Write(make([]byte, boostSize)); k != boostSize || err != nil {
		t.Fatalf("Write to a closed window: %d, %v", k, err)
	}
	p.sendBulk(boostSize)
	cs := &n.d.s.conns[c.c.id]
	if !cs.boosted || !cs.rcvBoost || cs.snd.heldChunks()*chunkSize != boostSize || cs.rcv.r.heldChunks()*chunkSize != boostSize {
		t.Fatalf("port %d: boosted %v %v, send ring %d, receive ring %d chunks", port, cs.boosted, cs.rcvBoost, cs.snd.heldChunks(), cs.rcv.r.heldChunks())
	}
	return c, p
}

// osThreads は runtime が作った OS の thread の数を返す。
func osThreads() int64 {
	s := []metrics.Sample{{Name: "/sched/threads/total:threads"}}
	metrics.Read(s)
	return int64(s[0].Value.Uint64())
}

// threadRuntime は runtime が新しい thread 1 つに確保する構造(m、g0、signal の g、profile の stack)の見積もり。
// linux/amd64 の Go 1.27 で約 5.5 KiB を測った。上界の式の外のランタイムの費用である。
const threadRuntime = 8 << 10

// TestHeapWithinBoundBoosted は、k 本の接続に両方の向きの boost を持たせて送信と受信の輪を満たし、生きて
// いるヒープの増加を、その k 本の枠の floor の項と boost の項と枠の外のランタイムの構造の和と比べる。
// 配列はヒープが切り上げた大きさで持つので、長さと要素の大きさの積で数えた項はこの和を超える。
func TestHeapWithinBoundBoosted(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates 8 MiB for each boosted connection")
	}
	tm := terms()
	// 測る前に同じ操作を別の Device で 1 回行い、ランタイムが一度だけ広げる構造(タイマーの heap など)を
	// 先に広げておく。前の試験が残したタイマーの数によって、広げる量が変わるため
	{
		n := newTestNetPool(t, smallLimits(), newBoostPool(1))
		boostFull(t, n, listen(t, n, 80), 39999)
		n.d.Close()
	}
	for _, k := range []int{1, 4, 16} {
		t.Run(strconv.Itoa(k), func(t *testing.T) {
			n := newTestNetPool(t, smallLimits(), newBoostPool(k))
			l := listen(t, n, 80)
			threads := osThreads()
			before := quietHeap()
			conns := make([]*Conn, 0, k)
			peers := make([]*peerConn, 0, k)
			for i := range k {
				c, p := boostFull(t, n, l, uint16(40000+i))
				conns, peers = append(conns, c), append(peers, p)
			}
			after := quietHeap()
			// 測る間に runtime が thread を作れば、その構造は式の外なので除く。試験の側の相手の構造(peerConn は
			// 240 byte)と、1 度だけ広がる構造(chunk の置き場の空きの list、runtime のタイマーの heap)も除く
			rt := max(0, osThreads()-threads) * threadRuntime
			harness := int64(k)*512 + 4<<10
			bound := int64(k) * (tm.floor() + tm.boost() + slotRuntime)
			t.Logf("%d boosted connections: live heap grew by %d bytes; the slot terms count %d; new threads' runtime %d, test harness %d", k, after-before, bound, rt, harness)
			if after-before-rt-harness > bound {
				t.Errorf("live heap grew by %d bytes, beyond the %d the slot terms count with %d of new threads and %d of test harness", after-before, bound, rt, harness)
			}
			runtime.KeepAlive(conns)
			runtime.KeepAlive(peers)
		})
	}
}

// TestHeapWithinBound は、本番の大きさの表を持つ Device に接続を満たしたときの生きているヒープを
// runtime/metrics で測り、上界の式の値と比べる。差は Go のランタイムの費用で、記録であり保証ではない。
func TestHeapWithinBound(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates the production-sized tables")
	}
	heap := liveHeap
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

// TestBoundDoesNotDependOnUse は、接続、握手の途中の行、TIME_WAIT の行、UDP の datagram が空きの list から枠を
// 取った後に初めて求めた Bound が、使う前の Device の Bound と同じであることを確かめる。空きの list の配列は
// 使っても作成の時の大きさのまま残る。
func TestBoundDoesNotDependOnUse(t *testing.T) {
	lim := smallLimits()
	lim.udpRxDgrams, lim.udpTxDgrams = 32, 32 // 1 つの endpoint が 6 つを持てる大きさ
	want := newTestNet(t, lim).d.Bound()

	n := newTestNet(t, lim)
	l := listen(t, n, 80)
	// 接続の枠:24 本のうち 16 本を使い、うち 4 本を TIME_WAIT の行に移す
	for i := range 16 {
		p := n.handshake(uint16(40000+i), 80, true, false, true)
		c := acceptOne(t, l)
		n.drain()
		if i < 4 {
			c.Close()
			p.absorb(n.drain())
			p.fin()
			n.drain()
		}
	}
	// 握手の途中の行:16 行のうち、1 つの待ち受けが持てる 8 行
	for i := range 8 {
		n.inject(tseg{sport: uint16(41000 + i), dport: 80, seq: 1, flags: flagSYN, wnd: 65535, mss: 1380, ws: -1})
	}
	n.drain()
	// UDP:受けて読まない datagram と、送って取り出さない datagram を 6 つずつ
	pc := listenUDP(t, n, 53)
	for i := range 6 {
		n.write(buildUDP(netip.AddrPortFrom(peerAddr, uint16(5000+i)), 53, []byte{byte(i)}))
		if _, err := pc.WriteTo([]byte{byte(i)}, net.UDPAddrFromAddrPort(netip.AddrPortFrom(peerAddr, 5000))); err != nil {
			t.Fatal(err)
		}
	}
	st := n.d.Stats()
	if st.Conns != 12 || st.TWRows != 4 || st.SynRows != 8 || st.UDPRxDatagrams != 6 || st.UDPTxDatagrams != 6 {
		t.Fatalf("setup: %+v", st)
	}
	if got := n.d.Bound(); got != want {
		t.Fatalf("Bound after use %+v, fresh %+v", got, want)
	}
}
