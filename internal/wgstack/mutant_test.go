package wgstack

import (
	"testing"
	"time"
)

// レビューの mutation の試験で生き残った変異を落とす試験。

func TestSynRowsPerListenerCap(t *testing.T) {
	n := newTestNet(t, smallLimits())
	listen(t, n, 80)
	for i := 0; i < 100; i++ {
		n.inject(tseg{src: spoofed(i), sport: uint16(i), dport: 80, seq: 1, flags: flagSYN, wnd: 1000, mss: 1380, ws: -1})
	}
	n.drain()
	if st := checkHeld(t, n); st.SynRows != n.d.s.lim.synRows/2 {
		t.Fatalf("one listener holds %d rows, want %d", st.SynRows, n.d.s.lim.synRows/2)
	}
}

func TestAcceptQueueCaps(t *testing.T) {
	for _, tc := range []struct {
		name      string
		listeners int
		want      func(q int) int
	}{
		{"per listener", 1, func(q int) int { return q / 2 }},
		{"device", 3, func(q int) int { return q }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := newTestNet(t, smallLimits())
			for i := 0; i < tc.listeners; i++ {
				listen(t, n, 80+uint16(i))
			}
			for i := 0; i < 4*n.d.s.lim.acceptQ; i++ {
				port := uint16(5000 + i)
				dport := 80 + uint16(i%tc.listeners)
				n.inject(tseg{sport: port, dport: dport, seq: 1, flags: flagSYN, wnd: 65535, mss: 1380, ws: -1})
				for _, o := range n.drain() {
					if o.seg.flags == flagSYN|flagACK {
						n.inject(tseg{sport: port, dport: dport, seq: 2, ack: o.seg.seq + 1, flags: flagACK, wnd: 65535, ws: -1})
					}
				}
			}
			q := n.d.s.lim.acceptQ
			st := checkHeld(t, n)
			if st.AcceptQueued != tc.want(q) || st.AcceptOverflow == 0 {
				t.Fatalf("accept queue %d, want %d; %+v", st.AcceptQueued, tc.want(q), st)
			}
		})
	}
}

// boostedConn は送信の向きの需要で boost を得た接続と、その相手を返す。相手は書いた分をすべて確認する。
func boostedConn(t *testing.T) (*testNet, *Conn, *peerConn) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	go c.Write(make([]byte, demandBytes))
	for i := 0; i < 10000 && (c.c.tailOff < demandBytes || c.c.unaOff != c.c.tailOff); i++ {
		p.absorb(n.drain())
		p.ack(nil)
	}
	if !c.c.boosted {
		t.Fatal("not boosted")
	}
	return n, c, p
}

func TestDemoteRefusedWhileRecordsExceedTheFloor(t *testing.T) {
	n, c, _ := boostedConn(t)
	for range floorRecords + 100 {
		c.Write([]byte{1}) // 相手は確認しない
		n.drain()
	}
	cs := c.c
	if cs.recs.n <= floorRecords || cs.tailOff-cs.unaOff > sendFloor {
		t.Fatalf("setup: %d records, %d bytes", cs.recs.n, cs.tailOff-cs.unaOff)
	}
	ok := demoteIdle(n, cs)
	if ok {
		t.Fatal("demoted a holder with more records than the floor ring holds")
	}
}

func TestDemoteRefusedWhileSendBytesExceedTheFloor(t *testing.T) {
	n, c, _ := boostedConn(t)
	c.Write(make([]byte, sendFloor+10000)) // 相手は確認しない
	n.drain()
	cs := c.c
	ok := demoteIdle(n, cs)
	if ok {
		t.Fatal("demoted a holder with more send bytes than the floor")
	}
}

func TestDataAfterCloseResets(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	c.Close() // FIN_WAIT_1、相手はまだ FIN を確認しない
	n.drain()
	p.ack([]byte("late"))
	outs := n.drain()
	if len(outs) != 1 || !outs[0].seg.has(flagRST) {
		t.Fatalf("data after Close: %v", outs)
	}
	if st := n.d.Stats(); st.Conns != 0 || st.TWRows != 0 {
		t.Fatalf("after the RST %+v", st)
	}
}

func TestOlderReorderedACKDoesNotChangeTheWindow(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	c.Write(make([]byte, 3000))
	p.absorb(n.drain())
	newer := p.seg(flagACK, nil)
	newer.wnd = 1000
	older := newer
	older.ack -= 1000 // 前に送った ACK が遅れて届く
	older.wnd = 30000
	n.inject(newer)
	n.inject(older)
	if w := c.c.sndWnd; w != 1000<<7 {
		t.Fatalf("send window %d after an older ACK, want %d", w, 1000<<7)
	}
}

func TestNoRetireBeforeDeliveryOrWithHeldData(t *testing.T) {
	t.Run("unacked data", func(t *testing.T) {
		n := newTestNet(t, smallLimits())
		l := listen(t, n, 80)
		p := n.handshake(40000, 80, true, false, true)
		c := acceptOne(t, l)
		n.drain()
		c.Write(make([]byte, 5000))
		c.Close()
		outs := n.drain()
		// 相手は FIN だけを確認したように見える番号を返さず、最初の segment だけを確認する
		p.rcv = outs[0].seg.seq + uint32(len(outs[0].seg.payload))
		p.ack(nil)
		if st := n.d.Stats(); st.TWRows != 0 || st.Conns != 1 {
			t.Fatalf("retired with unacked data: %+v", st)
		}
	})
	t.Run("out-of-order data", func(t *testing.T) {
		n := newTestNet(t, smallLimits())
		l := listen(t, n, 80)
		p := n.handshake(40000, 80, true, true, true)
		c := acceptOne(t, l)
		n.drain()
		s := p.seg(flagACK, []byte("ooo"))
		s.seq += 1000
		n.inject(s)
		n.drain()
		c.Close()
		p.absorb(n.drain())
		p.ack(nil) // FIN を確認する
		if st := n.d.Stats(); st.TWRows != 0 || st.Conns != 1 {
			t.Fatalf("retired while holding out-of-order data: %+v", st)
		}
	})
}

// demoteIdle は需要の時刻を 2 秒前にずらして demote を試す。時刻を進めると RTO が記録を外すためである。
// demote が panic しても錠を返し、試験の後片付けが止まらないようにする。
func demoteIdle(n *testNet, cs *tcb) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.lastDemand = n.d.s.clock() - int64(2*time.Second)
	return cs.demote(n.d.s.clock())
}
