package wgstack

import (
	"testing"
	"time"
)

// 受け手が小さな segment を読み終えた時の ACK(Linux の tcp_cleanup_rbuf)の試験。

func TestSmallSegmentACKedWhenReadDrainsTheBuffer(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, true, true)
	c := acceptOne(t, l)
	n.drain()
	skipQuickack(n)
	for i := range 3 {
		p.ack(make([]byte, 200))
		if outs := n.drain(); len(outs) != 0 {
			t.Fatalf("message %d: ACK before the read %v", i, outs)
		}
		readN(t, c, 200)
		outs := n.drain()
		if len(outs) != 1 || outs[0].seg.ack != p.snd || len(outs[0].seg.payload) != 0 {
			t.Fatalf("message %d: after the read sent %v, want one ACK of %d", i, outs, p.snd)
		}
		n.advance(20 * time.Millisecond)
		n.drain()
	}
}

func TestFullSegmentIsNotPushed(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, true, true)
	acceptOne(t, l)
	n.drain()
	cs := &n.d.s.conns[0]
	p.ack(make([]byte, testMTU-40-12))
	if cs.ackPushed || cs.rcvMSSEst != uint32(cs.rcvMSS()) {
		t.Fatalf("full segment: pushed %v, MSS estimate %d", cs.ackPushed, cs.rcvMSSEst)
	}
	p.ack(make([]byte, 200))
	if !cs.ackPushed {
		t.Fatal("a small segment is not marked")
	}
}

// TestNoDrainACKInInteractiveFlow は、受けた直後にデータで応える対話の流れでは、読み終えても中身の無い ACK を
// 足さず、応えるデータに ACK を載せることを確かめる。
func TestNoDrainACKInInteractiveFlow(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, true, true)
	c := acceptOne(t, l)
	n.drain()
	p.ack(make([]byte, 200))
	readN(t, c, 200)
	n.drain()
	c.Write(make([]byte, 100)) // 受けた直後に応える
	p.absorb(n.drain())
	p.ack(make([]byte, 200))
	readN(t, c, 200)
	if outs := n.drain(); len(outs) != 0 {
		t.Fatalf("pure ACK on drain in an interactive flow: %v", outs)
	}
}

// skipQuickack は、接続の始めの quickack を使い切った後の遅延 ACK を確かめる試験のために、接続が既にデータを
// 受けた状態にする。
func skipQuickack(n *testNet) {
	for i := range n.d.s.conns {
		c := &n.d.s.conns[i]
		c.mu.Lock()
		if c.state != stFree {
			c.rcvdData, c.lastDataRcvd = true, int64(n.clk.Now())
		}
		c.mu.Unlock()
	}
}

// TestQuickackAtStartAndAfterAGap は、接続の始めの segment と、RTO より長く黙った後の segment には ACK を遅らせず
// 返し、その数が quickackMax で止まることを確かめる(Linux の tcp_incr_quickack)。
func TestQuickackAtStartAndAfterAGap(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, true, true)
	c := acceptOne(t, l)
	n.drain()
	full := testMTU - 40 - 12
	immediate := 0
	for range 40 {
		p.ack(make([]byte, full))
		if outs := n.drain(); len(outs) > 0 {
			immediate++
		}
		readN(t, c, full)
		n.drain()
	}
	// 最初の quickackMax 個は 1 つずつ、その後は 2 つに 1 つ ACK する
	if want := quickackMax + (40-quickackMax)/2; immediate < want-1 || immediate > want+1 {
		t.Fatalf("%d immediate ACKs for 40 segments, want about %d", immediate, want)
	}
	n.advance(2 * time.Second) // RTO より長く黙る
	p.ack(make([]byte, full))
	if outs := n.drain(); len(outs) != 1 {
		t.Fatalf("after a gap: %v, want an immediate ACK", outs)
	}
}

// TestDuplicateSegmentGetsADSACK は、すべて届いていた segment に、その範囲を先頭の SACK の block(D-SACK)にした
// ACK を返すことを確かめる(RFC 2883)。順序外の区間の内側の重複では、区間の block が後に続く。
func TestDuplicateSegmentGetsADSACK(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, true, true)
	acceptOne(t, l)
	n.drain()
	base := p.snd
	p.ack(make([]byte, 500))
	n.drain()
	dup := p.seg(flagACK, make([]byte, 500))
	dup.seq = base
	n.inject(dup)
	outs := n.drain()
	if len(outs) != 1 || outs[0].seg.opt.nsack != 1 || outs[0].seg.opt.sack[0] != (sackBlock{base, base + 500}) {
		t.Fatalf("duplicate below RCV.NXT: %v", outs)
	}
	// 順序外の区間の内側の重複
	ooo := p.seg(flagACK, make([]byte, 300))
	ooo.seq = base + 1000
	n.inject(ooo)
	n.drain()
	n.inject(ooo)
	outs = n.drain()
	if len(outs) != 1 || outs[0].seg.opt.nsack != 2 || outs[0].seg.opt.sack[0] != (sackBlock{base + 1000, base + 1300}) || outs[0].seg.opt.sack[1] != (sackBlock{base + 1000, base + 1300}) {
		t.Fatalf("duplicate inside an out-of-order interval: %v", outs)
	}
	// D-SACK は 1 回だけ載せる
	p.ack(nil)
	n.advance(delackTimeout)
	for _, o := range n.drain() {
		if o.seg.opt.nsack > 1 {
			t.Fatalf("D-SACK repeated: %v", o)
		}
	}
}
