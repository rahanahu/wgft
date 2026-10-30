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
