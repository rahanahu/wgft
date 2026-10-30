package wgstack

import (
	"testing"
	"time"
)

// TestLostQueueSplitEndsWhenTheHeadIsSACKed は、分けて送っている途中の損失の待ち行列の先頭が SACK で外れた
// 時に、分けた位置を次の記録に持ち越さないことを確かめる。持ち越すと長さが巻き戻り、SND.MAX の先の輪の
// 中身、つまり chunk を前に使った別の接続のデータを送った(監査で再現した)。
func TestLostQueueSplitEndsWhenTheHeadIsSACKed(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	// another connection's data passes through a chunk that goes back to the pool
	pa := n.handshake(41000, 80, true, true, true)
	ca := acceptOne(t, l)
	secret := make([]byte, 8000)
	for i := range secret {
		secret[i] = 0x5a
	}
	ca.Write(secret)
	for range 20 {
		pa.absorb(n.drain())
		pa.ack(nil)
	}
	if ca.c.unaOff != ca.c.tailOff {
		t.Fatalf("A not acked")
	}
	t.Logf("pool free chunks %d", len(n.d.s.chunks.free))
	p := n.handshake(40000, 80, true, true, true)
	c := acceptOne(t, l)
	n.drain()
	cs := c.c
	cs.mu.Lock()
	cs.srtt, cs.rttvar, cs.minRTT, cs.hasRTT, cs.hasMinRTT = int64(testRTT), int64(testRTT)/2, int64(testRTT), true, true
	cs.rto = int64(rtoMin)
	cs.mu.Unlock()
	var recs []out
	for _, sz := range []int{testSegPayload, testSegPayload, 100, testSegPayload} {
		if _, err := c.Write(make([]byte, sz)); err != nil {
			t.Fatal(err)
		}
		o := n.drain()
		if len(o) != 1 {
			t.Fatalf("write %d sent %v", sz, o)
		}
		recs = append(recs, o[0])
	}
	// fill the stream with a pattern so that a read past the tail is visible
	n.advance(testRTT)
	q := newSackPeer(p)
	// peer gets only R3 and SACKs it
	q.recv(recs[3])
	q.ack()
	n.drain()
	// make the DUT hold out-of-order data so that its segments carry a SACK block
	s := p.seg(flagACK, make([]byte, 10))
	s.seq += 50
	n.inject(s)
	n.advance(10 * time.Millisecond) // past the reorder window: R0..R2 lost
	t.Logf("lostQ %d lossIdx %d inRecovery %v cwnd %d pipe %d", cs.lostQ.n, cs.lossIdx, cs.inRecovery, cs.cwnd, cs.pipe())
	cs.mu.Lock()
	cs.cwnd = 1 << 20
	cs.mu.Unlock()
	buf := make([]byte, 65536)
	for range 3 {
		k := n.d.Poll(buf)
		ip, _ := parseIPv4(append([]byte(nil), buf[:k]...))
		seg, _ := parseTCP(&ip)
		t.Logf("sent %v", out{ip: ip, seg: seg})
	}
	t.Logf("after: qOff %d qMid %v lostQ %d", cs.qOff, cs.qMid, cs.lostQ.n)
	// R1's original arrives late: SACK R1 and R3; cumulative ACK still at R0
	q.recv(recs[1])
	q.ack()
	t.Logf("after SACK of R1: qOff %d qMid %v lostQ %d head %d", cs.qOff, cs.qMid, cs.lostQ.n, cs.recIdx(cs.lostQ.head))
	if cs.qMid || cs.qOff != 0 {
		t.Errorf("the split position %d of the SACKed head was kept for the next record", cs.qOff)
	}
	max := cs.sndMax
	for _, o := range n.drain() {
		e := o.seg.seq + uint32(len(o.seg.payload))
		t.Logf("sent %v (rel %d..%d, SND.MAX rel %d)", o, o.seg.seq-recs[0].seg.seq, e-recs[0].seg.seq, max-recs[0].seg.seq)
		if seqGT(e, max) {
			t.Errorf("segment ends %d bytes past SND.MAX", e-max)
			leak := 0
			for _, b := range o.seg.payload {
				if b == 0x5a {
					leak++
				}
			}
			t.Errorf("payload holds %d bytes of the other connection's data", leak)
		}
	}
	if f := n.d.Stats().AccountingFaults; f != 0 {
		t.Errorf("%d accounting faults: the check closed the connection instead of the fix", f)
	}
}
