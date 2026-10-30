package wgstack

import (
	"testing"
	"time"
)

// RTT 80 ms(PTO 160 ms、RTO の下限 200 ms)で末尾の 2 segment を失う。probe を PTO に送った後、probe の
// SACK は 1 RTT の後(最後の ACK から 240 ms)に届く。probe の後に RTO を張り直さないと、その前の 200 ms に
// RTO が起きる。
func TestNoRTOBeforeTheProbeCanBeAcked(t *testing.T) {
	const rtt = 80 * time.Millisecond
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, true, true)
	c := acceptOne(t, l)
	n.drain()
	cs := c.c
	cs.mu.Lock()
	cs.srtt, cs.rttvar, cs.minRTT, cs.hasRTT, cs.hasMinRTT = int64(rtt), int64(5*time.Millisecond), int64(rtt), true, true
	cs.rto = int64(rtoMin)
	cs.mu.Unlock()
	q := newSackPeer(p)
	c.Write(make([]byte, 10*testSegPayload))
	outs := n.drain()
	n.advance(rtt)
	q.deliver(outs, func(i int, o out) bool { return i >= 8 })
	t.Logf("after the ACKs: rtoAt +%v tlpAt +%v", time.Duration(cs.rtoAt-int64(n.clk.Now())), time.Duration(cs.tlpAt-int64(n.clk.Now())))
	if cs.tlpAt == 0 {
		t.Fatal("no PTO armed")
	}
	start := n.clk.Now()
	var probe []out
	for probe == nil && n.clk.Now()-start < time.Second {
		n.advance(time.Millisecond)
		probe = n.drain()
	}
	at := n.clk.Now() - start
	t.Logf("probe at +%v: %v; RTO deadline +%v", at, probe, time.Duration(cs.rtoAt)-start)
	// probe は 1 RTT で届き、その SACK が返る前に RTO が起きるか
	for n.clk.Now()-start < at+rtt {
		n.advance(time.Millisecond)
		if got := n.drain(); len(got) > 0 {
			t.Logf("at +%v sent %v (RTOs %d)", n.clk.Now()-start, got, n.d.Stats().RTOs)
		}
	}
	if st := n.d.Stats(); st.RTOs > 0 {
		t.Errorf("RTO fired %v after the probe, before its ACK could return one RTT later", time.Duration(cs.rtoAt))
	}
}

// TestRTOWithAPendingFastRetransmitSendsTheHeadOnce は、SACK の無い接続で高速の再送を作る前に RTO が来ても、
// 先頭の segment を 1 度だけ送り直すことを確かめる。RTO の規則が SND.UNA から送り直すので、待っていた高速の
// 再送の印を消す。
func TestRTOWithAPendingFastRetransmitSendsTheHeadOnce(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	cs := c.c
	c.Write(make([]byte, 10*testSegPayload))
	outs := n.drain()
	if len(outs) < 5 {
		t.Fatalf("sent %d segments", len(outs))
	}
	head := outs[0].seg.seq
	for range 3 {
		p.ack(nil) // 先頭が失われた重複の ACK
	}
	if !cs.fastRtx {
		t.Fatal("no fast retransmit pending after three duplicate ACKs")
	}
	cs.mu.Lock()
	at := cs.rtoAt
	cs.mu.Unlock()
	n.clk.Advance(time.Duration(at-int64(n.clk.Now())) + time.Millisecond)
	n.d.Tick()
	heads := 0
	for _, o := range n.drain() {
		if o.seg.seq == head && len(o.seg.payload) > 0 {
			heads++
		}
	}
	if heads != 1 {
		t.Fatalf("the head was sent %d times after the RTO", heads)
	}
}
