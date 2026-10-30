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
