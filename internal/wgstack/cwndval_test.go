package wgstack

import (
	"testing"
	"time"
)

// TestCwndDoesNotGrowWhileAppLimited は、RTT ごとに 2 segment ずつしか送らない(アプリケーションに制限された)
// stream で、輻輳の窓が使わないまま育たないことを確かめる(RFC 7661)。
func TestCwndDoesNotGrowWhileAppLimited(t *testing.T) {
	for _, cc := range []CongestionControl{CongestionCubic, CongestionNewReno} {
		appLimitedRun(t, cc)
	}
}

func appLimitedRun(t *testing.T, cc CongestionControl) {
	const rtt = 50 * time.Millisecond
	n := newTestNet(t, smallLimits())
	n.d.s.ccPolicy = cc
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, true, true)
	c := acceptOne(t, l)
	n.drain()
	cs := c.c
	cs.mu.Lock()
	cs.srtt, cs.rttvar, cs.hasRTT = int64(rtt), int64(5*time.Millisecond), true
	cs.ssthresh = 10 * uint32(cs.segMSS()) // 輻輳の回避から始める
	cs.cwnd = cs.ssthresh
	cs.mu.Unlock()
	q := newSackPeer(p)
	for i := 0; i < 1200; i++ { // 60 秒
		c.Write(make([]byte, 2*testSegPayload))
		outs := n.drain()
		n.advance(rtt / 2)
		q.deliver(outs, nil)
		n.drain()
		n.advance(rtt / 2)
	}
	t.Logf("cc %d: after 60 s of 2 segments per RTT: cwnd %d segments (ssthresh %d)", cc, cs.cwnd/uint32(cs.segMSS()), cs.ssthresh/uint32(cs.segMSS()))
	if cs.cwnd > 4*cs.ssthresh {
		t.Errorf("cwnd grew to %d segments while only 2 were ever in flight", cs.cwnd/uint32(cs.segMSS()))
	}
}

// TestCwndGrowsWhenTheWindowIsFull は、送るデータが十分にあり、輻輳の窓に 1 segment の余地も無い間は窓が
// 増えることを確かめる。窓が segment の倍数でなくても、余りの byte で送れない間は輻輳の窓に制限されている。
func TestCwndGrowsWhenTheWindowIsFull(t *testing.T) {
	for _, cc := range []CongestionControl{CongestionCubic, CongestionNewReno} {
		const rtt = 50 * time.Millisecond
		n := newTestNet(t, smallLimits())
		n.d.s.ccPolicy = cc
		l := listen(t, n, 80)
		p := n.handshake(40000, 80, true, true, true)
		c := acceptOne(t, l)
		n.drain()
		cs := c.c
		cs.mu.Lock()
		cs.srtt, cs.rttvar, cs.hasRTT = int64(rtt), int64(5*time.Millisecond), true
		mss := uint32(cs.segMSS())
		cs.ssthresh = 4 * mss
		cs.cwnd = 4*mss + 100 // segment の倍数でない窓
		cs.mu.Unlock()
		start := cs.cwnd
		q := newSackPeer(p)
		c.Write(make([]byte, 200*int(mss)))
		for range 40 {
			outs := n.drain()
			n.advance(rtt / 2)
			q.deliver(outs, nil)
			n.advance(rtt / 2)
		}
		if cs.cwnd <= start+mss {
			t.Fatalf("cc %d: cwnd %d bytes after 40 RTTs of a full window, started at %d", cc, cs.cwnd, start)
		}
	}
}
