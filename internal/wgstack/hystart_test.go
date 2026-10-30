package wgstack

import (
	"testing"
	"time"
)

// HyStart++(RFC 9406)の試験。往復ごとに窓の分の segment を送ったとし、1 segment ごとの ACK に rtt(r) の
// RTT を付けて slowStartAck を直接呼ぶ。

// hsRounds は ACK ごとに窓いっぱいまで送る ACK の流れで rounds 往復を進め、往復ごとの窓(segment)を返す。
// rtt は往復の番号ごとの RTT である。
func hsRounds(c *tcb, rounds int, rtt func(round int) time.Duration) []uint32 {
	mss := uint32(c.segMSS())
	var w []uint32
	now := int64(time.Hour)
	ack := c.sndUna
	c.sndNxt = ack + c.cwnd
	end := c.sndNxt // 往復の終わり
	round := 0
	for round < rounds && c.cwnd < c.ssthresh {
		ack += mss
		now += int64(time.Millisecond)
		c.slowStartAck(ack, mss, int64(rtt(round)), now)
		c.sndUna = ack
		c.sndNxt = ack + c.cwnd // 窓いっぱいまで送る
		c.sndMax = c.sndNxt
		if seqGE(ack, end) {
			w = append(w, c.cwnd/mss)
			end = c.sndNxt
			round++
		}
	}
	return w
}

func hsConn(t *testing.T) *tcb {
	c := ccConn(t, CongestionCubic)
	c.mu.Lock()
	t.Cleanup(c.mu.Unlock)
	c.cwnd = 10 * uint32(c.segMSS())
	c.hs = hystart{}
	return c
}

func TestHyStartSteadyRTTKeepsSlowStart(t *testing.T) {
	c := hsConn(t)
	w := hsRounds(c, 6, func(int) time.Duration { return 50 * time.Millisecond })
	if c.hs.css || c.ssthresh != ^uint32(0) || w[len(w)-1] < 10<<5 {
		t.Fatalf("windows %v, CSS %v", w, c.hs.css)
	}
}

func TestHyStartEntersCSSAndExitsAfterFiveRounds(t *testing.T) {
	c := hsConn(t)
	// 3 往復目から RTT が 50 ms から 60 ms に増える(閾値は 50 / 8 = 6.25 ms)
	w := hsRounds(c, 20, func(r int) time.Duration {
		if r >= 2 {
			return 60 * time.Millisecond
		}
		return 50 * time.Millisecond
	})
	if c.s.hystartCSS.Load() != 1 || c.s.hystartExits.Load() != 1 || c.ssthresh == ^uint32(0) {
		t.Fatalf("windows %v; CSS %d exits %d ssthresh %d", w, c.s.hystartCSS.Load(), c.s.hystartExits.Load(), c.ssthresh)
	}
	// CSS の間は往復ごとに 1.25 倍ほどで、slow start の 2 倍より遅い
	for i := 3; i < len(w); i++ {
		if g := float64(w[i]) / float64(w[i-1]); g > 1.3 {
			t.Fatalf("round %d grew by %.2f in CSS; windows %v", i, g, w)
		}
	}
	if c.ssthresh != c.cwnd {
		t.Fatalf("ssthresh %d, cwnd %d after CSS", c.ssthresh, c.cwnd)
	}
}

func TestHyStartLeavesCSSWhenRTTFalls(t *testing.T) {
	c := hsConn(t)
	w := hsRounds(c, 8, func(r int) time.Duration {
		if r == 2 || r == 3 {
			return 60 * time.Millisecond
		}
		return 50 * time.Millisecond
	})
	if c.s.hystartCSS.Load() != 1 || c.hs.css || c.s.hystartExits.Load() != 0 || c.ssthresh != ^uint32(0) {
		t.Fatalf("windows %v; CSS %d now %v exits %d", w, c.s.hystartCSS.Load(), c.hs.css, c.s.hystartExits.Load())
	}
}

func TestHyStartOnlyInTheFirstSlowStart(t *testing.T) {
	c := hsConn(t)
	c.ssthresh = 1000 * uint32(c.segMSS()) // 損失か RTO の後
	hsRounds(c, 6, func(r int) time.Duration { return time.Duration(50+20*r) * time.Millisecond })
	if c.s.hystartCSS.Load() != 0 || c.hs.started {
		t.Fatal("HyStart++ ran after the first slow start")
	}
}
