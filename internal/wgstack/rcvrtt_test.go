package wgstack

import (
	"testing"
	"time"
)

// 受け手の RTT の推定と窓の上限の式(rcvwin.go)を、関数を直に呼んで確かめる試験。

const rrMS = int64(time.Millisecond)

func rrSeg(tsEcr uint32) *segment {
	s := &segment{}
	s.opt.hasTS, s.opt.tsEcr = true, tsEcr
	return s
}

// TestRcvRTTStampSamples は timestamp による標本の規則を確かめる。小さい標本は推定を置き換え、大きい標本は
// 8 分の 1 の重みで動かし、同じ TSecr と小さい segment と TSecr の 0 は標本にしない。
func TestRcvRTTStampSamples(t *testing.T) {
	_, _, _, cs := rwBoosted(t, false)
	cs.tsOffset, cs.rcvRTT, cs.rttTsecr, cs.rcvMSSEst = 0, 0, 0, 1000
	now := 1000 * rrMS // tsClock は ms
	step := func(ecr uint32, n int, want int64, why string) {
		t.Helper()
		cs.rcvRTTStamp(rrSeg(ecr), n, now)
		if cs.rcvRTT != want {
			t.Fatalf("%s: rcvRTT %d ns, want %d", why, cs.rcvRTT, want)
		}
	}
	step(900, 1000, 100*rrMS, "first sample")
	step(950, 1000, 50*rrMS, "smaller sample replaces the estimate")
	step(850, 1000, 50*rrMS+(150*rrMS-50*rrMS)/8, "larger sample moves by 1/8")
	est := cs.rcvRTT
	step(850, 1000, est, "the same TSecr is not sampled again")
	step(960, 999, est, "a segment below the peer's segment size is not sampled")
	step(0, 1000, est, "TSecr 0 is not sampled")
	step(990, 1000, 10*rrMS, "a new TSecr is sampled")
}

// TestRcvRTTWindowSamples は窓による標本が、窓の終わりを RCV.NXT が越えたときに 1 つ取れ、今の推定より小さい
// ときだけ推定を下げることを確かめる。timestamp を持たない相手の推定はこれだけで決まる。
func TestRcvRTTWindowSamples(t *testing.T) {
	_, _, _, cs := rwBoostedTS(t, false, false)
	cs.rcvRTT, cs.rttWinTime = 0, 0
	now := 1000 * rrMS
	cs.rcvRTTWindow(now) // 標本の始め
	if cs.rttWinTime != now || cs.rcvRTT != 0 {
		t.Fatalf("sample not started: time %d, rcvRTT %d", cs.rttWinTime, cs.rcvRTT)
	}
	cs.rcvRTTWindow(now + 10*rrMS) // RCV.NXT が窓の終わりに届かない
	if cs.rcvRTT != 0 {
		t.Fatalf("sampled before the window end: rcvRTT %d", cs.rcvRTT)
	}
	cs.rcv.nxtOff = cs.rttWinSeq
	now += 100 * rrMS
	cs.rcvRTTWindow(now)
	if cs.rcvRTT != 100*rrMS {
		t.Fatalf("first window sample: rcvRTT %d, want %d", cs.rcvRTT, 100*rrMS)
	}
	cs.rcv.nxtOff = cs.rttWinSeq
	cs.rcvRTTWindow(now + 300*rrMS)
	if cs.rcvRTT != 100*rrMS {
		t.Fatalf("a larger window sample raised the estimate to %d", cs.rcvRTT)
	}
	cs.rcv.nxtOff = cs.rttWinSeq
	cs.rcvRTTWindow(now + 300*rrMS + 40*rrMS)
	if cs.rcvRTT != 40*rrMS {
		t.Fatalf("a smaller window sample: rcvRTT %d, want %d", cs.rcvRTT, 40*rrMS)
	}
}

// TestRcvSpaceAdjustFormula は窓の上限の式を値で確かめる。前の区間に 64 KiB、今の区間に 128 KiB を読んだとき、
// 目標は (2·128 KiB + 16 MSS) に、増え方の比 1 の 2 倍を足した 3 倍である。
func TestRcvSpaceAdjustFormula(t *testing.T) {
	_, _, _, cs := rwBoosted(t, false)
	mss := uint64(cs.rcvMSS())
	cs.rcvRTT, cs.rcvWant = 50*rrMS, 0
	start := 1000 * rrMS
	cs.rsTime, cs.rsSeq, cs.rsSpace = start, cs.rcv.readOff, 64<<10
	cs.rcv.readOff += 128 << 10
	cs.rcvSpaceAdjust(start + 49*rrMS) // 受け手の RTT に届かない
	if cs.rcvWant != 0 || cs.rsSpace != 64<<10 {
		t.Fatalf("measured before one RTT: want %d, space %d", cs.rcvWant, cs.rsSpace)
	}
	cs.rcvSpaceAdjust(start + 50*rrMS)
	want := 3 * (2*(128<<10) + 16*mss)
	if cs.rcvWant != want {
		t.Fatalf("rcvWant %d, want %d", cs.rcvWant, want)
	}
	if cs.rsSpace != 128<<10 {
		t.Fatalf("rsSpace %d, want the 128 KiB just read", cs.rsSpace)
	}
	// 同じ量をもう一度読んでも上がらない
	cs.rcv.readOff += 128 << 10
	cs.rcvSpaceAdjust(start + 100*rrMS)
	if cs.rcvWant != want {
		t.Fatalf("rcvWant moved to %d with unchanged reads", cs.rcvWant)
	}
}

// TestRecvWindowKeepsMeasuredWantAcrossDemotion は、floor に戻しても測定が求めた上限を消さず、もう一度 boost
// を得たときにその値が効くことを確かめる。
func TestRecvWindowKeepsMeasuredWantAcrossDemotion(t *testing.T) {
	n, c1, p1, c2, p2 := boostTwo(t)
	cs1 := &n.d.s.conns[c1.c.id]
	cs1.rcvWant = 1 << 20
	n.advance(2 * time.Second)
	p2.sendBulk(demandBytes)
	readN(t, c2, demandBytes)
	if cs1.boosted {
		t.Fatal("holder not demoted")
	}
	if cs1.rcvWant != 1<<20 || cs1.rcvClamp() != recvFloor {
		t.Fatalf("after demotion: rcvWant %d, clamp %d", cs1.rcvWant, cs1.rcvClamp())
	}
	n.advance(2 * time.Second)
	p1.sendBulk(demandBytes)
	readN(t, c1, demandBytes)
	if !cs1.boosted || cs1.rcvClamp() != 1<<20 {
		t.Fatalf("after re-boost: boosted %v, clamp %d", cs1.boosted, cs1.rcvClamp())
	}
}
