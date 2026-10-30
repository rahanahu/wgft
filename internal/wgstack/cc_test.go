package wgstack

import (
	"math"
	"testing"
	"time"
)

// 輻輳の制御(RFC 9438 の CUBIC と RFC 5681 の NewReno)の試験。窓の動きは核の関数を直接呼んで確かめる。

func ccConn(t *testing.T, cc CongestionControl) *tcb {
	t.Helper()
	n := newTestNet(t, smallLimits())
	n.d.s.ccPolicy = cc
	l := listen(t, n, 80)
	n.handshake(40000, 80, true, true, true)
	return acceptOne(t, l).c
}

func TestCubicLossThreshAndFastConvergence(t *testing.T) {
	c := ccConn(t, CongestionCubic)
	c.mu.Lock()
	defer c.mu.Unlock()
	mss := uint32(c.segMSS())
	c.cwnd = 100 * mss
	c.sndMax = c.sndUna + 100*mss
	if ss := c.ccFor().lossThresh(c); ss != 70*mss || c.cubic.wMax != 100 {
		t.Fatalf("ssthresh %d segments, W_max %v", ss/mss, c.cubic.wMax)
	}
	// 前の W_max より小さな窓での次の損失は、W_max を (1 + β) / 2 倍に縮める(fast convergence)
	c.cwnd = 80 * mss
	c.sndMax = c.sndUna + 80*mss
	c.ccFor().lossThresh(c)
	if want := 80 * (1 + cubicBeta) / 2; math.Abs(c.cubic.wMax-want) > 1e-9 || c.cubic.cwndPrior != 80 {
		t.Fatalf("W_max %v, want %v", c.cubic.wMax, want)
	}
}

// runCubic は、窓 cwnd の分の確認を RTT ごとに MSS ずつ受ける ACK の流れで、d の間の窓の変化を返す。
func runCubic(c *tcb, rtt, d time.Duration, now int64) (map[time.Duration]float64, int64) {
	mss := uint32(c.segMSS())
	at := map[time.Duration]float64{}
	start := now
	for now-start < int64(d) {
		segs := c.cwnd / mss
		for i := uint32(0); i < segs; i++ {
			now += int64(rtt) / int64(segs)
			c.ccFor().congAvoid(c, mss, now)
		}
		at[time.Duration(now-start).Round(rtt)] = float64(c.cwnd) / float64(mss)
	}
	return at, now
}

func TestCubicWindowFollowsTheCubicFunction(t *testing.T) {
	c := ccConn(t, CongestionCubic)
	c.mu.Lock()
	defer c.mu.Unlock()
	mss := uint32(c.segMSS())
	rtt := 100 * time.Millisecond
	c.srtt = int64(rtt)
	c.cwnd = 100 * mss
	c.sndMax = c.sndUna + 100*mss
	c.ssthresh = c.ccFor().lossThresh(c)
	c.cwnd = c.ssthresh // 回復の後の窓
	now := int64(time.Hour)
	k := math.Cbrt((100 - 70) / cubicC)
	at, _ := runCubic(c, rtt, 8*time.Second, now)
	w := func(t float64) float64 { d := t - k; return cubicC*d*d*d + 100 }
	for _, s := range []float64{1, 2, 3, k, 5, 6} {
		got := at[time.Duration(s*float64(time.Second)).Round(rtt)]
		// 窓は 1 RTT 先の W_cubic を目標にし、1 RTT ごとに近づくので、W_cubic(t) と W_cubic(t + RTT) の間にある
		lo, hi := w(s)-2, w(s+rtt.Seconds())+2
		if got < lo || got > hi {
			t.Errorf("at %.2f s: cwnd %.1f segments, want within [%.1f, %.1f]", s, got, lo, hi)
		}
	}
	if got := at[time.Duration(k*float64(time.Second)).Round(rtt)]; math.Abs(got-100) > 3 {
		t.Errorf("cwnd %.1f at K = %.2f s, want about W_max = 100", got, k)
	}
}

// TestCubicRenoFriendlyRegion は、RTT が短く窓が小さいとき、窓が Reno と公平な推定 W_est に従うことを確かめる
// (RFC 9438 4.3)。
func TestCubicRenoFriendlyRegion(t *testing.T) {
	c := ccConn(t, CongestionCubic)
	c.mu.Lock()
	defer c.mu.Unlock()
	mss := uint32(c.segMSS())
	rtt := 2 * time.Millisecond
	c.srtt = int64(rtt)
	c.cwnd = 20 * mss
	c.sndMax = c.sndUna + 20*mss
	c.ssthresh = c.ccFor().lossThresh(c)
	c.cwnd = c.ssthresh
	// 100 RTT の間、W_cubic は 0.2 秒しか進まないので W_max(20)に届かない。W_est は 14 から RTT ごとに約
	// 0.53 segment 増えて約 11 RTT で cwnd_prior(20)を超え、その後は RTT ごとに 1 segment 増えて約 109 になる
	at, _ := runCubic(c, rtt, 100*rtt, int64(time.Hour))
	got := at[100*rtt]
	if got < 100 || got > 112 {
		t.Fatalf("cwnd %.1f segments after 100 RTTs in the Reno-friendly region", got)
	}
	if c.cubic.wEst < c.cubic.cwndPrior {
		t.Fatalf("W_est %.1f did not pass cwnd_prior %.1f", c.cubic.wEst, c.cubic.cwndPrior)
	}
}

func TestCubicIdleShiftsTheEpoch(t *testing.T) {
	c := ccConn(t, CongestionCubic)
	c.mu.Lock()
	defer c.mu.Unlock()
	mss := uint32(c.segMSS())
	c.srtt = int64(100 * time.Millisecond)
	c.cwnd = 50 * mss
	c.sndMax = c.sndUna + 50*mss
	c.ssthresh = c.ccFor().lossThresh(c)
	c.cwnd = c.ssthresh
	c.ccFor().congAvoid(c, mss, int64(time.Hour))
	epoch := c.cubic.epoch
	c.ccFor().onIdle(c, int64(3*time.Second), int64(time.Hour+10*time.Second))
	if c.cubic.epoch != epoch+int64(3*time.Second) {
		t.Fatalf("epoch %d, want %d", c.cubic.epoch, epoch+int64(3*time.Second))
	}
}

func TestCubicRTOResetsTheEpoch(t *testing.T) {
	c := ccConn(t, CongestionCubic)
	c.mu.Lock()
	defer c.mu.Unlock()
	mss := uint32(c.segMSS())
	c.cwnd = 50 * mss
	c.sndMax = c.sndUna + 50*mss
	c.ccFor().lossThresh(c)
	c.ccFor().onRTO(c)
	if c.cubic != (cubicCC{}) {
		t.Fatalf("state after RTO %+v", c.cubic)
	}
}

func TestNewRenoStaysSelectable(t *testing.T) {
	c := ccConn(t, CongestionNewReno)
	c.mu.Lock()
	defer c.mu.Unlock()
	mss := uint32(c.segMSS())
	c.cwnd = 100 * mss
	c.sndMax = c.sndUna + 100*mss
	if ss := c.ccFor().lossThresh(c); ss != 50*mss {
		t.Fatalf("NewReno ssthresh %d segments", ss/mss)
	}
	c.cwnd = 10 * mss
	c.caAcc = 0
	for range 10 {
		c.ccFor().congAvoid(c, mss, 0)
	}
	if c.cwnd != 11*mss {
		t.Fatalf("NewReno cwnd %d segments after one window of ACKs", c.cwnd/mss)
	}
	d, err := New(Config{Addr: dutAddr, MTU: testMTU, Clock: NewManualClock(), TestCongestion: CongestionNewReno})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if d.s.ccPolicy != CongestionNewReno {
		t.Fatal("Config.TestCongestion not applied")
	}
}

// TestCubicIdleShiftStaysBehindNow は、送り残しが空になるたびに送り始める流れで、epoch が今より先へ
// ずれないことを確かめる(Linux の CA_EVENT_TX_START)。
func TestCubicIdleShiftStaysBehindNow(t *testing.T) {
	c := ccConn(t, CongestionCubic)
	c.mu.Lock()
	defer c.mu.Unlock()
	k := &c.cubic
	mss := uint32(c.segMSS())
	c.cwnd, c.ssthresh, c.srtt = 20*mss, 10*mss, int64(50*time.Millisecond)
	now := int64(10 * time.Second)
	for range 50 {
		last := now                         // 1 segment を送る
		now += int64(50 * time.Millisecond) // 1 RTT の後に確認が届く
		k.congAvoid(c, mss, now)
		now += int64(10 * time.Millisecond) // 次の書き込み
		k.onIdle(c, now-last, now)          // buildNew が渡す値:最後に送ってからの時間
	}
	if k.epoch > now {
		t.Fatalf("epoch %v is %v after now", time.Duration(k.epoch), time.Duration(k.epoch-now))
	}
}
