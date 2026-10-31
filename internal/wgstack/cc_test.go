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
	if ss := c.lossThresh(); ss != 70*mss || c.cubic.wMax != 100 {
		t.Fatalf("ssthresh %d segments, W_max %v", ss/mss, c.cubic.wMax)
	}
	// 前の W_max より小さな窓での次の損失は、W_max を (1 + β) / 2 倍に縮める(fast convergence)
	c.cwnd = 80 * mss
	c.sndMax = c.sndUna + 80*mss
	c.lossThresh()
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
	c.ssthresh = c.lossThresh()
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
	c.ssthresh = c.lossThresh()
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
	c.ssthresh = c.lossThresh()
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
	c.lossThresh()
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
	if ss := c.lossThresh(); ss != 50*mss {
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

// TestRecoveryRightAfterRecoveryReducesTheWindow は、回復を終える ACK がそのまま次の回復に入る場合に、輻輳の
// 事象が窓を下げることを確かめる(RFC 5681 と RFC 9438 4.6 の乗算の減少、wgstack-performance.md の「CUBIC」)。
// 最初の回復の間に回復の点より先へ送ったデータが失われると、その穴より先の SACK 済みのデータは累積で確認されない
// まま SND.MAX - SND.UNA に残る。この量の β 倍を ssthresh にすると、ssthresh が輻輳の窓より大きくなり、損失の
// たびに送る量が増えていた。RecoverFS は RFC 9937 6.1 のとおり、回復の前に SACK 済みの byte を含まない。
func TestRecoveryRightAfterRecoveryReducesTheWindow(t *testing.T) {
	for _, tc := range []struct {
		name string
		cc   CongestionControl
		beta float64
	}{{"cubic", CongestionCubic, cubicBeta}, {"newreno", CongestionNewReno, 0.5}} {
		t.Run(tc.name, func(t *testing.T) { testRecoveryAfterRecovery(t, tc.cc, tc.beta) })
		t.Run(tc.name+"_floor", func(t *testing.T) {
			// 窓が 2 segment なら、β 倍は 2 SMSS の下限を下回るので ssthresh は下限になる
			c := ccConn(t, tc.cc)
			c.mu.Lock()
			defer c.mu.Unlock()
			mss := uint32(c.segMSS())
			c.cwnd = 2 * mss
			c.sndMax = c.sndUna + 40*mss
			if ss := c.lossThresh(); ss != 2*mss {
				t.Fatalf("ssthresh %d with a window of 2 segments, want the floor %d", ss, 2*mss)
			}
		})
	}
}

func testRecoveryAfterRecovery(t *testing.T, cc CongestionControl, beta float64) {
	n, c, q, outs := sackConn(t, 150)
	cs := c.c
	cs.s.ccPolicy = cc
	if len(outs) != 10 {
		t.Fatalf("IW10 sent %d", len(outs))
	}
	mss := uint32(cs.segMSS())
	// 先頭の segment を失い、残りの 9 つを SACK で知らせる:ssthresh が 10 segment の β 倍の回復に入る
	q.deliver(outs, func(i int, o out) bool { return i == 0 })
	if !cs.inRecovery {
		t.Fatal("not in recovery")
	}
	head, recover := outs[0].seg.seq, cs.recover
	// 先頭の再送を止めておく間に、回復の点より先の最初の新しい segment を失い、ほかはすべて届けて SACK で
	// 知らせる。PRR は SACK された分だけ新しいデータを送るので、穴の先の SACK 済みのデータが積もる
	var held []out
	var lostSeq uint32
	lostSet := false
	for range 6 {
		n.advance(10 * time.Millisecond)
		for _, o := range n.drain() {
			if len(o.seg.payload) == 0 {
				continue
			}
			switch s := o.seg.seq; {
			case s == head:
				held = append(held, o)
			case !lostSet && seqGE(s, recover):
				lostSeq, lostSet = s, true
			case lostSet && s == lostSeq:
				// 失った segment の再送も失う
			default:
				q.recv(o)
				q.ack()
			}
		}
	}
	if !lostSet || len(held) == 0 || !cs.inRecovery {
		t.Fatalf("setup: lost new segment %v, held %d, in recovery %v", lostSet, len(held), cs.inRecovery)
	}
	ss := cs.ssthresh
	priorUna, priorMax, priorSacked := cs.sndUna, cs.sndMax, cs.sacked
	// 先頭の再送を届ける。累積の確認は回復の点を越えて失った segment で止まり、回復を終えた同じ ACK で
	// 次の回復に入る
	q.recv(held[0])
	q.ack()
	flight := cs.sndMax - cs.sndUna
	t.Logf("old ssthresh %d segments; at the new recovery: flight %d segments, sacked %d, ssthresh %d, cwnd %d",
		ss/mss, flight/mss, cs.sacked/mss, cs.ssthresh/mss, cs.cwnd/mss)
	if !cs.inRecovery || cs.recover == recover {
		t.Fatalf("no new recovery: in recovery %v, recover %d", cs.inRecovery, cs.recover)
	}
	if flight <= ss {
		t.Fatalf("setup: flight %d is not above the window %d at the second loss", flight, ss)
	}
	// 回復を終えた時の窓は ssthresh である。次の輻輳の事象は、その窓を β 倍に下げなければならない
	if want := uint32(float64(ss) * beta); cs.ssthresh > want {
		t.Errorf("ssthresh %d after a second loss, want at most %d: beta times the window %d, not the flight %d", cs.ssthresh, want, ss, flight)
	}
	if cs.cwnd > ss {
		t.Errorf("cwnd %d above the window %d at the loss", cs.cwnd, ss)
	}
	// RFC 9937 6.1:RecoverFS は ACK の前の送り残しから、ACK の前に SACK 済みの byte を引いた量である
	if want := priorMax - priorUna - priorSacked; cs.recoverFS != want {
		t.Errorf("RecoverFS %d, want %d: the flight before the ACK less the %d bytes SACKed before recovery", cs.recoverFS, want, priorSacked)
	}
}

// TestRTODuringRecoveryKeepsTheRecoveryWindow は、SACK による回復の中の RTO が、PRR の途中の輻輳の窓ではなく
// 回復が目指す ssthresh を β 倍することを確かめる(wgstack-performance.md の「CUBIC」)。まとまった損失の後は
// pipe がほぼ 0 なので、PRR の窓は数 segment で、それを β 倍すると ssthresh が 2 SMSS の下限まで落ちる。
// RTO の後の回復の中で、新しい ACK が後退を 0 に戻した後の RTO も、slow start の途中の窓ではなく ssthresh を使う。
func TestRTODuringRecoveryKeepsTheRecoveryWindow(t *testing.T) {
	n, c, q, outs := sackConn(t, 150)
	cs := c.c
	if len(outs) != 10 {
		t.Fatalf("IW10 sent %d", len(outs))
	}
	// 先頭の 7 つを失い、残りの 3 つを SACK で知らせる:回復に入り、pipe はほぼ 0 になる
	q.deliver(outs, func(i int, o out) bool { return i < 7 })
	if !cs.inRecovery {
		t.Fatal("not in recovery")
	}
	ss0, flight0 := cs.ssthresh, cs.sndMax-cs.sndUna
	n.drain() // 再送はすべて失う
	t.Logf("in recovery: ssthresh %d, PRR cwnd %d, flight %d", ss0, cs.cwnd, flight0)
	n.advance(time.Second) // RTO
	if cs.s.rtos.Load() != 1 {
		t.Fatalf("RTOs %d after a second", cs.s.rtos.Load())
	}
	want := uint32(float64(min(ss0, flight0)) * cubicBeta)
	if cs.ssthresh != want {
		t.Fatalf("ssthresh %d after an RTO in recovery, want %d: beta times the recovery's ssthresh %d", cs.ssthresh, want, ss0)
	}
	// RTO の後の回復の中で、先頭の再送だけが届く。累積の確認が進んで後退は 0 に戻るが、SND.UNA は RTO の時の
	// SND.MAX に届かない
	ss1 := cs.ssthresh
	var head out
	for _, o := range n.drain() {
		if o.seg.seq == outs[0].seg.seq && len(o.seg.payload) > 0 {
			head = o
		}
	}
	if len(head.seg.payload) == 0 {
		t.Fatal("no retransmission of the head after the RTO")
	}
	q.recv(head)
	q.ack()
	if cs.backoff != 0 || !cs.rtoEpisode || !seqLT(cs.sndUna, cs.recover) {
		t.Fatalf("setup: backoff %d, RTO episode %v", cs.backoff, cs.rtoEpisode)
	}
	flight1 := cs.sndMax - cs.sndUna
	n.drain()
	n.advance(time.Second) // 2 回目の RTO。後退は 0 から数える
	if cs.s.rtos.Load() < 2 {
		t.Fatalf("RTOs %d", cs.s.rtos.Load())
	}
	want = max(uint32(float64(min(ss1, flight1))*cubicBeta), 2*uint32(cs.segMSS()))
	if cs.ssthresh != want {
		t.Fatalf("ssthresh %d after an RTO in the RTO's recovery, want %d: beta times the ssthresh %d", cs.ssthresh, want, ss1)
	}
}

// TestRTOEpisodeEndsWithoutSACK は、SACK を交渉しない接続でも、RTO の後に SND.UNA が recover に届いたら RTO の
// 後の回復の印を消すことを確かめる。残すと、SND.UNA が recover から 2^31 先へ進んだ後に、輻輳の事象の
// 送り手の窓を古い ssthresh で決める。
func TestRTOEpisodeEndsWithoutSACK(t *testing.T) {
	n := newTestNet(t, smallLimits())
	c, p := n.accepted(true, false)
	cs := c.c
	if _, err := c.Write(make([]byte, 5*testSegPayload)); err != nil {
		t.Fatal(err)
	}
	n.drain() // すべて失う
	n.advance(2 * time.Second)
	if cs.s.rtos.Load() == 0 || !cs.rtoEpisode || cs.sackOK {
		t.Fatalf("setup: RTOs %d, RTO episode %v, SACK %v", cs.s.rtos.Load(), cs.rtoEpisode, cs.sackOK)
	}
	recover := cs.recover
	for i := 0; i < 100 && cs.sndUna != cs.sndMax; i++ {
		p.absorb(n.drain())
		p.ack(nil)
		n.advance(10 * time.Millisecond)
	}
	if !seqGE(cs.sndUna, recover) {
		t.Fatalf("setup: SND.UNA %d short of recover %d", cs.sndUna, recover)
	}
	if cs.rtoEpisode {
		t.Fatal("RTO episode still marked after SND.UNA reached recover")
	}
}
