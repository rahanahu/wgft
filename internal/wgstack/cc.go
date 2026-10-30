package wgstack

import (
	"math"
	"time"
)

// 輻輳の制御(wgstack-performance.md の「CUBIC」)。slow start、回復の間の窓(NewReno の窓の膨らませ方と PRR)、
// RTO の後の 1 segment は共通の処理が持ち、輻輳の回避の窓の増やし方と、輻輳の事象での ssthresh の決め方
// だけを ccAlgo の後ろに置く。状態は接続の枠の中に値として埋め込み、接続ごとの確保を作らない。

// CongestionControl は試験だけが選ぶ輻輳の制御(Config.TestCongestion)。
type CongestionControl uint8

const (
	CongestionCubic   CongestionControl = iota // 既定。RFC 9438
	CongestionNewReno                          // RFC 5681 の輻輳の回避と RFC 6582
)

// ccAlgo は輻輳の制御の知らせを受ける。
type ccAlgo interface {
	// congAvoid は、回復の外で cwnd >= ssthresh の間に acked byte を確認した ACK で窓を増やす
	congAvoid(c *tcb, acked uint32, now int64)
	// lossThresh は輻輳の事象(回復に入る時、TLP の probe が損失を直した時、最初の RTO)の新しい ssthresh
	lossThresh(c *tcb) uint32
	// onRTO は RTO の後の状態を整える。ssthresh は呼び出し側が lossThresh で決める
	onRTO(c *tcb)
	// onIdle は、送り残しが無いまま idle ns の間何も送らなかった後に送り始める時に呼ぶ
	onIdle(c *tcb, idle int64)
}

// newRenoCC は RFC 5681 の輻輳の回避。状態は接続の caAcc だけを使う。
type newRenoCC struct{}

func (newRenoCC) congAvoid(c *tcb, acked uint32, now int64) {
	c.caAcc += acked
	if c.caAcc >= c.cwnd {
		c.caAcc -= c.cwnd
		c.cwnd += uint32(c.segMSS())
	}
}

func (newRenoCC) lossThresh(c *tcb) uint32 {
	return max((c.sndMax-c.sndUna)/2, 2*uint32(c.segMSS()))
}

func (newRenoCC) onRTO(c *tcb)              { c.caAcc = 0 }
func (newRenoCC) onIdle(c *tcb, idle int64) {}

// CUBIC の定数(RFC 9438 4.6 と 5)。
const (
	cubicBeta = 0.7
	cubicC    = 0.4
)

// cubicCC は RFC 9438 の CUBIC。窓は segment の数で計算し、byte の窓に 1 byte 未満の端数を持ち越す。
type cubicCC struct {
	wMax      float64 // 最後の輻輳の事象の直前の窓(fast convergence で縮めた値)
	cwndPrior float64 // 最後の輻輳の事象の直前の窓
	epoch     int64   // 輻輳の回避の epoch の始まり(ns)。0 なら次の ACK で始める
	k         float64 // 窓が wMax に戻るまでの時間(秒)
	origin    float64 // 3 次の式の原点の窓
	wEst      float64 // Reno と公平な窓の推定(RFC 9438 4.3)
	frac      float64 // cwnd に足していない byte の端数
}

func (k *cubicCC) congAvoid(c *tcb, acked uint32, now int64) {
	mss := float64(c.segMSS())
	cwnd := float64(c.cwnd) / mss
	if k.epoch == 0 {
		k.epoch = now
		k.wEst = cwnd
		if k.wMax <= cwnd {
			k.k, k.origin = 0, cwnd
		} else {
			k.k, k.origin = math.Cbrt((k.wMax-cwnd)/cubicC), k.wMax
		}
	}
	t := float64(now-k.epoch) / float64(time.Second)
	rtt := float64(c.srtt) / float64(time.Second)
	wCubic := func(t float64) float64 { d := t - k.k; return cubicC*d*d*d + k.origin }
	// Reno と公平な窓(RFC 9438 4.3)。cwnd_prior に届いた後の増え方は Reno と同じにする
	alpha := 3 * (1 - cubicBeta) / (1 + cubicBeta)
	if k.wEst >= k.cwndPrior {
		alpha = 1
	}
	ackedSeg := float64(acked) / mss
	k.wEst += alpha * ackedSeg / cwnd
	var inc float64 // segment
	if w := wCubic(t); w < k.wEst {
		inc = k.wEst - cwnd // Reno と公平な領域(RFC 9438 4.3)
	} else {
		// 凹と凸の領域(RFC 9438 4.4、4.5)。目標は 1 RTT 先の窓で、[cwnd, 1.5 cwnd] に収める
		target := min(max(wCubic(t+rtt), cwnd), 1.5*cwnd)
		inc = (target - cwnd) / cwnd * ackedSeg
	}
	if inc <= 0 {
		return
	}
	k.frac += inc * mss
	if add := math.Floor(k.frac); add >= 1 {
		k.frac -= add
		c.cwnd = uint32(min(float64(c.cwnd)+add, 1<<30))
	}
}

// lossThresh は RFC 9438 4.6 と 4.7(fast convergence)。ssthresh は送り残しの β 倍である。
func (k *cubicCC) lossThresh(c *tcb) uint32 {
	mss := float64(c.segMSS())
	cwnd := float64(c.cwnd) / mss
	if cwnd < k.wMax {
		k.wMax = cwnd * (1 + cubicBeta) / 2
	} else {
		k.wMax = cwnd
	}
	k.cwndPrior = cwnd
	k.epoch, k.frac = 0, 0
	return max(uint32(float64(c.sndMax-c.sndUna)*cubicBeta), 2*uint32(c.segMSS()))
}

// onRTO は Linux の bictcp_reset と同じく、RTO の後の epoch を 3 次の式の原点から始め直す。
func (k *cubicCC) onRTO(c *tcb) {
	*k = cubicCC{}
}

// onIdle は送らなかった時間だけ epoch を後ろへずらす(Linux の CA_EVENT_TX_START)。ずらさないと、黙った後の
// 最初の ACK で 3 次の式が先へ進んだ窓を一度に求める。
func (k *cubicCC) onIdle(c *tcb, idle int64) {
	if k.epoch != 0 && idle > 0 {
		k.epoch += idle
	}
}

// ccFor は接続 c の輻輳の制御を返す。
func (c *tcb) ccFor() ccAlgo {
	if c.s.ccPolicy == CongestionNewReno {
		return newRenoCC{}
	}
	return &c.cubic
}
