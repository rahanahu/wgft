package wgstack

import (
	"math"
	"time"
)

// HyStart++(RFC 9406、wgstack-performance.md の「HyStart++」)。最初の slow start の間、往復ごとの最小の RTT が
// 前の往復より閾値以上増えたら Conservative Slow Start(CSS)に移り、窓の増え方を 4 分の 1 にする。CSS の間に
// RTT が戻れば slow start に戻り、CSS_ROUNDS 往復続けば ssthresh を今の窓にして輻輳の回避に移る。輻輳の
// 制御の種類によらず、新しい保持を作らない。

const (
	hsMinRTTThresh  = 4 * time.Millisecond
	hsMaxRTTThresh  = 16 * time.Millisecond
	hsMinRTTDivisor = 8
	hsNRTTSample    = 8
	hsCSSGrowthDiv  = 4
	hsCSSRounds     = 5
	hsNoRTT         = math.MaxInt64
)

// hystart は HyStart++ の状態。接続の枠の中に値として埋め込む。
type hystart struct {
	started      bool
	windowEnd    uint32 // この往復の終わりの番号(往復を始めた時の SND.NXT)
	lastRoundMin int64  // 前の往復の最小の RTT。hsNoRTT は無し
	curRoundMin  int64
	samples      int
	css          bool
	cssBaseline  int64
	cssRounds    int
	// sndNxt は処理中の ACK の前に、ACK のたびに送る送り手なら送り終えていた番号(sendableEnd)。往復を
	// 始めた時の SND.NXT として使う
	sndNxt   uint32
	sndNxtOK bool
}

// hystartOn は最初の slow start の間だけ真を返す(RFC 9406 4.3。RTO や損失の後の slow start では使わない)。
func (c *tcb) hystartOn() bool { return c.ssthresh == ^uint32(0) && !c.inRecovery }

// slowStartAck は slow start の ACK で窓を増やす。acked は新しく確認された byte、sample はこの ACK で
// 測った RTT(ns、無ければ -1)。増やす量は RFC 3465 の L = 2 で、CSS の間は 4 分の 1 にする。
func (c *tcb) slowStartAck(ack, acked uint32, sample, now int64) {
	inc := min(acked, 2*uint32(c.segMSS()))
	if !c.hystartOn() {
		c.cwnd += inc
		return
	}
	h := &c.hs
	start := c.sndNxt
	if h.sndNxtOK && seqGT(h.sndNxt, start) {
		start = h.sndNxt
	}
	h.sndNxtOK = false
	if !h.started {
		*h = hystart{started: true, windowEnd: start, lastRoundMin: hsNoRTT, curRoundMin: hsNoRTT, cssBaseline: hsNoRTT}
	}
	if h.css {
		inc /= hsCSSGrowthDiv
	}
	c.cwnd += inc
	if sample >= 0 {
		h.curRoundMin = min(h.curRoundMin, sample)
		h.samples++
	}
	if h.samples >= hsNRTTSample && h.curRoundMin != hsNoRTT {
		switch {
		case !h.css && h.lastRoundMin != hsNoRTT:
			thresh := min(max(h.lastRoundMin/hsMinRTTDivisor, int64(hsMinRTTThresh)), int64(hsMaxRTTThresh))
			if h.curRoundMin >= h.lastRoundMin+thresh {
				h.css, h.cssBaseline, h.cssRounds = true, h.curRoundMin, 0
				c.s.hystartCSS.Add(1)
			}
		case h.css && h.curRoundMin < h.cssBaseline:
			h.css, h.cssBaseline = false, hsNoRTT // RTT が戻ったので slow start に戻る
		}
	}
	// 往復の終わり:windowEnd を確認した ACK で次の往復を始める
	if seqGE(ack, h.windowEnd) {
		// 往復を始めた時の SND.NXT は、まとめて届いた ACK が許してまだ作っていない segment を含む(lazyegress.go)
		h.lastRoundMin, h.curRoundMin, h.samples, h.windowEnd = h.curRoundMin, hsNoRTT, 0, start
		if h.css {
			h.cssRounds++
			if h.cssRounds >= hsCSSRounds {
				c.ssthresh = c.cwnd // 輻輳の回避に移る
				h.css = false
				c.s.hystartExits.Add(1)
			}
		}
	}
}
