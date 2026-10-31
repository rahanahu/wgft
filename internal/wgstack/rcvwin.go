package wgstack

import "time"

// 受信の窓の自動調整(wgstack-performance.md の「受信の窓と boost の方針」と「溢れた後の Linux の受け手」)。
// boost は受信の予約を 4 MiB にするが、広告する窓を一度には開かない。窓は 2 つの値で決める。
//
//   - 窓の上限(rcvClamp):受け手の往復ごとに読んだ量の測定(Linux の tcp_rcv_space_adjust)が上げ、測定では
//     下げない。予約の内側に収める
//   - 歩みの上限(rcvSsthresh):届いた segment ごとに有界の量だけ広げる(Linux の tcp_grow_window)
//
// 広告する窓は、上限から保持するデータ(未読と順序外)を引いた空きと、歩みの上限の小さい方で、RCV.NXT から
// 測る。右端は後ろへ戻さない(windowField)。右端は readOff + 上限 - 順序外の byte を超えないので、予約の
// 内側にある。

// rcvGrowMin は歩みの上限を広げる順序どおりの segment の中身の最小(Linux の tcp_event_data_recv の 128)。
const rcvGrowMin = 128

// rcvClamp は窓の上限。floor から予約までの間で、測定が求めた値である。
func (c *tcb) rcvClamp() uint64 {
	return min(max(c.rcvWant, recvFloor), c.rcvCap)
}

// rcvFree は窓の上限から保持するデータを引いた空き。順序外のデータも空きを減らす。
func (c *tcb) rcvFree() uint64 {
	held := c.rcv.unread() + c.rcv.ooo
	if cl := c.rcvClamp(); cl > held {
		return cl - held
	}
	return 0
}

// rcvTarget は今広告してよい右端(受信の offset)。空きと歩みの上限の小さい方を RCV.NXT に足し、窓の欄で
// 表せる量に収める。
func (c *tcb) rcvTarget() uint64 {
	nxt := c.rcv.nxtOff
	return nxt + min(c.rcvFree(), c.rcvSsthresh, uint64(65535)<<c.rcvWscale)
}

// rcvGrow は届いた n byte の segment で歩みの上限を広げる。順序どおりの rcvGrowMin byte 以上の segment と、
// SACK を交渉した接続の順序外の segment で広げる。広げる量は自分の MSS の 2 倍と中身の 2 倍の大きい方で、
// 上限と空きの小さい方を超えない。mu を持って呼ぶ。
func (c *tcb) rcvGrow(n int, ooo bool) {
	if ooo {
		if !c.sackOK {
			return
		}
	} else if n < rcvGrowMin {
		return
	}
	room := min(c.rcvClamp(), c.rcvFree())
	if room <= c.rcvSsthresh {
		return
	}
	incr := uint64(max(2*c.rcvMSS(), 2*n))
	c.rcvSsthresh += min(room-c.rcvSsthresh, incr)
}

// rcvRTTWindow は窓による受け手の RTT の標本を取る(Linux の tcp_rcv_rtt_measure)。標本は、始めの RCV.NXT に
// その時の窓を足した offset を RCV.NXT が越えるまでの時間で、今の推定より小さいときだけ推定を下げる。中身を
// 受け入れた後に呼ぶ。mu を持って呼ぶ。
func (c *tcb) rcvRTTWindow(now int64) {
	if c.rttWinTime != 0 {
		if c.rcv.nxtOff < c.rttWinSeq {
			return
		}
		if d := now - c.rttWinTime; d > 0 && (c.rcvRTT == 0 || d < c.rcvRTT) {
			c.rcvRTT = d
		}
	}
	c.rttWinSeq, c.rttWinTime = c.rcv.nxtOff+uint64(c.rcvWindow()), now
}

// rcvRTTStamp は timestamp による受け手の RTT の標本を取る(Linux の tcp_rcv_rtt_measure_ts)。推定した相手の
// MSS 以上の中身を持ち、前の標本と違う TSecr を持つ segment の、今の時刻と TSecr の差を標本にする。今の推定
// より小さい標本はそのまま推定にし、大きい標本は 8 分の 1 の重みで平滑する。mu を持って呼ぶ。
func (c *tcb) rcvRTTStamp(seg *segment, n int, now int64) {
	if !c.tsOK || !seg.opt.hasTS || seg.opt.tsEcr == 0 || seg.opt.tsEcr == c.rttTsecr || uint32(n) < c.rcvMSSEst {
		return
	}
	c.rttTsecr = seg.opt.tsEcr
	d := int32(tsClock(now) + c.tsOffset - seg.opt.tsEcr)
	if d < 0 {
		return
	}
	r := max(int64(d), 1) * int64(time.Millisecond)
	if c.rcvRTT == 0 || r < c.rcvRTT {
		c.rcvRTT = r
	} else {
		c.rcvRTT += (r - c.rcvRTT) / 8
	}
}

// rcvSpaceAdjust は読み取りの後に、受け手の RTT の 1 回の間に読んだ量で窓の上限を上げる(Linux の
// tcp_rcv_space_adjust)。目標は読んだ量の 2 倍に 16 MSS を足した量で、前の区間からの増え方の比を掛けた量の
// 2 倍を足す。上限は下げない。mu を持って呼ぶ。
func (c *tcb) rcvSpaceAdjust(now int64) {
	if c.rsTime == 0 {
		c.rsTime, c.rsSeq = now, c.rcv.readOff
		c.rsSpace = 10 * uint64(c.rcvMSS())
		return
	}
	if c.rcvRTT == 0 || now-c.rsTime < c.rcvRTT {
		return
	}
	copied := c.rcv.readOff - c.rsSeq
	if copied > c.rsSpace {
		mss := uint64(c.rcvMSS())
		cp := min(copied, boostSize) // 目標は予約で抑えるので、これより大きな量は目標を変えない
		win := 2*cp + 16*mss
		win += 2 * (win * (cp - min(c.rsSpace, cp)) / c.rsSpace)
		c.rcvWant = max(c.rcvWant, min(win, boostSize))
		c.rsSpace = copied
	}
	c.rsTime, c.rsSeq = now, c.rcv.readOff
}

// rcvWindow は今広告している窓の大きさ(byte)。
func (c *tcb) rcvWindow() uint32 {
	if c.advRight <= c.rcv.nxtOff {
		return 0
	}
	return uint32(min(c.advRight-c.rcv.nxtOff, 1<<30))
}

// windowField は広告する窓の欄を返し、広告した右端を更新する。右端は rcvTarget に向けて広げ、後ろへ戻さない。
// 右端を広げるのは、広げる量が min(窓の上限の半分, MSS) 以上のときだけである(受け手の SWS の回避、
// RFC 9293 3.8.6.2.2)。
// 窓の scale で切り捨てた分だけ欄の右端が論理の右端より手前に見えることは scale の性質で、論理の右端の
// 手前までのデータは受け入れる。
func (c *tcb) windowField() uint16 {
	nxt := c.rcv.nxtOff
	target := c.rcvTarget()
	if target > c.advRight && target-c.advRight >= min(c.rcvClamp()/2, uint64(c.rcvMSS())) {
		c.advRight = target
	}
	if c.advRight <= nxt {
		return 0
	}
	return uint16(min((c.advRight-nxt)>>c.rcvWscale, 65535))
}

// windowUpdate は、読み取りで空いた受信のバッファが広告する窓を大きく広げるときに ACK を送る。Linux の
// tcp_cleanup_rbuf と同じく、今の窓が窓の上限の半分以下で、広げた後の窓が今の窓の 2 倍以上になるときである。
func (c *tcb) windowUpdate() {
	cur := uint64(c.rcvWindow())
	if 2*cur > c.rcvClamp() {
		return
	}
	target := c.rcvTarget()
	if target <= c.rcv.nxtOff {
		return
	}
	next := target - c.rcv.nxtOff
	if next >= 2*cur && next-cur >= uint64(c.rcvMSS()) {
		c.ackNow = true
	}
}
