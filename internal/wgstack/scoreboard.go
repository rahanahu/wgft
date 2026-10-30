package wgstack

import "time"

// SACK の scoreboard(wgstack-performance.md の「SACK による回復」)。送信の記録の輪の印を scoreboard にし、
// RFC 6675 の pipe と IsLost を記録を順に調べずに求める。ACK 1 つの手間は、SACK の block の数 x log(記録の数)
// と、印付けの均した手間と、定数の更新の和を超えない(「ACK 1 つの手間の上界」)。
//
// 欄の意味は次のとおりである。
//   - sacked:SACK 済みの記録の byte の和
//   - lossIdx:損失の境目。これより手前の SACK 済みでない記録は失われた(IsLost が真)
//   - beyondBytes、beyondCnt:境目から先(境目の記録を含む)の SACK 済みの記録の byte の和と数
//   - rtxBytes:今の再送の世代で再送した記録の byte の和
//   - rxtIdx、rxtOff:次に再送を考える記録と、その記録の中で送り終えた byte(RFC 6675 の HighRxt)。
//     rxtMid は rxtIdx の記録を途中まで送った(PMTU の引き下げで分けて送る)ことを示す
//   - highSack:SACK 済みの記録の最も右の端(sacked が 0 でないときだけ意味を持つ)
//
// pipe は SND.MAX - SND.UNA - sacked - (境目より手前の SACK 済みでない byte) + rtxBytes である。

const dupThresh = 3

// renegeDelayMin は、SACK の取り消しを疑ってから RTO の処理に移るまでの最短の時間(Linux の
// tcp_check_sack_reneging と同じく max(SRTT/2, 10 ms))。
const renegeDelayMin = 10 * time.Millisecond

func (c *tcb) isSacked(r *record) bool { return r.flags&recSacked != 0 && r.sackGen == c.sackGen }

func (c *tcb) rtxLive(r *record) bool { return r.flags&recRtx != 0 && r.rtxGen == c.rtxGen }

// lostBytes は境目より手前の SACK 済みでない byte。
func (c *tcb) lostBytes() uint32 {
	front := c.sndMax
	if int(c.lossIdx) < c.recs.n {
		front = c.recs.at(int(c.lossIdx)).seq
	}
	return (front - c.sndUna) - (c.sacked - c.beyondBytes)
}

// pipe は RFC 6675 の送り残しの量。SACK を交渉しない接続では、回復の外の重複した ACK 2 つまでを
// 受け手が受けた segment とみなす(RFC 3042 の Limited Transmit、Linux の tcp_add_reno_sack)。
func (c *tcb) pipe() uint32 {
	p := (c.sndMax - c.sndUna) - c.sacked - c.lostBytes() + c.rtxBytes
	if !c.sackOK && !c.inRecovery && c.dupAcks > 0 {
		p -= min(p, uint32(min(c.dupAcks, dupThresh-1)*c.segMSS()))
	}
	return p
}

// firstRecFrom は開始の番号が seq 以上の最初の記録の位置を返す。記録は番号の順に隙間なく並ぶ。
func (c *tcb) firstRecFrom(seq uint32) int {
	key := seq - c.sndUna
	lo, hi := 0, c.recs.n
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		c.scoreSteps++
		if c.recs.at(mid).seq-c.sndUna < key {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo
}

// nextUnsacked は、SACK 済みの記録 i から続く SACK 済みの記録を飛ばし、SACK 済みでない最初の記録の位置
// (無ければ記録の数)を返す。たどった記録の skip を返す位置に書き直す(経路の圧縮)。
func (c *tcb) nextUnsacked(i int) int {
	j := i
	for j < c.recs.n {
		r := c.recs.at(j)
		if !c.isSacked(r) {
			break
		}
		c.scoreSteps++
		j += int(r.skip)
	}
	j = min(j, c.recs.n)
	for k := i; k < j; {
		r := c.recs.at(k)
		if !c.isSacked(r) {
			break
		}
		next := k + int(r.skip)
		r.skip = int32(j - k)
		c.scoreSteps++
		k = next
	}
	return j
}

// markSACK は segment の SACK の block で記録に印を付け、損失の境目を進める。新しく SACK 済みになった
// byte を返す。block の 1 つでも範囲の外にあれば、segment の block をすべて捨てる。
func (c *tcb) markSACK(seg *segment) uint32 {
	n := seg.opt.nsack
	if n == 0 {
		return 0
	}
	for _, b := range seg.opt.sack[:n] {
		if !seqLT(b.left, b.right) || seqLT(b.left, c.sndUna-c.maxSndWnd) || seqGT(b.right, c.sndMax) {
			return 0
		}
	}
	if !c.sackOK || c.recs.n == 0 {
		return 0
	}
	before := c.sacked
	for _, b := range seg.opt.sack[:n] {
		if !seqGT(b.right, c.sndUna) {
			continue // D-SACK か、確認済みの範囲
		}
		left := b.left
		if seqLT(left, c.sndUna) {
			left = c.sndUna
		}
		key := b.right - c.sndUna
		for i := c.firstRecFrom(left); i < c.recs.n; {
			r := c.recs.at(i)
			c.scoreSteps++
			if r.seq+uint32(r.length)-c.sndUna > key {
				break
			}
			if c.isSacked(r) {
				i = c.nextUnsacked(i)
				continue
			}
			c.setSacked(i, r)
			i++
		}
	}
	c.advanceLoss()
	return c.sacked - before
}

// setSacked は位置 i の記録 r に SACK 済みの印を付け、欄を更新する。
func (c *tcb) setSacked(i int, r *record) {
	l := uint32(r.length)
	r.flags |= recSacked
	r.sackGen = c.sackGen
	r.skip = 1
	if c.sacked == 0 || seqGT(r.seq+l, c.highSack) {
		c.highSack = r.seq + l
	}
	c.sacked += l
	if i >= int(c.lossIdx) {
		c.beyondBytes += l
		c.beyondCnt++
	}
	if c.rtxLive(r) {
		r.flags &^= recRtx
		c.rtxBytes -= l
	}
}

// advanceLoss は、境目の記録より先の SACK 済みの量が RFC 6675 の閾値(DupThresh 個の記録か
// (DupThresh - 1) x SMSS byte を超える量)に届く間、境目を先へ進める。境目は後ろへ戻らない。
func (c *tcb) advanceLoss() {
	limit := uint32((dupThresh - 1) * c.segMSS())
	for int(c.lossIdx) < c.recs.n {
		r := c.recs.at(int(c.lossIdx))
		cnt, by := c.beyondCnt, c.beyondBytes
		s := c.isSacked(r)
		if s {
			cnt--
			by -= uint32(r.length)
		}
		if cnt < dupThresh && by <= limit {
			return
		}
		c.passLoss(r, s)
	}
}

// passLoss は境目を記録 r の先へ進める。s は r が SACK 済みか。
func (c *tcb) passLoss(r *record, s bool) {
	if s {
		c.beyondCnt--
		c.beyondBytes -= uint32(r.length)
	}
	c.lossIdx++
	c.scoreSteps++
}

// markAllLost は SACK 済みでない記録をすべて損失にし、再送の世代を進め、再送の手がかりを SND.UNA に戻す。
// RTO と PMTU の引き下げで呼ぶ。手間は記録の数によらない。
func (c *tcb) markAllLost(cause uint8) {
	c.lossIdx = int32(c.recs.n)
	c.beyondBytes, c.beyondCnt = 0, 0
	c.rtxGen++
	if c.rtxGen == 0 {
		for i := range c.recs.recs {
			c.recs.recs[i].flags &^= recRtx
		}
	}
	c.rtxBytes = 0
	c.rxtIdx, c.rxtOff, c.rxtMid = 0, 0, false
	c.resendCause = cause
}

// clearSACK は SACK の取り消しで、すべての記録の SACK 済みの印を世代の番号で消す。
func (c *tcb) clearSACK() {
	c.sackGen++
	if c.sackGen == 0 {
		for i := range c.recs.recs {
			c.recs.recs[i].flags &^= recSacked
		}
	}
	c.sacked, c.beyondBytes, c.beyondCnt = 0, 0, 0
	c.s.sackReneging.Add(1)
}

// dropHead は累積の確認で外す先頭の記録 r の分を欄から引き、位置の欄を 1 つ前へずらす。
func (c *tcb) dropHead(r *record) {
	l := uint32(r.length)
	if c.isSacked(r) {
		c.sacked -= l
		if c.lossIdx == 0 {
			c.beyondBytes -= l
			c.beyondCnt--
		}
	}
	if c.rtxLive(r) {
		c.rtxBytes -= l
	}
	if c.lossIdx > 0 {
		c.lossIdx--
	}
	if c.rxtIdx > 0 {
		c.rxtIdx--
	} else {
		c.rxtOff, c.rxtMid = 0, false
	}
}

// trimHead は累積の確認が先頭の記録 r の内側に届いたとき、確認された d byte を記録から外す。
func (c *tcb) trimHead(r *record, d uint32) {
	if c.isSacked(r) {
		c.sacked -= d
		if c.lossIdx == 0 {
			c.beyondBytes -= d
		}
	}
	if c.rtxLive(r) {
		c.rtxBytes -= d
	}
	r.seq += d
	r.length -= uint16(d)
	if c.rxtIdx == 0 {
		c.rxtOff -= min(c.rxtOff, d)
	}
}

// nextResend は RFC 6675 の NextSeg の規則 1 の記録(SACK 済みでなく、失われ、今の世代で再送していない
// 記録)の位置を返す。無ければ -1 を返す。手がかりは前へだけ進むので、手間は均すと記録ごとに定数である。
func (c *tcb) nextResend() int { return c.nextResendUpTo(int(c.lossIdx)) }

// nextRule3 は NextSeg の規則 3 の記録(SACK 済みでなく、今の世代で再送しておらず、最も右の SACK 済みの
// byte より手前にある記録。失われたかは問わない)の位置を返す。回復の中で、規則 1 と 2 で送るものが無い
// ときだけ使う。規則 4(rescue の再送)は使わない。
func (c *tcb) nextRule3() int {
	if !c.inRecovery || c.sacked == 0 {
		return -1
	}
	i := c.nextResendUpTo(c.recs.n)
	if i < 0 || !seqLT(c.recs.at(i).seq, c.highSack) {
		return -1
	}
	return i
}

func (c *tcb) nextResendUpTo(limit int) int {
	for int(c.rxtIdx) < limit && int(c.rxtIdx) < c.recs.n {
		r := c.recs.at(int(c.rxtIdx))
		c.scoreSteps++
		switch {
		case c.isSacked(r):
			c.rxtIdx = int32(c.nextUnsacked(int(c.rxtIdx)))
			c.rxtOff, c.rxtMid = 0, false
		case c.rtxLive(r) && !c.rxtMid:
			c.rxtIdx++
		default:
			return int(c.rxtIdx)
		}
	}
	return -1
}

// resendLen は記録 i の再送で次に送る segment の中身の長さと、FIN を付けるかを返す。
func (c *tcb) resendLen(i int, payCap int) (uint32, bool) {
	r := c.recs.at(i)
	start := r.seq + c.rxtOff
	end := r.seq + uint32(r.length)
	var left uint32
	if de := c.dataEndSeq(); seqLT(start, de) {
		left = seqMin(end, de) - start
	}
	n := min(left, uint32(max(payCap, 0)))
	fin := c.finSent && n == left && seqGT(end, c.dataEndSeq())
	return n, fin
}

// enterRecovery は SACK による回復に入る(RFC 6675 5 節、RFC 6937)。先頭の記録は損失とみなす。
func (c *tcb) enterRecovery() {
	mss := uint32(c.segMSS())
	flight := c.sndMax - c.sndUna
	c.ssthresh = max(flight/2, 2*mss)
	c.recover = c.sndMax
	c.inRecovery = true
	c.prrDelivered, c.prrOut = 0, 0
	c.recoverFS = flight
	c.rxtIdx, c.rxtOff, c.rxtMid = 0, 0, false
	c.resendCause = rtxFast
	if c.lossIdx == 0 && c.recs.n > 0 {
		r := c.recs.at(0)
		c.passLoss(r, c.isSacked(r))
		c.advanceLoss()
	}
	c.s.fastRecoveries.Add(1)
}

// prrUpdate は回復の中の ACK ごとに、PRR(RFC 6937 の PRR-SSRB)で輻輳の窓を決める。delivered はこの ACK
// が累積の確認と SACK で新しく届けたと知らせた byte である。
func (c *tcb) prrUpdate(delivered uint32) {
	mss := int64(c.segMSS())
	c.prrDelivered += delivered
	pipe := int64(c.pipe())
	ss := int64(c.ssthresh)
	var sndcnt int64
	if pipe > ss {
		fs := max(int64(c.recoverFS), 1)
		sndcnt = (int64(c.prrDelivered)*ss+fs-1)/fs - int64(c.prrOut)
	} else {
		limit := max(int64(c.prrDelivered)-int64(c.prrOut), int64(delivered)) + mss
		sndcnt = min(ss-pipe, limit)
	}
	sndcnt = max(sndcnt, 0)
	if c.prrOut == 0 && sndcnt < mss {
		sndcnt = mss // 回復に入った時の最初の再送(Linux の tcp_cwnd_reduction)
	}
	c.cwnd = uint32(min(pipe+sndcnt, 1<<30))
}

// sackAfterAck は SACK を交渉した接続で、ACK の処理の後に回復に入るかを決め、回復の中なら窓を決める。
func (c *tcb) sackAfterAck(delivered uint32) {
	if !c.inRecovery && c.sndUna != c.sndMax && seqGE(c.sndUna, c.recover) && (c.dupAcks >= dupThresh || c.lossIdx > 0) {
		c.enterRecovery()
	}
	if c.inRecovery {
		c.prrUpdate(delivered)
	}
}

// renegeTimer は、累積の確認の後も先頭の記録が SACK 済みのとき(相手が SACK 済みのデータを捨てた疑い)、
// 再送のタイマーを max(SRTT/2, 10 ms) に早める。期限までに直す ACK が来なければ、RTO の処理が印を消す。
func (c *tcb) renegeTimer(now int64) {
	if c.persist || c.recs.n == 0 || !c.isSacked(c.recs.at(0)) {
		return
	}
	at := now + max(c.srtt/2, int64(renegeDelayMin))
	if c.tdl[tmrRetrans] == 0 || at < c.tdl[tmrRetrans] {
		c.arm(tmrRetrans, at)
	}
}
