package wgstack

import "time"

// 接続の枠の ACK の欄の処理(RFC 9293、RFC 5681、RFC 6582、RFC 6298 の RTT の測定)。

// rttSample は RTT の測定値 r(ns)で SRTT、RTTVAR、RTO を更新する(RFC 6298 2 節)。
func (c *tcb) rttSample(r int64) {
	if r < 0 {
		return
	}
	c.tlpSampled = true
	if !c.hasRTT {
		c.srtt, c.rttvar, c.hasRTT = r, r/2, true
	} else {
		d := c.srtt - r
		if d < 0 {
			d = -d
		}
		c.rttvar = (3*c.rttvar + d) / 4
		c.srtt = (7*c.srtt + r) / 8
	}
	if !c.hasMinRTT || r < c.minRTT {
		c.minRTT, c.hasMinRTT = r, true
	}
	// 下限は RTO 全体ではなく RTTVAR の項に掛ける(Linux と同じ)。RFC 6298 の式の値以上で、RTTVAR の小さな
	// 経路でも Linux より早く RTO を起こさない(wgstack-performance.md の「RACK-TLP」のタイマーの規則)
	c.rto = min(c.srtt+max(4*c.rttvar, int64(rtoMin)), int64(rtoMax))
}

// tsRTTSample は、相手が返した自分の TSval(TSecr)から RTT を測る(RFC 7323 4.1)。自分の今の TSval より
// 先の TSecr は、自分が送っていない値なので使わない。
func (c *tcb) tsRTTSample(tsEcr uint32, now int64) int64 {
	d := int32(tsClock(now) + c.tsOffset - tsEcr)
	if d < 0 {
		return -1
	}
	r := int64(d) * int64(time.Millisecond)
	c.rttSample(r)
	return r
}

// processAck は ACK の欄を処理する(RFC 9293、RFC 5681、RFC 6582)。
func (c *tcb) processAck(seg *segment, now int64) {
	ack := seg.ack
	if c.hystartOn() {
		c.hs.sndNxt, c.hs.sndNxtOK = c.sendableEnd(), true // この ACK の前の SND.NXT(lazyegress.go)
	}
	c.probesOut = 0
	if c.persist {
		c.retransStart = 0 // 相手は probe に応えている
	}
	wndChanged := c.updateSendWindow(seg)
	// RFC 6937 の DeliveredData は SND.UNA の差と SACK 済みの byte の差の和である。累積の確認が先に SACK した
	// byte を覆うと SACK 済みの byte は減るので、差は確認の前の値から取る
	var delivered int64
	sackedBefore := c.sacked
	rackX, rackE := c.rackXmit, c.rackEnd
	c.origDelivered = false
	advanced := seqGT(ack, c.sndUna)
	c.priorUna, c.priorCwnd = c.sndUna, c.cwnd
	switch {
	case advanced:
		delivered = int64(ack - c.sndUna)
		c.newAck(seg, ack, now)
	case ack == c.sndUna && len(seg.payload) == 0 && !seg.has(flagFIN) && !wndChanged && c.sndMax != c.sndUna:
		c.dupAck(now)
	}
	if c.state == stFree || c.state == stClosed {
		return
	}
	newly := c.markSACK(seg, now)
	delivered += int64(c.sacked) - int64(sackedBefore)
	if c.sackOK {
		if c.rackXmit != rackX || c.rackEnd != rackE {
			c.rackChanges++
		}
		c.rackDetect(now)
		if c.frto != 0 && seqLT(c.sndUna, c.recover) {
			c.frtoAfterAck(seg, advanced, newly > 0 || (!advanced && c.sndUna != c.sndMax))
		} else if c.rtoEpisode && seqGE(c.sndUna, c.recover) {
			c.rtoRecovered(seg)
		}
		c.tlpOnAck(ack, advanced, newly)
		c.sackAfterAck(uint32(max(delivered, 0)))
		if advanced {
			c.scheduleTLP(now)
		} else if c.inRecovery {
			c.tlpAt = 0
		}
		c.rearmRetrans()
	} else if c.rtoEpisode && seqGE(c.sndUna, c.recover) {
		// SACK を交渉しない接続の RTO の後の回復の終わり。SND.UNA が recover から 2^31 先へ進んだ後に、番号の
		// 比べで回復の中に戻ったとみなさないように、印を消す
		c.rtoEpisode = false
	}
	if advanced {
		c.noteDrainedWithData(now)
	}
	if c.sndWnd > 0 && c.persist {
		c.clearRetransTimers()
		c.leavePersist(now)
	}
	if c.s.trace != nil {
		c.traceEvent(TraceAck, now)
	}
}

// updateSendWindow は、segment が SND.WL1 と SND.WL2 より新しければ相手の窓を更新する(RFC 9293 3.10.7.4)。
// 窓の大きさが変わったかを返す。
func (c *tcb) updateSendWindow(seg *segment) bool {
	if !(seqLT(c.sndWl1, seg.seq) || (c.sndWl1 == seg.seq && seqLE(c.sndWl2, seg.ack))) {
		return false
	}
	w := uint32(seg.wnd) << c.sndWscale
	changed := w != c.sndWnd
	c.sndWnd, c.sndWl1, c.sndWl2 = w, seg.seq, seg.ack
	c.maxSndWnd = max(c.maxSndWnd, w)
	return changed
}

// newAck は累積の確認を進める ACK を処理する。確認された byte と記録を外し、RTT を測り、輻輳の窓、再送の
// タイマー、自分の FIN の確認による状態の順に進める。
func (c *tcb) newAck(seg *segment, ack uint32, now int64) {
	acked := ack - c.sndUna
	sample, rtxAcked := c.retireAcked(ack, now)
	c.sndUna = ack
	if c.tlpCut && seqGE(ack, c.tlpCutSeq) {
		c.tlpCut = false // 縮小が覆う窓のデータはすべて確認された。番号が 1 周した後に古い番号と比べない
	}
	if seqLT(c.sndNxt, ack) {
		c.sndNxt = ack
	}
	ackRTT := c.rttOnAck(seg, sample, rtxAcked, now)
	c.backoff = 0
	c.retransStart = 0
	c.cwndOnAck(seg, ack, acked, ackRTT, now)
	c.dupAcks = 0
	c.retransTimerOnAck(now)
	c.finAckedState(now)
	c.signalWrite()
}

// retireAcked は SND.UNA から ack までに確認された byte を送信の輪から外し、確認された記録を外す。FIN の 1 は
// byte に数えない。最後に外した再送していない記録の RTT の標本(無ければ -1)と、再送した記録を 1 つでも
// 確認したかを返す(Karn。Linux の FLAG_RETRANS_DATA_ACKED)。記録は RTO の後も残るので、再送を待つ間に
// 届いていた元の segment で測ると、穴が埋まるまでの時間を RTT に含めてしまう。欄の更新は記録を外す前に
// 古い SND.UNA で行うので、SND.UNA を進める前に呼ぶ。
func (c *tcb) retireAcked(ack uint32, now int64) (sample int64, rtxAcked bool) {
	acked := ack - c.sndUna
	dataAcked := min(uint64(acked), c.tailOff-c.unaOff)
	old := c.unaOff
	c.unaOff += dataAcked
	c.snd.trim(old, c.unaOff, c.tailOff)
	sample = -1
	for c.recs.n > 0 {
		r := c.recs.at(0)
		end := r.seq + uint32(r.length)
		if seqGT(end, ack) {
			if seqLT(r.seq, ack) {
				c.trimHead(r, ack-r.seq)
			}
			break
		}
		if r.flags&recRetransmitted == 0 {
			sample = now - r.sentAt
		} else {
			rtxAcked = true
		}
		c.dropHead(r, now)
		c.recs.pop()
		c.recBase++
	}
	return sample, rtxAcked
}

// rttOnAck は ACK で RTT を測り、この ACK で測った RTT を返す(HyStart++ が使う。測らなければ -1)。timestamp
// があればその TSecr で、無ければ retireAcked の標本で測る。再送した記録を確認した ACK の標本は使わない。
func (c *tcb) rttOnAck(seg *segment, sample int64, rtxAcked bool, now int64) int64 {
	if c.tsOK && seg.opt.hasTS && seg.opt.tsEcr != 0 {
		return c.tsRTTSample(seg.opt.tsEcr, now)
	}
	if sample >= 0 && !rtxAcked {
		c.rttSample(sample)
		return sample
	}
	return -1
}

// cwndOnAck は累積の確認で輻輳の窓を進める。回復の中では回復の終わりか部分の確認を処理し、回復の外では
// slow start か輻輳の回避で窓を増やす。SND.UNA を ack に進めた後に呼ぶ。
func (c *tcb) cwndOnAck(seg *segment, ack, acked uint32, ackRTT, now int64) {
	mss := uint32(c.segMSS())
	flight := c.sndMax - c.sndUna
	if c.inRecovery {
		if seqGE(ack, c.recover) {
			// 回復の終わり。SACK では RFC 6937 の cwnd = ssthresh、SACK が無ければ RFC 6582 3.2 の 3
			c.inRecovery = false
			c.rackRecoveryDone()
			if c.sackOK {
				c.cwnd = c.ssthresh
			} else {
				c.cwnd = min(c.ssthresh, max(flight, mss)+mss)
			}
			if c.mayUndo(seg) {
				c.undo() // 回復の再送は不要だった(Linux の tcp_try_undo_recovery)
			}
			c.undoMarker = false
		} else if c.sackOK {
			// SACK による回復の部分の確認。再送は NextSeg が選び、窓は PRR が決める
			c.s.partialAcks.Add(1)
		} else {
			// 部分の確認(RFC 6582 3.2 の 5):次の穴を再送し、確認された分だけ窓を縮め、1 SMSS 以上を
			// 確認したら SMSS を足し戻す
			c.fastRtx = true
			c.rtxCause = rtxPartial
			c.s.partialAcks.Add(1)
			c.cwnd -= min(c.cwnd, acked)
			if acked >= mss {
				c.cwnd += mss
			}
			c.cwnd = max(c.cwnd, mss)
		}
	} else if !c.isCwndLimited() {
		// アプリケーションに制限された間は窓を増やさない(RFC 7661、Linux の tcp_is_cwnd_limited)
	} else if c.cwnd < c.ssthresh {
		c.slowStartAck(ack, acked, ackRTT, now)
	} else {
		c.ccFor().congAvoid(c, acked, now)
	}
	c.cwnd = min(c.cwnd, 1<<30)
}

// retransTimerOnAck は累積の確認の後に再送のタイマーを張り直す(RFC 6298 5.2、5.3)。窓の probe の間は
// 張り直さない。
func (c *tcb) retransTimerOnAck(now int64) {
	if c.persist {
		return
	}
	if c.sndUna == c.sndMax {
		c.clearRetransTimers()
	} else {
		c.setRTO(now + c.curRTO())
		c.renegeTimer(now)
	}
}

// finAckedState は自分の FIN が確認されたときの状態の遷移を行う。
func (c *tcb) finAckedState(now int64) {
	if !c.finAcked() {
		return
	}
	switch c.state {
	case stFinWait1:
		c.state = stFinWait2
	case stClosing:
		c.enterTimeWait(now)
	case stLastAck:
		c.toClosed(nil)
	}
}

// dupAck は重複した ACK を処理する(RFC 5681 3.2、RFC 6582)。
func (c *tcb) dupAck(now int64) {
	c.s.dupAcksIn.Add(1)
	c.dupAcks++
	if c.sackOK {
		return // 回復に入るかは sackAfterAck が決める
	}
	mss := uint32(c.segMSS())
	if c.inRecovery {
		c.cwnd += mss
		return
	}
	if c.dupAcks == 3 && seqGT(c.sndUna, c.recover) {
		c.enterFastRecovery()
		c.cwnd = c.ssthresh + 3*mss
		c.fastRtx = true
		c.rtxCause = rtxFast
	}
}
