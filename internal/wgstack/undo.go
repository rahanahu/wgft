package wgstack

// 不要な再送の取り消し(wgstack-performance.md の「並べ替えと不要な再送」)。回復に入る時と回復の外の最初の RTO の
// 時に輻輳の窓と ssthresh を覚え、再送が不要だったと分かれば戻す(Linux の tcp_init_undo、tcp_may_undo、
// tcp_try_undo_recovery、tcp_try_undo_loss)。不要と分かる条件は、すべての再送が D-SACK で知らされたこと
// (RFC 3708)か、確認の TSecr が最初の再送の時刻より前であること(RFC 3522 の Eifel)である。

// initUndo は輻輳の窓を下げる前に呼び、今の窓と ssthresh を覚える。既に印があれば覚え直さない。
func (c *tcb) initUndo() {
	if c.undoMarker {
		return
	}
	c.undoMarker = true
	c.undoCwnd, c.undoSsthresh = c.cwnd, c.ssthresh
	c.undoRetrans, c.retransTSOK = 0, false
}

// noteRetransmit は再送するたびに呼ぶ。最初の再送の時刻(自分の TSval)と再送の数を数える。
func (c *tcb) noteRetransmit(now int64) {
	if !c.undoMarker {
		return
	}
	if !c.retransTSOK && c.tsOK {
		c.retransTS, c.retransTSOK = tsClock(now)+c.tsOffset, true
	}
	c.undoRetrans++
}

// noteUndoDSACK は D-SACK で知らされた再送を数から引く。
func (c *tcb) noteUndoDSACK() {
	if c.undoMarker && c.undoRetrans > 0 {
		c.undoRetrans--
	}
}

// packetDelayed は確認が元の segment への確認か(TSecr が最初の再送の時刻より前)を返す。
func (c *tcb) packetDelayed(seg *segment) bool {
	return c.retransTSOK && seg.opt.hasTS && seg.opt.tsEcr != 0 && int32(seg.opt.tsEcr-c.retransTS) < 0
}

// mayUndo は再送が不要だったと分かるかを返す(Linux の tcp_may_undo)。
func (c *tcb) mayUndo(seg *segment) bool {
	return c.undoMarker && (c.undoRetrans <= 0 || c.packetDelayed(seg))
}

// undo は覚えた輻輳の窓と ssthresh に戻し、並べ替えを見たことにする(Linux の tcp_undo_cwnd_reduction、
// RFC 4015 の応答)。
func (c *tcb) undo() {
	c.cwnd = max(c.cwnd, c.undoCwnd)
	c.ssthresh = max(c.ssthresh, c.undoSsthresh)
	c.reorderSeen = true
	c.undoMarker = false
	c.frto = 0
	c.s.spuriousUndos.Add(1)
}

// frtoEligible は RTO で F-RTO を使えるかを返す(RFC 5682 の SACK を使う形。回復の外の最初の RTO)。
func (c *tcb) frtoEligible() bool {
	return c.sackOK && c.backoff == 0 && !c.inRecovery && c.recs.n > 1
}

// markHeadLost は先頭の記録だけを損失にする(F-RTO の RTO)。
func (c *tcb) markHeadLost(cause uint8) {
	if c.recs.n == 0 {
		return
	}
	r := c.recs.at(0)
	if c.rtxLive(r) {
		r.flags &^= recRtx
		c.rtxBytes -= uint32(r.length)
	}
	if c.lossIdx == 0 {
		c.passLoss(r, c.isSacked(r))
	}
	if c.genFlag(r, recInT) {
		c.listRemove(&c.tList, 0, r, recInT)
	}
	if c.genFlag(r, recInQ) {
		if c.lostQ.head == c.recBase {
			c.qOff, c.qMid = 0, false
		}
		c.listRemove(&c.lostQ, 0, r, recInQ)
	}
	c.rxtIdx, c.rxtOff, c.rxtMid = 0, 0, false
	c.resendCause = cause
}

// frtoAfterAck は F-RTO の RTO の後の ACK を処理する(RFC 5682 3.1、Linux の tcp_process_loss)。advanced は
// ACK が SND.UNA を進めたか、dup は進めない重複の ACK か SACK で新しく届いたデータがあったか。
func (c *tcb) frtoAfterAck(seg *segment, advanced, dup bool) {
	switch {
	case c.origDelivered || (advanced && c.packetDelayed(seg)):
		// 再送していないデータが届いたか、元の segment への確認:RTO は不要だった
		c.undo()
		c.s.spuriousRTOs.Add(1)
		c.recover = c.sndUna
	case c.frto == 2:
		// 3 の段:新しいデータを送った後に、届いたのが再送だけなら損失は本物で、今の RTO の規則で送り直す
		c.frto = 0
		c.markAllLost(rtxRTO)
	case advanced:
		// 2 の段:新しいデータを 2 つまで輻輳の窓によらず送る。送るデータか窓が無ければ今の RTO の規則に戻る
		if c.hasNewData() {
			c.frto, c.frtoHigh, c.frtoNew = 2, c.sndMax, 2
		} else {
			c.frto = 0
			c.markAllLost(rtxRTO)
		}
	case dup:
		c.frto = 0
		c.markAllLost(rtxRTO)
	}
}

// hasNewData は未送信のデータがあり、相手の窓に余地があるかを返す。
func (c *tcb) hasNewData() bool {
	return seqLT(c.sndNxt, c.dataEndSeq()) && seqLT(c.sndNxt, c.sndUna+c.sndWnd)
}
