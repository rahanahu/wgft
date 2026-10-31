package wgstack

// 不要な再送の取り消し(wgstack-performance.md の「並べ替えと不要な再送」)。回復に入る時と回復の外の最初の RTO の
// 時に輻輳の窓と ssthresh を覚え、再送が不要だったと分かれば戻す(Linux の tcp_init_undo、tcp_may_undo、
// tcp_try_undo_recovery、tcp_try_undo_loss)。不要と分かる条件は、すべての再送が D-SACK で知らされたこと
// (RFC 3708)か、確認の TSecr が最初の再送の時刻より前であること(RFC 3522 の Eifel)である。

// initUndo は輻輳の窓を下げる前に呼び、今の窓と ssthresh と SND.UNA を覚える(Linux の tcp_init_undo)。
// undoRetrans の -1 は、まだ再送していないので数では取り消せないことを表す。
func (c *tcb) initUndo() {
	c.undoMarker, c.undoSeq = true, c.sndUna
	c.undoCwnd, c.undoSsthresh = c.cwnd, c.ssthresh
	c.undoRetrans, c.retransTSOK = -1, false
}

// noteRetransmit は再送するたびに呼ぶ。接続の再送の数と、印の後の最初の再送の時刻(自分の TSval)と再送の数を
// 数える。
func (c *tcb) noteRetransmit(now int64) {
	c.totalRetrans++
	if !c.undoMarker {
		return
	}
	if !c.retransTSOK && c.tsOK {
		c.retransTS, c.retransTSOK = tsClock(now)+c.tsOffset, true
	}
	c.undoRetrans = max(c.undoRetrans, 0) + 1
}

// dsackUndoWalk は SND.UNA より先の D-SACK の block で調べる記録の数の上限。ACK ごとの手間を定数に保つ。
const dsackUndoWalk = 4

// dsackSeen は先頭の block が D-SACK の ACK で、重複した segment の数を返す(Linux の tcp_dsack_seen)。
// 範囲が相手の窓の最大より広い block と、D-SACK の累計が再送の累計を超えた block は疑わしいので 0 を返す。
// tlp は block が TLP の probe の再送の D-SACK であること(Linux の FLAG_DSACK_TLP)。
func (c *tcb) dsackSeen(b sackBlock) (dup uint32, tlp bool) {
	l := b.right - b.left
	if l == 0 || l > c.maxSndWnd {
		return 0, false
	}
	mss := uint32(max(c.segMSS(), 1))
	dup = 1
	if l > mss {
		dup = (l + mss - 1) / mss
	} else if c.tlpRetrans && b.right == c.tlpEnd {
		tlp = true
	}
	c.dsackDups += dup
	if c.dsackDups > c.totalRetrans {
		return 0, false
	}
	return dup, tlp
}

// noteUndoDSACK は D-SACK で知らされた、印の後の再送を数から引く(Linux の tcp_check_dsack と
// tcp_sacktag_one)。priorUna はこの ACK の前の SND.UNA である。確認済みの範囲の block は、印より後に終わり
// priorUna までに終わるときだけ dup を数える。SND.UNA より先の block は、再送した記録を数える。TLP の probe の
// D-SACK は数えない。
func (c *tcb) noteUndoDSACK(b sackBlock, dup uint32, tlp bool) {
	if !c.undoMarker || c.undoRetrans <= 0 || dup == 0 || tlp {
		return
	}
	n := int32(0)
	switch {
	case seqLE(b.right, c.priorUna):
		if seqGT(b.right, c.undoSeq) {
			n = int32(dup)
		}
	case seqLT(b.left, c.sndUna):
		// 確認済みの範囲と記録の両方にかかる block:確認済みの側の記録は消えたので数えない
	default:
		for i, k := c.firstRecFrom(b.left), 0; i < c.recs.n && k < dsackUndoWalk; i, k = i+1, k+1 {
			r := c.recs.at(i)
			if seqGT(r.seq+uint32(r.length), b.right) {
				break
			}
			if r.flags&recRetransmitted != 0 && seqGE(r.seq, c.undoSeq) {
				n++
			}
		}
	}
	c.undoRetrans = max(c.undoRetrans-n, 0)
}

// packetDelayed は確認が元の segment への確認か(TSecr が最初の再送の時刻より前)を返す。
func (c *tcb) packetDelayed(seg *segment) bool {
	return c.retransTSOK && seg.opt.hasTS && seg.opt.tsEcr != 0 && int32(seg.opt.tsEcr-c.retransTS) < 0
}

// mayUndo は再送が不要だったと分かるかを返す(Linux の tcp_may_undo)。
func (c *tcb) mayUndo(seg *segment) bool {
	return c.undoMarker && (c.undoRetrans == 0 || c.packetDelayed(seg))
}

// undo は覚えた輻輳の窓と ssthresh に戻し、並べ替えを見たことにする(Linux の tcp_undo_cwnd_reduction、
// RFC 4015 の応答)。
func (c *tcb) undo() {
	c.cwnd = max(c.cwnd, c.undoCwnd)
	c.ssthresh = max(c.ssthresh, c.undoSsthresh)
	c.reorderSeen = true
	c.undoMarker = false
	c.frto, c.rtoEpisode = 0, false
	c.s.spuriousUndos.Add(1)
}

// rtoRecovered は RTO の後の回復が終わった ACK で、再送が不要だったと分かれば窓を戻し、F-RTO と取り消しの
// 印を終える(Linux の tcp_process_loss の recovered と tcp_try_undo_recovery)。
func (c *tcb) rtoRecovered(seg *segment) {
	if c.mayUndo(seg) {
		c.undo()
		c.s.spuriousRTOs.Add(1)
	}
	c.rtoEpisode, c.frto, c.undoMarker = false, 0, false
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
	c.clearRtx(r)
	if c.lossIdx == 0 {
		c.passLoss(r, c.isSacked(r))
	}
	c.unlinkRec(0, r)
	c.resetRxt()
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
			c.frto, c.frtoNew = 2, 2
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
