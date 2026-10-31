package wgstack

import "syscall"

// 接続の枠のタイマーの期限(設計文書の「タイマー」)。再送、窓の probe、遅延 ACK、閉じた後の期限を処理する。
// 再送の節を分け合う RTO、並べ替え、TLP の期限の張り方は rack.go にある。

// curRTO は今の後退を含めた RTO。
func (c *tcb) curRTO() int64 {
	r := c.rto
	for range c.backoff {
		r *= 2
		if r >= int64(rtoMax) {
			return int64(rtoMax)
		}
	}
	return r
}

// enterPersist は再送のタイマーの節を窓の probe に使い始める。RTO、並べ替え、TLP の期限と TLP の probe の
// 印を消す。確認を待つものが無いので、前の RTO の起点と後退を持ち越さない。持ち越すと、相手が probe に
// 応え続けた長い persist の後の最初の RTO で、再送の打ち切りの時間を過ぎたと数える。
func (c *tcb) enterPersist(now int64) {
	c.clearRetransTimers()
	c.cancelTLP()
	c.persist = true
	c.retransStart = 0
	c.backoff = 0
	c.arm(tmrRetrans, now+c.curRTO())
}

// leavePersist は窓の probe を終え、確認を待つデータがあれば RTO を今から張る。再送のタイマーの節の古い
// 期限を消すかは呼び出し側が決める。
func (c *tcb) leavePersist(now int64) {
	c.persist = false
	c.backoff = 0
	if c.sndUna != c.sndMax {
		c.setRTO(now + c.curRTO())
	}
}

// onTimer はタイマーの節 kind の期限を処理する。
func (c *tcb) onTimer(kind int, now int64) {
	switch kind {
	case tmrRetrans:
		if c.persist {
			c.onPersist(now)
		} else {
			c.onRetransTimer(now)
		}
	case tmrDelack:
		if !c.ackNow {
			c.ackDelayed = true
		}
		c.ackNow = true
		c.pingpong = false // Linux の tcp_delack_timer_handler と同じく対話の印を外す
	case tmrClose:
		switch c.state {
		case stTimeWait, stFinWait2:
			c.toClosed(nil)
		}
	}
	c.afterInput(now)
}

// onRTO は再送のタイマーの期限(RFC 6298 5.4 から 5.7、RFC 5681 3.1)。
func (c *tcb) onRTO(now int64) {
	if c.sndUna == c.sndMax || c.state == stClosed {
		return
	}
	if c.retransStart == 0 {
		c.retransStart = now - c.curRTO()
	}
	if now-c.retransStart >= int64(retransmitDeadline) {
		c.s.rtxAborted.Add(1)
		c.sendRST()
		c.abortWith(syscall.ETIMEDOUT)
		return
	}
	c.s.rtos.Add(1)
	if c.backoff > 0 {
		c.s.rtosBackedOff.Add(1)
	}
	if !c.inRecovery && c.dupAcks > 0 && c.dupAcks < 3 {
		c.s.rtosShortOfDupThresh.Add(1)
	}
	// SACK の取り消し:先頭の記録が SACK 済みのままか、同じ SND.UNA で 2 回目の RTO なら、相手が SACK 済みの
	// データを捨てたとみなす(Linux の tcp_timeout_mark_lost と wgstack-performance.md の「scoreboard の記録の扱い」)
	reneged := false
	if c.sackOK && (c.backoff > 0 || (c.recs.n > 0 && c.isSacked(c.recs.at(0)))) && c.sacked > 0 {
		c.clearSACK()
		reneged = true
	}
	mss := uint32(c.segMSS())
	frto := c.frtoEligible() && !reneged // 取り消した SACK の記録は損失にして送り直す
	if c.backoff == 0 {
		// 最初の RTO が輻輳の事象として ssthresh を下げる。続く RTO は ssthresh を下げ直さず、F-RTO を終える
		if !c.inRecovery {
			c.initUndo()
		}
		c.ssthresh = c.lossThresh()
	} else {
		c.frto = 0
	}
	c.fastRtx = false // RTO の規則が SND.UNA から送り直すので、待っている高速の再送で先頭を 2 度送らない
	c.ccFor().onRTO(c)
	c.cwnd = mss
	c.recover = c.sndMax
	c.inRecovery = false
	c.dupAcks = 0
	c.backoff++
	// 記録は消さずに残し、SACK 済みでない記録を損失にして SND.UNA から順に送り直す(RFC 6675 5.1 節)。F-RTO では
	// 先頭の記録だけを損失にして、次の ACK で RTO が不要だったかを決める(RFC 5682)
	c.rtoEpisode = true
	if frto {
		c.frto = 1
		c.markHeadLost(rtxRTO)
	} else {
		c.markAllLost(rtxRTO)
	}
	c.reoAt, c.tlpAt = 0, 0
	c.cancelTLP()
	c.setRTO(now + c.curRTO())
	if c.s.trace != nil {
		c.traceEvent(TraceRTO, now)
	}
}

// onPersist は窓の probe のタイマーの期限。相手が probe に応える間は打ち切らない。
func (c *tcb) onPersist(now int64) {
	if c.sndWnd != 0 || !c.hasUnsent() {
		c.leavePersist(now)
		return
	}
	c.probesOut++
	// アプリケーションが閉じた接続は、Linux の tcp_probe_timer と同じく、相手が応えても戻らない後退の回数が
	// orphanRetries 以上で、後退を含めた RTO が上限に届いた(生きていない)ときに打ち切る。閉じた接続の FIN は
	// 窓が開くまで送らないので、打ち切らなければ窓を 0 のまま probe に応える相手が枠をいつまでも持たせる
	if c.probesOut > probeRetries || (c.appClosed && c.backoff >= orphanRetries && c.curRTO() >= int64(rtoMax)) {
		c.s.probeAborted.Add(1)
		c.sendRST()
		c.abortWith(syscall.ETIMEDOUT)
		return
	}
	c.probePending = true
	c.backoff++
	c.arm(tmrRetrans, now+c.curRTO())
}
