package wgstack

import "time"

// 接続の枠の入力。接続の枠に当たった segment の受け入れの判定(RFC 9293、RFC 7323 の PAWS、RFC 5961)、中身と FIN の
// 受け入れ、TIME_WAIT の枠の入力、PMTU の引き下げ。ACK の欄の処理は ack.go にある。

// acceptable は RFC 9293 3.10.7.4 の segment の受け入れの判定。窓が 0 のときは、番号が RCV.NXT と一致する
// segment を ACK と RST のために受け入れ、中身は後で窓の外として捨てる。
func (c *tcb) acceptable(seg *segment) bool {
	wnd := c.rcvWindow()
	n := seg.seqLen()
	in := func(x uint32) bool { return seqGE(x, c.rcvNxt) && seqLT(x, c.rcvNxt+wnd) }
	switch {
	case wnd == 0:
		return seg.seq == c.rcvNxt
	case n == 0:
		return in(seg.seq)
	default:
		return in(seg.seq) || in(seg.seq+n-1)
	}
}

// oowAck は受け入れられない segment に ACK を返す。Linux の tcp_oow_rate_limited と同じく、中身のある
// segment には制限なく返し、中身の無い segment には接続ごとに 500 ms に 1 回まで返す。
func (c *tcb) oowAck(seg *segment, now int64) {
	if len(seg.payload) == 0 || seg.has(flagSYN) {
		if c.lastOOW != 0 && now-c.lastOOW < int64(500*time.Millisecond) {
			return
		}
		c.lastOOW = now
	}
	// RCV.NXT より前にある重複の部分は、範囲を D-SACK で知らせる(RFC 2883、Linux の tcp_dsack_set)
	if n := uint32(len(seg.payload)); n > 0 && !seg.has(flagSYN) && seqLT(seg.seq, c.rcvNxt) {
		c.noteDuplicate(seg.seq, seqMin(seg.seq+n, c.rcvNxt)-seg.seq, now)
	}
	c.ackNow = true
}

// challengeAck は RFC 5961 の challenge ACK を、Device 全体の速さの制限の内側で送る。
func (c *tcb) challengeAck(now int64) {
	if c.s.challengeAllowed(now) {
		c.ackNow = true
	}
}

// input は接続の枠への segment を処理する。mu を持って呼ぶ。真を返したら、呼び出し側は segment を
// もう一度表から引く(TIME_WAIT の接続が RFC 6191 の SYN を受けて CLOSED になった)。そのとき reuse に
// 前の接続の SND.NXT を書く。
func (c *tcb) input(seg *segment, now int64, reuse *reuseISS) bool {
	if c.state == stTimeWait {
		again := c.timeWaitInput(seg, now, reuse)
		c.afterInput(now)
		return again
	}
	// PAWS(RFC 7323 5.3)。24 日を超えて TS.Recent を更新していなければ、相手の時計が一周しうるので
	// TS.Recent を古いとみなして比べない(RFC 7323 5.5)
	if c.tsOK && seg.opt.hasTS && !seg.has(flagRST) && seqLT(seg.opt.tsVal, c.tsRecent) && now-c.tsRecentAt <= int64(pawsIdle) {
		c.oowAck(seg, now)
		c.afterInput(now)
		return false
	}
	if !c.acceptable(seg) {
		if !seg.has(flagRST) {
			if seg.has(flagSYN) {
				c.challengeAck(now)
			} else {
				c.oowAck(seg, now)
			}
		}
		c.afterInput(now)
		return false
	}
	// RST(RFC 5961 3.2)
	if seg.has(flagRST) {
		if seg.seq == c.rcvNxt {
			c.resetByPeer()
			return false
		}
		c.challengeAck(now)
		c.afterInput(now)
		return false
	}
	// 確立した後の SYN(RFC 5961 4.2)
	if seg.has(flagSYN) {
		c.challengeAck(now)
		c.afterInput(now)
		return false
	}
	if !seg.has(flagACK) {
		return false
	}
	// ACK の受け入れの範囲(RFC 5961 5.2)
	if seqGT(seg.ack, c.sndMax) || seqLT(seg.ack, c.sndUna-c.maxSndWnd) {
		c.challengeAck(now)
		c.afterInput(now)
		return false
	}
	// TS.Recent の更新(RFC 7323 4.3)
	if c.tsOK && seg.opt.hasTS && seqLE(seg.seq, c.lastAckSent) {
		c.tsRecent, c.tsRecentAt = seg.opt.tsVal, now
	}
	c.processAck(seg, now)
	if c.state == stFree || c.state == stClosed {
		return false
	}
	c.inputData(seg, now)
	c.afterInput(now)
	return false
}

// timeWaitInput は枠に残る TIME_WAIT の接続への segment を処理する。
func (c *tcb) timeWaitInput(seg *segment, now int64, reuse *reuseISS) bool {
	if seg.has(flagRST) {
		if seg.seq == c.rcvNxt {
			c.toClosed(nil)
		}
		return false
	}
	if seg.has(flagSYN) {
		if !seg.has(flagACK) && rfc6191(seg, c.tsOK, c.tsRecent, c.rcvNxt) {
			s := c.s
			s.tmu.Lock()
			verdict := s.reuseVerdict(seg)
			if verdict == reuseFull {
				s.refuseReuse(now)
			}
			s.tmu.Unlock()
			switch verdict {
			case reuseNoListener:
				c.challengeAck(now) // Linux と同じく TIME_WAIT の ACK を返す
				return false
			case reuseFull:
				return false // 枠の TIME_WAIT を保ち、相手の SYN の再送を待つ
			}
			// 接続は CLOSED になり、アプリケーションはそれまでのデータと io.EOF を読める
			*reuse = reuseISS{ok: true, sndNxt: c.sndMax}
			c.toClosed(nil)
			return true
		}
		c.challengeAck(now)
		return false
	}
	if seg.has(flagFIN) && seg.seq+uint32(len(seg.payload))+1 == c.rcvNxt {
		c.ackNow = true
		c.twEnter = now
		c.arm(tmrClose, now+int64(twTimeout))
		return false
	}
	if seg.seqLen() > 0 || seg.seq != c.rcvNxt {
		c.oowAck(seg, now)
	}
	return false
}

// inputData は segment の中身と FIN を受信のバッファに入れ、ACK の送り方を決める。
func (c *tcb) inputData(seg *segment, now int64) {
	n := len(seg.payload)
	if n == 0 && !seg.has(flagFIN) {
		return
	}
	switch c.state {
	case stEstablished, stFinWait1, stFinWait2:
	default:
		// 相手の FIN の後に届いた segment。重複なら ACK を返す
		if seg.seqLen() > 0 {
			c.ackNow = true
		}
		return
	}
	if c.appClosed && n > 0 && seqGT(seg.seq+uint32(n), c.rcvNxt) {
		// 閉じた後に届いたデータ。Linux と同じく RST で終える
		c.sendRST()
		c.release()
		return
	}
	base := c.irs + 1
	off := int64(c.rcv.nxtOff) + int64(int32(seg.seq-(base+uint32(c.rcv.nxtOff))))
	if off < 0 {
		return
	}
	limit := min(c.advRight, c.rcv.readOff+c.rcvCap)
	res := c.rcv.insert(uint64(off), seg.payload, limit)
	if res.dupHi > res.dupLo {
		c.noteDuplicate(base+uint32(res.dupLo), uint32(res.dupHi-res.dupLo), now)
	}
	if res.dropped {
		c.s.refused(&c.s.oooDropped, &c.s.oooGate, now, "dropped out-of-order segments that would need more than the fixed number of receive intervals")
	}
	if res.trimmed {
		c.s.rcvTrimmed.Add(1)
	}
	if res.accepted > 0 {
		c.signalRead()
		c.rcvGrow(res.accepted, res.ooo)
		c.rcvRTTStamp(seg, n, now)
		c.rcvRTTWindow(now)
	}
	if seg.has(flagFIN) && !res.trimmed && !res.dropped {
		finOff := uint64(off) + uint64(n)
		if finOff == c.rcv.nxtOff {
			c.finRecv(now)
		} else if finOff > c.rcv.nxtOff {
			c.oooFin, c.oooFinOff = true, finOff
		}
	}
	if c.oooFin && !c.finRcvd && c.rcv.nxtOff == c.oooFinOff {
		c.finRecv(now)
	}
	if !c.finRcvd {
		c.rcvNxt = base + uint32(c.rcv.nxtOff)
	}
	switch {
	case res.ooo || res.dropped || res.trimmed || res.duplicate || res.filled || c.rcv.n > 0:
		c.ackNow = true
	case res.advanced:
		c.rcvSinceAck += res.accepted
		c.measureRcvMSS(n)
		c.noteQuickack(now)
		// 推定した相手の MSS より多くの byte を確認していなければ ACK を遅らせる(Linux の __tcp_ack_snd_check)
		if c.rcvSinceAck > int(c.rcvMSSEst) || (c.quickAcks > 0 && !c.pingpong) {
			c.ackNow = true
		} else if c.tdl[tmrDelack] == 0 {
			c.arm(tmrDelack, now+int64(delackTimeout))
		}
	}
	if res.accepted > 0 {
		c.lastDataRcvd, c.rcvdData = now, true
	}
}

// finRecv は相手の FIN を順序どおりに受けた後の遷移を行う。
func (c *tcb) finRecv(now int64) {
	c.finRcvd = true
	c.oooFin = false
	c.rcvNxt = c.irs + 1 + uint32(c.rcv.nxtOff) + 1
	c.ackNow = true
	switch c.state {
	case stEstablished:
		c.state = stCloseWait
	case stFinWait1:
		if c.finAcked() {
			c.enterTimeWait(now)
		} else {
			c.state = stClosing
		}
	case stFinWait2:
		c.enterTimeWait(now)
	}
	c.signalRead()
}

func (c *tcb) enterTimeWait(now int64) {
	c.state = stTimeWait
	c.twEnter = now
	c.persist = false
	c.clearRetransTimers()
	// TIME_WAIT の接続は ACK だけを送る。送り残しの probe と再送の印を残すと、build が何も作らないのに
	// wantOutput が送るものがあると答え続ける
	c.cancelSends()
	c.arm(tmrClose, now+int64(twTimeout))
}

// pmtuDrop は Fragmentation Needed による PMTU の引き下げ(RFC 1191)。引用された番号が SND.UNA から
// SND.NXT の範囲にあるときだけ受け入れる(RFC 5927)。送り残しは小さな segment で送り直す。SND.NXT は
// 再送で戻さないので、いつも SND.MAX と等しい。
func (c *tcb) pmtuDrop(seq uint32, mtu int, now int64) {
	if !seqGE(seq, c.sndUna) || !seqLT(seq, c.sndNxt) {
		c.s.icmpDropped.Add(1)
		return
	}
	if mtu >= c.pmtu {
		return
	}
	c.pmtu = mtu
	if c.sndMax != c.sndUna {
		// 記録の境目は保ち、新しい大きさに入らない記録だけを損失にして送り直す(Linux の
		// tcp_simple_retransmit と同じ)。入る記録は届いているかもしれないので、損失の印を付けない。SACK の
		// 無い接続は記録の印を使わないので、今までどおり SND.UNA から送り直す
		c.fastRtx = false
		if c.sackOK {
			c.markLostLonger(c.segMSS(), rtxPMTU)
			c.advanceLoss() // 小さくなった MSS で DupThresh の byte の規則を数え直す
		} else {
			c.markAllLost(rtxPMTU)
		}
	}
	c.afterInput(now)
}
