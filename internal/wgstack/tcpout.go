package wgstack

// 接続の枠の出力。接続は packet を待ち行列に積まず、Read の時に poll が今の状態から segment を 1 つ作る
// (設計文書の「出力」)。再送は送信の輪から segment を作り直す。

// poll は接続の組から取り出した枠の segment を 1 つ作る。まだ送るものがあれば list の末尾に入れ直す。
func (c *tcb) poll(b []byte, now int64) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == stFree || c.state == stClosed {
		return 0
	}
	n := c.build(b, now)
	// 何も作らなかった項目は入れ直さない。入れ直すと stack.poll が同じ項目を回り続ける。送るものが後で
	// できれば、入力、タイマー、書き込みが入れ直す
	if n > 0 && c.wantOutput() {
		c.s.out.queueConn(c.id)
	}
	return n
}

// wantOutput は今送るものがあるかを返す。
func (c *tcb) wantOutput() bool {
	switch c.state {
	case stFree, stClosed:
		return false
	}
	if c.state == stTimeWait {
		return c.ackNow // TIME_WAIT の接続は ACK だけを送る(build と同じ)
	}
	if c.fastRtx || c.probePending || c.ackNow || c.tlpProbe {
		return true
	}
	o := c.options(0, false)
	pc := c.payloadCap(&o, c.pmtu)
	if p := c.pickRule1(); p.i >= 0 && c.resendAllowed(p, pc, false) {
		return true
	}
	if n, fin := c.nextNew(pc, false); n > 0 || fin {
		return true
	}
	p := c.pickRule3()
	return p.i >= 0 && c.resendAllowed(p, pc, false)
}

// options は segment の option を作る。sack が真なら、順序外の区間があるときに SACK の block を足す。
func (c *tcb) options(now int64, sack bool) optWriter {
	var o optWriter
	if c.tsOK {
		o.ts(tsClock(now)+c.tsOffset, c.tsRecent)
	}
	if sack && c.sackOK && (c.rcv.n > 0 || c.dsackPending) {
		var blocks [4]sackBlock
		bs := blocks[:0]
		if c.dsackPending {
			bs = append(bs, c.dsack) // D-SACK は先頭の block(RFC 2883)
		}
		bs = append(bs, c.rcv.sackBlocks(blocks[len(bs):], c.irs+1)...)
		o.sack(bs)
	}
	o.pad()
	return o
}

// payloadCap は option o を付けた segment の中身の上限。space は packet の大きさの上限である。
func (c *tcb) payloadCap(o *optWriter, space int) int {
	return min(c.peerMSS, c.pmtu-ipHeaderLen-tcpHeaderLen, space-ipHeaderLen-tcpHeaderLen) - o.n
}

// windowField は広告する窓の欄を返し、広告した右端を更新する。右端は後ろへ戻さない。右端を広げるのは、
// 広げる量が min(容量の半分, MSS) 以上のときだけである(受け手の SWS の回避、RFC 9293 3.8.6.2.2)。
// 窓の scale で切り捨てた分だけ欄の右端が論理の右端より手前に見えることは scale の性質で、論理の右端の
// 手前までのデータは受け入れる。
func (c *tcb) windowField() uint16 {
	nxt := c.rcv.nxtOff
	target := min(c.rcv.readOff+c.rcvCap, nxt+uint64(65535)<<c.rcvWscale)
	if target > c.advRight && target-c.advRight >= min(c.rcvCap/2, uint64(c.rcvMSS())) {
		c.advRight = target
	}
	if c.advRight <= nxt {
		return 0
	}
	return uint16(min((c.advRight-nxt)>>c.rcvWscale, 65535))
}

// nextNew は、窓と輻輳の窓と送り手の SWS の回避(RFC 9293 3.8.6.2.1、Nagle を使わない)が許す新しいデータの
// 長さと、FIN を付けるかを返す。force が真なら輻輳の窓を見ない(TLP の probe、RFC 8985 7.3)。
func (c *tcb) nextNew(payCap int, force bool) (int, bool) {
	if payCap <= 0 || c.recs.full() {
		return 0, false
	}
	var avail uint32
	if end := c.dataEndSeq(); seqLT(c.sndNxt, end) {
		avail = end - c.sndNxt
	}
	finPending := c.sndShut && seqLE(c.sndNxt, c.finSeq())
	inflight := c.sndNxt - c.sndUna
	pipe := c.pipe()
	var usable, room uint32
	if c.sndWnd > inflight {
		usable = c.sndWnd - inflight
	}
	if c.cwnd > pipe {
		room = c.cwnd - pipe
	}
	if force || (c.frto == 2 && c.frtoNew > 0) {
		room = ^uint32(0) // TLP の probe と F-RTO の 2 の段(RFC 5682 2b)
	}
	if avail == 0 {
		// FIN は番号を 1 つ使うので、Linux と同じく窓に 1 byte の余地があるときだけ送る。窓が 0 の間は
		// 窓の probe を続ける。RFC 9293 の受け入れの判定では、窓が 0 の受け手は長さ 1 の segment を捨てる
		return 0, finPending && usable > 0
	}
	if c.persist && c.sndWnd == 0 {
		return 0, false
	}
	want := min(avail, uint32(payCap))
	if room < want && pipe > 0 {
		c.cwndBlocked = true // 送るデータがあるのに輻輳の窓が止めた
		return 0, false
	}
	n := min(want, usable)
	switch {
	case n == 0:
		return 0, false
	case n == want, n >= c.maxSndWnd/2, inflight == 0:
		// 中身の後ろに FIN を付けるのは、FIN の 1 も窓に入るときだけ
		return int(n), finPending && n == avail && n < usable
	}
	return 0, false
}

// build は送るものの優先の順(高速の再送、窓の probe、新しいデータと FIN、ACK)に segment を 1 つ作る。
func (c *tcb) build(b []byte, now int64) int {
	space := min(len(b), c.pmtu)
	if space < ipHeaderLen+tcpHeaderLen+maxOptionLen {
		return 0
	}
	if c.fastRtx {
		c.fastRtx = false
		if n := c.buildRtx(b, space, now); n > 0 {
			return n
		}
	}
	if c.probePending {
		c.probePending = false
		return c.buildBare(b, c.sndUna-1, now)
	}
	if c.state != stTimeWait {
		if c.tlpProbe {
			c.tlpProbe = false
			if n := c.buildTLP(b, space, now); n > 0 {
				return n
			}
		}
		if n := c.buildResend(b, space, now, c.pickRule1(), false); n > 0 {
			return n
		}
		if n := c.buildNew(b, space, now, false); n > 0 {
			return n
		}
		if n := c.buildResend(b, space, now, c.pickRule3(), false); n > 0 {
			return n
		}
	}
	if c.ackNow {
		return c.buildBare(b, c.sndNxt, now)
	}
	return 0
}

// emit は header と option を書き、送信の輪の offset off から n byte を中身にして packet を作る。
func (c *tcb) emit(b []byte, seq uint32, flags uint8, o *optWriter, off uint64, n int, now int64) int {
	if n > 0 && (off < c.unaOff || off+uint64(n) > c.tailOff) {
		// 送信の輪の生きている範囲の外を読もうとした:会計の不整合なので接続を閉じる
		c.accountingFault(now)
		return 0
	}
	h := tcpHeader{tup: c.tup, seq: seq, ack: c.rcvNxt, flags: flags | flagACK, wnd: c.windowField()}
	p := writeTCP(b, c.s.nextID(), h, o, n)
	if n > 0 {
		c.snd.read(off, b[p:p+n])
	}
	c.ackSent()
	return finishTCP(b)
}

// ackSent は ACK を運ぶ segment を送った後の状態を整える。
func (c *tcb) ackSent() {
	if c.ackNow {
		if c.ackDelayed {
			c.s.acksDelayed.Add(1)
		} else {
			c.s.acksImmediate.Add(1)
		}
	}
	if c.quickAcks > 0 && c.ackNow && !c.ackDelayed {
		c.quickAcks--
	}
	c.ackDelayed = false
	c.ackNow = false
	c.ackPushed = false
	c.dsackPending = false
	c.rcvSinceAck = 0
	c.disarm(tmrDelack)
	c.lastAckSent = c.rcvNxt
}

// buildBare は中身の無い ACK を作る。窓の probe は seq に SND.UNA - 1 を渡す(Linux と同じ)。
func (c *tcb) buildBare(b []byte, seq uint32, now int64) int {
	o := c.options(now, true)
	return c.emit(b, seq, 0, &o, 0, 0, now)
}

// buildNew は SND.MAX から新しいデータを segment にする(RFC 6675 の NextSeg の規則 2)。force は nextNew と同じ。
func (c *tcb) buildNew(b []byte, space int, now int64, force bool) int {
	// 黙った後の輻輳の窓(RFC 5681 4.1)
	if c.sndUna == c.sndMax {
		if now-c.lastSendAt > c.curRTO() {
			c.cwnd = min(c.cwnd, uint32(initialWindowSegs*c.segMSS()))
		}
		c.ccFor().onIdle(c, now-c.lastSendAt, now)
	}
	o := c.options(now, true)
	c.cwndBlocked = false
	n, fin := c.nextNew(c.payloadCap(&o, space), force)
	if n == 0 && !fin {
		if c.cwndBlocked {
			c.noteCwndUse(true)
		}
		return 0
	}
	seq := c.sndNxt
	flags := uint8(0)
	if n > 0 && seq+uint32(n) == c.dataEndSeq() {
		flags |= flagPSH
	}
	if fin {
		flags |= flagFIN
	}
	off := c.unaOff + uint64(seq-c.sndUna)
	length := n
	if fin {
		length++
		c.finSent = true
	}
	if c.inRecovery {
		c.prrOut += uint32(length)
	}
	if n > 0 && c.rcvdData && now-c.lastDataRcvd < int64(delackTimeout) {
		c.pingpong = true // 受けた直後に応える対話の流れ(Linux の tcp_event_data_sent)
	}
	if c.frto == 2 && c.frtoNew > 0 {
		c.frtoNew--
	}
	c.recs.push(record{seq: seq, length: uint16(length), sentAt: now, skip: 1, rtxGen: c.rtxGen})
	c.listAppend(&c.tList, c.recs.n-1, c.recs.at(c.recs.n-1), recInT)
	c.sndNxt = seq + uint32(length)
	c.sndMax = seqMax(c.sndMax, c.sndNxt)
	// 送った後の輻輳の窓に 1 segment の余地が無ければ、その窓は輻輳の窓に制限されている(Linux の tcp_write_xmit
	// が packet で数える tcp_packets_in_flight >= cwnd と同じ)
	c.noteCwndUse(c.pipe()+uint32(c.segMSS()) > c.cwnd)
	if c.rtoAt == 0 && !c.persist {
		c.rtoAt = now + c.curRTO()
	}
	if !force {
		c.scheduleTLP(now) // 新しいデータの後に PTO を張り直す(RFC 8985 7.2)
	}
	c.rearmRetrans()
	c.lastSendAt = now
	return c.emit(b, seq, flags, &o, off, n, now)
}

// resendAllowed は選んだ記録の再送を窓と輻輳の窓が許すかを返す。payCap は segment の中身の上限である。
// force が真なら輻輳の窓を見ない(TLP の probe)。
func (c *tcb) resendAllowed(p resendPick, payCap int, force bool) bool {
	i := p.i
	n, fin := c.resendLen(i, c.pickOff(p), payCap)
	if n == 0 && !fin {
		return false
	}
	if fin {
		n++
	}
	// 窓の外から始まる記録は送らない。先頭の記録は窓の probe を兼ねて送る(Linux の tcp_retransmit_skb)。
	// 窓の probe を張っている間は送らない
	seq := c.recs.at(i).seq + c.pickOff(p)
	if c.persist || (seq != c.sndUna && !seqLT(seq, c.sndUna+c.sndWnd)) {
		return false
	}
	pipe := c.pipe()
	// F-RTO の RTO の後の先頭の再送は輻輳の窓によらず送る(RFC 5682 の 1 の段)。ほかの記録はまだ送り残しに数える
	return force || pipe == 0 || c.cwnd >= pipe+n || (c.frto == 1 && i == 0)
}

// buildResend は記録 i(NextSeg の規則 1 か 3 が選んだ記録)を再送する。記録は SND.UNA から番号の順に
// 選ばれ、SACK 済みの記録は飛ばす。新しい segment の大きさを超える記録は複数の segment に分けて送り、
// 記録は分けない。
func (c *tcb) buildResend(b []byte, space int, now int64, p resendPick, force bool) int {
	i := p.i
	if i < 0 {
		return 0
	}
	o := c.options(now, true)
	pc := c.payloadCap(&o, space)
	if !c.resendAllowed(p, pc, force) {
		return 0
	}
	off := c.pickOff(p)
	n, fin := c.resendLen(i, off, pc)
	if n == 0 && !fin {
		return 0
	}
	r := c.recs.at(i)
	seq := r.seq + off
	if !c.sendRangeOK(seq, n) {
		c.accountingFault(now)
		return 0
	}
	length := n
	flags := uint8(0)
	if fin {
		flags |= flagFIN
		length++
	}
	c.adoptGen(r)
	if !c.rtxLive(r) {
		r.flags |= recRtx
		c.rtxBytes += uint32(r.length)
	}
	r.flags |= recRetransmitted
	r.sentAt = now
	// 再送した記録は送った時刻の順の list の末尾へ移す(RFC 8985)。記録の節は 1 つの list にしか使えないので、
	// 損失の待ち行列から外してから足す。待ち行列の記録を分けて送る間は、送り終えるまで待ち行列に残す
	toT := true
	switch p.src {
	case srcPos:
		c.rxtOff += length
		c.rxtMid = c.rxtOff < uint32(r.length)
		if !c.rxtMid {
			c.rxtIdx++
			c.rxtOff = 0
		}
	case srcQueue:
		c.qOff += length
		c.qMid = c.qOff < uint32(r.length)
		toT = !c.qMid
		if !c.qMid {
			c.qOff = 0
		}
	}
	if toT {
		if c.genFlag(r, recInQ) {
			if c.lostQ.head == c.recAbs(i) {
				c.qOff, c.qMid = 0, false
			}
			c.listRemove(&c.lostQ, i, r, recInQ)
		}
		if c.genFlag(r, recInT) {
			c.listRemove(&c.tList, i, r, recInT)
		}
		c.listAppend(&c.tList, i, r, recInT)
	}
	if c.inRecovery {
		c.prrOut += length
	}
	cause := c.resendCause
	if p.src == srcTLP {
		cause = rtxTLP
	}
	c.noteRetransmit(now)
	c.s.retrans[cause].Add(1)
	if (c.rtoAt == 0 || i == 0) && !c.persist {
		// 先頭の記録を送り直したら RTO を張り直す(Linux の tcp_xmit_retransmit_queue)。張り直さないと、回復の
		// 途中で先頭を再送した直後に、前の累積の確認から数えた RTO が起きる
		c.setRTO(now + c.curRTO())
	}
	c.lastSendAt = now
	return c.emit(b, seq, flags, &o, c.unaOff+uint64(seq-c.sndUna), int(n), now)
}

// buildTLP は TLP の probe を 1 つ送る(RFC 8985 7.3)。窓が許せば新しいデータを、許さなければ最も番号の
// 大きい記録を送る。どちらも輻輳の窓を見ない。probe の確認を待つ間は次の probe を張らない(I5)。probe の後は
// RTO を張り直す。
func (c *tcb) buildTLP(b []byte, space int, now int64) int {
	retrans := false
	n := c.buildNew(b, space, now, true)
	if n == 0 {
		i := c.recs.n - 1
		if i < 0 || c.isSacked(c.recs.at(i)) {
			return 0
		}
		n = c.buildResend(b, space, now, resendPick{i, srcTLP}, true)
		retrans = true
	}
	if n > 0 {
		c.tlpActive, c.tlpRetrans, c.tlpEnd = true, retrans, c.sndMax
		c.tlpAt = 0
		c.s.tlpProbes.Add(1)
		// probe の後は RTO を今から張り直す(RFC 8985 7.3、Linux の tcp_send_loss_probe)。前の累積の確認から
		// 数えた期限のままだと、SRTT が RTO の 3 分の 1 を超える経路では probe の確認が届く前に RTO が起きる
		c.setRTO(now + c.curRTO())
	}
	return n
}

// buildRtx は SND.UNA からの 1 segment を再送する(SACK を交渉しない接続の高速の再送と NewReno の部分の確認)。
func (c *tcb) buildRtx(b []byte, space int, now int64) int {
	if c.sndUna == c.sndMax {
		return 0
	}
	o := c.options(now, true)
	pc := c.payloadCap(&o, space)
	if pc <= 0 {
		return 0
	}
	// 送ったことのある範囲(SND.MAX まで)だけを送り直す。記録は SND.MAX まで隙間なく並ぶ
	seq := c.sndUna
	var left uint32
	if end := c.dataEndSeq(); seqLT(seq, end) {
		left = seqMin(end, c.sndMax) - seq
	}
	n := min(left, uint32(pc))
	fin := c.finSent && seq+n == c.dataEndSeq() && seqGT(c.sndMax, c.dataEndSeq())
	flags := uint8(0)
	if fin {
		flags |= flagFIN
	}
	length := n
	if fin {
		length++
	}
	// 再送する範囲に掛かる記録をすべて再送の印にする(Karn の規則)
	for i := 0; i < c.recs.n; i++ {
		r := c.recs.at(i)
		if !seqLT(r.seq, seq+length) {
			break
		}
		r.flags |= recRetransmitted
		r.sentAt = now
		if c.genFlag(r, recInT) {
			// 送った時刻の順を保つ
			c.listRemove(&c.tList, i, r, recInT)
			c.listAppend(&c.tList, i, r, recInT)
		}
	}
	c.lastSendAt = now
	c.s.retrans[c.rtxCause].Add(1)
	c.noteRetransmit(now)
	return c.emit(b, seq, flags, &o, c.unaOff, int(n), now)
}
