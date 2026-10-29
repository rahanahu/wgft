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
	if c.wantOutput() {
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
	if c.fastRtx || c.probePending || c.ackNow {
		return true
	}
	if c.state == stTimeWait {
		return false
	}
	o := c.options(0, false)
	n, fin := c.nextNew(c.payloadCap(&o, c.pmtu))
	return n > 0 || fin
}

// options は segment の option を作る。sack が真なら、順序外の区間があるときに SACK の block を足す。
func (c *tcb) options(now int64, sack bool) optWriter {
	var o optWriter
	if c.tsOK {
		o.ts(tsClock(now)+c.tsOffset, c.tsRecent)
	}
	if sack && c.sackOK && c.rcv.n > 0 {
		var blocks [4]sackBlock
		o.sack(c.rcv.sackBlocks(blocks[:], c.irs+1))
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
// 長さと、FIN を付けるかを返す。
func (c *tcb) nextNew(payCap int) (int, bool) {
	if payCap <= 0 || c.recs.full() {
		return 0, false
	}
	var avail uint32
	if end := c.dataEndSeq(); seqLT(c.sndNxt, end) {
		avail = end - c.sndNxt
	}
	finPending := c.sndShut && seqLE(c.sndNxt, c.finSeq())
	if avail == 0 {
		return 0, finPending // FIN だけの segment は窓によらず送る
	}
	if c.persist && c.sndWnd == 0 {
		return 0, false
	}
	inflight := c.sndNxt - c.sndUna
	var usable, room uint32
	if c.sndWnd > inflight {
		usable = c.sndWnd - inflight
	}
	if c.cwnd > inflight {
		room = c.cwnd - inflight
	}
	want := min(avail, uint32(payCap))
	if room < want && inflight > 0 {
		return 0, false
	}
	n := min(want, usable)
	switch {
	case n == 0:
		return 0, false
	case n == want, n >= c.maxSndWnd/2, inflight == 0:
		return int(n), finPending && n == avail
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
		if n := c.buildNew(b, space, now); n > 0 {
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
	c.ackNow = false
	c.rcvSinceAck = 0
	c.disarm(tmrDelack)
	c.lastAckSent = c.rcvNxt
}

// buildBare は中身の無い ACK を作る。窓の probe は seq に SND.UNA - 1 を渡す(Linux と同じ)。
func (c *tcb) buildBare(b []byte, seq uint32, now int64) int {
	o := c.options(now, true)
	return c.emit(b, seq, 0, &o, 0, 0, now)
}

// buildNew は新しいデータか、RTO の後に SND.NXT から送り直すデータを segment にする。
func (c *tcb) buildNew(b []byte, space int, now int64) int {
	// 黙った後の輻輳の窓(RFC 5681 4.1)
	if c.sndUna == c.sndMax && now-c.lastSendAt > c.curRTO() {
		c.cwnd = min(c.cwnd, uint32(initialWindowSegs*c.segMSS()))
	}
	o := c.options(now, true)
	n, fin := c.nextNew(c.payloadCap(&o, space))
	if n == 0 && !fin {
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
	rtx := seqLT(seq, c.sndMax)
	off := c.unaOff + uint64(seq-c.sndUna)
	length := n
	if fin {
		length++
		c.finSent = true
	}
	var rf uint8
	if rtx {
		rf = recRetransmitted
	}
	c.recs.push(record{seq: seq, length: uint16(length), sentAt: now, flags: rf, prev: -1, next: -1})
	c.sndNxt = seq + uint32(length)
	c.sndMax = seqMax(c.sndMax, c.sndNxt)
	if c.persist {
		// 窓が 0 の間に送った FIN は窓の probe ではなく再送のタイマーで守る
		c.persist = false
		c.backoff = 0
		c.disarm(tmrRetrans)
	}
	if c.tdl[tmrRetrans] == 0 {
		c.arm(tmrRetrans, now+c.curRTO())
	}
	c.lastSendAt = now
	return c.emit(b, seq, flags, &o, off, n, now)
}

// buildRtx は SND.UNA からの 1 segment を再送する(高速の再送と NewReno の部分の確認)。
func (c *tcb) buildRtx(b []byte, space int, now int64) int {
	if c.sndUna == c.sndMax {
		return 0
	}
	o := c.options(now, true)
	pc := c.payloadCap(&o, space)
	if pc <= 0 {
		return 0
	}
	seq := c.sndUna
	var left uint32
	if end := c.dataEndSeq(); seqLT(seq, end) {
		left = end - seq
	}
	n := min(left, uint32(pc))
	fin := c.finSent && n == left
	flags := uint8(0)
	if fin {
		flags |= flagFIN
	}
	length := n
	if fin {
		length++
	}
	if c.recs.n > 0 && c.recs.at(0).seq == seq {
		r := c.recs.at(0)
		r.flags |= recRetransmitted
		r.sentAt = now
	}
	if end := seq + length; seqLT(c.sndNxt, end) {
		c.sndNxt = end
	}
	c.lastSendAt = now
	return c.emit(b, seq, flags, &o, c.unaOff, int(n), now)
}
