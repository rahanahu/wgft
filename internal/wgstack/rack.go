package wgstack

import "time"

// RACK-TLP(RFC 8985、wgstack-performance.md の「RACK-TLP」)。
//
// 送り残しの記録は、次の 2 つの list のどちらかに入るか、どちらにも入らない。
//   - 送った時刻の順の list(tList):送って確認を待つ記録。新しく送った記録と再送した記録を末尾に足す
//   - 損失の待ち行列(lostQ):RACK が失われたとみなし、まだ送り直していない記録
//
// SACK 済みの記録と、損失の境目より手前で送り直しを待つ記録は、どちらの list にも入らない。list の節は
// 記録の prev と next で、自分の位置からの記録の数の差(0 は無し)で持つので、輪の大きさを変えても、
// 先頭の記録を外しても変わらない。list に入っている印(recInT、recInQ)と RACK の損失の印(recLost)は、
// recRtx と同じく記録の rtxGen が接続の世代と等しいときだけ有効で、RTO と PMTU の引き下げは世代を進めて
// list を一度に空にする。

// recList は記録の list。head と tail は記録の通し番号(recBase からの位置で記録を引く)。
type recList struct {
	head, tail uint32
	n          int32
}

const (
	tlpOneSegExtra = 200 * time.Millisecond // RFC 8985 7.2 の WCDelAckT
	tlpNoRTT       = time.Second            // RTT を測る前の PTO
)

func (c *tcb) recAbs(i int) uint32 { return c.recBase + uint32(i) }

func (c *tcb) recIdx(a uint32) int { return int(a - c.recBase) }

// adoptGen は記録 r の世代の印を今の世代に合わせる。古い世代の印はすべて消す。
func (c *tcb) adoptGen(r *record) {
	if r.rtxGen != c.rtxGen {
		r.flags &^= recRtx | recInT | recInQ | recLost
		r.rtxGen = c.rtxGen
	}
}

func (c *tcb) genFlag(r *record, f uint8) bool { return r.flags&f != 0 && r.rtxGen == c.rtxGen }

func (c *tcb) listAppend(l *recList, i int, r *record, flag uint8) {
	c.adoptGen(r)
	r.flags |= flag
	a := c.recAbs(i)
	r.next = 0
	if l.n == 0 {
		r.prev = 0
		l.head = a
	} else {
		t := c.recs.at(c.recIdx(l.tail))
		t.next = int32(a - l.tail)
		r.prev = int32(l.tail - a)
	}
	l.tail = a
	l.n++
}

func (c *tcb) listRemove(l *recList, i int, r *record, flag uint8) {
	a := c.recAbs(i)
	pa, na := a+uint32(r.prev), a+uint32(r.next)
	switch {
	case r.prev != 0 && r.next != 0:
		c.recs.at(i + int(r.prev)).next = int32(na - pa)
		c.recs.at(i + int(r.next)).prev = int32(pa - na)
	case r.prev != 0:
		c.recs.at(i + int(r.prev)).next = 0
		l.tail = pa
	case r.next != 0:
		c.recs.at(i + int(r.next)).prev = 0
		l.head = na
	}
	r.prev, r.next = 0, 0
	r.flags &^= flag
	l.n--
}

// unlinkRec は記録をどちらの list からも外す。
func (c *tcb) unlinkRec(i int, r *record) {
	if c.genFlag(r, recInT) {
		c.listRemove(&c.tList, i, r, recInT)
	}
	if c.genFlag(r, recInQ) {
		c.listRemove(&c.lostQ, i, r, recInQ)
	}
}

// rackLost は記録 r が RACK の損失の印を持つかを返す。
func (c *tcb) rackLost(r *record) bool { return c.genFlag(r, recLost) }

// sentAfter は (t1, e1) が (t2, e2) より後に送られたかを返す(RFC 8985 の RACK_sent_after)。
func sentAfter(t1 int64, e1 uint32, t2 int64, e2 uint32) bool {
	return t1 > t2 || (t1 == t2 && seqGT(e1, e2))
}

// rackDelivered は、累積の確認か SACK で新しく届いたと知らせた記録 r で RACK の状態を更新する
// (RFC 8985 6.2 の手順 1 と 2)。
func (c *tcb) rackDelivered(r *record, now int64) {
	end := r.seq + uint32(r.length)
	if r.flags&recRetransmitted != 0 {
		// 元の segment への確認かもしれない再送は使わない。Linux の tcp_rack_advance と同じく最小の RTT だけで
		// 見分け、RFC 8985 の TSecr による判定は使わない。穴のある間の SACK の TSecr は受け手の TS.Recent で、
		// 穴より前の segment の時刻のままなので、再送への SACK をすべて元の segment への確認とみなしてしまう
		if now-r.sentAt < c.minRTT {
			return
		}
	} else if c.rackFackOK && seqLT(end, c.rackFack) {
		c.reorderSeen = true
	}
	if !c.rackFackOK || seqGT(end, c.rackFack) {
		c.rackFack, c.rackFackOK = end, true
	}
	if !c.rackOK || sentAfter(r.sentAt, end, c.rackXmit, c.rackEnd) {
		c.rackXmit, c.rackEnd, c.rackRTT, c.rackOK = r.sentAt, end, now-r.sentAt, true
	}
}

// reoWnd は並べ替えの窓(RFC 8985 6.2 の手順 4、D-SACK による広げ方は持たない)。
func (c *tcb) reoWnd() int64 {
	if !c.reorderSeen && (c.inRecovery || c.sackedRecs >= dupThresh) {
		return 0
	}
	return min(c.minRTT/4, c.srtt)
}

// rackDetect は送った時刻の順の list の先頭から、RACK の時刻で失われた記録に印を付けて損失の待ち行列へ
// 移す(RFC 8985 6.2 の手順 5)。まだ期限の来ない最初の記録で止め、その期限を並べ替えの期限にする。
// 印を付けた記録があれば真を返す。止まった記録より後の記録は送った時刻が遅いので、期限も遅い。
func (c *tcb) rackDetect(now int64) bool {
	c.reoAt = 0
	if !c.sackOK || !c.rackOK {
		return false
	}
	marked := false
	wnd := c.reoWnd()
	for c.tList.n > 0 {
		i := c.recIdx(c.tList.head)
		r := c.recs.at(i)
		c.scoreSteps++
		if !sentAfter(c.rackXmit, c.rackEnd, r.sentAt, r.seq+uint32(r.length)) {
			break
		}
		if remain := r.sentAt + c.rackRTT + wnd - now; remain > 0 {
			c.reoAt = now + remain
			break
		}
		c.markRackLost(i, r)
		marked = true
	}
	return marked
}

// markRackLost は送った時刻の順の list の記録 i を失われたとみなし、損失の待ち行列の末尾へ移す。
func (c *tcb) markRackLost(i int, r *record) {
	c.listRemove(&c.tList, i, r, recInT)
	l := uint32(r.length)
	if c.rtxLive(r) {
		r.flags &^= recRtx
		c.rtxBytes -= l
	}
	if !c.rackLost(r) {
		r.flags |= recLost
		if i >= int(c.lossIdx) {
			c.rackLostBeyond += l
		}
	}
	c.listAppend(&c.lostQ, i, r, recInQ)
	c.s.rackLost.Add(1)
}

// nextQueued は損失の待ち行列の先頭の、送り直しを待つ記録の位置を返す。無ければ -1 を返す。
func (c *tcb) nextQueued() int {
	for c.lostQ.n > 0 {
		i := c.recIdx(c.lostQ.head)
		r := c.recs.at(i)
		c.scoreSteps++
		if !c.isSacked(r) && (!c.rtxLive(r) || c.qMid) {
			return i
		}
		c.listRemove(&c.lostQ, i, r, recInQ)
		c.qOff, c.qMid = 0, false
	}
	return -1
}

// tlpEligible は、TLP の probe の期限を張れるかを返す(RFC 8985 7.2)。回復と RTO の後の回復の間、
// probe の確認を待つ間、窓の probe の間は張らない。
func (c *tcb) tlpEligible() bool {
	return c.sackOK && !c.persist && !c.inRecovery && !c.tlpActive && c.sndUna != c.sndMax && seqGE(c.sndUna, c.recover)
}

// scheduleTLP は PTO の期限を決める。新しいデータを送った後と、累積の確認が進んだ後に呼ぶ。RTO の
// 期限より遅くなるなら張らない。
func (c *tcb) scheduleTLP(now int64) {
	c.tlpAt = 0
	if !c.tlpEligible() {
		return
	}
	pto := int64(tlpNoRTT)
	if c.hasRTT {
		pto = 2 * c.srtt
		if c.sndMax-c.sndUna <= uint32(c.segMSS()) {
			pto = max(pto, c.srtt*3/2+int64(tlpOneSegExtra))
		}
	}
	at := now + max(pto, int64(time.Millisecond))
	if c.rtoAt != 0 && at >= c.rtoAt {
		return
	}
	c.tlpAt = at
}

// onTLP は PTO の期限。新しいデータか最後の記録の再送を probe として 1 つ送る(RFC 8985 7.3)。
func (c *tcb) onTLP(now int64) {
	if !c.tlpEligible() {
		return
	}
	c.tlpProbe = true
}

// tlpOnAck は probe の確認を処理する(RFC 8985 7.4、Linux の tcp_process_tlp_ack)。probe が再送で、
// 確認が probe より先まで進んだときは、probe が損失を直したとみなして輻輳の窓を下げる。
func (c *tcb) tlpOnAck(ack uint32, unaAdvanced bool, newlySacked uint32) {
	if !c.tlpActive || seqLT(ack, c.tlpEnd) {
		return
	}
	switch {
	case !c.tlpRetrans:
		c.tlpActive = false
	case seqGT(ack, c.tlpEnd):
		c.tlpActive = false
		if !c.inRecovery {
			c.ssthresh = c.ccFor().lossThresh(c)
			c.cwnd = c.ssthresh
			c.s.tlpRecoveries.Add(1)
		}
	case !unaAdvanced && newlySacked == 0:
		c.tlpActive = false // 元の segment と probe の両方が届いた
	}
}

// setRTO は RTO の期限を at にする。0 なら RTO の期限を消す。
func (c *tcb) setRTO(at int64) {
	c.rtoAt = at
	c.rearmRetrans()
}

// clearRetransTimers は RTO、並べ替え、TLP の期限をすべて消す。
func (c *tcb) clearRetransTimers() {
	c.rtoAt, c.reoAt, c.tlpAt = 0, 0, 0
	c.disarm(tmrRetrans)
}

// rearmRetrans は再送のタイマーの節に、RTO、並べ替え、TLP の期限のうち最も早いものを張る。窓の probe の
// 間は窓の probe が節を使う。
func (c *tcb) rearmRetrans() {
	if c.persist {
		return
	}
	at := int64(0)
	for _, d := range [3]int64{c.rtoAt, c.reoAt, c.tlpAt} {
		if d != 0 && (at == 0 || d < at) {
			at = d
		}
	}
	switch {
	case at == 0:
		c.disarm(tmrRetrans)
	case at != c.tdl[tmrRetrans]:
		c.arm(tmrRetrans, at)
	}
}

// onRetransTimer は再送のタイマーの節の期限。期限の来た種類を 1 つ処理し、残る期限を張り直す。並べ替えの
// 期限は RTO の期限を動かさない。TLP の probe を送った時だけ、buildTLP が RTO を張り直す。
func (c *tcb) onRetransTimer(now int64) {
	switch {
	case c.rtoAt != 0 && now >= c.rtoAt:
		c.rtoAt = 0
		c.onRTO(now)
	case c.reoAt != 0 && now >= c.reoAt:
		c.reoAt = 0
		c.s.reoTimeouts.Add(1)
		if c.rackDetect(now) {
			c.sackAfterAck(0)
		}
	case c.tlpAt != 0 && now >= c.tlpAt:
		c.tlpAt = 0
		c.onTLP(now)
	}
	c.rearmRetrans()
}
