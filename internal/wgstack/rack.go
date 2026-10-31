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

// rackReoPersist は D-SACK で上げた倍率を保つ回復の数(RFC 8985 の 16)。
const rackReoPersist = 16

// rackReoMultMax は倍率の上限(Linux の reo_wnd_steps と同じ 255)。倍率と最小の RTT の積が溢れないようにする。
const rackReoMultMax = 255

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

// listRemove は記録 i を list l から外す。損失の待ち行列の先頭を外すときは、先頭の記録の中で送り終えた位置
// (qOff、qMid)も 0 に戻す。
func (c *tcb) listRemove(l *recList, i int, r *record, flag uint8) {
	a := c.recAbs(i)
	if l == &c.lostQ && l.head == a {
		c.qOff, c.qMid = 0, false // 分けて送っていた先頭の記録が待ち行列を出た
	}
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
	} else {
		if seqLE(end, c.recover) {
			c.origDelivered = true // RTO の前に送り、再送していないデータ(Linux の FLAG_ORIG_SACK_ACKED)
		}
		if c.rackFackOK && seqLT(end, c.rackFack) {
			c.reorderSeen = true
		}
	}
	if !c.rackFackOK || seqGT(end, c.rackFack) {
		c.rackFack, c.rackFackOK = end, true
	}
	if !c.rackOK || sentAfter(r.sentAt, end, c.rackXmit, c.rackEnd) {
		c.rackXmit, c.rackEnd, c.rackRTT, c.rackOK = r.sentAt, end, now-r.sentAt, true
	}
}

// reoWnd は並べ替えの窓(RFC 8985 6.2 の手順 4)。D-SACK を受けた往復ごとに倍率を 1 つ上げる。
func (c *tcb) reoWnd() int64 {
	if !c.reorderSeen && (c.inRecovery || c.sackedRecs >= dupThresh) {
		return 0
	}
	return min(max(c.reoWndMult, 1)*c.minRTT/4, c.srtt)
}

// rackDSACK は D-SACK を受けた ACK で並べ替えの窓の倍率を上げる。1 往復に 1 回だけ上げ、16 回の回復の間
// 保つ(RFC 8985 6.2 の手順 4)。
func (c *tcb) rackDSACK() {
	if c.dsackRoundOn && seqGE(c.sndUna, c.dsackRound) {
		c.dsackRoundOn = false
	}
	if c.dsackRoundOn {
		return
	}
	c.dsackRound, c.dsackRoundOn = c.sndMax, true
	c.reoWndMult = min(max(c.reoWndMult, 1)+1, rackReoMultMax)
	c.reoPersist = rackReoPersist
	c.s.dsacksIn.Add(1)
}

// rackRecoveryDone は回復を終えるたびに倍率を保つ残りを減らし、尽きたら倍率を 1 に戻す。
func (c *tcb) rackRecoveryDone() {
	if c.reoPersist > 0 {
		c.reoPersist--
		if c.reoPersist == 0 {
			c.reoWndMult = 1
		}
	}
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
	c.clearRtx(r)
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
		c.listRemove(&c.lostQ, i, r, recInQ) // 先頭なので、分けて送った位置も戻す
	}
	return -1
}

// tlpEligible は、TLP の probe の期限を張れるかを返す(RFC 8985 7.2)。回復と RTO の後の回復の間、
// SACK 済みの記録がある間、probe の確認を待つ間、窓の probe の間は張らない。SACK 済みの記録があれば、
// RACK の並べ替えの期限と、相手が SACK を取り消した疑いの早めた RTO(renegeTimer)が損失を扱う。
func (c *tcb) tlpEligible() bool {
	return c.sackOK && !c.persist && !c.inRecovery && !c.tlpActive && c.sacked == 0 && c.sndUna != c.sndMax &&
		seqGE(c.sndUna, c.recover)
}

// scheduleTLP は PTO の期限を決める。新しいデータを送った後と、累積の確認が進んだ後に呼ぶ。RTO の
// 期限より遅くなるなら RTO の期限に張り、その時刻には RTO ではなく probe を送る(RFC 8985 7.2)。
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
	if c.rtoAt != 0 {
		at = min(at, c.rtoAt)
	}
	c.tlpAt = at
}

// tlpCanProbe は PTO の期限に probe を送れるかを返す。前の probe の後に RTT を測っていなければ(RFC 8985 7.3 の
// 条件 2)送らない。
func (c *tcb) tlpCanProbe() bool { return c.tlpEligible() && c.tlpSampled }

// cancelTLP は送る前の TLP の probe と、確認を待つ probe の印を消す。PTO の期限(tlpAt)は消さない。
func (c *tcb) cancelTLP() { c.tlpProbe, c.tlpActive, c.tlpRetrans = false, false, false }

// tlpOnAck は probe の確認を処理する(RFC 8985 7.4、Linux の tcp_process_tlp_ack)。probe が再送で、
// 確認が probe より先まで進んだときは、probe が損失を直したとみなして、この ACK の前の窓で輻輳の窓を下げる。
// この縮小は今の SND.MAX までに送ったデータの輻輳の事象なので、SND.UNA がそこへ届く前に入る回復は窓を下げ直さず、
// その番号で終わる(enterFastRecovery)。
func (c *tcb) tlpOnAck(ack uint32, unaAdvanced bool, newlySacked uint32) {
	if !c.tlpActive || seqLT(ack, c.tlpEnd) {
		return
	}
	switch {
	case !c.tlpRetrans:
		c.tlpActive = false
	case seqGT(ack, c.tlpEnd):
		c.tlpActive = false
		// probe を送った後に回復か RTO が始まっていれば、その応答が probe の前の損失への輻輳の事象なので、
		// 下げ直さない(RFC 8985 7.4.1)。probe を送れたのは SND.UNA >= recover の時なので、recover が probe の
		// 終わりに届いているのは、その後に回復か RTO が recover を進めたときである
		if !c.inRecovery && !seqGE(c.recover, c.tlpEnd) {
			// 窓は損失を見つけた ACK の前の値で決める。この ACK が probe の後のデータまで確認すると、ACK の後の
			// 送り残しは 0 に近く、窓が下限まで落ちる。TLP は回復の外だけで働くので、送り手の窓は輻輳の窓である
			c.ssthresh = c.ccFor().lossThresh(c, c.priorCwnd, min(c.sndMax-c.priorUna, c.priorCwnd))
			c.cwnd = c.ssthresh
			c.tlpCut, c.tlpCutSeq = true, c.sndMax
			c.s.tlpRecoveries.Add(1)
		}
	case !unaAdvanced && newlySacked == 0:
		c.tlpActive = false // 元の segment と probe の両方が届いた
	}
	if !c.tlpActive {
		c.tlpRetrans = false // 片付いた probe の終わりで後の D-SACK を probe のものとみなさない
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
	case c.tlpAt != 0 && c.rtoAt != 0 && now >= c.rtoAt && c.tlpAt <= c.rtoAt && c.tlpCanProbe():
		// PTO を RTO の期限に揃えてある。RTO ではなく probe を送り、送れたかによらず RTO を今から張り直す
		// (RFC 8985 7.2、7.3)。前の probe の後に RTT を測っていなければ probe を送れないので、その期限の RTO を
		// 起こす(次の case)
		c.tlpAt = 0
		c.rtoAt = now + c.curRTO()
		c.tlpProbe = true
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
		// PTO の期限。新しいデータか最後の記録の再送を probe として 1 つ送る(RFC 8985 7.3)。probe を送れなければ、
		// RTO は最後の手段として残すので、張ってある RTO の期限は動かさず、無いときだけ今から張る。動かすと、PTO を
		// 張り直す新しいデータが続く間 RTO が起きない
		c.tlpAt = 0
		switch {
		case c.tlpCanProbe():
			c.tlpProbe = true
		case c.tlpEligible() && c.rtoAt == 0:
			c.rtoAt = now + c.curRTO()
		}
	}
	c.rearmRetrans()
}
