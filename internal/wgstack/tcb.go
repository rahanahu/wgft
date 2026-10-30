package wgstack

import (
	"sync"
	"syscall"
	"time"
)

// tcpState は接続の枠の状態。握手の途中(SYN-RCVD)は行(syn.go)、行に移った TIME_WAIT と FIN_WAIT_2 は
// TIME_WAIT の表(timewait.go)が持つ。
type tcpState uint8

const (
	stFree tcpState = iota // 枠は空き
	stEstablished
	stFinWait1
	stFinWait2
	stCloseWait
	stClosing
	stLastAck
	stTimeWait
	stClosed // プロトコルは終わったが、アプリケーションがまだ閉じていない
)

var stateNames = [...]string{"FREE", "ESTABLISHED", "FIN_WAIT_1", "FIN_WAIT_2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT", "CLOSED"}

func (s tcpState) String() string { return stateNames[s] }

// 接続の枠に固定で埋め込むタイマーの節(設計文書の「タイマー」)。
const (
	tmrRetrans   = iota // RTO と窓の probe
	tmrDelack           // 遅延 ACK
	tmrClose            // TIME_WAIT と、閉じた後の FIN_WAIT_2 の期限
	tmrKeepalive        // 用意だけで使わない(keepalive は完成に含めない)
	numTimers
)

// tcb は接続の枠。枠は作成の時に N_c 個を確保し、確立の時に使い、枠を返すときに世代を進める。世代は、
// 表の錠を離した後の古い検索の結果と、枠を返した後も中継が持ち続ける元の接続の値(Conn)を見分ける。
// mu が接続の錠で、枠のすべての欄を守る。inIndex、gen、queued、qprev、qnext、lst は表の錠でも守り、
// 書くときは両方を持つ。
type tcb struct {
	mu      sync.Mutex
	s       *stack
	id      int32
	gen     uint32
	inIndex bool

	// accept の待ち行列の節(表の錠)
	lst          *listener
	queued       bool
	qprev, qnext int32

	snd       ring
	rcv       recvBuf
	floorRecs []record // floor の送信の記録の輪。枠が最初に使われたときに確保し、枠と共に持ち続ける
	rdl, wdl  deadline

	tcbState
}

// tcbState は確立の時に 0 から始める欄。
type tcbState struct {
	state tcpState
	tup   tuple

	accepted  bool
	appClosed bool // 最後の Close か Abort を呼んだ
	sndShut   bool // FIN を送る(CloseWrite か Close)
	err       error
	rch, wch  chan struct{} // 読み取りと書き込みの通知(容量 1)。枠を返すときに閉じる

	// 送信
	iss, sndUna, sndNxt, sndMax uint32
	unaOff, tailOff             uint64 // 送信の輪の [unaOff, tailOff) が未確認と未送信のデータ
	sndWnd, maxSndWnd           uint32
	sndWl1, sndWl2              uint32
	sndWscale, rcvWscale        uint8
	wsOK, sackOK, tsOK          bool
	peerMSS, pmtu               int
	finSent                     bool
	sndCap                      uint64
	recs                        recordRing

	// 受信
	irs, rcvNxt uint32
	rcvCap      uint64
	advRight    uint64 // 広告した窓の右端(受信の offset)。後ろへ戻さない
	finRcvd     bool
	oooFin      bool
	oooFinOff   uint64
	rcvSinceAck int

	tsRecent, tsOffset uint32
	lastAckSent        uint32
	lastOOW            int64

	// RTT と再送(RFC 6298)
	srtt, rttvar, rto int64
	hasRTT            bool
	backoff           uint
	retransStart      int64
	persist           bool // 再送のタイマーを窓の probe に使っている
	probesOut         int

	// 輻輳の制御(RFC 5681、RFC 6582)
	cwnd, ssthresh uint32
	recover        uint32
	inRecovery     bool
	dupAcks        int
	caAcc          uint32
	lastSendAt     int64

	fastRtx      bool // 先頭の segment を再送する
	probePending bool // 窓の probe を送る
	ackNow       bool // ACK を送る

	tdl     [numTimers]int64
	twEnter int64

	// boost(設計文書の「boost の取得と floor への戻り」)
	boosted    bool
	rcvBoost   bool
	onBoost    func(boosted bool) bool
	rdem, wdem demand
	lastDemand int64
}

func (c *tcb) timerNode(kind int) int32 { return c.id*numTimers + int32(kind) }

func (c *tcb) arm(kind int, at int64) {
	c.tdl[kind] = at
	c.s.wheel.set(c.timerNode(kind), at)
	c.s.noteDeadline(at)
}

func (c *tcb) disarm(kind int) {
	if c.tdl[kind] != 0 {
		c.tdl[kind] = 0
		c.s.wheel.cancel(c.timerNode(kind))
	}
}

// segMSS は相手へ送る segment の中身の上限(SACK の block を除く option を引いた値)。
func (c *tcb) segMSS() int {
	m := min(c.peerMSS, c.pmtu-ipHeaderLen-tcpHeaderLen)
	if c.tsOK {
		m -= tsOptionLen
	}
	return max(m, 1)
}

// rcvMSS は相手から受ける segment の中身の大きさの見積もり。遅延 ACK と受け手の SWS の回避に使う。
func (c *tcb) rcvMSS() int {
	m := c.s.ourMSS()
	if c.tsOK {
		m -= tsOptionLen
	}
	return m
}

func (c *tcb) dataEndSeq() uint32 { return c.iss + 1 + uint32(c.tailOff) }

// finSeq は自分の FIN のシーケンス番号。sndShut の後だけ意味を持つ。
func (c *tcb) finSeq() uint32 { return c.dataEndSeq() }

func (c *tcb) finAcked() bool { return c.finSent && seqGT(c.sndUna, c.finSeq()) }

func (c *tcb) signalRead() {
	if c.rch != nil {
		select {
		case c.rch <- struct{}{}:
		default:
		}
	}
}

func (c *tcb) signalWrite() {
	if c.wch != nil {
		select {
		case c.wch <- struct{}{}:
		default:
		}
	}
}

// establish は握手の途中の行と最後の ACK から接続を確立する。枠の floor の予約は枠そのものが持つ。
func (c *tcb) establish(r *synRow, seg *segment, now int64) {
	s := c.s
	c.tcbState = tcbState{
		state:    stEstablished,
		tup:      r.tup,
		iss:      r.iss,
		irs:      r.irs,
		sndUna:   r.iss + 1,
		sndNxt:   r.iss + 1,
		sndMax:   r.iss + 1,
		wsOK:     r.wsOK,
		sackOK:   r.sackOK,
		tsOK:     r.tsOK,
		peerMSS:  int(r.peerMSS),
		pmtu:     s.mtu,
		sndCap:   sendFloor,
		rcvNxt:   r.irs + 1,
		rcvCap:   recvFloor,
		advRight: uint64(r.rcvWnd),
		tsRecent: r.tsRecent,
		tsOffset: r.tsOffset,
		rto:      int64(rtoInit),
		ssthresh: ^uint32(0),
		recover:  r.iss,
		rch:      make(chan struct{}, 1),
		wch:      make(chan struct{}, 1),
	}
	c.lastAckSent = c.rcvNxt
	if c.wsOK {
		c.sndWscale, c.rcvWscale = r.sndWscale, rcvWindowShft
	}
	c.sndWnd = uint32(seg.wnd) << c.sndWscale
	c.maxSndWnd = c.sndWnd
	c.sndWl1, c.sndWl2 = seg.seq, seg.ack
	c.snd = ring{pool: &s.chunks, cap: sendFloor}
	c.rcv = recvBuf{r: ring{pool: &s.chunks, cap: recvFloor}}
	if c.floorRecs == nil {
		c.floorRecs = make([]record, floorRecords)
	}
	c.recs = recordRing{recs: c.floorRecs}
	if c.tsOK && seg.opt.hasTS {
		c.tsRecent = seg.opt.tsVal
		if seg.opt.tsEcr != 0 {
			c.tsRTTSample(seg.opt.tsEcr, now)
		}
	} else if !r.rtx && r.sentAt != 0 {
		c.rttSample(now - r.sentAt)
	}
	if r.rtx {
		c.cwnd = uint32(c.segMSS()) // RFC 5681 3.1、Linux と同じく 1 segment
	} else {
		c.cwnd = uint32(initialWindowSegs * c.segMSS())
	}
	c.lastSendAt = now
	c.rdl.reset()
	c.wdl.reset()
}

// rttSample は RTT の測定値 r(ns)で SRTT、RTTVAR、RTO を更新する(RFC 6298 2 節)。
func (c *tcb) rttSample(r int64) {
	if r < 0 {
		return
	}
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
	rto := c.srtt + max(int64(time.Millisecond), 4*c.rttvar)
	c.rto = min(max(rto, int64(rtoMin)), int64(rtoMax))
}

// tsRTTSample は、相手が返した自分の TSval(TSecr)から RTT を測る(RFC 7323 4.1)。自分の今の TSval より
// 先の TSecr は、自分が送っていない値なので使わない。
func (c *tcb) tsRTTSample(tsEcr uint32, now int64) {
	d := int32(tsClock(now) + c.tsOffset - tsEcr)
	if d < 0 {
		return
	}
	c.rttSample(int64(d) * int64(time.Millisecond))
}

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

// rcvWindow は今広告している窓の大きさ(byte)。
func (c *tcb) rcvWindow() uint32 {
	if c.advRight <= c.rcv.nxtOff {
		return 0
	}
	return uint32(min(c.advRight-c.rcv.nxtOff, 1<<30))
}

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
	// PAWS(RFC 7323 5.3)
	if c.tsOK && seg.opt.hasTS && !seg.has(flagRST) && seqLT(seg.opt.tsVal, c.tsRecent) {
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
		c.tsRecent = seg.opt.tsVal
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

// processAck は ACK の欄を処理する(RFC 9293、RFC 5681、RFC 6582)。
func (c *tcb) processAck(seg *segment, now int64) {
	ack := seg.ack
	c.probesOut = 0
	if c.persist {
		c.retransStart = 0 // 相手は probe に応えている
	}
	wndChanged := false
	if seqLT(c.sndWl1, seg.seq) || (c.sndWl1 == seg.seq && seqLE(c.sndWl2, ack)) {
		w := uint32(seg.wnd) << c.sndWscale
		wndChanged = w != c.sndWnd
		c.sndWnd, c.sndWl1, c.sndWl2 = w, seg.seq, ack
		c.maxSndWnd = max(c.maxSndWnd, w)
	}
	c.checkSACK(seg)
	switch {
	case seqGT(ack, c.sndUna):
		c.newAck(seg, ack, now)
	case ack == c.sndUna && len(seg.payload) == 0 && !seg.has(flagFIN) && !wndChanged && c.sndMax != c.sndUna:
		c.dupAck(now)
	}
	if c.sndWnd > 0 && c.persist {
		c.persist = false
		c.backoff = 0
		c.disarm(tmrRetrans)
		if c.sndUna != c.sndMax {
			c.arm(tmrRetrans, now+c.curRTO())
		}
	}
}

// checkSACK は受けた SACK の block を検査するだけで、回復には使わない(RFC 2018 は送り手が使わないことを
// 許す。設計文書の「完成に含める機能」)。
func (c *tcb) checkSACK(seg *segment) {
	for _, b := range seg.opt.sack[:seg.opt.nsack] {
		if !seqLT(b.left, b.right) || seqLT(b.left, c.sndUna-c.maxSndWnd) || seqGT(b.right, c.sndMax) {
			return
		}
	}
}

// newAck は累積の確認を進める ACK を処理する。
func (c *tcb) newAck(seg *segment, ack uint32, now int64) {
	acked := ack - c.sndUna
	// 確認された byte を送信の輪から外す。FIN の 1 は byte に数えない
	dataAcked := min(uint64(acked), c.tailOff-c.unaOff)
	old := c.unaOff
	c.unaOff += dataAcked
	c.snd.trim(old, c.unaOff, c.tailOff)
	c.sndUna = ack
	if seqLT(c.sndNxt, ack) {
		c.sndNxt = ack
	}
	// 記録を外し、timestamp が無ければ再送していない記録で RTT を測る(Karn)
	var sample int64 = -1
	for c.recs.n > 0 {
		r := c.recs.at(0)
		end := r.seq + uint32(r.length)
		if seqGT(end, ack) {
			if seqLT(r.seq, ack) {
				d := ack - r.seq
				r.seq = ack
				r.length -= uint16(d)
			}
			break
		}
		if r.flags&recRetransmitted == 0 {
			sample = now - r.sentAt
		}
		c.recs.pop()
	}
	if c.tsOK && seg.opt.hasTS && seg.opt.tsEcr != 0 {
		c.tsRTTSample(seg.opt.tsEcr, now)
	} else if sample >= 0 {
		c.rttSample(sample)
	}
	c.backoff = 0
	c.retransStart = 0
	mss := uint32(c.segMSS())
	flight := c.sndMax - c.sndUna
	if c.inRecovery {
		if seqGE(ack, c.recover) {
			// 回復の終わり(RFC 6582 3.2 の 3)
			c.inRecovery = false
			c.cwnd = min(c.ssthresh, max(flight, mss)+mss)
		} else {
			// 部分の確認(RFC 6582 3.2 の 5):次の穴を再送し、確認された分だけ窓を縮め、1 SMSS 以上を
			// 確認したら SMSS を足し戻す
			c.fastRtx = true
			c.cwnd -= min(c.cwnd, acked)
			if acked >= mss {
				c.cwnd += mss
			}
			c.cwnd = max(c.cwnd, mss)
		}
	} else if c.cwnd < c.ssthresh {
		c.cwnd += min(acked, 2*mss)
	} else {
		c.caAcc += acked
		if c.caAcc >= c.cwnd {
			c.caAcc -= c.cwnd
			c.cwnd += mss
		}
	}
	c.cwnd = min(c.cwnd, 1<<30)
	c.dupAcks = 0
	// 再送のタイマー(RFC 6298 5.2、5.3)
	if !c.persist {
		if c.sndUna == c.sndMax {
			c.disarm(tmrRetrans)
		} else {
			c.arm(tmrRetrans, now+c.curRTO())
		}
	}
	if c.finAcked() {
		switch c.state {
		case stFinWait1:
			c.state = stFinWait2
		case stClosing:
			c.enterTimeWait(now)
		case stLastAck:
			c.toClosed(nil)
		}
	}
	c.signalWrite()
}

// dupAck は重複した ACK を処理する(RFC 5681 3.2、RFC 6582)。
func (c *tcb) dupAck(now int64) {
	c.dupAcks++
	mss := uint32(c.segMSS())
	if c.inRecovery {
		c.cwnd += mss
		return
	}
	if c.dupAcks == 3 && seqGT(c.sndUna, c.recover) {
		flight := c.sndMax - c.sndUna
		c.ssthresh = max(flight/2, 2*mss)
		c.recover = c.sndMax
		c.cwnd = c.ssthresh + 3*mss
		c.inRecovery = true
		c.fastRtx = true
	}
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
	if res.dropped {
		c.s.refused(&c.s.oooDropped, &c.s.oooGate, now, "dropped out-of-order segments that would need more than the fixed number of receive intervals")
	}
	if res.trimmed {
		c.s.rcvTrimmed.Add(1)
	}
	if res.accepted > 0 {
		c.signalRead()
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
		if c.rcvSinceAck >= 2*c.rcvMSS() {
			c.ackNow = true
		} else if c.tdl[tmrDelack] == 0 {
			c.arm(tmrDelack, now+int64(delackTimeout))
		}
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
	c.disarm(tmrRetrans)
	c.persist = false
	c.arm(tmrClose, now+int64(twTimeout))
}

// pmtuDrop は Fragmentation Needed による PMTU の引き下げ(RFC 1191)。引用された番号が SND.UNA から
// SND.NXT の範囲にあるときだけ受け入れる(RFC 5927)。送り残しは小さな segment で送り直す。
func (c *tcb) pmtuDrop(seq uint32, mtu int, now int64) {
	if !seqGE(seq, c.sndUna) || !seqLT(seq, c.sndNxt) {
		c.s.icmpDropped.Add(1)
		return
	}
	if mtu >= c.pmtu {
		return
	}
	c.pmtu = mtu
	if c.sndNxt != c.sndUna {
		c.sndNxt = c.sndUna
		c.recs.reset()
	}
	c.afterInput(now)
}

// afterInput は入力、タイマー、アプリケーションの操作の後に、枠を返すか行に移すかを決め、送るものが
// あれば接続の組に並べる。
func (c *tcb) afterInput(now int64) {
	if c.state == stFree {
		return
	}
	if c.tryRetire(now) {
		return
	}
	if c.wantOutput() {
		c.s.out.queueConn(c.id)
	}
	// 窓が 0 で送るものがあり、確認を待つものが無ければ窓の probe を張る
	if c.sndWnd == 0 && !c.persist && c.sndNxt == c.sndUna && c.hasUnsent() && c.state != stClosed {
		// 確認を待つものが無いので、前の RTO の起点と後退を持ち越さない。持ち越すと、相手が probe に
		// 応え続けた長い persist の後の最初の RTO で、再送の打ち切りの時間を過ぎたと数える
		c.persist = true
		c.retransStart = 0
		c.backoff = 0
		c.disarm(tmrRetrans)
		c.arm(tmrRetrans, now+c.curRTO())
	}
}

// hasUnsent は、未送信のデータか未送信の FIN があるかを返す。
func (c *tcb) hasUnsent() bool {
	if seqLT(c.sndNxt, c.dataEndSeq()) {
		return true
	}
	return c.sndShut && seqLE(c.sndNxt, c.finSeq())
}

// tryRetire は、行に移る条件を満たした接続を TIME_WAIT の表の行に移し、プロトコルの終わった閉じた接続の
// 枠を返す。移したか返したかを返す。
func (c *tcb) tryRetire(now int64) bool {
	if !c.appClosed {
		return false
	}
	if c.state == stClosed {
		c.release()
		return true
	}
	if !c.rcv.empty() || c.sndUna != c.sndMax || !c.finAcked() {
		if c.state == stFinWait2 && c.tdl[tmrClose] == 0 {
			// 順序外のデータを持って閉じた FIN_WAIT_2。Linux の tcp_fin_timeout の後に終える
			c.arm(tmrClose, now+int64(finTimeout))
		}
		return false
	}
	var state uint8
	var deadline int64
	switch c.state {
	case stFinWait2:
		state, deadline = twStateFinWait2, now+int64(finTimeout)
	case stTimeWait:
		state, deadline = twStateTimeWait, c.twEnter+int64(twTimeout)
	default:
		return false
	}
	s := c.s
	c.dropResources()
	s.tmu.Lock()
	if !s.closed && c.inIndex {
		s.connIdx.remove(c.tup)
		c.inIndex = false
		s.addTWRow(c, state, deadline, now)
	}
	c.freeSlotLocked()
	s.tmu.Unlock()
	return true
}

// toClosed は接続を CLOSED にし、4 つ組の hash の表から外す。err はアプリケーションの読み書きに返す誤り
// (nil なら、受けたデータの後に io.EOF を返す)。アプリケーションが閉じていれば枠を返す。
func (c *tcb) toClosed(err error) {
	if c.state == stFree {
		return
	}
	c.state = stClosed
	if err != nil && c.err == nil {
		c.err = err
	}
	for k := range c.tdl {
		c.disarm(k)
	}
	c.s.out.unqueueConn(c.id)
	c.fastRtx, c.probePending, c.ackNow = false, false, false
	// 送信の輪はもう使わない。受信の未読のデータは読ませるために残し、順序外のデータは捨てる
	c.snd.release()
	c.unaOff = c.tailOff
	c.rcv.n = 0
	c.rcv.r.retain(c.rcv.readOff, c.rcv.nxtOff)
	// boost の枠は、boost の大きさの未読のデータを持ちうるので、枠を返すまで持つ
	s := c.s
	s.tmu.Lock()
	if c.inIndex {
		s.connIdx.remove(c.tup)
		c.inIndex = false
	}
	if c.queued {
		c.lst.dequeue(c)
	}
	s.tmu.Unlock()
	c.signalRead()
	c.signalWrite()
	if c.appClosed {
		c.release()
	}
}

// resetByPeer は相手の RST で接続を終える。accept の待ち行列にいる接続は待ち行列から外して枠を返す。
func (c *tcb) resetByPeer() {
	if !c.accepted {
		c.release()
		return
	}
	// Linux と同じく、RST の前に受けた順序どおりのデータは読ませ、その後に誤りを返す
	c.toClosed(syscall.ECONNRESET)
}

// sendRST は接続の今の番号で RST を制御の輪に積む。
func (c *tcb) sendRST() {
	c.s.sendCtl(tcpHeader{tup: c.tup, seq: c.sndNxt, ack: c.rcvNxt, flags: flagRST | flagACK})
}

// dropResources は枠のバッファ、タイマー、出力の節、boost の枠を返す。
func (c *tcb) dropResources() {
	for k := range c.tdl {
		c.disarm(k)
	}
	c.s.out.unqueueConn(c.id)
	c.snd.release()
	c.rcv.r.release()
	c.rcv.n = 0
	c.releaseBoost()
	c.recs = recordRing{recs: c.floorRecs}
}

// release は枠を返す。アプリケーションの待ちを解き、世代を進める。
func (c *tcb) release() {
	if c.state == stFree {
		return
	}
	c.dropResources()
	s := c.s
	s.tmu.Lock()
	if c.inIndex {
		s.connIdx.remove(c.tup)
		c.inIndex = false
	}
	c.freeSlotLocked()
	s.tmu.Unlock()
}

// freeSlotLocked は枠を空きの list に戻す。tmu を持って呼ぶ。
func (c *tcb) freeSlotLocked() {
	s := c.s
	if c.queued {
		c.lst.dequeue(c)
	}
	c.gen++
	c.state = stFree
	if s.closed {
		c.floorRecs = nil // 閉じた Device では、Close と競った確立が確保した輪も残さない
	}
	if c.rch != nil {
		close(c.rch)
		close(c.wch)
	}
	c.tcbState = tcbState{}
	s.free = append(s.free, c.id)
}

// onTimer はタイマーの節 kind の期限を処理する。
func (c *tcb) onTimer(kind int, now int64) {
	switch kind {
	case tmrRetrans:
		if c.persist {
			c.onPersist(now)
		} else {
			c.onRTO(now)
		}
	case tmrDelack:
		c.ackNow = true
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
	mss := uint32(c.segMSS())
	if c.backoff == 0 {
		flight := c.sndMax - c.sndUna
		c.ssthresh = max(flight/2, 2*mss)
	}
	c.cwnd = mss
	c.caAcc = 0
	c.recover = c.sndMax
	c.inRecovery = false
	c.dupAcks = 0
	c.backoff++
	c.sndNxt = c.sndUna
	c.recs.reset()
	c.arm(tmrRetrans, now+c.curRTO())
}

// onPersist は窓の probe のタイマーの期限。相手が probe に応える間は打ち切らない。
func (c *tcb) onPersist(now int64) {
	if c.sndWnd != 0 || !c.hasUnsent() {
		c.persist = false
		c.backoff = 0
		if c.sndUna != c.sndMax {
			c.arm(tmrRetrans, now+c.curRTO())
		}
		return
	}
	c.probesOut++
	// アプリケーションが閉じた接続は、Linux の tcp_orphan_retries と同じく、相手が応えても戻らない後退の回数で
	// 打ち切る。閉じた接続の FIN は窓が開くまで送らないので、打ち切らなければ窓を 0 のまま probe に応える相手が
	// 枠をいつまでも持たせる
	if c.probesOut > probeRetries || (c.appClosed && c.backoff >= orphanRetries) {
		c.s.probeAborted.Add(1)
		c.sendRST()
		c.abortWith(syscall.ETIMEDOUT)
		return
	}
	c.probePending = true
	c.backoff++
	c.arm(tmrRetrans, now+c.curRTO())
}

// abortWith は TCP の義務を果たせない接続を終える。アプリケーションが閉じていれば枠を返し、閉じていなければ
// CLOSED にして誤りを返す。
func (c *tcb) abortWith(err error) {
	if c.appClosed || !c.accepted {
		c.release()
		return
	}
	c.toClosed(err)
}
