package wgstack

import (
	"sync"
	"syscall"
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
	floorRecs []record   // floor の送信の記録の輪。枠が最初に使われたときに確保し、枠と共に持ち続ける
	floorIv   []interval // floor の順序外の区間の表。floorRecs と同じく枠と共に持ち続ける
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
	irs, rcvNxt   uint32
	rcvCap        uint64
	advRight      uint64 // 広告した窓の右端(受信の offset)。後ろへ戻さない
	rcvSsthresh   uint64 // 広告する窓の歩みの上限(Linux の rcv_ssthresh、rcvwin.go)
	rcvWant       uint64 // 受け手の往復ごとの測定が求めた窓の上限。下げない
	rsTime        int64  // 窓の自動調整の区間の始めの時刻
	rsSeq         uint64 // 数え始めた時の readOff
	rsSpace       uint64 // 前の区間に読んだ量
	rcvRTT        int64  // 受け手の RTT の推定。0 は推定が無い
	rttWinSeq     uint64 // 窓による標本の終わりの offset
	rttWinTime    int64  // 窓による標本の始めの時刻。0 は標本を始めていない
	rttTsecr      uint32 // 前の timestamp による標本の TSecr
	finRcvd       bool
	oooFin        bool
	oooFinOff     uint64
	rcvSinceAck   int
	rcvMSSEst     uint32    // 相手の segment の大きさの推定(Linux の rcv_mss)
	pingpong      bool      // 対話の印:データを受けてから遅延 ACK の時間の内にデータを送った
	lastDataRcvd  int64     // 最後に中身を受け入れた時刻
	rcvdData      bool      // lastDataRcvd が有効
	quickAcks     uint8     // 遅らせずに返す ACK の残り(Linux の icsk_ack.quick)
	dsack         sackBlock // 次の ACK の先頭に載せる D-SACK の block(RFC 2883)
	dsackPending  bool
	reoWndMult    int64  // RACK の並べ替えの窓の倍率(RFC 8985 6.2 の reo_wnd_mult)
	reoPersist    int    // 倍率を保つ残りの回復の数(reo_wnd_persist)
	dsackRound    uint32 // D-SACK で倍率を上げた往復の終わり(dsack_round)
	dsackRoundOn  bool
	undoMarker    bool   // 取り消しの印(undo.go)
	undoSeq       uint32 // 印を付けた時の SND.UNA(Linux の undo_marker)
	priorUna      uint32 // 処理中の ACK の前の SND.UNA
	priorCwnd     uint32 // 処理中の ACK の前の輻輳の窓
	totalRetrans  uint32 // 接続の再送の累計(Linux の total_retrans)
	dsackDups     uint32 // D-SACK で知らされた重複の累計(Linux の dsack_dups)
	rtoEpisode    bool   // RTO の後の回復の最中
	undoCwnd      uint32 // 覚えた輻輳の窓
	undoSsthresh  uint32
	undoRetrans   int32  // D-SACK で知らされていない再送の数
	retransTS     uint32 // 最初の再送の時刻(自分の TSval)
	retransTSOK   bool
	frto          uint8 // F-RTO の段階。0 は使っていない
	frtoNew       uint8 // F-RTO の 2 の段で輻輳の窓によらず送れる新しい segment の数
	origDelivered bool  // 処理中の ACK が再送していない記録を届けた

	tsRecent, tsOffset uint32
	tsRecentAt         int64 // TS.Recent を最後に更新した時刻(RFC 7323 5.5 の 24 日の規則)
	lastAckSent        uint32
	lastOOW            int64

	// RTT と再送(RFC 6298)
	srtt, rttvar, rto int64
	hasRTT            bool
	backoff           uint
	retransStart      int64
	persist           bool // 再送のタイマーを窓の probe に使っている
	probesOut         int

	// SACK の scoreboard(scoreboard.go)
	sackGen, rtxGen uint8
	sacked          uint32
	beyondBytes     uint32
	beyondCnt       int32
	lossIdx         int32
	rxtIdx          int32
	rxtOff          uint32
	highSack        uint32
	rxtMid          bool
	recBase         uint32  // 輪の先頭の記録の通し番号
	tList, lostQ    recList // RACK の送った時刻の順の list と損失の待ち行列(rack.go)
	rackLostBeyond  uint32  // 損失の境目から先で RACK が失われたとみなした byte
	qOff            uint32  // 損失の待ち行列の先頭の記録の中で送り終えた byte
	qMid            bool
	sackedRecs      int32 // SACK 済みの記録の数

	// RACK-TLP(RFC 8985、rack.go)
	rackXmit                        int64 // 届いた記録のうち最も後に送った記録の送った時刻
	rackEnd                         uint32
	rackRTT                         int64
	rackOK                          bool
	rackFack                        uint32 // 届いた記録の最も右の端
	rackFackOK                      bool
	reorderSeen                     bool
	rackChanges                     uint64 // 試験だけが読む、RACK の状態を変えた ACK の数
	minRTT                          int64
	hasMinRTT                       bool
	rtoAt, reoAt, tlpAt             int64 // 再送のタイマーの節が分け合う期限
	tlpActive, tlpRetrans, tlpProbe bool
	tlpSampled                      bool // 前の probe の後(probe が無ければ接続の始めの後)に RTT を測った(RFC 8985 7.3 の 2)
	tlpEnd                          uint32
	tlpCutSeq                       uint32 // TLP の probe が窓を下げた時の SND.MAX。tlpCut の間だけ意味を持つ
	tlpCut                          bool   // SND.UNA が tlpCutSeq に届く前の損失は、TLP の縮小と同じ輻輳の事象である
	rtxBytes                        uint32
	prrDelivered                    uint32 // PRR(RFC 6937)
	prrOut                          uint32
	recoverFS                       uint32
	scoreSteps                      uint64 // 試験だけが読む scoreboard の手間の数

	// 輻輳の制御(RFC 5681、RFC 6582、RFC 6675、RFC 6937)
	cwnd, ssthresh uint32
	recover        uint32
	inRecovery     bool
	dupAcks        int
	caAcc          uint32
	cubic          cubicCC // CUBIC の状態(cc.go)。NewReno を選んだ接続では使わない
	cwndBlocked    bool    // 最後の nextNew を輻輳の窓が止めた
	cwndLimited    bool    // この窓の間に輻輳の窓が送るのを止めた(cwndval.go)
	maxFlight      uint32  // この窓の間の送り残しの最大
	cwndUsageSeq   uint32  // この窓の終わりの番号
	hs             hystart // HyStart++ の状態(hystart.go)
	lastSendAt     int64

	fastRtx      bool  // 先頭の segment を再送する
	rtxCause     uint8 // fastRtx の原因(rtxFast か rtxPartial)
	resendCause  uint8 // SND.NXT を SND.UNA に戻した原因(rtxRTO か rtxPMTU)
	ackDelayed   bool  // 送る ACK は遅延 ACK のタイマーが求めた
	probePending bool  // 窓の probe を送る
	ackNow       bool  // ACK を送る

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
		state:       stEstablished,
		tup:         r.tup,
		iss:         r.iss,
		irs:         r.irs,
		sndUna:      r.iss + 1,
		sndNxt:      r.iss + 1,
		sndMax:      r.iss + 1,
		wsOK:        r.wsOK,
		sackOK:      r.sackOK,
		tsOK:        r.tsOK,
		peerMSS:     int(r.peerMSS),
		pmtu:        s.mtu,
		sndCap:      sendFloor,
		rcvNxt:      r.irs + 1,
		rcvCap:      recvFloor,
		rcvSsthresh: recvFloor,
		advRight:    uint64(r.rcvWnd),
		tsRecent:    r.tsRecent,
		tsRecentAt:  now,
		tsOffset:    r.tsOffset,
		rto:         int64(rtoInit),
		ssthresh:    ^uint32(0),
		recover:     r.iss,
		rch:         make(chan struct{}, 1),
		wch:         make(chan struct{}, 1),
	}
	c.lastAckSent = c.rcvNxt
	if c.wsOK {
		c.sndWscale, c.rcvWscale = r.sndWscale, rcvWindowShft
	}
	c.sndWnd = uint32(seg.wnd) << c.sndWscale
	c.maxSndWnd = c.sndWnd
	c.sndWl1, c.sndWl2 = seg.seq, seg.ack
	c.snd = ring{pool: &s.chunks, cap: sendFloor}
	if c.floorIv == nil {
		c.floorIv = make([]interval, floorIntervals)
	}
	// 区間の木の優先度の種は接続ごとの秘密で、相手が木の形を選べないようにする
	c.rcv = recvBuf{r: ring{pool: &s.chunks, cap: recvFloor}, iv: c.floorIv, seed: s.randomU64N(1 << 62)}
	if c.floorRecs == nil {
		c.floorRecs = make([]record, floorRecords)
	}
	c.recs = recordRing{recs: c.floorRecs}
	if c.tsOK && seg.opt.hasTS {
		c.tsRecent, c.tsRecentAt = seg.opt.tsVal, now
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
	// 送り残しの量が 0 の間だけ張る。RTO の後に失われた記録だけが残る間は、送り直しを待つ記録も送るものに数える
	if c.sndWnd == 0 && !c.persist && c.pipe() == 0 && c.hasUnsent() && c.state != stClosed {
		c.enterPersist(now)
	}
}

// cancelSends は送る予定の高速の再送、窓の probe、TLP の probe と、確認を待つ TLP の probe の印を消す。
func (c *tcb) cancelSends() {
	c.cancelTLP()
	c.fastRtx, c.probePending = false, false
}

// hasUnsent は、未送信のデータか未送信の FIN か、送り直しを待つ失われた記録があるかを返す。
func (c *tcb) hasUnsent() bool {
	if c.pickRule1().i >= 0 {
		return true
	}
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
	c.cancelSends()
	c.ackNow = false
	// 送信の輪はもう使わない。受信の未読のデータは読ませるために残し、順序外のデータは捨てる
	c.snd.release()
	c.unaOff = c.tailOff
	c.rcv.clearIntervals()
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
	c.rcv.clearIntervals()
	c.releaseBoost()
	c.recs = recordRing{recs: c.floorRecs}
	c.rcv.iv = c.floorIv
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
		c.floorIv = nil
		c.rcv.iv = nil // 受信のバッファは tcbState の外にあり、区間の表を指したまま残るため
	}
	if c.rch != nil {
		close(c.rch)
		close(c.wch)
	}
	c.tcbState = tcbState{}
	s.free = append(s.free, c.id)
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
