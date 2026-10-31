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
	finRcvd       bool
	oooFin        bool
	oooFinOff     uint64
	rcvSinceAck   int
	rcvMSSEst     uint32    // 相手の segment の大きさの推定(Linux の icsk_ack.rcv_mss)
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
	frto          uint8  // F-RTO の段階。0 は使っていない
	frtoHigh      uint32 // F-RTO の 2 の段の SND.MAX
	frtoNew       uint8  // F-RTO の 2 の段で輻輳の窓によらず送れる新しい segment の数
	origDelivered bool   // 処理中の ACK が再送していない記録を届けた

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
		state:      stEstablished,
		tup:        r.tup,
		iss:        r.iss,
		irs:        r.irs,
		sndUna:     r.iss + 1,
		sndNxt:     r.iss + 1,
		sndMax:     r.iss + 1,
		wsOK:       r.wsOK,
		sackOK:     r.sackOK,
		tsOK:       r.tsOK,
		peerMSS:    int(r.peerMSS),
		pmtu:       s.mtu,
		sndCap:     sendFloor,
		rcvNxt:     r.irs + 1,
		rcvCap:     recvFloor,
		advRight:   uint64(r.rcvWnd),
		tsRecent:   r.tsRecent,
		tsRecentAt: now,
		tsOffset:   r.tsOffset,
		rto:        int64(rtoInit),
		ssthresh:   ^uint32(0),
		recover:    r.iss,
		rch:        make(chan struct{}, 1),
		wch:        make(chan struct{}, 1),
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
	c.rcv = recvBuf{r: ring{pool: &s.chunks, cap: recvFloor}, iv: c.floorIv, seed: uint64(s.randomN(1 << 62))}
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

// rttSample は RTT の測定値 r(ns)で SRTT、RTTVAR、RTO を更新する(RFC 6298 2 節)。
func (c *tcb) rttSample(r int64) {
	if r < 0 {
		return
	}
	c.tlpSampled = true
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
	if !c.hasMinRTT || r < c.minRTT {
		c.minRTT, c.hasMinRTT = r, true
	}
	// 下限は RTO 全体ではなく RTTVAR の項に掛ける(Linux と同じ)。RFC 6298 の式の値以上で、RTTVAR の小さな
	// 経路でも Linux より早く RTO を起こさない(wgstack-performance.md の「RACK-TLP」のタイマーの規則)
	c.rto = min(c.srtt+max(4*c.rttvar, int64(rtoMin)), int64(rtoMax))
}

// tsRTTSample は、相手が返した自分の TSval(TSecr)から RTT を測る(RFC 7323 4.1)。自分の今の TSval より
// 先の TSecr は、自分が送っていない値なので使わない。
func (c *tcb) tsRTTSample(tsEcr uint32, now int64) int64 {
	d := int32(tsClock(now) + c.tsOffset - tsEcr)
	if d < 0 {
		return -1
	}
	r := int64(d) * int64(time.Millisecond)
	c.rttSample(r)
	return r
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

// processAck は ACK の欄を処理する(RFC 9293、RFC 5681、RFC 6582)。
func (c *tcb) processAck(seg *segment, now int64) {
	ack := seg.ack
	if c.hystartOn() {
		c.hs.sndNxt, c.hs.sndNxtOK = c.sendableEnd(), true // この ACK の前の SND.NXT(lazyegress.go)
	}
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
	// RFC 6937 の DeliveredData は SND.UNA の差と SACK 済みの byte の差の和である。累積の確認が先に SACK した
	// byte を覆うと SACK 済みの byte は減るので、差は確認の前の値から取る
	var delivered int64
	sackedBefore := c.sacked
	rackX, rackE := c.rackXmit, c.rackEnd
	c.origDelivered = false
	advanced := seqGT(ack, c.sndUna)
	c.priorUna, c.priorCwnd = c.sndUna, c.cwnd
	switch {
	case advanced:
		delivered = int64(ack - c.sndUna)
		c.newAck(seg, ack, now)
	case ack == c.sndUna && len(seg.payload) == 0 && !seg.has(flagFIN) && !wndChanged && c.sndMax != c.sndUna:
		c.dupAck(now)
	}
	if c.state == stFree || c.state == stClosed {
		return
	}
	newly := c.markSACK(seg, now)
	delivered += int64(c.sacked) - int64(sackedBefore)
	if c.sackOK {
		if c.rackXmit != rackX || c.rackEnd != rackE {
			c.rackChanges++
		}
		c.rackDetect(now)
		if c.frto != 0 && seqLT(c.sndUna, c.recover) {
			c.frtoAfterAck(seg, advanced, newly > 0 || (!advanced && c.sndUna != c.sndMax))
		} else if c.rtoEpisode && seqGE(c.sndUna, c.recover) {
			c.rtoRecovered(seg)
		}
		c.tlpOnAck(ack, advanced, newly)
		c.sackAfterAck(uint32(max(delivered, 0)))
		if advanced {
			c.scheduleTLP(now)
		} else if c.inRecovery {
			c.tlpAt = 0
		}
		c.rearmRetrans()
	}
	if advanced {
		c.noteDrainedWithData(now)
	}
	if c.sndWnd > 0 && c.persist {
		c.clearRetransTimers()
		c.leavePersist(now)
	}
	if c.s.trace != nil {
		c.traceEvent(TraceAck, now)
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
	// 記録を外し、timestamp が無ければ再送していない記録で RTT を測る(Karn)。この ACK が再送した記録を
	// 1 つでも確認したら測らない(Linux の FLAG_RETRANS_DATA_ACKED)。記録は RTO の後も残るので、再送を待つ間に
	// 届いていた元の segment で測ると、穴が埋まるまでの時間を RTT に含めてしまう。欄の更新は記録を外す前に
	// 古い SND.UNA で行う
	var sample int64 = -1
	rtxAcked := false
	for c.recs.n > 0 {
		r := c.recs.at(0)
		end := r.seq + uint32(r.length)
		if seqGT(end, ack) {
			if seqLT(r.seq, ack) {
				c.trimHead(r, ack-r.seq)
			}
			break
		}
		if r.flags&recRetransmitted == 0 {
			sample = now - r.sentAt
		} else {
			rtxAcked = true
		}
		c.dropHead(r, now)
		c.recs.pop()
		c.recBase++
	}
	c.sndUna = ack
	if c.tlpCut && seqGE(ack, c.tlpCutSeq) {
		c.tlpCut = false // 縮小が覆う窓のデータはすべて確認された。番号が 1 周した後に古い番号と比べない
	}
	if seqLT(c.sndNxt, ack) {
		c.sndNxt = ack
	}
	ackRTT := int64(-1) // この ACK で測った RTT(HyStart++ が使う)
	if c.tsOK && seg.opt.hasTS && seg.opt.tsEcr != 0 {
		ackRTT = c.tsRTTSample(seg.opt.tsEcr, now)
	} else if sample >= 0 && !rtxAcked {
		c.rttSample(sample)
		ackRTT = sample
	}
	c.backoff = 0
	c.retransStart = 0
	mss := uint32(c.segMSS())
	flight := c.sndMax - c.sndUna
	if c.inRecovery {
		if seqGE(ack, c.recover) {
			// 回復の終わり。SACK では RFC 6937 の cwnd = ssthresh、SACK が無ければ RFC 6582 3.2 の 3
			c.inRecovery = false
			c.rackRecoveryDone()
			if c.sackOK {
				c.cwnd = c.ssthresh
			} else {
				c.cwnd = min(c.ssthresh, max(flight, mss)+mss)
			}
			if c.mayUndo(seg) {
				c.undo() // 回復の再送は不要だった(Linux の tcp_try_undo_recovery)
			}
			c.undoMarker = false
		} else if c.sackOK {
			// SACK による回復の部分の確認。再送は NextSeg が選び、窓は PRR が決める
			c.s.partialAcks.Add(1)
		} else {
			// 部分の確認(RFC 6582 3.2 の 5):次の穴を再送し、確認された分だけ窓を縮め、1 SMSS 以上を
			// 確認したら SMSS を足し戻す
			c.fastRtx = true
			c.rtxCause = rtxPartial
			c.s.partialAcks.Add(1)
			c.cwnd -= min(c.cwnd, acked)
			if acked >= mss {
				c.cwnd += mss
			}
			c.cwnd = max(c.cwnd, mss)
		}
	} else if !c.isCwndLimited() {
		// アプリケーションに制限された間は窓を増やさない(RFC 7661、Linux の tcp_is_cwnd_limited)
	} else if c.cwnd < c.ssthresh {
		c.slowStartAck(ack, acked, ackRTT, now)
	} else {
		c.ccFor().congAvoid(c, acked, now)
	}
	c.cwnd = min(c.cwnd, 1<<30)
	c.dupAcks = 0
	// 再送のタイマー(RFC 6298 5.2、5.3)
	if !c.persist {
		if c.sndUna == c.sndMax {
			c.clearRetransTimers()
		} else {
			c.setRTO(now + c.curRTO())
			c.renegeTimer(now)
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
	c.s.dupAcksIn.Add(1)
	c.dupAcks++
	if c.sackOK {
		return // 回復に入るかは sackAfterAck が決める
	}
	mss := uint32(c.segMSS())
	if c.inRecovery {
		c.cwnd += mss
		return
	}
	if c.dupAcks == 3 && seqGT(c.sndUna, c.recover) {
		c.initUndo()
		c.ssthresh = c.lossThresh()
		c.recover = c.sndMax
		c.cwnd = c.ssthresh + 3*mss
		c.inRecovery = true
		c.fastRtx = true
		c.rtxCause = rtxFast
		c.s.fastRecoveries.Add(1)
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
		c.frto, c.frtoHigh = 1, c.sndMax
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

// abortWith は TCP の義務を果たせない接続を終える。アプリケーションが閉じていれば枠を返し、閉じていなければ
// CLOSED にして誤りを返す。
func (c *tcb) abortWith(err error) {
	if c.appClosed || !c.accepted {
		c.release()
		return
	}
	c.toClosed(err)
}
