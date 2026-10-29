package wgstack

// 握手の途中の表(設計文書の「握手の途中の表と accept の待ち行列」)。SYN-RCVD の接続を、接続の枠とは別の、
// バッファを持たない固定の数 N_syn の行に置く。SYN-ACK の再送の間隔は回数ごとに一定なので、回数ごとに
// 1 つの順序つきの list を持ち、各 list の先頭から期限を見る。行は表の錠(stack.tmu)で守る。

// 行が次に送るもの。
const (
	rowSendNone uint8 = iota
	rowSendSynAck
	rowSendAck
)

type synRow struct {
	tup       tuple
	lst       *listener
	iss, irs  uint32
	tsRecent  uint32
	tsOffset  uint32
	deadline  int64
	sentAt    int64 // 最初の SYN-ACK を作った時刻
	prev      int32
	next      int32
	peerMSS   uint16
	rcvWnd    uint16 // SYN-ACK で広告した窓(scale しない値)
	sndWscale uint8
	retries   uint8
	wsOK      bool
	sackOK    bool
	tsOK      bool
	rtx       bool // SYN-ACK を再送した
	promoting bool // 接続の枠へ移している途中
	used      bool
	pending   uint8
}

type synTable struct {
	rows  []synRow
	idx   index
	free  []int32
	lists [synackRetries + 1]struct{ head, tail int32 }
	n     int
}

func newSynTable(n int, key sipKey) synTable {
	t := synTable{rows: make([]synRow, n), idx: newIndex(n, key), free: make([]int32, n)}
	for i := range t.free {
		t.free[i] = int32(n - 1 - i)
	}
	for i := range t.lists {
		t.lists[i].head, t.lists[i].tail = -1, -1
	}
	return t
}

func (t *synTable) find(tup tuple) int32 {
	id, _ := t.idx.find(tup)
	return id
}

func (t *synTable) listPush(id int32) {
	r := &t.rows[id]
	l := &t.lists[r.retries]
	r.prev, r.next = l.tail, -1
	if l.tail >= 0 {
		t.rows[l.tail].next = id
	} else {
		l.head = id
	}
	l.tail = id
}

func (t *synTable) listRemove(id int32) {
	r := &t.rows[id]
	l := &t.lists[r.retries]
	if r.prev >= 0 {
		t.rows[r.prev].next = r.next
	} else {
		l.head = r.next
	}
	if r.next >= 0 {
		t.rows[r.next].prev = r.prev
	} else {
		l.tail = r.prev
	}
	r.prev, r.next = -1, -1
}

func (t *synTable) nextDeadline() int64 {
	next := int64(0)
	for _, l := range t.lists {
		if l.head >= 0 {
			if d := t.rows[l.head].deadline; next == 0 || d < next {
				next = d
			}
		}
	}
	return next
}

// newSynRow は待ち受け l への SYN から行を作り、SYN-ACK を送る。表が満杯か、待ち受けが N_syn の半分を
// 使っていれば、状態を作らずに捨てる。tmu を持って呼ぶ。
func (s *stack) newSynRow(l *listener, seg *segment, now int64) {
	t := &s.syn
	if len(t.free) == 0 || l.synCount >= s.lim.synRows/2 {
		s.refused(&s.synFull, &s.synGate, now, "dropped SYNs because the half-open table was full")
		return
	}
	id := t.free[len(t.free)-1]
	t.free = t.free[:len(t.free)-1]
	r := &t.rows[id]
	*r = synRow{
		tup:      seg.tup,
		lst:      l,
		iss:      s.isn(seg.tup, now),
		irs:      seg.seq,
		deadline: now + int64(synackRTO),
		peerMSS:  minMSS,
		used:     true,
		pending:  rowSendSynAck,
	}
	if seg.opt.hasMSS && seg.opt.mss != 0 {
		r.peerMSS = seg.opt.mss
	}
	if seg.opt.hasWS {
		r.wsOK, r.sndWscale = true, seg.opt.wscale
	}
	r.sackOK = seg.opt.sackOK
	if seg.opt.hasTS {
		r.tsOK, r.tsRecent, r.tsOffset = true, seg.opt.tsVal, s.random32()
	}
	r.rcvWnd = uint16(s.initialWindow(r.tsOK))
	t.idx.insert(seg.tup, id, 0)
	t.listPush(id)
	t.n++
	l.synCount++
	s.out.queueRow(id)
	s.noteDeadline(r.deadline)
}

// ourMSS は自分が示す MSS。MTU から IPv4 と TCP の header の 40 byte を引いた値である。
func (s *stack) ourMSS() int { return s.mtu - ipHeaderLen - tcpHeaderLen }

// initialWindow は SYN-ACK で広告する窓。Linux と同じく、65535 と受信の floor の小さい方を、中身の
// 大きさの倍数に切り下げる。
func (s *stack) initialWindow(ts bool) int {
	mss := s.ourMSS()
	if ts {
		mss -= tsOptionLen
	}
	w := min(65535, recvFloor)
	return w / mss * mss
}

func (s *stack) removeSynRow(id int32) {
	t := &s.syn
	r := &t.rows[id]
	if !r.used {
		return
	}
	t.idx.remove(r.tup)
	t.listRemove(id)
	s.out.unqueueRow(id)
	r.lst.synCount--
	r.used, r.lst = false, nil
	t.free = append(t.free, id)
	t.n--
}

// promotion は、握手の最後の ACK で行を接続の枠へ移すときに、表の錠の外へ持ち出す値。
type promotion struct {
	row   synRow
	rowID int32
	slot  int32
	gen   uint32
}

// synInput は握手の途中の行への segment を処理する。握手の最後の ACK で接続の枠と accept の待ち行列の
// 枠を予約できたら、行を移すための値と真を返す。予約できなければ ACK を捨て、行は残る(Linux の
// tcp_abort_on_overflow=0 と同じ)。tmu を持って呼ぶ。
func (s *stack) synInput(id int32, seg *segment, now int64) (promotion, bool) {
	r := &s.syn.rows[id]
	if r.promoting {
		return promotion{}, false
	}
	rcvNxt := r.irs + 1
	inWindow := func() bool {
		end := seg.seq + seg.seqLen()
		return seqGE(end, rcvNxt) && seqLE(seg.seq, rcvNxt+uint32(r.rcvWnd))
	}
	if seg.has(flagRST) {
		if inWindow() {
			s.removeSynRow(id)
		}
		return promotion{}, false
	}
	if seg.has(flagSYN) {
		if !seg.has(flagACK) && seg.seq == r.irs {
			// 相手が SYN を再送した。SYN-ACK を送り直す
			r.pending, r.rtx = rowSendSynAck, true
			s.out.queueRow(id)
			return promotion{}, false
		}
		if inWindow() {
			s.replyRST(seg)
			s.removeSynRow(id)
			return promotion{}, false
		}
		s.rowAck(id, r, now)
		return promotion{}, false
	}
	if !seg.has(flagACK) {
		return promotion{}, false
	}
	if seg.ack != r.iss+1 {
		s.replyRST(seg)
		return promotion{}, false
	}
	if r.tsOK && seg.opt.hasTS && seqLT(seg.opt.tsVal, r.tsRecent) {
		s.rowAck(id, r, now)
		return promotion{}, false
	}
	if !inWindow() {
		s.rowAck(id, r, now)
		return promotion{}, false
	}
	l := r.lst
	if l.closed || l.qLen >= s.lim.acceptQ/2 || s.queued >= s.lim.acceptQ || len(s.free) == 0 {
		s.refused(&s.acceptOverflow, &s.acceptGate, now, "dropped final handshake ACKs because the accept queue or the connection table was full")
		return promotion{}, false
	}
	slot := s.free[len(s.free)-1]
	s.free = s.free[:len(s.free)-1]
	r.promoting = true
	s.queued++
	l.qLen++
	return promotion{row: *r, rowID: id, slot: slot, gen: s.conns[slot].gen}, true
}

// rowAck は行から ACK を送る。challenge ACK と同じ速さの制限を受ける。
func (s *stack) rowAck(id int32, r *synRow, now int64) {
	if !s.challengeAllowed(now) {
		return
	}
	if r.pending == rowSendNone {
		r.pending = rowSendAck
	}
	s.out.queueRow(id)
}

// promote は予約した接続の枠に行を移し、accept の待ち行列に入れる。錠を持たずに呼ぶ。
func (s *stack) promote(p promotion, seg *segment, now int64) {
	c := &s.conns[p.slot]
	c.mu.Lock()
	defer c.mu.Unlock()
	c.establish(&p.row, seg, now)
	l := p.row.lst
	s.tmu.Lock()
	r := &s.syn.rows[p.rowID]
	ok := !s.closed && !l.closed && r.used && r.promoting && r.tup == p.row.tup
	if r.used && r.promoting && r.tup == p.row.tup {
		r.promoting = false
		s.removeSynRow(p.rowID)
	}
	if ok {
		s.connIdx.insert(c.tup, c.id, c.gen)
		c.inIndex = true
		l.enqueue(c)
	} else {
		s.queued--
		l.qLen--
	}
	s.tmu.Unlock()
	if !ok {
		c.sendRST()
		c.release()
		return
	}
	l.signal()
	// 最後の ACK が運んだデータと FIN を処理する
	c.inputData(seg, now)
	c.afterInput(now)
}

// expireSynRows は SYN-ACK の再送の期限が来た行を処理する。再送の回数を使い切った行は消す。tmu を持って呼ぶ。
func (s *stack) expireSynRows(now int64) {
	t := &s.syn
	for k := range t.lists {
		for {
			id := t.lists[k].head
			if id < 0 {
				break
			}
			r := &t.rows[id]
			if r.deadline > now || r.promoting {
				break
			}
			if r.retries >= synackRetries {
				s.removeSynRow(id)
				continue
			}
			t.listRemove(id)
			r.retries++
			r.deadline = now + int64(synackRTO)<<r.retries
			t.listPush(id)
			r.pending, r.rtx = rowSendSynAck, true
			s.out.queueRow(id)
		}
	}
}

// pollRow は行の組の項目 id の packet を作る。
func (s *stack) pollRow(id int32, b []byte, now int64) int {
	s.tmu.Lock()
	defer s.tmu.Unlock()
	if s.closed {
		return 0
	}
	if int(id) < len(s.syn.rows) {
		r := &s.syn.rows[id]
		if !r.used || r.pending == rowSendNone {
			return 0
		}
		kind := r.pending
		r.pending = rowSendNone
		if kind == rowSendSynAck {
			if r.sentAt == 0 {
				r.sentAt = now
			}
			return s.buildSynAck(r, b, now)
		}
		h := tcpHeader{tup: r.tup, seq: r.iss + 1, ack: r.irs + 1, flags: flagACK, wnd: r.rcvWnd}
		return s.buildRowAck(b, h, r.tsOK, r.tsOffset, r.tsRecent, now)
	}
	return s.pollTWRow(id-int32(len(s.syn.rows)), b, now)
}

func tsClock(now int64) uint32 { return uint32(now / 1_000_000) }

// buildSynAck は行の SYN-ACK を作る。option は Linux と同じ並び(MSS、SACK-perm と TS、窓の scale)である。
func (s *stack) buildSynAck(r *synRow, b []byte, now int64) int {
	var o optWriter
	o.mss(uint16(s.ourMSS()))
	switch {
	case r.sackOK && r.tsOK:
		o.sackPermWithTS(tsClock(now)+r.tsOffset, r.tsRecent)
	case r.tsOK:
		o.ts(tsClock(now)+r.tsOffset, r.tsRecent)
	case r.sackOK:
		o.sackPerm()
	}
	if r.wsOK {
		o.wscale(rcvWindowShft)
	}
	h := tcpHeader{tup: r.tup, seq: r.iss, ack: r.irs + 1, flags: flagSYN | flagACK, wnd: r.rcvWnd}
	if len(b) < ipHeaderLen+tcpHeaderLen+maxOptionLen {
		return 0
	}
	writeTCP(b, s.nextID(), h, &o, 0)
	return finishTCP(b)
}

// buildRowAck は行から送る ACK を作る。
func (s *stack) buildRowAck(b []byte, h tcpHeader, ts bool, tsOffset, tsRecent uint32, now int64) int {
	if len(b) < ipHeaderLen+tcpHeaderLen+tsOptionLen {
		return 0
	}
	var o optWriter
	if ts {
		o.ts(tsClock(now)+tsOffset, tsRecent)
	}
	writeTCP(b, s.nextID(), h, &o, 0)
	return finishTCP(b)
}
