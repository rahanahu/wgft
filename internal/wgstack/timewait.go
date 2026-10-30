package wgstack

// TIME_WAIT の表(設計文書の「TIME_WAIT の表」)。行に移る条件を満たした TIME_WAIT と FIN_WAIT_2 の接続を、
// バッファを持たない小さな行に移す。行は固定の配列の上の両方向の list に入れた順で並べ、先頭から期限を
// 過ぎた行を外す。満杯のときは最も古い行を外して数える。行は表の錠(stack.tmu)で守る。
//
// 接続の枠で TIME_WAIT に入った後に行に移る接続は、残りの期限を持って list の末尾に入るので、list は
// 期限の順にならないことがある。先頭からの掃除は先頭が期限を過ぎるまで後ろの行を外さないので、引くときにも
// 期限を確かめ、過ぎた行はその場で外す。

const (
	twStateFinWait2 uint8 = iota + 1
	twStateTimeWait
)

type twRow struct {
	tup      tuple
	sndNxt   uint32
	rcvNxt   uint32
	tsRecent uint32
	tsOffset uint32
	deadline int64
	origin   int32 // 元の接続の枠
	gen      uint32
	prev     int32
	next     int32
	wnd      uint16
	wscale   uint8 // 広告する窓の scale
	state    uint8
	tsOK     bool
	used     bool
	pending  bool
}

type twTable struct {
	rows       []twRow
	idx        index
	free       []int32
	head, tail int32
	n          int
}

func newTWTable(n int, key sipKey) twTable {
	t := twTable{rows: make([]twRow, n), idx: newIndex(n, key), free: make([]int32, n), head: -1, tail: -1}
	for i := range t.free {
		t.free[i] = int32(n - 1 - i)
	}
	return t
}

func (t *twTable) find(tup tuple) int32 {
	id, _ := t.idx.find(tup)
	return id
}

func (t *twTable) pushBack(id int32) {
	r := &t.rows[id]
	r.prev, r.next = t.tail, -1
	if t.tail >= 0 {
		t.rows[t.tail].next = id
	} else {
		t.head = id
	}
	t.tail = id
}

func (t *twTable) unlink(id int32) {
	r := &t.rows[id]
	if r.prev >= 0 {
		t.rows[r.prev].next = r.next
	} else {
		t.head = r.next
	}
	if r.next >= 0 {
		t.rows[r.next].prev = r.prev
	} else {
		t.tail = r.prev
	}
	r.prev, r.next = -1, -1
}

func (t *twTable) nextDeadline() int64 {
	if t.head < 0 {
		return 0
	}
	return t.rows[t.head].deadline
}

func (s *stack) twRowID(id int32) int32 { return int32(len(s.syn.rows)) + id }

func (s *stack) removeTWRow(id int32) {
	t := &s.tw
	r := &t.rows[id]
	if !r.used {
		return
	}
	t.idx.remove(r.tup)
	t.unlink(id)
	s.out.unqueueRow(s.twRowID(id))
	r.used = false
	t.free = append(t.free, id)
	t.n--
}

// addTWRow は接続の枠 c の状態を行に移す。満杯なら最も古い行を外して数える。枠が送るはずだった ACK
// (例えば自分の FIN を確認する相手の FIN への ACK)は、行が送る。tmu を持って呼ぶ。
func (s *stack) addTWRow(c *tcb, state uint8, deadline, now int64) {
	t := &s.tw
	if len(t.free) == 0 {
		s.removeTWRow(t.head)
		s.refused(&s.twEvicted, &s.twGate, now, "evicted the oldest TIME_WAIT rows because the table was full")
	}
	id := t.free[len(t.free)-1]
	t.free = t.free[:len(t.free)-1]
	r := &t.rows[id]
	*r = twRow{
		tup:      c.tup,
		sndNxt:   c.sndMax,
		rcvNxt:   c.rcvNxt,
		tsRecent: c.tsRecent,
		tsOffset: c.tsOffset,
		deadline: deadline,
		origin:   c.id,
		gen:      c.gen,
		wnd:      c.windowField(),
		wscale:   c.rcvWscale,
		state:    state,
		tsOK:     c.tsOK,
		used:     true,
	}
	t.idx.insert(c.tup, id, 0)
	t.pushBack(id)
	t.n++
	s.noteDeadline(deadline)
	if c.ackNow {
		s.twAck(id, now, false)
	}
}

// expireTWRows は先頭から期限を過ぎた行を外す。tmu を持って呼ぶ。
func (s *stack) expireTWRows(now int64) {
	for s.tw.head >= 0 && s.tw.rows[s.tw.head].deadline <= now {
		s.removeTWRow(s.tw.head)
	}
}

func (s *stack) twAck(id int32, now int64, limited bool) {
	if limited && !s.challengeAllowed(now) {
		return
	}
	s.tw.rows[id].pending = true
	s.out.queueRow(s.twRowID(id))
}

// acceptable は行への segment が RFC 9293 3.10.7.4 の受け入れの範囲にあるかを返す。窓は行に移した時に
// 広告した窓である。
func (r *twRow) acceptable(seg *segment) bool {
	wnd := uint32(r.wnd) << r.wscale
	n := seg.seqLen()
	inWnd := func(x uint32) bool { return seqGE(x, r.rcvNxt) && seqLT(x, r.rcvNxt+wnd) }
	switch {
	case n == 0 && wnd == 0:
		return seg.seq == r.rcvNxt
	case n == 0:
		return inWnd(seg.seq)
	case wnd == 0:
		return false
	}
	return inWnd(seg.seq) || inWnd(seg.seq+n-1)
}

// rfc6191 は、TIME_WAIT の 4 つ組への新しい SYN を受け入れてよいかを返す(RFC 6191 2 節)。前の接続が
// timestamp を使っていれば、SYN が timestamp を持つときはその値が前の接続の最後の値より大きいこと、
// 持たないときはシーケンス番号が前の接続の最後の番号より大きいことを求める。
func rfc6191(seg *segment, tsOK bool, tsRecent, rcvNxt uint32) bool {
	if tsOK && seg.opt.hasTS {
		return seqGT(seg.opt.tsVal, tsRecent)
	}
	return seqGT(seg.seq, rcvNxt)
}

// twInput は行への segment を処理し、処理し終えたかを返す。偽を返すのは、TIME_WAIT の行が RFC 6191 の
// 条件を満たす SYN を受けて行を外したか、期限を過ぎた行を外したときで、呼び出し側はその segment を
// どの行にも当たらない segment として扱う。SYN で行を外したときは reuse に前の接続の SND.NXT を書く。tmu を持って呼ぶ。
func (s *stack) twInput(id int32, seg *segment, now int64, reuse *reuseISS) bool {
	r := &s.tw.rows[id]
	if r.deadline <= now {
		s.removeTWRow(id)
		return false
	}
	if seg.has(flagRST) {
		// Linux の既定(tcp_rfc1337=0)と同じく、番号の合う RST で行を外す
		if seg.seq == r.rcvNxt {
			s.removeTWRow(id)
		}
		return true
	}
	if seg.has(flagSYN) {
		if !seg.has(flagACK) && r.state == twStateTimeWait && rfc6191(seg, r.tsOK, r.tsRecent, r.rcvNxt) {
			// 行を外す前に、新しい行を作れるかを確かめる。作れないまま外すと、相手が再送した SYN は
			// 前の接続の番号を知らない時計だけの ISN を受ける
			switch s.reuseVerdict(seg) {
			case reuseNoListener:
				s.twAck(id, now, true)
				return true
			case reuseFull:
				s.refuseReuse(now)
				return true
			}
			*reuse = reuseISS{ok: true, sndNxt: r.sndNxt}
			s.removeTWRow(id)
			return false
		}
		s.twAck(id, now, true)
		return true
	}
	if r.state == twStateFinWait2 {
		// 確立した接続と同じく、PAWS と窓の外の segment には速さを抑えた ACK を返すだけにする(RFC 7323 5.3、
		// RFC 9293 3.10.7.4)。窓の外の古い data で行を外させない
		if (r.tsOK && seg.opt.hasTS && seqLT(seg.opt.tsVal, r.tsRecent)) || !r.acceptable(seg) {
			s.twAck(id, now, true)
			return true
		}
		if len(seg.payload) > 0 && seqGT(seg.seq+uint32(len(seg.payload)), r.rcvNxt) {
			// 閉じた後に届いたデータ。Linux と同じく RST を返して行を外す
			s.replyRST(seg)
			s.removeTWRow(id)
			return true
		}
		if seg.has(flagFIN) && seg.seq+uint32(len(seg.payload)) == r.rcvNxt {
			if r.tsOK && seg.opt.hasTS && seqGE(seg.opt.tsVal, r.tsRecent) {
				r.tsRecent = seg.opt.tsVal
			}
			r.rcvNxt++
			r.state = twStateTimeWait
			r.deadline = now + int64(twTimeout)
			s.tw.unlink(id)
			s.tw.pushBack(id)
			s.twAck(id, now, false)
			s.noteDeadline(r.deadline)
		}
		return true
	}
	// TIME_WAIT
	if seg.has(flagFIN) && seg.seq+uint32(len(seg.payload))+1 == r.rcvNxt {
		// 再送された FIN。ACK を返し、Linux と同じく期限を数え直す。ACK はこの FIN の TSval を返す
		if r.tsOK && seg.opt.hasTS && seqGE(seg.opt.tsVal, r.tsRecent) {
			r.tsRecent = seg.opt.tsVal
		}
		r.deadline = now + int64(twTimeout)
		s.tw.unlink(id)
		s.tw.pushBack(id)
		s.twAck(id, now, false)
		return true
	}
	if seg.seqLen() > 0 || seg.seq != r.rcvNxt {
		s.twAck(id, now, true)
	}
	return true
}

// pollTWRow は TIME_WAIT の行の ACK を作る。tmu を持って呼ぶ。
func (s *stack) pollTWRow(id int32, b []byte, now int64) int {
	r := &s.tw.rows[id]
	if !r.used || !r.pending {
		return 0
	}
	r.pending = false
	h := tcpHeader{tup: r.tup, seq: r.sndNxt, ack: r.rcvNxt, flags: flagACK, wnd: r.wnd}
	return s.buildRowAck(b, h, r.tsOK, r.tsOffset, r.tsRecent, now)
}

// abortTWRow は、元の接続の値の Abort で、その接続の行が表に残っていれば RST を送って外す。tmu を
// 持って呼ぶ。
func (s *stack) abortTWRow(tup tuple, origin int32, gen uint32) {
	id := s.tw.find(tup)
	if id < 0 {
		return
	}
	r := &s.tw.rows[id]
	if r.origin != origin || r.gen != gen {
		return
	}
	s.sendCtl(tcpHeader{tup: tup, seq: r.sndNxt, ack: r.rcvNxt, flags: flagRST | flagACK})
	s.removeTWRow(id)
}
