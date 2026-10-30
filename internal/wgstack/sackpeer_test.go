package wgstack

import (
	"slices"
	"testing"
)

// sackPeer は DUT のデータを受ける相手の受信の側。順序外の区間を覚え、累積の確認と、最近に伸びた順の
// SACK の block を返す。
type sackPeer struct {
	p     *peerConn
	ivs   []peerIv
	touch int
}

type peerIv struct {
	l, r  uint32
	touch int
}

func newSackPeer(p *peerConn) *sackPeer { return &sackPeer{p: p} }

// recv は DUT の segment o を受ける。
func (q *sackPeer) recv(o out) {
	if o.seg.opt.hasTS {
		q.p.dutTS = o.seg.opt.tsVal
	}
	s := o.seg.seq
	e := s + uint32(len(o.seg.payload))
	if o.seg.has(flagFIN) {
		e++
	}
	if !seqGT(e, q.p.rcv) {
		return
	}
	q.touch++
	if seqLE(s, q.p.rcv) {
		q.p.rcv = e
	} else {
		q.ivs = append(q.ivs, peerIv{s, e, q.touch})
	}
	// 区間を合わせ、累積の確認に届いた区間を取り込む
	slices.SortFunc(q.ivs, func(a, b peerIv) int { return int(int32(a.l - b.l)) })
	var m []peerIv
	for _, iv := range q.ivs {
		if k := len(m) - 1; k >= 0 && seqLE(iv.l, m[k].r) {
			m[k].r = seqMax(m[k].r, iv.r)
			m[k].touch = max(m[k].touch, iv.touch)
			continue
		}
		m = append(m, iv)
	}
	q.ivs = q.ivs[:0]
	for _, iv := range m {
		if seqLE(iv.l, q.p.rcv) {
			q.p.rcv = seqMax(q.p.rcv, iv.r)
			continue
		}
		q.ivs = append(q.ivs, iv)
	}
}

// blocks は最近に伸びた順の SACK の block を最大 max 個返す。
func (q *sackPeer) blocks(max int) []sackBlock {
	ivs := slices.Clone(q.ivs)
	slices.SortFunc(ivs, func(a, b peerIv) int { return b.touch - a.touch })
	var bs []sackBlock
	for _, iv := range ivs {
		if len(bs) == max {
			break
		}
		bs = append(bs, sackBlock{iv.l, iv.r})
	}
	return bs
}

// ack は今の累積の確認と SACK の block を DUT に送る。
func (q *sackPeer) ack() {
	s := q.p.seg(flagACK, nil)
	s.sack = q.blocks(3)
	q.p.n.inject(s)
}

// deliver は outs を順に受け、受けるたびに ACK を返す。drop が真の segment は失う。
func (q *sackPeer) deliver(outs []out, drop func(i int, o out) bool) {
	for i, o := range outs {
		if drop != nil && drop(i, o) {
			continue
		}
		q.recv(o)
		q.ack()
	}
}

// checkScoreboard は接続の scoreboard の欄を記録を順に調べて求め直し、増減で保つ値と比べる。
func checkScoreboard(t testing.TB, c *tcb) {
	t.Helper()
	var sacked, beyondB, rtx uint32
	var beyondC int32
	seq := c.sndUna
	for i := 0; i < c.recs.n; i++ {
		r := c.recs.at(i)
		if r.seq != seq {
			t.Fatalf("record %d starts at %d, want %d", i, r.seq-c.sndUna, seq-c.sndUna)
		}
		seq += uint32(r.length)
		if c.isSacked(r) {
			sacked += uint32(r.length)
			if i >= int(c.lossIdx) {
				beyondB += uint32(r.length)
				beyondC++
			}
			for k := i; k < i+int(r.skip) && k < c.recs.n; k++ {
				if !c.isSacked(c.recs.at(k)) {
					t.Fatalf("record %d skips over unSACKed record %d", i, k)
				}
			}
		}
		if c.rtxLive(r) {
			rtx += uint32(r.length)
		}
	}
	if c.recs.n > 0 && seq != c.sndMax {
		t.Fatalf("records end at %d, SND.MAX is %d", seq-c.sndUna, c.sndMax-c.sndUna)
	}
	if sacked != c.sacked || beyondB != c.beyondBytes || beyondC != c.beyondCnt || rtx != c.rtxBytes {
		t.Fatalf("scoreboard: sacked %d/%d beyond %d/%d count %d/%d rtx %d/%d", c.sacked, sacked, c.beyondBytes, beyondB, c.beyondCnt, beyondC, c.rtxBytes, rtx)
	}
	if int(c.lossIdx) > c.recs.n || int(c.rxtIdx) > c.recs.n {
		t.Fatalf("lossIdx %d rxtIdx %d beyond %d records", c.lossIdx, c.rxtIdx, c.recs.n)
	}
	// pipe を RFC 6675 の定義どおりに求める
	var pipe int64
	for i := 0; i < c.recs.n; i++ {
		r := c.recs.at(i)
		if c.isSacked(r) {
			continue
		}
		if i >= int(c.lossIdx) {
			pipe += int64(r.length)
		}
		if c.rtxLive(r) {
			pipe += int64(r.length)
		}
	}
	if !c.sackOK && !c.inRecovery && c.dupAcks > 0 {
		pipe -= min(pipe, int64(min(c.dupAcks, dupThresh-1)*c.segMSS()))
	}
	if pipe != int64(c.pipe()) {
		t.Fatalf("pipe %d, recomputed %d", c.pipe(), pipe)
	}
}
