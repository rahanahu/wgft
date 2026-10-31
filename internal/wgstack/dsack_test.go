package wgstack

import "testing"

// TestDSACKBlocksForDuplicateParts は、RCV.NXT より前の重複、順序外の区間の内側の重複、前半だけが重複する segment に、
// 重複の部分を先頭の block にした D-SACK を返し、次の ACK には載せないことを確かめる(RFC 2883、Linux の
// tcp_dsack_set)。
func TestDSACKBlocksForDuplicateParts(t *testing.T) {
	n := newTestNet(t, smallLimits())
	_, p := n.accepted(true, true)
	base := p.snd
	p.ack(make([]byte, 1000)) // [0, 1000)
	n.drain()
	// 1. RCV.NXT より前の重複
	s := p.seg(flagACK, make([]byte, 500))
	s.seq = base + 200
	n.inject(s)
	outs := n.drain()
	if len(outs) != 1 || outs[0].seg.opt.nsack < 1 || outs[0].seg.opt.sack[0] != (sackBlock{base + 200, base + 700}) {
		t.Errorf("duplicate below RCV.NXT: %v", outs)
	}
	// 2. 順序外の区間の内側の重複:先頭は D-SACK、2 つ目はそれを含む区間
	s = p.seg(flagACK, make([]byte, 1000))
	s.seq = base + 3000 // [3000, 4000)
	n.inject(s)
	s = p.seg(flagACK, make([]byte, 300))
	s.seq = base + 6000 // 別の区間 [6000, 6300)
	n.inject(s)
	n.drain()
	s = p.seg(flagACK, make([]byte, 200))
	s.seq = base + 3200
	n.inject(s)
	outs = n.drain()
	if len(outs) != 1 {
		t.Fatalf("dup in interval: %v", outs)
	}
	o := outs[0].seg.opt
	if o.nsack < 2 || o.sack[0] != (sackBlock{base + 3200, base + 3400}) || o.sack[1] != (sackBlock{base + 3000, base + 4000}) {
		t.Errorf("want D-SACK [3200,3400) then [3000,4000), got %v", o.sack[:o.nsack])
	}
	// 3. 前半が重複で後半が新しい segment(Linux は重複の部分を D-SACK で知らせる)
	s = p.seg(flagACK, make([]byte, 600))
	s.seq = base + 700 // [700,1300)、700-1000 は重複
	n.inject(s)
	outs = n.drain()
	if len(outs) != 1 || outs[0].seg.opt.nsack < 1 || outs[0].seg.opt.sack[0] != (sackBlock{base + 700, base + 1000}) {
		t.Errorf("partial overlap: want D-SACK [700,1000), got %v", outs)
	}
	// 4. 次の ACK には D-SACK を載せない
	p.snd = base + 1300
	p.ack(nil)
	s = p.seg(flagACK, make([]byte, 10))
	s.seq = base + 6300
	n.inject(s)
	for _, x := range n.drain() {
		for _, b := range x.seg.opt.sack[:x.seg.opt.nsack] {
			if b == (sackBlock{base + 3200, base + 3400}) || b == (sackBlock{base + 200, base + 700}) {
				t.Errorf("D-SACK repeated: %v", x)
			}
		}
	}
}

// TestDSACKExtendsAndQuickackOnlyRises は、ACK を送る前に届いた 2 つ目の重複が接していれば D-SACK の block を広げ、
// 重複が対話の印を外して quickack の数を窓に合わせて上げ、進んでいる数を下げないことを確かめる。
func TestDSACKExtendsAndQuickackOnlyRises(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	n.handshake(40000, 80, true, true, true)
	acceptOne(t, l)
	cs := &n.d.s.conns[0]
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.pingpong = true
	cs.quickAcks = 0
	cs.noteDuplicate(100, 50, 0)
	cs.noteDuplicate(150, 50, 0)
	if cs.dsack != (sackBlock{100, 200}) {
		t.Fatalf("D-SACK %v, want [100,200)", cs.dsack)
	}
	cs.noteDuplicate(500, 10, 0) // 接しない重複は最初の block を保つ
	if cs.dsack != (sackBlock{100, 200}) {
		t.Fatalf("D-SACK %v after a separate duplicate", cs.dsack)
	}
	if cs.pingpong || cs.quickAcks != quickackMax {
		t.Fatalf("pingpong %v quickAcks %d after a duplicate", cs.pingpong, cs.quickAcks)
	}
	cs.quickAcks = quickackMax
	cs.rcvMSSEst = 1 << 20 // 窓に対して大きな MSS:窓から求める数は 2
	cs.raiseQuickack()
	if cs.quickAcks != quickackMax {
		t.Fatalf("raiseQuickack lowered a running count to %d", cs.quickAcks)
	}
}
