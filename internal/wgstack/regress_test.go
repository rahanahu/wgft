package wgstack

import (
	"testing"
	"time"
)

// TIME_WAIT の行が RFC 6191 の SYN で外れた後、新しい接続の ISS が前の接続の SND.NXT より先にあり
// (Linux は tw_snd_nxt + 65537 を使う)、TSval が前の接続より大きいことを確かめる。
func TestTimeWaitReuseISSAndTimestampAdvance(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	const size = 1 << 20
	go func() {
		c.Write(make([]byte, size))
		c.Close()
	}()
	for i := 0; i < 100000 && n.d.Stats().TWRows == 0; i++ {
		p.absorb(n.drain())
		p.ack(nil)
		if i%50 == 0 {
			n.advance(time.Millisecond)
		}
	}
	p.fin()
	n.drain()
	if n.d.Stats().TWRows != 1 {
		t.Fatalf("no TIME_WAIT row: %+v", n.d.Stats())
	}
	oldNxt := p.rcv
	n.advance(time.Second)
	p.tsVal += 1000
	n.inject(tseg{sport: 40000, dport: 80, seq: p.snd + 100000, flags: flagSYN, wnd: 65535, mss: 1380, ws: 7, ts: true, tsVal: p.tsVal})
	outs := n.drain()
	if len(outs) != 1 || outs[0].seg.flags != flagSYN|flagACK {
		t.Fatalf("no SYN-ACK for the reuse: %v", outs)
	}
	newISS := outs[0].seg.seq
	oldTS := p.dutTS
	t.Logf("old SND.NXT %d new ISS %d; new ISS is %d bytes behind", oldNxt, newISS, int32(oldNxt-newISS))
	if seqLT(newISS, oldNxt) {
		t.Errorf("new ISS %d is inside the previous incarnation's sequence space (old SND.NXT %d)", newISS, oldNxt)
	}
	// 新しい接続の TSval は前の接続の TSval より大きく、相手の PAWS を通る
	if !seqGT(outs[0].seg.opt.tsVal, oldTS) {
		t.Errorf("SYN-ACK TSval %d is not above the previous incarnation's %d", outs[0].seg.opt.tsVal, oldTS)
	}
}

// TestTimeWaitSlotReuseISS は、枠に残る TIME_WAIT の接続(CloseWrite の後で、アプリケーションがまだ閉じて
// いない)を RFC 6191 の SYN が使い直すときも、新しい ISS が前の接続の SND.NXT より先にあることを確かめる。
func TestTimeWaitSlotReuseISS(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	c.Write(make([]byte, 50000))
	c.CloseWrite()
	for i := 0; i < 1000 && !n.d.s.conns[c.c.id].finAcked(); i++ {
		p.absorb(n.drain())
		p.ack(nil)
	}
	p.fin()
	n.drain()
	if st := n.d.s.conns[c.c.id].state; st != stTimeWait {
		t.Fatalf("state %v", st)
	}
	oldNxt := p.rcv
	p.tsVal += 1000
	n.inject(tseg{sport: 40000, dport: 80, seq: p.snd + 100000, flags: flagSYN, wnd: 65535, mss: 1380, ws: 7, ts: true, tsVal: p.tsVal})
	var sa *out
	for _, o := range n.drain() {
		if o.seg.flags == flagSYN|flagACK {
			sa = &o
		}
	}
	if sa == nil {
		t.Fatal("no SYN-ACK for the reuse")
	}
	if seqLT(sa.seg.seq, oldNxt+65537) {
		t.Errorf("new ISS %d is not 65537 beyond the old SND.NXT %d", sa.seg.seq, oldNxt)
	}
}

// TestFutureTSEcrIsIgnored は、自分の今の TSval より先の TSecr を RTT の測定に使わないことを確かめる。
func TestFutureTSEcrIsIgnored(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	c.Write([]byte("x"))
	p.absorb(n.drain())
	cs := &n.d.s.conns[c.c.id]
	before := cs.rto
	s := p.seg(flagACK, nil)
	s.tsEcr = p.dutTS + 1_000_000
	n.inject(s)
	if cs.rto != before {
		t.Fatalf("RTO changed from %v to %v on a TSecr from the future", before, cs.rto)
	}
}

// TestFastRetransmitMarksEveryRecord は、高速の再送が覆うすべての送信の記録に再送の印を付けることを
// 確かめる(Karn の規則)。
func TestFastRetransmitMarksEveryRecord(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	for range 20 {
		c.Write([]byte{1, 2, 3}) // 小さな segment を 20 個
		n.drain()
	}
	for range 3 {
		p.ack(nil)
	}
	got := n.drain()
	if len(got) == 0 || len(got[0].seg.payload) != 60 {
		t.Fatalf("fast retransmit %v", got)
	}
	cs := &n.d.s.conns[c.c.id]
	for i := 0; i < cs.recs.n; i++ {
		if cs.recs.at(i).flags&recRetransmitted == 0 {
			t.Fatalf("record %d of %d is not marked retransmitted", i, cs.recs.n)
		}
	}
}

// TestPromoteAfterCloseLeavesNothing は、Device の Close と競って最後の ACK の処理が接続を確立しても、
// 記録の輪と chunk が残らないことを確かめる。
func TestPromoteAfterCloseLeavesNothing(t *testing.T) {
	n := newTestNet(t, smallLimits())
	listen(t, n, 80)
	n.inject(tseg{sport: 9, dport: 80, seq: 1, flags: flagSYN, wnd: 65535, mss: 1380, ws: 7})
	sa := n.drain()[0]
	pkt := buildPeer(tseg{sport: 9, dport: 80, seq: 2, ack: sa.seg.seq + 1, flags: flagACK, wnd: 65535, ws: -1, payload: []byte("data")})
	ip, _ := parseIPv4(pkt)
	seg, _ := parseTCP(&ip)
	s := n.d.s
	s.tmu.Lock()
	pr, ok := s.synInput(s.syn.find(seg.tup), &seg, 0)
	s.tmu.Unlock()
	if !ok {
		t.Fatal("no promotion")
	}
	n.d.Close()
	s.promote(pr, &seg, 0)
	s.chunks.put(new(chunk))
	s.chunks.held++
	if st := s.stats(); st.RecordBytes != 0 || st.IntervalBytes != 0 || st.ChunkBytes != 0 || st.Conns != 0 || len(s.chunks.free) != 0 {
		t.Fatalf("after a promotion that lost the race with Close: %+v, %d pooled chunks", st, len(s.chunks.free))
	}
}
