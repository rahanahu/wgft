package wgstack

import (
	"testing"
	"time"
)

// SACK による回復(wgstack-performance.md の「SACK による回復」)の試験。

const testSegPayload = testMTU - 40 - 12 // timestamp を付けた segment の中身

// sackConn は SACK と timestamp を交渉した接続を開き、DUT に n 個の segment を送らせて返す。
func sackConn(t *testing.T, segs int) (*testNet, *Conn, *sackPeer, []out) {
	t.Helper()
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, true, true)
	c := acceptOne(t, l)
	n.drain()
	if _, err := c.Write(make([]byte, segs*testSegPayload)); err != nil {
		t.Fatal(err)
	}
	outs := n.drain()
	return n, c, newSackPeer(p), outs
}

// seqSet は segment の開始の番号の集合。
func seqSet(outs []out) map[uint32]int {
	m := map[uint32]int{}
	for _, o := range outs {
		if len(o.seg.payload) > 0 {
			m[o.seg.seq]++
		}
	}
	return m
}

func TestSACKRecoveryRepairsSeveralHolesWithoutRTO(t *testing.T) {
	n, c, q, outs := sackConn(t, 10)
	if len(outs) != 10 {
		t.Fatalf("IW10 sent %d", len(outs))
	}
	lost := map[uint32]bool{outs[1].seg.seq: true, outs[4].seg.seq: true, outs[7].seg.seq: true}
	var resent []out
	q.deliver(outs, func(i int, o out) bool { return lost[o.seg.seq] })
	cs := c.c
	checkScoreboard(t, cs)
	if !cs.inRecovery {
		t.Fatal("not in recovery after three holes")
	}
	for range 20 {
		got := n.drain()
		checkScoreboard(t, cs)
		if p := cs.pipe(); cs.inRecovery && p > cs.cwnd && len(got) > 0 {
			t.Fatalf("pipe %d above cwnd %d after sending", p, cs.cwnd)
		}
		if len(got) == 0 {
			break
		}
		resent = append(resent, got...)
		q.deliver(got, nil)
	}
	set := seqSet(resent)
	for s := range set {
		if !lost[s] {
			t.Errorf("resent %d, which the peer SACKed", s-outs[0].seg.seq)
		}
	}
	for s := range lost {
		if set[s] != 1 {
			t.Errorf("hole %d resent %d times", s-outs[0].seg.seq, set[s])
		}
	}
	st := n.d.Stats()
	if st.RTOs != 0 || st.FastRecoveries != 1 || st.RetransFast != 3 || cs.inRecovery || cs.sndUna != cs.sndMax {
		t.Fatalf("stats %+v inRecovery %v una==max %v", st, cs.inRecovery, cs.sndUna == cs.sndMax)
	}
	if cs.cwnd != cs.ssthresh {
		t.Fatalf("cwnd %d after recovery, ssthresh %d", cs.cwnd, cs.ssthresh)
	}
}

func TestRTOKeepsSACKedRangesAndSkipsThem(t *testing.T) {
	n, c, q, outs := sackConn(t, 10)
	cs := c.c
	// 1 と 2 を失い、残りを SACK で知らせる。回復の再送も失う
	q.deliver(outs, func(i int, o out) bool { return i == 1 || i == 2 })
	n.drain()
	for {
		n.advance(10 * time.Millisecond)
		if n.d.Stats().RTOs > 0 {
			break
		}
		n.drain()
	}
	checkScoreboard(t, cs)
	if cs.sacked != 7*uint32(testSegPayload) {
		t.Fatalf("SACKed bytes %d after the RTO", cs.sacked)
	}
	var resent []out
	for range 20 {
		got := n.drain()
		if len(got) == 0 {
			break
		}
		resent = append(resent, got...)
		q.deliver(got, nil)
		checkScoreboard(t, cs)
	}
	for s := range seqSet(resent) {
		if s != outs[1].seg.seq && s != outs[2].seg.seq {
			t.Errorf("resent %d after the RTO, which the peer SACKed", (s-outs[0].seg.seq)/uint32(testSegPayload))
		}
	}
	if cs.sndUna != cs.sndMax {
		t.Fatalf("not everything acknowledged: una %d max %d", cs.sndUna, cs.sndMax)
	}
}

func TestPMTUDropResendsLargeRecordsInPieces(t *testing.T) {
	n, c, q, outs := sackConn(t, 10)
	cs := c.c
	// 5 から 9 を SACK で知らせる
	q.deliver(outs, func(i int, o out) bool { return i < 5 })
	n.drain()
	recs := cs.recs.n
	cs.mu.Lock()
	cs.pmtuDrop(outs[0].seg.seq, 600, int64(n.clk.Now()))
	cs.mu.Unlock()
	if cs.recs.n != recs {
		t.Fatalf("records %d, were %d", cs.recs.n, recs)
	}
	end := outs[5].seg.seq
	covered := outs[0].seg.seq
	sent := 0
	for range 50 {
		got := n.drain()
		if len(got) == 0 {
			break
		}
		for _, o := range got {
			if len(o.seg.payload) == 0 {
				continue
			}
			sent++
			if len(o.seg.payload) > 600-40-12 {
				t.Fatalf("segment of %d bytes after the PMTU drop", len(o.seg.payload))
			}
			if !seqLT(o.seg.seq, end) {
				t.Fatalf("resent SACKed data at %d", o.seg.seq-outs[0].seg.seq)
			}
			if o.seg.seq == covered {
				covered += uint32(len(o.seg.payload))
			}
		}
		q.deliver(got, nil)
		checkScoreboard(t, cs)
	}
	if covered != end || cs.sndUna != cs.sndMax {
		t.Fatalf("resent up to %d, want %d", covered-outs[0].seg.seq, end-outs[0].seg.seq)
	}
	checkScoreboard(t, cs)
	if st := n.d.Stats(); st.RetransPMTU != uint64(sent) {
		t.Fatalf("RetransPMTU %d, %d segments", st.RetransPMTU, sent)
	}
}

func TestSACKRenegingClearsMarksOnTheRTOPath(t *testing.T) {
	n, c, q, outs := sackConn(t, 10)
	cs := c.c
	// 3 から 9 を SACK で知らせた後、相手が 0 から 2 だけを累積で確認し、SACK した 3 から先を捨てる
	q.deliver(outs, func(i int, o out) bool { return i < 3 })
	n.drain()
	q.ivs = nil
	q.p.rcv = outs[3].seg.seq
	q.ack()
	now := int64(n.clk.Now())
	want := now + max(cs.srtt/2, int64(renegeDelayMin))
	if cs.tdl[tmrRetrans] != want {
		t.Fatalf("retransmit timer at %d, want %d", cs.tdl[tmrRetrans]-now, want-now)
	}
	n.drain()
	n.advance(time.Duration(want - now))
	st := n.d.Stats()
	if st.SACKReneging != 1 || st.RTOs != 1 || cs.sacked != 0 {
		t.Fatalf("stats %+v sacked %d", st, cs.sacked)
	}
	checkScoreboard(t, cs)
	got := n.drain()
	if len(got) != 1 || got[0].seg.seq != outs[3].seg.seq {
		t.Fatalf("after reneging sent %v, want the first reneged segment", got)
	}
	for range 50 {
		q.deliver(got, nil)
		if got = n.drain(); len(got) == 0 {
			break
		}
	}
	if cs.sndUna != cs.sndMax {
		t.Fatal("did not resend the reneged data up to the cumulative ACK")
	}
}

// 期限の前に相手が SACK 済みの記録を累積で確認すれば、取り消しの扱いにしない。
func TestSACKRenegeSuspicionClearedByTheNextACK(t *testing.T) {
	n, c, q, outs := sackConn(t, 10)
	cs := c.c
	q.deliver(outs, func(i int, o out) bool { return i < 3 })
	n.drain()
	q.p.rcv = outs[3].seg.seq
	q.ack() // 0 から 2 を確認し、3 から 9 は SACK のまま
	q.p.rcv = outs[9].seg.seq + uint32(testSegPayload)
	q.ivs = nil
	q.ack()
	n.advance(time.Second)
	if st := n.d.Stats(); st.SACKReneging != 0 || st.RTOs != 0 || cs.sndUna != cs.sndMax {
		t.Fatalf("stats %+v", st)
	}
}

func TestSecondRTOAtTheSameUnaClearsSACK(t *testing.T) {
	n, c, q, outs := sackConn(t, 10)
	cs := c.c
	q.deliver(outs, func(i int, o out) bool { return i == 0 })
	n.drain()
	for n.d.Stats().RTOs < 1 {
		n.advance(10 * time.Millisecond)
		n.drain()
	}
	if cs.sacked == 0 || n.d.Stats().SACKReneging != 0 {
		t.Fatal("the first RTO cleared the SACK marks")
	}
	for n.d.Stats().RTOs < 2 {
		n.advance(10 * time.Millisecond)
		n.drain()
	}
	if cs.sacked != 0 || n.d.Stats().SACKReneging != 1 {
		t.Fatalf("the second RTO at the same SND.UNA kept %d SACKed bytes", cs.sacked)
	}
	checkScoreboard(t, cs)
}

func TestLimitedTransmit(t *testing.T) {
	for _, sack := range []bool{false, true} {
		n := newTestNet(t, smallLimits())
		l := listen(t, n, 80)
		p := n.handshake(40000, 80, true, sack, true)
		c := acceptOne(t, l)
		n.drain()
		c.Write(make([]byte, 20*testSegPayload))
		outs := n.drain()
		q := newSackPeer(p)
		// 1 つ目を確認する。slow start でさらに 2 つ送る
		q.recv(outs[0])
		q.ack()
		outs = append(outs, n.drain()...)
		// 2 つ目を失い、3 つ目と 4 つ目への重複した ACK で 1 つずつ新しい segment を送る
		for i := 2; i <= 3; i++ {
			q.recv(outs[i])
			q.ack()
			got := n.drain()
			if len(got) != 1 || got[0].seg.seq != outs[len(outs)-1].seg.seq+uint32(testSegPayload) {
				t.Fatalf("sack %v: duplicate ACK %d sent %v, want one new segment", sack, i-1, got)
			}
			outs = append(outs, got...)
		}
		if c.c.inRecovery || n.d.Stats().RetransFast != 0 {
			t.Fatalf("sack %v: recovery before the third duplicate ACK", sack)
		}
	}
}

// TestRecoveryStaysWithinCwnd は、多くの損失のある窓の回復の間、送った後の pipe が輻輳の窓を超えず、
// PRR が回復の間に送る量を届いた量の ssthresh / RecoverFS 倍に抑えることを確かめる。
func TestRecoveryStaysWithinCwnd(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, true, true)
	c := acceptOne(t, l)
	n.drain()
	cs := c.c
	c.Write(make([]byte, 150*testSegPayload))
	q := newSackPeer(p)
	outs := n.drain()
	// slow start で窓を広げる
	for range 3 {
		var next []out
		for _, o := range outs {
			q.recv(o)
			q.ack()
			next = append(next, n.drain()...)
		}
		outs = next
	}
	// 1 つおきに失う
	maxOut := uint32(0)
	for i, o := range outs {
		if i%2 == 1 {
			continue
		}
		q.recv(o)
		q.ack()
		got := n.drain()
		checkScoreboard(t, cs)
		if cs.inRecovery {
			if len(got) > 0 && cs.pipe() > cs.cwnd+uint32(testSegPayload) {
				t.Fatalf("pipe %d above cwnd %d", cs.pipe(), cs.cwnd)
			}
			fs := uint64(max(cs.recoverFS, 1))
			if lim := (uint64(cs.prrDelivered)*uint64(cs.ssthresh)+fs-1)/fs + uint64(testSegPayload); cs.pipe() > cs.ssthresh && uint64(cs.prrOut) > lim {
				t.Fatalf("PRR sent %d with %d delivered, limit %d", cs.prrOut, cs.prrDelivered, lim)
			}
			maxOut = max(maxOut, cs.prrOut)
		}
	}
	if maxOut == 0 {
		t.Fatal("no sending during recovery")
	}
	if n.d.Stats().RTOs != 0 {
		t.Fatal("RTO during recovery")
	}
}
