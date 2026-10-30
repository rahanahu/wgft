package wgstack

import (
	"testing"
	"time"
)

// RACK-TLP(RFC 8985、wgstack-performance.md の「RACK-TLP」)の試験。

const testRTT = 20 * time.Millisecond

// rackConn は SACK を交渉した接続に RTT を与え、DUT に segs 個の segment を送らせて返す。手で進める時計の
// 握手は RTT が 0 なので、RTT の推定を直接与える。
func rackConn(t *testing.T, segs int) (*testNet, *tcb, *sackPeer, []out) {
	n, _, cs, q, outs := rackConnApp(t, segs)
	return n, cs, q, outs
}

// rackConnApp は rackConn と同じで、アプリケーションの側の接続も返す。
func rackConnApp(t *testing.T, segs int) (*testNet, *Conn, *tcb, *sackPeer, []out) {
	t.Helper()
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, true, true)
	c := acceptOne(t, l)
	n.drain()
	cs := c.c
	cs.mu.Lock()
	cs.srtt, cs.rttvar, cs.minRTT, cs.hasRTT, cs.hasMinRTT = int64(testRTT), int64(testRTT)/2, int64(testRTT), true, true
	cs.rto = int64(rtoMin)
	cs.mu.Unlock()
	if _, err := c.Write(make([]byte, segs*testSegPayload)); err != nil {
		t.Fatal(err)
	}
	outs := n.drain()
	n.advance(testRTT)
	return n, c, cs, newSackPeer(p), outs
}

func TestRACKMarksLossAfterTheReorderWindow(t *testing.T) {
	n, cs, q, outs := rackConn(t, 3)
	q.deliver(outs, func(i int, o out) bool { return i == 1 })
	if got := n.drain(); len(got) != 0 {
		t.Fatalf("resent %v inside the reorder window", got)
	}
	if cs.reoAt == 0 || cs.tdl[tmrRetrans] != cs.reoAt {
		t.Fatalf("reorder deadline %d, retransmit node %d", cs.reoAt, cs.tdl[tmrRetrans])
	}
	n.advance(time.Duration(cs.reoAt - int64(n.clk.Now())))
	got := n.drain()
	if len(got) != 1 || got[0].seg.seq != outs[1].seg.seq {
		t.Fatalf("after the reorder window sent %v", got)
	}
	st := n.d.Stats()
	if st.ReorderTimeouts != 1 || st.RACKLost != 1 || st.RTOs != 0 || !cs.inRecovery {
		t.Fatalf("stats %+v", st)
	}
	checkScoreboard(t, cs)
	q.deliver(got, nil)
	if cs.sndUna != cs.sndMax {
		t.Fatal("not repaired")
	}
}

func TestRACKFindsALostRetransmission(t *testing.T) {
	n, c, cs, q, outs := rackConnApp(t, 10)
	// 1 を失う。SACK で回復に入り、1 を再送するが、その再送も失う
	q.deliver(outs, func(i int, o out) bool { return i == 1 })
	resend := n.drain()
	if len(resend) == 0 || resend[0].seg.seq != outs[1].seg.seq {
		t.Fatalf("first resend %v", resend)
	}
	// 再送の後に新しいデータを送り、それが届くと、RACK は再送も失われたとみなす
	n.advance(testRTT / 2)
	if _, err := c.Write(make([]byte, 4*testSegPayload)); err != nil {
		t.Fatal(err)
	}
	fresh := n.drain()
	var newer []out
	for _, o := range fresh {
		if seqGE(o.seg.seq, outs[9].seg.seq+uint32(testSegPayload)) {
			newer = append(newer, o)
		}
	}
	if len(newer) == 0 {
		t.Fatalf("no new data after the resend: %v", fresh)
	}
	n.advance(testRTT)
	q.deliver(newer, nil)
	again := false
	for range 3 {
		for _, o := range n.drain() {
			again = again || o.seg.seq == outs[1].seg.seq
		}
		if again {
			break
		}
		n.advance(time.Duration(max(cs.reoAt-int64(n.clk.Now()), int64(time.Millisecond))))
	}
	if !again {
		t.Fatalf("the lost retransmission was not resent; stats %+v", n.d.Stats())
	}
	if st := n.d.Stats(); st.RTOs != 0 || st.RACKLost == 0 {
		t.Fatalf("stats %+v", st)
	}
	checkScoreboard(t, cs)
}

func TestTLPProbesATailLoss(t *testing.T) {
	n, cs, q, outs := rackConn(t, 10)
	// 最後の 2 つを失い、残りを確認する
	q.deliver(outs, func(i int, o out) bool { return i >= 8 })
	if cs.tlpAt == 0 {
		t.Fatal("no PTO armed")
	}
	pto := time.Duration(cs.tlpAt - int64(n.clk.Now()))
	if pto < 2*time.Duration(cs.srtt)-time.Millisecond || pto > 2*time.Duration(cs.srtt)+time.Millisecond {
		t.Fatalf("PTO %v, SRTT %v", pto, time.Duration(cs.srtt))
	}
	n.advance(pto)
	got := n.drain()
	if len(got) != 1 || got[0].seg.seq != outs[9].seg.seq {
		t.Fatalf("probe %v, want the last segment", got)
	}
	// probe の SACK がもう 1 つの損失を見せる
	n.advance(testRTT)
	q.deliver(got, nil)
	got = n.drain()
	n.advance(time.Duration(max(cs.reoAt-int64(n.clk.Now()), 0)))
	got = append(got, n.drain()...)
	q.deliver(got, nil)
	st := n.d.Stats()
	if cs.sndUna != cs.sndMax || st.RTOs != 0 || st.TLPProbes != 1 || st.RetransTLP != 1 {
		t.Fatalf("una==max %v stats %+v", cs.sndUna == cs.sndMax, st)
	}
	checkScoreboard(t, cs)
}

// TestTLPOneProbePerTail は、probe の後に相手が黙っても、重複した ACK だけを返し続けても、次の probe を
// 送らずに RTO に移ることを確かめる(I5)。
func TestTLPOneProbePerTail(t *testing.T) {
	n, cs, q, outs := rackConn(t, 10)
	q.deliver(outs[:8], nil)
	n.advance(time.Duration(cs.tlpAt - int64(n.clk.Now())))
	if got := n.drain(); len(got) != 1 {
		t.Fatalf("probe %v", got)
	}
	for range 50 {
		n.advance(10 * time.Millisecond)
		n.drain()
		q.ack() // 進まない ACK
	}
	for range 20 {
		n.advance(500 * time.Millisecond)
		n.drain()
	}
	st := n.d.Stats()
	if st.TLPProbes != 1 || st.RTOs == 0 {
		t.Fatalf("stats %+v", st)
	}
	if cs.tlpAt != 0 && !cs.tlpEligible() {
		t.Fatal("PTO armed while not eligible")
	}
	checkScoreboard(t, cs)
}

// TestRTODeadlineIsNotPushedByReorderOrTLP は、並べ替えの期限の処理が RTO の期限を動かさず、TLP の probe が
// RTO を probe の時刻から張り直すことを確かめる。
func TestRTODeadlineIsNotPushedByReorderOrTLP(t *testing.T) {
	n, cs, q, outs := rackConn(t, 3)
	q.deliver(outs, func(i int, o out) bool { return i == 1 })
	rto := cs.rtoAt
	if cs.reoAt == 0 || cs.reoAt >= rto {
		t.Fatalf("reorder deadline %d, RTO %d", cs.reoAt, rto)
	}
	n.advance(time.Duration(cs.reoAt - int64(n.clk.Now())))
	if n.d.Stats().ReorderTimeouts != 1 || cs.rtoAt != rto {
		t.Fatalf("after the reorder deadline: RTO %d, was %d", cs.rtoAt, rto)
	}

	n, cs, q, outs = rackConn(t, 10)
	q.deliver(outs[:8], nil)
	n.advance(time.Duration(cs.tlpAt - int64(n.clk.Now())))
	if got := n.drain(); len(got) != 1 {
		t.Fatalf("probe %v", got)
	}
	if want := int64(n.clk.Now()) + cs.curRTO(); cs.rtoAt != want {
		t.Fatalf("RTO deadline %d after the probe, want %d", cs.rtoAt, want)
	}
}

// TestRACKTimersStayBoundedUnderAdversarialACKs は、SACK と累積の確認の洪水で、並べ替えの期限と TLP の
// probe が増え続けないことを確かめる(I5)。並べ替えの期限の処理は、記録に損失の印を付けるか、ACK が
// 張り直した期限ごとに 1 回までで、probe は送り残しの末尾ごとに 1 つである。タイマーの節は接続の枠の
// 固定の数のままで、保持は上界の内側にある。
func TestRACKTimersStayBoundedUnderAdversarialACKs(t *testing.T) {
	n, _, q, cs := floodConn(t)
	cs.mu.Lock()
	cs.srtt, cs.minRTT, cs.hasRTT, cs.hasMinRTT = int64(testRTT), int64(testRTT), true, true
	cs.mu.Unlock()
	nrec := cs.recs.n
	acks, advances := 0, 0
	steps0 := cs.scoreSteps
	for k := range 4000 {
		if k == 2000 {
			// 後半は RTT を長くし、並べ替えの期限が張られたまま ACK が続くようにする
			cs.mu.Lock()
			cs.srtt, cs.minRTT = int64(4*time.Second), int64(4*time.Second)
			cs.mu.Unlock()
		}
		n.advance(time.Duration(1+k%7) * time.Millisecond)
		s := q.p.seg(flagACK, nil)
		// 送り残しの先の記録を 1 つずつ SACK で知らせ、時々累積の確認を少し進める
		i := 1 + (k*7919)%max(cs.recs.n-1, 1)
		if i < cs.recs.n {
			r := cs.recs.at(i)
			s.sack = []sackBlock{{r.seq, r.seq + uint32(r.length)}}
		}
		if k%50 == 0 && cs.recs.n > 2 {
			s.ack = cs.recs.at(1).seq
			advances++
		} else {
			s.ack = cs.sndUna
		}
		q.p.n.inject(s)
		acks++
		n.drain()
		if k%200 == 0 {
			checkScoreboard(t, cs)
			checkHeld(t, n)
		}
	}
	st := n.d.Stats()
	t.Logf("%d records: %d ACKs, %d reorder timeouts, %d RACK losses, %d probes, %d RTOs", nrec, acks, st.ReorderTimeouts, st.RACKLost, st.TLPProbes, st.RTOs)
	if st.ReorderTimeouts > st.RACKLost+cs.rackChanges {
		t.Fatalf("%d reorder timeouts for %d losses and %d ACKs that changed the RACK state", st.ReorderTimeouts, st.RACKLost, cs.rackChanges)
	}
	if st.TLPProbes > uint64(advances)+st.RTOs+1 {
		t.Fatalf("%d probes for %d advancing ACKs", st.TLPProbes, advances)
	}
	if steps := cs.scoreSteps - steps0; steps > uint64(acks)*64+uint64(nrec)*16 {
		t.Fatalf("%d scoreboard steps for %d ACKs and %d records", steps, acks, nrec)
	}
	checkScoreboard(t, cs)
	checkHeld(t, n)
}

// TestHolesResentInSequenceOrderAndHeadRearmsRTO は、RACK の待ち行列と損失の境目の両方に穴があるとき番号の
// 小さい穴から送り直し、先頭の記録の再送が RTO を張り直すことを確かめる。
func TestHolesResentInSequenceOrderAndHeadRearmsRTO(t *testing.T) {
	n, cs, q, outs := rackConn(t, 10)
	q.deliver(outs, func(i int, o out) bool { return i == 0 || i == 6 })
	n.advance(time.Duration(max(cs.reoAt-int64(n.clk.Now()), 0)))
	got := n.drain()
	if len(got) == 0 || got[0].seg.seq != outs[0].seg.seq {
		t.Fatalf("first resend %v, want the head", got)
	}
	if want := int64(n.clk.Now()) + cs.curRTO(); cs.rtoAt != want {
		t.Fatalf("RTO deadline %d after resending the head, want %d", cs.rtoAt, want)
	}
	checkScoreboard(t, cs)
}

// TestOneProbeWhileACKsAdvanceBelowTheProbe は、再送の probe の後に累積の確認が probe の手前まで進み続けても、
// probe の確認を待つ間は次の PTO を張らず、probe が 1 つだけであることを確かめる(I5)。
func TestOneProbeWhileACKsAdvanceBelowTheProbe(t *testing.T) {
	n, cs, q, outs := rackConn(t, 10)
	q.deliver(outs[:2], nil)
	n.advance(time.Duration(cs.tlpAt - int64(n.clk.Now())))
	probe := n.drain()
	if len(probe) != 1 || probe[0].seg.seq != outs[9].seg.seq || !cs.tlpActive || !cs.tlpRetrans {
		t.Fatalf("probe %v active %v retrans %v", probe, cs.tlpActive, cs.tlpRetrans)
	}
	// 2 から 7 の確認が 1 つずつ遅れて届き、累積の確認は probe の手前で止まる
	for i := 2; i < 8; i++ {
		n.advance(time.Duration(2 * cs.curRTO() / 10))
		q.recv(outs[i])
		q.ack()
		n.drain()
		n.advance(time.Duration(max(cs.tlpAt-int64(n.clk.Now()), 0)))
		n.drain()
	}
	if st := n.d.Stats(); st.TLPProbes != 1 {
		t.Fatalf("%d probes while ACKs advanced below the probe", st.TLPProbes)
	}
}

// TestReorderTimeoutsNeedRACKProgress は、RACK の状態を変えない重複した ACK を何度受けても、並べ替えの期限の
// 処理が損失の印と RACK の状態を変えた ACK の数を超えて起きないことを確かめる。
func TestReorderTimeoutsNeedRACKProgress(t *testing.T) {
	n, cs, q, outs := rackConn(t, 3)
	q.deliver(outs, func(i int, o out) bool { return i == 1 })
	n.advance(time.Duration(cs.reoAt - int64(n.clk.Now())))
	n.drain() // RACK が穴を失われたとみなして送り直す。送り直しも失う
	for range 300 {
		n.advance(time.Millisecond)
		q.ack() // 同じ SACK の block を繰り返す
		n.drain()
	}
	st := n.d.Stats()
	if st.ReorderTimeouts > st.RACKLost+cs.rackChanges {
		t.Fatalf("%d reorder timeouts for %d losses and %d ACKs that changed the RACK state", st.ReorderTimeouts, st.RACKLost, cs.rackChanges)
	}
	if st.ReorderTimeouts == 0 || st.RACKLost == 0 {
		t.Fatalf("stats %+v", st)
	}
}
