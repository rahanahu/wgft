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
	c, p := n.accepted(true, true)
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

// TestDSACKWidensTheReorderWindow は、D-SACK を受けた往復ごとに並べ替えの窓の倍率を 1 つ上げ、16 回の回復の後に
// 1 に戻すことを確かめる(RFC 8985 6.2 の手順 4)。
func TestDSACKWidensTheReorderWindow(t *testing.T) {
	n, cs, q, outs := rackConn(t, 10)
	q.deliver(outs[:2], nil)
	cs.mu.Lock()
	cs.reorderSeen = true
	cs.mu.Unlock()
	w1 := cs.reoWnd()
	dsack := func() {
		s := q.p.seg(flagACK, nil)
		s.sack = []sackBlock{{outs[0].seg.seq, outs[0].seg.seq + uint32(testSegPayload)}} // 確認済みの範囲
		n.inject(s)
	}
	dsack() // 再送していないデータの D-SACK は疑わしいので使わない(Linux の tcp_dsack_seen)
	if cs.reoWndMult > 1 || n.d.Stats().DSACKsIn != 0 {
		t.Fatalf("a D-SACK with no retransmissions raised the multiplier to %d", cs.reoWndMult)
	}
	cs.mu.Lock()
	cs.totalRetrans = 100 // 再送を送ったことにする
	cs.mu.Unlock()
	dsack()
	if cs.reoWndMult != 2 || n.d.Stats().DSACKsIn != 1 || cs.reoWnd() != min(2*w1, cs.srtt) {
		t.Fatalf("after one D-SACK: mult %d, window %d, was %d", cs.reoWndMult, cs.reoWnd(), w1)
	}
	dsack() // 同じ往復の 2 つ目は数えない
	if cs.reoWndMult != 2 {
		t.Fatalf("second D-SACK in the round raised the multiplier to %d", cs.reoWndMult)
	}
	q.deliver(outs[2:], nil) // 往復を終える
	n.drain()
	dsack()
	if cs.reoWndMult != 3 {
		t.Fatalf("D-SACK in the next round: multiplier %d", cs.reoWndMult)
	}
	cs.mu.Lock()
	for range rackReoPersist {
		cs.rackRecoveryDone()
	}
	cs.mu.Unlock()
	if cs.reoWndMult != 1 {
		t.Fatalf("multiplier %d after %d recoveries", cs.reoWndMult, rackReoPersist)
	}
}

// tlpCutConn は、末尾の 2 segment を失った接続で TLP の probe に末尾を送り直させ、続けて新しいデータを newSegs
// segment 書かせる。返す more は probe の後に送った新しい segment である。
func tlpCutConn(t *testing.T, newSegs int) (*testNet, *Conn, *tcb, *sackPeer, []out, out, []out) {
	t.Helper()
	n, c, cs, q, outs := rackConnApp(t, 10)
	for i := 0; i < 8; i++ {
		n.advance(time.Millisecond)
		q.recv(outs[i])
		q.ack()
		n.drain()
	}
	n.advance(time.Duration(max(cs.tlpAt-int64(n.clk.Now()), 0)) + 2*time.Millisecond)
	probe := n.drain()
	if len(probe) != 1 || !cs.tlpRetrans || probe[0].seg.seq != outs[9].seg.seq {
		t.Fatalf("setup: probe %d, retransmission %v", len(probe), cs.tlpRetrans)
	}
	if _, err := c.Write(make([]byte, newSegs*testSegPayload)); err != nil {
		t.Fatal(err)
	}
	more := n.drain()
	if len(more) != newSegs {
		t.Fatalf("setup: %d new segments after the probe, want %d", len(more), newSegs)
	}
	n.advance(5 * time.Millisecond)
	return n, c, cs, q, outs, probe[0], more
}

// tlpCutWant は、ACK の前の送り残し flight と輻輳の窓 w で起きた輻輳の事象の ssthresh(CUBIC)である。
func tlpCutWant(cs *tcb, flight, w uint32) uint32 {
	return max(uint32(float64(min(flight, w))*cubicBeta), 2*uint32(cs.segMSS()))
}

// TestTLPRepairAndLossOnOneACKReduceOnce は、TLP の probe が損失を直したと分かる ACK が、probe の後に送った
// データの損失も RACK で知らせるとき、輻輳の窓を 1 回だけ下げることを確かめる(wgstack-performance.md の
// 「RACK-TLP」、RFC 8985 7.4、RFC 5681 3.2)。probe の縮小の後に回復に入る時に下げ直すと、β の 2 乗になる。
func TestTLPRepairAndLossOnOneACKReduceOnce(t *testing.T) {
	_, _, cs, q, outs, probe, more := tlpCutConn(t, 15)
	// 1 つの ACK:遅れた 8、probe、more[0] が届き、more[1] は失われ、残りは SACK される
	q.recv(outs[8])
	q.recv(probe)
	q.recv(more[0])
	for _, o := range more[2:] {
		q.recv(o)
	}
	w, flight := cs.cwnd, cs.sndMax-cs.sndUna
	tlp0, fast0 := cs.s.tlpRecoveries.Load(), cs.s.fastRecoveries.Load()
	q.ack()
	if cs.s.tlpRecoveries.Load() != tlp0+1 || cs.s.fastRecoveries.Load() != fast0+1 || !cs.inRecovery {
		t.Fatalf("setup: TLP reductions +%d, fast recoveries +%d, in recovery %v",
			cs.s.tlpRecoveries.Load()-tlp0, cs.s.fastRecoveries.Load()-fast0, cs.inRecovery)
	}
	if want := tlpCutWant(cs, flight, w); cs.ssthresh != want {
		t.Errorf("ssthresh %d after one ACK, want one reduction %d from the window %d and flight %d before the ACK", cs.ssthresh, want, w, flight)
	}
	// W_max は損失の前の窓で、この ACK の slow start の増分を含まない
	if want := float64(w) / float64(cs.segMSS()); cs.cubic.wMax != want || cs.cubic.cwndPrior != want {
		t.Errorf("W_max %v, cwnd_prior %v, want the window %v before the ACK", cs.cubic.wMax, cs.cubic.cwndPrior, want)
	}
}

// TestLossAfterTLPRepairInTheSameWindowReducesOnce は、probe の縮小の後の ACK が、縮小の時までに送ったデータの
// 損失で回復に入るとき、ssthresh を下げ直さないことを確かめる。
func TestLossAfterTLPRepairInTheSameWindowReducesOnce(t *testing.T) {
	n, _, cs, q, outs, probe, more := tlpCutConn(t, 15)
	// probe の確認:累積の確認が probe と more[1] まで進み、窓を 1 回下げる
	q.recv(outs[8])
	q.recv(probe)
	q.recv(more[0])
	q.recv(more[1])
	tlp0 := cs.s.tlpRecoveries.Load()
	q.ack()
	if cs.s.tlpRecoveries.Load() != tlp0+1 || cs.inRecovery {
		t.Fatalf("setup: TLP reductions +%d, in recovery %v", cs.s.tlpRecoveries.Load()-tlp0, cs.inRecovery)
	}
	ss := cs.ssthresh
	// 次の ACK 群:more[2] が失われ、残りは SACK される。どれも縮小の前に送ったデータである
	fast0 := cs.s.fastRecoveries.Load()
	q.deliver(more[3:], nil)
	if cs.s.fastRecoveries.Load() != fast0+1 || !cs.inRecovery {
		t.Fatalf("setup: fast recoveries +%d, in recovery %v", cs.s.fastRecoveries.Load()-fast0, cs.inRecovery)
	}
	if cs.ssthresh != ss || cs.recover != cs.tlpCutSeq {
		t.Errorf("ssthresh %d, recover %d after a loss in the window the probe's reduction covers, want %d and the cut point %d", cs.ssthresh, cs.recover, ss, cs.tlpCutSeq)
	}
	// 穴の再送が届き、累積の確認が縮小の時の SND.MAX を越えると、縮小の印は消える
	for _, o := range n.drain() {
		q.recv(o)
	}
	q.ack()
	if !seqGE(cs.sndUna, cs.tlpCutSeq) || cs.tlpCut {
		t.Errorf("after the window is acknowledged: SND.UNA %d, cut at %d, mark %v", cs.sndUna, cs.tlpCutSeq, cs.tlpCut)
	}
}

// TestLossBeyondTheTLPCutReducesAgain は、縮小の時までのデータの損失で入った回復が縮小の時の SND.MAX で終わり、
// その先に送ったデータの損失が次の回復で窓を下げることを確かめる(RFC 6582 の 1 つの窓に 1 回の縮小)。
func TestLossBeyondTheTLPCutReducesAgain(t *testing.T) {
	n, c, cs, q, outs, probe, more := tlpCutConn(t, 15)
	q.recv(outs[8])
	q.recv(probe)
	q.recv(more[0])
	q.ack()
	ss := cs.ssthresh
	cut := cs.tlpCutSeq
	if !cs.tlpCut || cut != more[len(more)-1].seg.seq+uint32(len(more[len(more)-1].seg.payload)) {
		t.Fatalf("setup: mark %v at %d", cs.tlpCut, cut)
	}
	if _, err := c.Write(make([]byte, 20*testSegPayload)); err != nil {
		t.Fatal(err)
	}
	// more[1..7] の確認が順に届き、窓が開いて縮小の後のデータ post が出る
	var post []out
	for _, o := range more[1:8] {
		q.recv(o)
		q.ack()
		post = append(post, n.drain()...)
	}
	if len(post) < 5 {
		t.Fatalf("setup: %d segments after the cut", len(post))
	}
	// 縮小の前の more[8] と縮小の後の post[1] を失い、残りを SACK で知らせる
	fast0 := cs.s.fastRecoveries.Load()
	lostPost := post[1].seg.seq
	for _, o := range more[9:] {
		q.recv(o)
		q.ack()
	}
	for i, o := range post {
		if i != 1 {
			q.recv(o)
			q.ack()
		}
	}
	if !cs.inRecovery || cs.ssthresh != ss || cs.recover != cut {
		t.Fatalf("held recovery: in recovery %v, ssthresh %d want %d, recover %d want the cut point %d", cs.inRecovery, cs.ssthresh, ss, cs.recover, cut)
	}
	// more[8] の再送だけが届く。post[1] は送り直しも失う。累積の確認は縮小の時の SND.MAX を越えて回復が終わり、
	// 同じ ACK で post[1] の損失の回復に入って窓を下げる
	var held out
	for range 4 {
		for _, o := range n.drain() {
			if o.seg.seq == more[8].seg.seq && len(o.seg.payload) > 0 {
				held = o
			}
		}
		if len(held.seg.payload) > 0 {
			break
		}
		n.advance(5 * time.Millisecond)
	}
	if len(held.seg.payload) == 0 {
		t.Fatal("setup: no retransmission of more[8]")
	}
	q.recv(held)
	w := cs.cwnd
	q.ack()
	t.Logf("ssthresh %d at the cut, %d after the loss beyond it; window %d; fast recoveries +%d", ss, cs.ssthresh, w, cs.s.fastRecoveries.Load()-fast0)
	if cs.s.fastRecoveries.Load() != fast0+2 || !cs.inRecovery || !seqGT(cs.recover, cut) || cs.sndUna != lostPost {
		t.Fatalf("no second recovery for the loss beyond the cut: fast recoveries +%d, in recovery %v, recover %d, SND.UNA %d at %d",
			cs.s.fastRecoveries.Load()-fast0, cs.inRecovery, cs.recover, cs.sndUna, lostPost)
	}
	if cs.ssthresh >= ss {
		t.Errorf("ssthresh %d after a loss beyond the cut, want below %d", cs.ssthresh, ss)
	}
}

// TestTLPCutUsesTheWindowBeforeTheACK は、probe の確認が probe の後のデータまで確認するとき、縮小が ACK の前の
// 窓で決まり、ACK の後の送り残し(0)で下限に落ちないことを確かめる。続けて、縮小がすべてを確認した後に送った
// 最初の segment を失うと、縮小の窓の外の損失として窓を下げ直すことを確かめる。
func TestTLPCutUsesTheWindowBeforeTheACK(t *testing.T) {
	n, c, cs, q, outs, probe, more := tlpCutConn(t, 3)
	mss := uint32(cs.segMSS())
	q.recv(outs[8])
	q.recv(probe)
	for _, o := range more {
		q.recv(o)
	}
	w, flight := cs.cwnd, cs.sndMax-cs.sndUna
	tlp0 := cs.s.tlpRecoveries.Load()
	q.ack()
	if cs.s.tlpRecoveries.Load() != tlp0+1 || cs.sndUna != cs.sndMax {
		t.Fatalf("setup: TLP reductions +%d, flight %d", cs.s.tlpRecoveries.Load()-tlp0, cs.sndMax-cs.sndUna)
	}
	ss := cs.ssthresh
	if want := tlpCutWant(cs, flight, w); ss != want || ss <= 2*mss {
		t.Fatalf("ssthresh %d after an ACK that covers everything, want %d from the flight %d and window %d before it", ss, want, flight, w)
	}
	// 縮小の時の SND.MAX はすべて確認された。その後に送った最初の segment を失い、残りを SACK で知らせる
	if _, err := c.Write(make([]byte, 10*testSegPayload)); err != nil {
		t.Fatal(err)
	}
	post := n.drain()
	if len(post) < 3 {
		t.Fatalf("setup: %d segments after the cut", len(post))
	}
	fast0 := cs.s.fastRecoveries.Load()
	for _, o := range post[1:] {
		q.recv(o)
		q.ack()
	}
	n.advance(time.Duration(max(cs.reoAt-int64(n.clk.Now()), 0)) + time.Millisecond)
	if cs.s.fastRecoveries.Load() != fast0+1 || !cs.inRecovery {
		t.Fatalf("setup: fast recoveries +%d, in recovery %v", cs.s.fastRecoveries.Load()-fast0, cs.inRecovery)
	}
	if cs.ssthresh >= ss {
		t.Errorf("ssthresh %d after a loss in data sent after the cut, want below %d", cs.ssthresh, ss)
	}
}

// TestRecoveryDuringAProbeIsTheOnlyCut は、probe の確認を待つ間に RACK が回復に入ったとき、回復を終える ACK が
// probe の先まで確認しても TLP の縮小を重ねないことを確かめる(RFC 8985 7.4.1)。回復の応答が probe の前の損失
// への輻輳の事象であり、ACK の前の輻輳の窓は PRR の途中の値である。
func TestRecoveryDuringAProbeIsTheOnlyCut(t *testing.T) {
	n, _, cs, q, outs, probe, more := tlpCutConn(t, 12)
	// outs[8] を失ったまま、probe と新しい 12 segment を届ける。RACK が回復に入る
	q.recv(probe)
	q.ack()
	q.deliver(more, nil)
	if !cs.inRecovery || !cs.tlpActive {
		t.Fatalf("setup: in recovery %v, probe outstanding %v", cs.inRecovery, cs.tlpActive)
	}
	ss := cs.ssthresh
	tlp0, fast0 := cs.s.tlpRecoveries.Load(), cs.s.fastRecoveries.Load()
	// outs[8] の再送が届き、累積の確認が probe と回復の点を越える
	var rtx out
	for range 4 {
		for _, o := range n.drain() {
			if o.seg.seq == outs[8].seg.seq && len(o.seg.payload) > 0 {
				rtx = o
			}
		}
		if len(rtx.seg.payload) > 0 {
			break
		}
		n.advance(5 * time.Millisecond)
	}
	if len(rtx.seg.payload) == 0 {
		t.Fatal("setup: no retransmission of outs[8]")
	}
	q.recv(rtx)
	q.ack()
	if cs.inRecovery || !seqGT(cs.sndUna, cs.tlpEnd) {
		t.Fatalf("setup: in recovery %v, SND.UNA %d, probe end %d", cs.inRecovery, cs.sndUna, cs.tlpEnd)
	}
	t.Logf("ssthresh %d segments in the recovery, %d after it ended past the probe", ss/uint32(cs.segMSS()), cs.ssthresh/uint32(cs.segMSS()))
	if got := cs.s.tlpRecoveries.Load() - tlp0; got != 0 || cs.ssthresh != ss {
		t.Errorf("TLP reductions +%d, ssthresh %d after the recovery ended past the probe, want no TLP cut and %d", got, cs.ssthresh, ss)
	}
	if cs.s.fastRecoveries.Load() != fast0 {
		t.Errorf("fast recoveries +%d", cs.s.fastRecoveries.Load()-fast0)
	}
}
