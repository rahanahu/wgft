package wgstack

import (
	"testing"
	"time"
)

// 並べ替えと不要な再送(wgstack-performance.md の「並べ替えと不要な再送」)の試験。

// TestNoDupThreshRecoveryAfterReorderingSeen は、並べ替えを見た後は 3 つ以上の SACK でも DupThresh で回復に
// 入らず、並べ替えの窓の内側で遅れて届いた segment を再送しないことを確かめる。
func TestNoDupThreshRecoveryAfterReorderingSeen(t *testing.T) {
	n, cs, q, outs := rackConn(t, 10)
	cs.mu.Lock()
	cs.reorderSeen = true
	cs.mu.Unlock()
	q.deliver(outs, func(i int, o out) bool { return i == 1 }) // 1 だけ遅れる
	if got := n.drain(); len(got) != 0 || cs.inRecovery {
		t.Fatalf("resent %v, in recovery %v, inside the reorder window", got, cs.inRecovery)
	}
	n.advance(time.Millisecond)
	q.deliver(outs[1:2], nil)
	st := n.d.Stats()
	if st.FastRecoveries != 0 || st.RetransFast != 0 || cs.sndUna != cs.sndMax {
		t.Fatalf("stats %+v", st)
	}
}

// spuriousRecovery は 1 を遅らせて回復に入れ、再送を送らせて、元の segment を届ける。返り値は回復の前の
// 輻輳の窓である。
func spuriousRecovery(t *testing.T, n *testNet, cs *tcb, q *sackPeer, outs []out) uint32 {
	t.Helper()
	before := cs.cwnd
	q.deliver(outs, func(i int, o out) bool { return i == 1 })
	if !cs.inRecovery || cs.cwnd >= before {
		t.Fatalf("not in recovery with a reduced window: %v %d", cs.inRecovery, cs.cwnd)
	}
	resent := n.drain()
	if len(resent) == 0 || resent[0].seg.seq != outs[1].seg.seq {
		t.Fatalf("resend %v", resent)
	}
	return before
}

func TestEifelUndoRestoresTheWindow(t *testing.T) {
	n, cs, q, outs := rackConn(t, 10)
	before := spuriousRecovery(t, n, cs, q, outs)
	n.advance(time.Millisecond)
	q.recv(outs[1]) // 元の segment が届き、TSecr はその TSval になる
	q.ack()
	if cs.inRecovery || cs.cwnd < before || n.d.Stats().SpuriousUndos != 1 || !cs.reorderSeen {
		t.Fatalf("after the original arrived: recovery %v cwnd %d (was %d) stats %+v", cs.inRecovery, cs.cwnd, before, n.d.Stats())
	}
}

func TestDSACKUndoRestoresTheWindow(t *testing.T) {
	n, cs, q, outs := rackConn(t, 10)
	spuriousRecovery(t, n, cs, q, outs)
	cs.mu.Lock()
	cs.retransTSOK = false // timestamp による判定を使わない
	cs.mu.Unlock()
	q.deliver(outs[1:2], nil) // 元の segment が累積の確認を進める
	if cs.inRecovery {
		t.Fatal("still in recovery")
	}
	if n.d.Stats().SpuriousUndos != 0 {
		t.Fatal("undid without evidence")
	}
	// 遅れて届いた再送への D-SACK では、回復はもう終わっているので取り消さない。回復の終わりの前の D-SACK を
	// 確かめる
	n2, cs2, q2, outs2 := rackConn(t, 10)
	before := spuriousRecovery(t, n2, cs2, q2, outs2)
	cs2.mu.Lock()
	cs2.retransTSOK = false
	cs2.mu.Unlock()
	s := q2.p.seg(flagACK, nil) // 再送が届いた重複への D-SACK(2 つ目の block の内側)
	s.sack = []sackBlock{{outs2[1].seg.seq, outs2[1].seg.seq + uint32(testSegPayload)}, {outs2[1].seg.seq, outs2[9].seg.seq + uint32(testSegPayload)}}
	n2.inject(s)
	q2.deliver(outs2[1:2], nil)
	if cs2.inRecovery || cs2.cwnd < before || n2.d.Stats().SpuriousUndos != 1 {
		t.Fatalf("D-SACK undo: recovery %v cwnd %d (was %d) stats %+v", cs2.inRecovery, cs2.cwnd, before, n2.d.Stats())
	}
}

func TestFRTOUndoesASpuriousRTO(t *testing.T) {
	n, cs, q, outs := rackConn(t, 10)
	before, ssBefore := cs.cwnd, cs.ssthresh
	for n.d.Stats().RTOs == 0 {
		n.advance(5 * time.Millisecond)
	}
	if cs.frto == 0 || cs.cwnd != uint32(cs.segMSS()) {
		t.Fatalf("F-RTO %d cwnd %d after the RTO", cs.frto, cs.cwnd)
	}
	resent := n.drain()
	if len(resent) != 1 || resent[0].seg.seq != outs[0].seg.seq {
		t.Fatalf("after the RTO sent %v, want only the head", resent)
	}
	// 元の segment がすべて遅れて届く
	q.deliver(outs, nil)
	st := n.d.Stats()
	if st.SpuriousRTOs != 1 || cs.cwnd < before || cs.ssthresh < ssBefore || cs.frto != 0 {
		t.Fatalf("after the originals: cwnd %d (was %d) ssthresh %d stats %+v", cs.cwnd, before, cs.ssthresh, st)
	}
	if st.RetransRTO != 1 {
		t.Fatalf("resent %d segments for a spurious RTO", st.RetransRTO)
	}
}

func TestFRTOFallsBackOnRealLoss(t *testing.T) {
	n, c, cs, q, outs := rackConnApp(t, 10)
	c.Write(make([]byte, 10*testSegPayload)) // 送り残しの後に新しいデータがある
	for n.d.Stats().RTOs == 0 {
		n.advance(5 * time.Millisecond)
	}
	resent := n.drain()
	q.deliver(resent, nil) // 先頭の再送だけが届く:SND.UNA が進む
	fresh := n.drain()
	if cs.frto == 0 {
		t.Fatal("F-RTO left before step 2")
	}
	// 新しいデータが届き、その SACK は 1 から 9 が失われたままであることを示す
	q.deliver(fresh, nil)
	n.drain()
	st := n.d.Stats()
	if st.SpuriousRTOs != 0 || cs.frto != 0 || st.RetransRTO < 2 {
		t.Fatalf("real loss after F-RTO: frto %d stats %+v (fresh %d)", cs.frto, st, len(fresh))
	}
	_ = outs
}

// TestForgedDSACKDoesNotUndoARealLoss は、再送していない、回復の前に確認済みのデータの D-SACK では、本当の損失の
// 窓の縮小を取り消さないことを確かめる(D-SACK は印の後に終わる範囲だけを数える)。
func TestForgedDSACKDoesNotUndoARealLoss(t *testing.T) {
	n, cs, q, outs := rackConn(t, 10)
	q.deliver(outs, func(i int, o out) bool { return i == 1 })
	if !cs.inRecovery {
		t.Fatal("not in recovery")
	}
	resent := n.drain()
	n.advance(testRTT)
	// 再送が届く前の重複した ACK に、確認済みの segment 0 の D-SACK を偽って載せ、続けて再送を届ける
	// (元の segment は失われた)
	s := q.p.seg(flagACK, nil)
	s.sack = append([]sackBlock{{outs[0].seg.seq, outs[0].seg.seq + uint32(len(outs[0].seg.payload))}}, q.blocks(2)...)
	q.p.n.inject(s)
	n.drain()
	q.recv(resent[0])
	q.ack()
	if cs.inRecovery || n.d.Stats().SpuriousUndos != 0 {
		t.Fatalf("a D-SACK for data that was never retransmitted undid the reduction of a real loss: cwnd %d", cs.cwnd)
	}
}

// TestForgedDSACKAboveTheAckDoesNotUndo は、SND.UNA より先の、再送していない記録の D-SACK では、本当の損失の窓の
// 縮小を取り消さないことを確かめる(SND.UNA より先の D-SACK は再送した記録だけを数える)。
func TestForgedDSACKAboveTheAckDoesNotUndo(t *testing.T) {
	n, cs, q, outs := rackConn(t, 10)
	q.deliver(outs, func(i int, o out) bool { return i == 1 })
	resent := n.drain()
	n.advance(testRTT)
	cs.mu.Lock()
	cs.retransTSOK = false // timestamp による判定を使わない
	cs.mu.Unlock()
	// SACK 済みで再送していない segment 5 の D-SACK(2 つ目の block の内側)を偽って載せる
	b5 := sackBlock{outs[5].seg.seq, outs[5].seg.seq + uint32(len(outs[5].seg.payload))}
	s := q.p.seg(flagACK, nil)
	s.sack = append([]sackBlock{b5}, q.blocks(2)...)
	q.p.n.inject(s)
	n.drain()
	q.recv(resent[0])
	q.ack()
	if cs.inRecovery || n.d.Stats().SpuriousUndos != 0 {
		t.Fatalf("a D-SACK for a record that was never retransmitted undid a real loss: cwnd %d", cs.cwnd)
	}
}

// TestStaleDSACKDoesNotUndoALaterRecovery は、前の回復の不要な再送への遅れた D-SACK を、次の回復の再送に数えない
// ことを確かめる。D-SACK の範囲は次の回復の印(回復に入った時の SND.UNA)より前に終わる。
func TestStaleDSACKDoesNotUndoALaterRecovery(t *testing.T) {
	n, c, cs, q, outs := rackConnApp(t, 10)
	c.Write(make([]byte, 10*testSegPayload))
	// 1 回目の回復:segment 1 が遅れ、再送は不要だった。遅れた D-SACK のために再送の範囲を覚えておく
	q.deliver(outs, func(i int, o out) bool { return i == 1 })
	resent := n.drain()
	stale := sackBlock{outs[1].seg.seq, outs[1].seg.seq + uint32(len(outs[1].seg.payload))}
	q.deliver(outs[1:2], nil)
	q.deliver(resent, func(i int, o out) bool { return o.seg.seq == stale.left }) // 再送は届かない(重複の知らせも無い)
	if cs.inRecovery {
		t.Fatal("first recovery did not end")
	}
	undos := n.d.Stats().SpuriousUndos
	// 2 回目の回復:本当の損失
	n.advance(testRTT)
	outs2 := n.drain()
	if len(outs2) < 4 {
		t.Fatalf("only %d new segments", len(outs2))
	}
	q.deliver(outs2, func(i int, o out) bool { return i == 0 })
	if !cs.inRecovery {
		t.Fatal("not in the second recovery")
	}
	resent2 := n.drain()
	cs.mu.Lock()
	cs.retransTSOK = false // timestamp による判定を使わない
	cs.mu.Unlock()
	// 1 回目の回復の再送への遅れた D-SACK が届き、続けて 2 回目の回復の再送が届く
	s := q.p.seg(flagACK, nil)
	s.sack = append([]sackBlock{stale}, q.blocks(2)...)
	q.p.n.inject(s)
	n.drain()
	q.deliver(resent2[:1], nil)
	if cs.inRecovery || n.d.Stats().SpuriousUndos != undos {
		t.Fatalf("a stale D-SACK from an earlier recovery undid a real loss: recovery %v undos %d (was %d)", cs.inRecovery, n.d.Stats().SpuriousUndos, undos)
	}
}

// TestTLPProbeDSACKIsNotCounted は、TLP の probe の D-SACK を回復の再送に数えず、並べ替えの窓も広げないことを
// 確かめる(Linux の FLAG_DSACK_TLP)。
func TestTLPProbeDSACKIsNotCounted(t *testing.T) {
	n, cs, q, outs := rackConn(t, 10)
	cs.mu.Lock()
	cs.reorderSeen = true
	cs.mu.Unlock()
	// 最後の 2 つの segment の確認が遅れ、TLP が最後の segment を再送する
	q.deliver(outs[:8], nil)
	if cs.tlpAt == 0 {
		t.Fatal("no PTO armed")
	}
	var probe []out
	for i := 0; i < 1000 && len(probe) == 0; i++ {
		n.advance(time.Millisecond)
		probe = n.drain()
	}
	if n.d.Stats().TLPProbes != 1 || len(probe) != 1 || probe[0].seg.seq != outs[9].seg.seq {
		t.Fatalf("probe %v, stats %+v", probe, n.d.Stats())
	}
	cs.mu.Lock()
	cs.initUndo() // probe より前に取り消しの印を付け、印の後の再送が 1 つあるとする
	cs.undoRetrans = 1
	cs.mu.Unlock()
	q.deliver(outs[8:], nil) // 元の segment が届く
	mult := cs.reoWndMult
	s := q.p.seg(flagACK, nil)
	s.sack = []sackBlock{{outs[9].seg.seq, outs[9].seg.seq + uint32(len(outs[9].seg.payload))}}
	n.inject(s) // probe への D-SACK
	if cs.reoWndMult != mult || n.d.Stats().DSACKsIn != 0 {
		t.Fatalf("a TLP probe's D-SACK widened the reorder window: mult %d (was %d)", cs.reoWndMult, mult)
	}
	if cs.undoRetrans != 1 {
		t.Fatalf("a TLP probe's D-SACK was counted as a spurious retransmission: %d left", cs.undoRetrans)
	}
	if cs.dsackDups == 0 {
		t.Fatal("the probe's D-SACK was not seen")
	}
}

// TestFRTOEndsWhenOneAckPassesRecover は、1 つの ACK が RTO の時の SND.MAX を越えた時に F-RTO と RTO の後の回復を
// 終え、本当の損失なら窓を戻さないことを確かめる。F-RTO の段階が残ると、先頭の再送が輻輳の窓によらず送られる。
func TestFRTOEndsWhenOneAckPassesRecover(t *testing.T) {
	n, cs, q, outs := rackConn(t, 10)
	for _, o := range outs[1:] {
		q.recv(o) // 相手は 1 から 9 を受けたが、その ACK は失われた
	}
	for n.d.Stats().RTOs == 0 {
		n.advance(5 * time.Millisecond)
	}
	if cs.frto != 1 {
		t.Fatalf("F-RTO %d after the RTO", cs.frto)
	}
	resent := n.drain()
	q.deliver(resent, nil) // 先頭の再送が届き、1 つの ACK がすべてを確認する
	if cs.sndUna != cs.sndMax || cs.frto != 0 || cs.rtoEpisode || cs.undoMarker {
		t.Fatalf("after one ACK past recover: una %d max %d frto %d episode %v marker %v", cs.sndUna-cs.iss, cs.sndMax-cs.iss, cs.frto, cs.rtoEpisode, cs.undoMarker)
	}
	if st := n.d.Stats(); st.SpuriousRTOs != 0 || st.SpuriousUndos != 0 || cs.cwnd > uint32(4*cs.segMSS()) {
		t.Fatalf("a real loss was undone: cwnd %d stats %+v", cs.cwnd, st)
	}
}

// TestTLPProbeEndIsForgottenOnceResolved は、片付いた probe の後に、probe と同じ範囲で終わる D-SACK を probe のもの
// とみなさないことを確かめる。
func TestTLPProbeEndIsForgottenOnceResolved(t *testing.T) {
	n, cs, q, outs := rackConn(t, 10)
	q.deliver(outs[:8], nil)
	var probe []out
	for i := 0; i < 1000 && len(probe) == 0; i++ {
		n.advance(time.Millisecond)
		probe = n.drain()
	}
	if len(probe) != 1 || probe[0].seg.seq != outs[9].seg.seq {
		t.Fatalf("probe %v", probe)
	}
	q.deliver(outs[8:], nil)
	b := sackBlock{outs[9].seg.seq, outs[9].seg.seq + uint32(len(outs[9].seg.payload))}
	dsack := func() {
		s := q.p.seg(flagACK, nil)
		s.sack = []sackBlock{b}
		n.inject(s)
	}
	dsack() // probe への D-SACK:probe が片付く
	if cs.tlpActive || cs.tlpRetrans || n.d.Stats().DSACKsIn != 0 {
		t.Fatalf("after the probe's D-SACK: active %v retrans %v stats %+v", cs.tlpActive, cs.tlpRetrans, n.d.Stats())
	}
	cs.mu.Lock()
	cs.totalRetrans = 10 // 後の再送を送ったことにする
	cs.mu.Unlock()
	dsack() // 同じ範囲で終わる後の D-SACK は probe のものではない
	if n.d.Stats().DSACKsIn != 1 {
		t.Fatalf("a later D-SACK ending at an old probe's end was taken for the probe's: stats %+v", n.d.Stats())
	}
}

// TestDSACKWiderThanTheWindowIsIgnored は、相手が示した窓の最大より広い D-SACK の block を使わないことを確かめる。
func TestDSACKWiderThanTheWindowIsIgnored(t *testing.T) {
	n, cs, q, outs := rackConn(t, 10)
	q.deliver(outs[:2], nil)
	cs.mu.Lock()
	cs.totalRetrans = 1 << 20 // 再送の累計の上限には掛からない
	b := sackBlock{cs.sndUna - cs.maxSndWnd, cs.sndUna + uint32(testSegPayload)}
	cs.mu.Unlock()
	s := q.p.seg(flagACK, nil)
	s.sack = []sackBlock{b, b} // 2 つ目の block の内側なので D-SACK
	n.inject(s)
	if n.d.Stats().DSACKsIn != 0 || cs.dsackDups != 0 {
		t.Fatalf("a D-SACK wider than the peer's largest window was used: dups %d stats %+v", cs.dsackDups, n.d.Stats())
	}
}

// TestNoUndoBeforeARetransmission は、印の後に再送を送る前に回復が終わっても、数による取り消しをしないことを
// 確かめる(数は -1 から始まる)。
func TestNoUndoBeforeARetransmission(t *testing.T) {
	n, cs, q, outs := rackConn(t, 10)
	q.deliver(outs, func(i int, o out) bool { return i == 1 })
	if !cs.inRecovery || cs.undoRetrans != -1 {
		t.Fatalf("recovery %v, count %d", cs.inRecovery, cs.undoRetrans)
	}
	q.deliver(outs[1:2], nil) // 再送を作る前に元の segment が届き、回復が終わる
	if cs.inRecovery || n.d.Stats().RetransFast != 0 || n.d.Stats().SpuriousUndos != 0 {
		t.Fatalf("recovery %v stats %+v", cs.inRecovery, n.d.Stats())
	}
}

// TestDSACKOfDataThisAckAcknowledgesIsNotCounted は、確認済みの範囲の D-SACK を、この ACK の前の SND.UNA と比べる
// ことを確かめる。同じ ACK が確認するデータの D-SACK は、確認済みのデータの重複ではないので数えない。
func TestDSACKOfDataThisAckAcknowledgesIsNotCounted(t *testing.T) {
	n, cs, q, outs := rackConn(t, 10)
	q.deliver(outs, func(i int, o out) bool { return i == 1 || i == 3 })
	resent := n.drain()
	if len(resent) < 2 || cs.undoRetrans != 2 {
		t.Fatalf("resent %d, count %d", len(resent), cs.undoRetrans)
	}
	q.recv(resent[0]) // 再送が最初の穴を埋める。その ACK に、埋めた segment の D-SACK を偽って載せる
	s := q.p.seg(flagACK, nil)
	s.sack = append([]sackBlock{{outs[1].seg.seq, outs[1].seg.seq + uint32(len(outs[1].seg.payload))}}, q.blocks(2)...)
	n.inject(s)
	if cs.sndUna != outs[3].seg.seq || !cs.inRecovery {
		t.Fatalf("una %d, recovery %v", cs.sndUna-cs.iss, cs.inRecovery)
	}
	if cs.undoRetrans != 2 {
		t.Fatalf("a D-SACK of data the same ACK acknowledges was counted: %d left", cs.undoRetrans)
	}
}
