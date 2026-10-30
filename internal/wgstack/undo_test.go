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
