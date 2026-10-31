package wgstack

import (
	"testing"
	"time"
)

// 受信の窓の自動調整(rcvwin.go)の試験。どれも手で進める時計で決まった順に segment を送る。

const rwMSS = testMTU - 40 - 12 // timestamp を使う接続の中身の大きさ

// rwBoosted は timestamp と、sack が真なら SACK を許した接続を開き、受信の向きの boost を得させる。
func rwBoosted(t *testing.T, sack bool) (*testNet, *Conn, *peerConn, *tcb) {
	t.Helper()
	return rwBoostedTS(t, sack, true)
}

// rwBoostedTS は rwBoosted の timestamp を選べる版である。
func rwBoostedTS(t *testing.T, sack, ts bool) (*testNet, *Conn, *peerConn, *tcb) {
	t.Helper()
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, ts, sack, true)
	c := acceptOne(t, l)
	p.sendBulk(demandBytes)
	readN(t, c, demandBytes)
	p.absorb(n.drain())
	cs := &n.d.s.conns[c.c.id]
	if !cs.rcvBoost {
		t.Fatal("no receive boost")
	}
	return n, c, p, cs
}

// rwEdge は ACK の右端(受信の offset)。窓の欄は scale で切り下げた値である。
func rwEdge(cs *tcb, o out) uint64 {
	return uint64(o.seg.ack-(cs.irs+1)) + uint64(o.seg.wnd)<<cs.rcvWscale
}

// rwSend は相手から k byte の segment を 1 つ送り、DUT の ACK を受けて返す。
func rwSend(p *peerConn, k int) []out {
	p.ack(make([]byte, k))
	outs := p.n.drain()
	p.absorb(outs)
	return outs
}

// rwCheck は右端が予約の内側にあり、後ろへ戻っていないことを確かめ、今の右端を返す。
func rwCheck(t *testing.T, cs *tcb, prev uint64, ctx string) uint64 {
	t.Helper()
	if cs.advRight < prev {
		t.Fatalf("%s: advertised edge went back from %d to %d", ctx, prev, cs.advRight)
	}
	if cs.advRight > cs.rcv.readOff+cs.rcvCap {
		t.Fatalf("%s: advertised edge %d beyond the reservation %d from %d", ctx, cs.advRight, cs.rcvCap, cs.rcv.readOff)
	}
	if cs.rcvClamp() > cs.rcvCap || cs.rcvSsthresh > max(cs.rcvClamp(), recvFloor) {
		t.Fatalf("%s: clamp %d, rcv_ssthresh %d, reservation %d", ctx, cs.rcvClamp(), cs.rcvSsthresh, cs.rcvCap)
	}
	return cs.advRight
}

// TestRecvWindowClampFollowsMeasuredReads は、窓の上限が受け手の RTT ごとに読んだ量が増えたときだけ上がり、
// 読む量が増えなければ上がらず、測定で下がらないことを確かめる。相手は広告された窓の内側だけを送る。
func TestRecvWindowClampFollowsMeasuredReads(t *testing.T) {
	t.Run("timestamps", func(t *testing.T) { recvClampFollowsReads(t, true) })
	// timestamp を持たない相手(多くの Windows)は窓による標本だけで受け手の RTT を得る
	t.Run("no-timestamps", func(t *testing.T) { recvClampFollowsReads(t, false) })
}

func recvClampFollowsReads(t *testing.T, ts bool) {
	n, c, p, cs := rwBoostedTS(t, false, ts)
	mss := rwMSS
	if !ts {
		mss = testMTU - 40
	}
	if cs.rcvClamp() != recvFloor {
		t.Fatalf("clamp %d right after the boost", cs.rcvClamp())
	}
	edge := cs.advRight
	var clamps []uint64
	// 往復ごとに読む量:5 回倍にし、1 回 1 割だけ増やし、同じ量を続け、半分に減らしてから元に戻す。1 割の
	// 増加の目標は前の目標より小さいが、上限は下げない。減った後に元の量へ戻っても、前の区間の最大を超えない
	// ので上限は上がらない
	chunks := []int{32 << 10, 64 << 10, 128 << 10, 256 << 10, 512 << 10, 563 << 10, 563 << 10, 563 << 10, 563 << 10, 563 << 10,
		281 << 10, 281 << 10, 563 << 10, 563 << 10}
	for round, chunk := range chunks {
		n.advance(50 * time.Millisecond)
		for sent := 0; sent < chunk; {
			k := min(chunk-sent, mss, int(cs.advRight-cs.rcv.nxtOff))
			if k <= 0 {
				t.Fatalf("round %d: window closed with the reader keeping up", round)
			}
			rwSend(p, k)
			readN(t, c, k)
			edge = rwCheck(t, cs, edge, "read rounds")
			sent += k
		}
		clamps = append(clamps, cs.rcvClamp())
	}
	t.Logf("clamps per round %v", clamps)
	for i := 1; i < len(clamps); i++ {
		if clamps[i] < clamps[i-1] {
			t.Fatalf("clamp lowered by a measurement: %v", clamps)
		}
	}
	if clamps[4] <= recvFloor {
		t.Fatalf("clamp did not rise while reads doubled every RTT: %v", clamps)
	}
	if clamps[9] != clamps[6] {
		t.Fatalf("clamp kept rising while reads stayed flat: %v", clamps)
	}
	if clamps[13] != clamps[9] {
		t.Fatalf("clamp rose when reads came back to an earlier level: %v", clamps)
	}
}

// TestRecvWindowWithoutReadsStaysAtFloor は、boost の後も読み取りの測定が無ければ、届く segment が窓の上限
// (floor)の外へ右端を広げないことを確かめる。
func TestRecvWindowWithoutReadsStaysAtFloor(t *testing.T) {
	n, _, p, cs := rwBoosted(t, true)
	edge := cs.advRight
	for range 300 {
		if cs.advRight-cs.rcv.nxtOff < rwMSS {
			break
		}
		n.advance(time.Millisecond)
		rwSend(p, rwMSS)
		edge = rwCheck(t, cs, edge, "no reads")
	}
	if cs.advRight > cs.rcv.readOff+recvFloor {
		t.Fatalf("edge %d beyond the floor from the oldest unread byte %d without a measured read", cs.advRight, cs.rcv.readOff)
	}
}

// TestRecvWindowStepPerSegment は、窓の上限が上がった後の右端が、届いた segment ごとに有界の量(rcv_ssthresh
// の歩みの 2 MSS と、確認で進む 1 segment)だけ広がり、一度に開かないことを確かめる。右端は RCV.NXT と
// rcv_ssthresh の和を超えない。
func TestRecvWindowStepPerSegment(t *testing.T) {
	n, c, p, cs := rwBoosted(t, true)
	cs.rcvWant = boostSize // 測定が上限を上げた後の状態
	// 読んだ分の右端をまず知らせ、そこから測る
	rwSend(p, rwMSS)
	readN(t, c, rwMSS)
	p.absorb(n.drain()) // 読み終えた時の ACK
	edge := cs.advRight
	start := edge
	unit := uint64(1) << cs.rcvWscale
	segs := 0
	for range 400 {
		n.advance(time.Millisecond)
		ss := cs.rcvSsthresh
		outs := rwSend(p, rwMSS)
		if d := cs.rcvSsthresh - ss; d > 2*uint64(max(cs.rcvMSS(), rwMSS)) {
			t.Fatalf("rcv_ssthresh stepped %d on one segment", d)
		}
		if cs.advRight > edge && cs.advRight > cs.rcv.nxtOff+cs.rcvSsthresh {
			t.Fatalf("edge %d beyond RCV.NXT %d + rcv_ssthresh %d", cs.advRight, cs.rcv.nxtOff, cs.rcvSsthresh)
		}
		readN(t, c, rwMSS)
		read := n.drain() // 読み終えた時の ACK
		p.absorb(read)
		outs = append(outs, read...)
		segs++
		if len(outs) == 0 {
			continue
		}
		// 窓の欄の切り下げで、欄から読む右端は論理の右端より最大 1 単位手前にある
		got := rwEdge(cs, outs[len(outs)-1])
		if got > edge+uint64(segs)*3*uint64(cs.rcvMSS())+unit {
			t.Fatalf("edge stepped from %d to %d over %d segments", edge, got, segs)
		}
		edge = rwCheck(t, cs, edge, "step")
		edge = max(edge, got)
		segs = 0
	}
	if cs.advRight-start < 400*uint64(cs.rcvMSS()) {
		t.Fatalf("edge grew only %d bytes over 400 segments", cs.advRight-start)
	}
	if cs.rcvSsthresh > cs.rcvClamp() {
		t.Fatalf("rcv_ssthresh %d above the clamp %d", cs.rcvSsthresh, cs.rcvClamp())
	}
}

// TestRecvSsthreshStep は rcv_ssthresh の歩みの規則を確かめる。順序どおりの 128 byte 未満の segment と、SACK
// の無い接続の順序外の segment では広げず、広げる量は自分の MSS の 2 倍と中身の 2 倍の大きい方で、上限と空き
// の小さい方を超えない。
func TestRecvSsthreshStep(t *testing.T) {
	_, _, _, cs := rwBoosted(t, true)
	cs.mu.Lock()
	defer cs.mu.Unlock()
	mss := uint64(cs.rcvMSS())
	cs.rcvWant = boostSize
	cs.rcvSsthresh = recvFloor
	cs.rcvGrow(rcvGrowMin-1, false)
	if cs.rcvSsthresh != recvFloor {
		t.Fatalf("grew on a %d byte segment", rcvGrowMin-1)
	}
	cs.rcvGrow(rcvGrowMin, false)
	if cs.rcvSsthresh != recvFloor+2*mss {
		t.Fatalf("step %d on a small segment, want %d", cs.rcvSsthresh-recvFloor, 2*mss)
	}
	cs.rcvGrow(4000, true)
	if cs.rcvSsthresh != recvFloor+2*mss+8000 {
		t.Fatalf("step %d on a 4000 byte out-of-order segment, want 8000", cs.rcvSsthresh-recvFloor-2*mss)
	}
	cs.sackOK = false
	before := cs.rcvSsthresh
	cs.rcvGrow(int(mss), true)
	if cs.rcvSsthresh != before {
		t.Fatal("grew on out-of-order data without SACK")
	}
	cs.sackOK = true
	// 余地は上限と空きの小さい方まで。保持するデータの分だけ空きが上限より小さい
	cs.rcv.ooo = 50 << 10
	free := cs.rcvFree()
	if free != cs.rcvClamp()-cs.rcv.unread()-cs.rcv.ooo {
		t.Fatalf("free %d does not count held data", free)
	}
	cs.rcvSsthresh = free - 100
	cs.rcvGrow(int(mss), false)
	if cs.rcvSsthresh != free {
		t.Fatalf("rcv_ssthresh %d, want the free space %d", cs.rcvSsthresh, free)
	}
	cs.rcvGrow(int(mss), false)
	if cs.rcvSsthresh != free {
		t.Fatal("grew past the free space")
	}
	cs.rcv.ooo = 0
	cs.rcvSsthresh = cs.rcvClamp() - 100
	cs.rcvGrow(int(mss), false)
	cs.rcvGrow(int(mss), false)
	if cs.rcvSsthresh != cs.rcvClamp() {
		t.Fatalf("rcv_ssthresh %d, want the clamp %d", cs.rcvSsthresh, cs.rcvClamp())
	}
}

// TestRecvWindowHeldOutOfOrder は、保持する順序外のデータが空きを減らし、歩みの上限が届いている間は重複した
// ACK の右端と窓の欄が変わらないこと、穴を埋めても読むまで右端が進まないこと、読んだ後に進むことを確かめる。ここで確かめるのはこの状態だけである。順序外の
// segment が多く、歩みの上限が大きい接続では、穴を埋めた segment で右端が読み取りなしに大きく進みうる(空きの
// 式のとおり)。
func TestRecvWindowHeldOutOfOrder(t *testing.T) {
	n, c, p, cs := rwBoosted(t, true)
	cs.rcvWant, cs.rcvSsthresh = recvFloor+64<<10, recvFloor+64<<10 // 歩みの上限が上限に届いた状態
	cs.ackNow = true
	cs.mu.Lock()
	cs.afterInput(int64(n.clk.Now()))
	cs.mu.Unlock()
	p.absorb(n.drain())
	edge := rwCheck(t, cs, 0, "start")
	if edge != cs.rcv.readOff+cs.rcvClamp() {
		t.Fatalf("edge %d, want %d", edge, cs.rcv.readOff+cs.rcvClamp())
	}
	hole := p.snd
	p.snd += rwMSS // 失われた segment
	var wnd uint16
	for i := range 20 {
		outs := rwSend(p, rwMSS)
		if len(outs) != 1 || outs[0].seg.ack != hole {
			t.Fatalf("out-of-order segment %d: %v", i, outs)
		}
		if i > 0 && outs[0].seg.wnd != wnd {
			t.Fatalf("window field changed on duplicate ACK %d: %d to %d", i, wnd, outs[0].seg.wnd)
		}
		wnd = outs[0].seg.wnd
		edge = rwCheck(t, cs, edge, "holes")
		if cs.advRight != edge {
			t.Fatal("edge moved")
		}
	}
	if cs.rcv.ooo != 20*rwMSS {
		t.Fatalf("held out-of-order bytes %d, want %d", cs.rcv.ooo, 20*rwMSS)
	}
	if got := cs.rcvTarget(); got > cs.rcv.readOff+cs.rcvClamp()-cs.rcv.ooo {
		t.Fatalf("target %d does not count %d held out-of-order bytes", got, cs.rcv.ooo)
	}
	// 穴を埋める。読むまで保持するデータは同じなので右端は進まない
	end := p.snd
	p.snd = hole
	outs := rwSend(p, rwMSS)
	p.snd = end
	if len(outs) != 1 || outs[0].seg.ack != end || cs.rcv.ooo != 0 {
		t.Fatalf("hole fill: %v, ooo %d", outs, cs.rcv.ooo)
	}
	if rwCheck(t, cs, edge, "fill") != edge {
		t.Fatal("edge moved before the reader read")
	}
	readN(t, c, 21*rwMSS)
	p.absorb(n.drain())
	rwSend(p, rwMSS)
	rwSend(p, rwMSS) // 2 segment で ACK を返す
	if rwCheck(t, cs, edge, "read") <= edge {
		t.Fatal("edge did not move after the reader drained the buffer")
	}
}

// TestRecvWindowOutOfOrderGrowsBelowClamp は、歩みの上限が上限より小さい間は、SACK の接続の順序外の segment
// が歩みの上限を広げ、重複した ACK の窓の欄が大きくなることを確かめる(Linux の tcp_data_queue_ofo)。
func TestRecvWindowOutOfOrderGrowsBelowClamp(t *testing.T) {
	_, _, p, cs := rwBoosted(t, true)
	cs.rcvWant = boostSize
	p.snd += rwMSS
	edge := cs.advRight
	before := cs.rcvSsthresh
	var last uint16
	grew := 0
	for i := range 10 {
		outs := rwSend(p, rwMSS)
		if len(outs) != 1 {
			t.Fatalf("out-of-order segment %d: %v", i, outs)
		}
		if i > 0 && outs[0].seg.wnd > last {
			grew++
		}
		last = outs[0].seg.wnd
		edge = rwCheck(t, cs, edge, "ofo growth")
	}
	if cs.rcvSsthresh != before+10*2*uint64(cs.rcvMSS()) || grew != 9 {
		t.Fatalf("rcv_ssthresh %d from %d, window field grew on %d of 9 duplicate ACKs", cs.rcvSsthresh, before, grew)
	}
}

// TestRecvWindowDemoteLowersSsthresh は、floor に戻すと歩みの上限も floor に戻り、右端は縮めないことを確かめる。
func TestRecvWindowDemoteLowersSsthresh(t *testing.T) {
	n, c1, _, c2, p2 := boostTwo(t)
	cs1 := &n.d.s.conns[c1.c.id]
	edge := cs1.advRight
	n.advance(2 * time.Second)
	p2.sendBulk(demandBytes)
	readN(t, c2, demandBytes)
	if cs1.boosted {
		t.Fatal("holder not demoted")
	}
	if cs1.rcvSsthresh > recvFloor || cs1.rcvClamp() != recvFloor || cs1.advRight != edge {
		t.Fatalf("after demotion: rcv_ssthresh %d, clamp %d, edge %d (was %d)", cs1.rcvSsthresh, cs1.rcvClamp(), cs1.advRight, edge)
	}
}
