package wgstack

import (
	"testing"
	"time"
)

// RTO の値と、確認の途絶えた通信量の少ない stream の再送の期限の列の試験(wgstack-performance.md の
// 「RACK-TLP」のタイマーの規則)。

// TestRTOFloorAppliesToTheVarianceTerm は、RTO を SRTT + max(4 × RTTVAR, 200 ms) で求めることを確かめる。
// 200 ms で RTO 全体を丸めると、RTTVAR の小さな経路で Linux より SRTT の分だけ早く RTO が起きる。
func TestRTOFloorAppliesToTheVarianceTerm(t *testing.T) {
	var c tcb
	const r = 50 * time.Millisecond
	for range 50 {
		c.rttSample(int64(r))
	}
	if want := c.srtt + max(4*c.rttvar, int64(rtoMin)); c.rto != want {
		t.Fatalf("RTO %v with SRTT %v and RTTVAR %v, want %v", time.Duration(c.rto), time.Duration(c.srtt), time.Duration(c.rttvar), time.Duration(want))
	}
	if c.rto < int64(r+rtoMin) {
		t.Fatalf("RTO %v on a steady %v path, want at least %v", time.Duration(c.rto), r, r+rtoMin)
	}
	// 揺れの大きな経路では 4 × RTTVAR の項が下限を超える
	var v tcb
	for _, s := range []time.Duration{50, 300, 50, 300, 50, 300} {
		v.rttSample(int64(s * time.Millisecond))
	}
	if 4*v.rttvar <= int64(rtoMin) {
		t.Fatalf("RTTVAR %v does not exceed the floor; pick wider samples", time.Duration(v.rttvar))
	}
	if want := v.srtt + 4*v.rttvar; v.rto != want {
		t.Fatalf("RTO %v, want SRTT + 4 x RTTVAR = %v", time.Duration(v.rto), time.Duration(want))
	}
}

// TestThinStreamProbesAtTheRTODeadline は、新しいデータが PTO を RTO の期限より後ろへ押した通信量の少ない
// stream で、RTO の期限に RTO ではなく probe を送ることを確かめる(RFC 8985 7.2)。その後は確認が無いので、
// probe から RTO、2 × RTO、4 × RTO の間隔で RTO が続く。
func TestThinStreamProbesAtTheRTODeadline(t *testing.T) {
	const srtt = 50 * time.Millisecond
	n := newTestNet(t, smallLimits())
	c, p := n.accepted(true, true)
	cs := c.c
	cs.mu.Lock()
	cs.srtt, cs.rttvar, cs.minRTT, cs.hasRTT, cs.hasMinRTT = int64(srtt), int64(time.Millisecond), int64(srtt), true, true
	cs.rto = int64(rtoMin) // 期限の規則だけを確かめるため、RTO の値は固定する
	cs.mu.Unlock()
	_ = p
	start := n.clk.Now()
	// 20 ms ごとに 200 byte を書く。最初の segment が RTO を張り、後の書き込みが PTO を後ろへ押す
	var sent []out
	for i := range 6 {
		if i > 0 {
			n.advance(20 * time.Millisecond)
		}
		if _, err := c.Write(make([]byte, 200)); err != nil {
			t.Fatal(err)
		}
		sent = append(sent, n.drain()...)
	}
	if len(sent) != 6 {
		t.Fatalf("sent %d segments for 6 writes: %v", len(sent), sent)
	}
	rto := time.Duration(cs.rto)
	if got := time.Duration(cs.rtoAt) - start; got != rto {
		t.Fatalf("RTO deadline +%v, want +%v from the first segment", got, rto)
	}
	if cs.tlpAt != cs.rtoAt {
		t.Fatalf("PTO deadline %v, want the RTO deadline %v", time.Duration(cs.tlpAt)-start, time.Duration(cs.rtoAt)-start)
	}
	// 確認の無いまま 2 秒進め、時刻ごとに送った segment を記録する
	type fire struct {
		at   time.Duration
		segs []out
	}
	var fires []fire
	for n.clk.Now()-start < 2*time.Second {
		n.advance(time.Millisecond)
		if got := n.drain(); len(got) > 0 {
			fires = append(fires, fire{n.clk.Now() - start, got})
		}
	}
	if len(fires) < 4 {
		t.Fatalf("%d timer sends, want at least 4", len(fires))
	}
	st := n.d.Stats()
	t.Logf("timer sends at %v %v %v %v; stats RTOs %d TLPProbes %d", fires[0].at, fires[1].at, fires[2].at, fires[3].at, st.RTOs, st.TLPProbes)
	// 最初の期限は probe で、最後の segment を 1 つだけ送り直す
	probe := fires[0]
	if probe.at != rto || len(probe.segs) != 1 || probe.segs[0].seg.seq != sent[5].seg.seq {
		t.Fatalf("at +%v sent %d segments starting at %d, want one probe of the last segment at +%v", probe.at, len(probe.segs), probe.segs[0].seg.seq-sent[0].seg.seq, rto)
	}
	if st.TLPProbes != 1 {
		t.Fatalf("TLPProbes %d, want 1", st.TLPProbes)
	}
	// probe の後は RTO を今から張り、後退で倍にする
	for k, want := range []time.Duration{2 * rto, 4 * rto, 8 * rto} {
		f := fires[k+1]
		if f.at != want || f.segs[0].seg.seq != sent[0].seg.seq {
			t.Fatalf("timer send %d at +%v starting at %d, want the head at +%v", k+1, f.at, f.segs[0].seg.seq-sent[0].seg.seq, want)
		}
	}
	if st.RTOs != 3 {
		t.Fatalf("RTOs %d after the probe, want 3", st.RTOs)
	}
}

// TestProbeAtTheRTODeadlineRearmsTheRTO は、RTO の期限に揃えた PTO で probe を決めた時に RTO を今から
// 張り直すことを確かめる(RFC 8985 7.3)。probe は次に送り出す時に作るので、張り直さないと、送り出す前の
// 次の時刻に過ぎた RTO の期限が起き、probe の代わりに RTO になる。
func TestProbeAtTheRTODeadlineRearmsTheRTO(t *testing.T) {
	const srtt = 50 * time.Millisecond
	n := newTestNet(t, smallLimits())
	c, _ := n.accepted(true, true)
	cs := c.c
	cs.mu.Lock()
	cs.srtt, cs.rttvar, cs.minRTT, cs.hasRTT, cs.hasMinRTT = int64(srtt), int64(time.Millisecond), int64(srtt), true, true
	cs.rto = int64(rtoMin)
	cs.mu.Unlock()
	for i := range 6 {
		if i > 0 {
			n.advance(20 * time.Millisecond)
		}
		if _, err := c.Write(make([]byte, 200)); err != nil {
			t.Fatal(err)
		}
		n.drain()
	}
	// 期限の時刻と、その 1 ms 後の時刻を、送り出さずに進める
	n.advance(time.Duration(cs.rtoAt - int64(n.clk.Now())))
	if want := int64(n.clk.Now()) + cs.curRTO(); cs.rtoAt != want {
		t.Fatalf("RTO deadline +%v after deciding the probe, want +%v", time.Duration(cs.rtoAt-int64(n.clk.Now())), time.Duration(cs.curRTO()))
	}
	n.advance(time.Millisecond)
	got := n.drain()
	st := n.d.Stats()
	if len(got) != 1 || st.TLPProbes != 1 || st.RTOs != 0 {
		t.Fatalf("sent %d segments, TLPProbes %d, RTOs %d; want one probe and no RTO", len(got), st.TLPProbes, st.RTOs)
	}
}

// TestRenegeRTOOutsideRecoveryIsNotAProbe は、回復の外で相手が SACK 済みのデータを捨てた疑いのとき、早めた
// RTO の期限に RTO が起きて SACK 済みの印を消すことを確かめる。SACK 済みの記録がある間は PTO を張らない
// (RFC 8985 7.2)。張ると、PTO が早めた RTO の期限に揃い、その時刻に probe を決めて RTO を 1 RTO 後ろへ送る。
func TestRenegeRTOOutsideRecoveryIsNotAProbe(t *testing.T) {
	n, c, q, outs := sackConn(t, 3)
	cs := c.c
	cs.mu.Lock()
	cs.srtt, cs.rttvar, cs.minRTT, cs.hasRTT, cs.hasMinRTT = int64(50*time.Millisecond), int64(time.Millisecond), int64(50*time.Millisecond), true, true
	cs.rto = cs.srtt + int64(rtoMin)
	cs.reorderSeen = true // 並べ替えを見た接続は、最初の SACK で回復に入らない
	cs.mu.Unlock()
	n.advance(50 * time.Millisecond)
	q.deliver(outs, func(i int, o out) bool { return i == 1 })
	n.drain()
	if cs.inRecovery || cs.sacked == 0 {
		t.Fatalf("after the SACK: in recovery %v, SACKed %d; want SACKed data outside recovery", cs.inRecovery, cs.sacked)
	}
	// 相手が SACK 済みの segment を捨て、その手前までだけを確認する
	q.ivs = nil
	q.p.rcv = outs[2].seg.seq
	q.ack()
	n.drain()
	start := n.clk.Now()
	want := time.Duration(max(cs.srtt/2, int64(renegeDelayMin)))
	for n.d.Stats().RTOs == 0 && n.clk.Now()-start < time.Second {
		n.advance(time.Millisecond)
		n.drain()
	}
	st := n.d.Stats()
	if at := n.clk.Now() - start; at != want || st.SACKReneging != 1 || st.TLPProbes != 0 {
		t.Fatalf("RTO at +%v after the renege ACK, SACKReneging %d, TLPProbes %d; want the RTO at +%v, 1 and 0", at, st.SACKReneging, st.TLPProbes, want)
	}
}

// TestTLPNeedsAnRTTSampleSinceTheLastProbe は RFC 8985 7.3 の条件 2 を確かめる。probe は RTT の測定の印を
// 消し、測定が印を戻す。印の無いまま PTO の期限が来たら probe を送らず、張ってある RTO の期限を動かさない。
func TestTLPNeedsAnRTTSampleSinceTheLastProbe(t *testing.T) {
	n, cs, q, outs := rackConn(t, 10)
	q.deliver(outs[:9], nil)
	if !cs.tlpSampled {
		t.Fatal("no RTT sample recorded after the ACKs")
	}
	n.advance(time.Duration(cs.tlpAt - int64(n.clk.Now())))
	probe := n.drain()
	if len(probe) != 1 || cs.tlpSampled {
		t.Fatalf("probe %d segments, sampled %v; want one probe that clears the mark", len(probe), cs.tlpSampled)
	}
	n.advance(testRTT)
	q.deliver(probe, nil)
	if !cs.tlpSampled {
		t.Fatal("the probe's ACK with a timestamp did not record an RTT sample")
	}

	// 前の probe の後に測定が無いまま、次の末尾の PTO の期限が来る
	n, cs, q, outs = rackConn(t, 10)
	q.deliver(outs[:8], nil)
	cs.mu.Lock()
	cs.tlpSampled = false
	cs.mu.Unlock()
	oldRTO := cs.rtoAt
	if cs.tlpAt == 0 || cs.tlpAt >= oldRTO {
		t.Fatalf("PTO %v, RTO %v; want a PTO before the RTO deadline", time.Duration(cs.tlpAt), time.Duration(oldRTO))
	}
	n.advance(time.Duration(cs.tlpAt - int64(n.clk.Now())))
	if got := n.drain(); len(got) != 0 || n.d.Stats().TLPProbes != 0 {
		t.Fatalf("sent %d segments at the PTO without an RTT sample since the last probe", len(got))
	}
	if cs.rtoAt != oldRTO {
		t.Fatalf("RTO deadline moved by %v at the skipped probe", time.Duration(cs.rtoAt-oldRTO))
	}
	n.advance(time.Duration(oldRTO - int64(n.clk.Now())))
	if got := n.drain(); len(got) == 0 || n.d.Stats().RTOs != 1 || n.d.Stats().TLPProbes != 0 {
		t.Fatalf("at the RTO deadline sent %d segments, RTOs %d, TLPProbes %d; want the RTO", len(got), n.d.Stats().RTOs, n.d.Stats().TLPProbes)
	}
}

// TestThinWriterWithoutRTTSampleKeepsTheRTODeadline は、前の probe の後に RTT を測っていない接続で、確認の
// 無いまま小さな書き込みが続いても、最初の RTO が RFC 6298 の期限(最初の segment から RTO)に起きることを
// 確かめる。新しいデータごとの PTO が RTO の期限を後ろへ送ると、輻輳の窓が埋まるまで RTO が起きない。
func TestThinWriterWithoutRTTSampleKeepsTheRTODeadline(t *testing.T) {
	const srtt = 50 * time.Millisecond
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	n.handshake(40000, 80, false, true, true) // timestamp なし
	c := acceptOne(t, l)
	n.drain()
	cs := c.c
	cs.mu.Lock()
	cs.srtt, cs.rttvar, cs.minRTT, cs.hasRTT, cs.hasMinRTT = int64(srtt), int64(time.Millisecond), int64(srtt), true, true
	cs.rto = cs.srtt + int64(rtoMin)
	cs.tlpSampled = false // 前の probe の後に測定が無い
	cs.mu.Unlock()
	start := n.clk.Now()
	rto := time.Duration(cs.rto)
	// 100 ms ごとに 20 byte を書き、確認は返さない
	for n.d.Stats().RTOs == 0 && n.clk.Now()-start < 10*time.Second {
		if (n.clk.Now()-start)%(100*time.Millisecond) == 0 {
			if _, err := c.Write(make([]byte, 20)); err != nil {
				t.Fatal(err)
			}
		}
		n.drain()
		n.advance(time.Millisecond)
	}
	n.drain()
	st := n.d.Stats()
	if at := n.clk.Now() - start; at != rto || st.RTOs != 1 || st.TLPProbes != 0 {
		t.Fatalf("first RTO at +%v, RTOs %d, TLPProbes %d; want the RTO at +%v from the first segment and no probe", at, st.RTOs, st.TLPProbes, rto)
	}
}
