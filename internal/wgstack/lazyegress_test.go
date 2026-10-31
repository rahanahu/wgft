package wgstack

import (
	"testing"
	"time"
)

// まとめて届いた ACK の試験(wgstack-performance.md の「ACK のまとまりと遅れた送り出し」)。sackPeer の deliver
// は、Device から何も読まずに往復のすべての ACK を書き込むので、wireguard-go が受けたバッチを書き込む時と
// 同じになる。

// TestHyStartRoundEndsAfterWhatTheBurstLetsOut は、まとめて届いた ACK で往復が終わった時、次の往復の終わりが
// 往復を終えた ACK の前の ACK が許した segment の後ろになることを確かめる(RFC 9406 の windowEnd = SND.NXT)。
// 往復を終えた ACK とその後の ACK が許した分は次の往復に入るので、Read の後の SND.NXT より手前になる。
func TestHyStartRoundEndsAfterWhatTheBurstLetsOut(t *testing.T) {
	n, c, cs, q, outs := rackConnApp(t, 10)
	c.Write(make([]byte, 100*testSegPayload)) // 窓に制限される
	q.deliver(outs, nil)                      // 最初の往復が始まる
	outs = n.drain()
	n.advance(testRTT)
	q.deliver(outs, nil) // 最初の往復が終わり、次の往復が始まる
	if !cs.hystartOn() || !cs.hs.started || seqLT(cs.sndUna, cs.sndMax) {
		t.Fatalf("HyStart++ on %v started %v, flight %d", cs.hystartOn(), cs.hs.started, cs.sndMax-cs.sndUna)
	}
	end := cs.hs.windowEnd
	sent := n.drain()
	una := cs.sndUna
	if len(sent) < 2 || !seqGT(end, una) || seqGT(end, cs.sndNxt) || cs.sndNxt-end > 8*uint32(cs.segMSS()) {
		t.Fatalf("round ends at %d, after ACKs to %d that let out data to %d", end-cs.iss, una-cs.iss, cs.sndNxt-cs.iss)
	}
}

// TestBurstThatDrainsTheFlightIsNotIdle は、送るデータがあるまま ACK が送り残しを空にした後の Read を、黙った後
// の送り始めとみなさないことを確かめる。CUBIC の epoch をずらさず(Linux の CA_EVENT_TX_START は送り残しが
// 空の時にしか起きない)、輻輳の窓を初めの窓に戻さない。
func TestBurstThatDrainsTheFlightIsNotIdle(t *testing.T) {
	n, c, cs, q, outs := rackConnApp(t, 10)
	cs.mu.Lock()
	cs.ssthresh = cs.cwnd // 輻輳の回避から始める
	cs.mu.Unlock()
	c.Write(make([]byte, 200*testSegPayload))
	q.deliver(outs, nil) // epoch はこの ACK の時刻から始まる
	epoch := cs.cubic.epoch
	if epoch == 0 {
		t.Fatal("no CUBIC epoch after the first ACKs in congestion avoidance")
	}
	outs = n.drain()
	n.advance(testRTT)
	q.deliver(outs, nil)
	cs.mu.Lock()
	cs.rto = int64(testRTT) / 2 // 往復より短い RTO:黙った後の規則が働けば窓を初めの窓に戻す
	cs.mu.Unlock()
	cwnd := cs.cwnd
	n.drain()
	if cs.cubic.epoch != epoch {
		t.Fatalf("epoch moved by %v after a burst", time.Duration(cs.cubic.epoch-epoch))
	}
	if cs.cwnd < cwnd {
		t.Fatalf("cwnd fell from %d to %d after a burst", cwnd, cs.cwnd)
	}
}
