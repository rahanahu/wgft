package wgstack

import (
	"testing"
	"time"
)

// timestamp を使う接続の ACK の TSecr が自分の今の TSval より先(送っていない値)なら、その ACK では RTT を
// 測らない。同じ ACK が再送していない記録を確認して Karn の標本が取れても、それで代わりに測らない(rttOnAck)。
func TestRejectedTSecrDoesNotFallBackToTheKarnSample(t *testing.T) {
	n := newTestNet(t, smallLimits())
	c, p := n.accepted(true, true)
	if _, err := c.Write(make([]byte, 1000)); err != nil {
		t.Fatal(err)
	}
	p.absorb(n.drain())
	cs := &n.d.s.conns[c.c.id]
	cs.mu.Lock()
	srtt, rttvar := cs.srtt, cs.rttvar
	cs.mu.Unlock()
	n.advance(300 * time.Millisecond) // Karn の標本は 300 ms になり、今の SRTT と違う
	s := p.seg(flagACK, nil)
	s.tsEcr = p.dutTS + 1_000_000 // 自分が送っていない TSval
	n.inject(s)
	cs.mu.Lock()
	una, gotSRTT, gotVar := cs.sndUna, cs.srtt, cs.rttvar
	cs.mu.Unlock()
	if una != p.rcv {
		t.Fatalf("the ACK did not advance SND.UNA: %d, want %d", una, p.rcv)
	}
	if gotSRTT != srtt || gotVar != rttvar {
		t.Fatalf("SRTT %v RTTVAR %v changed to %v %v by an ACK whose TSecr was rejected", time.Duration(srtt), time.Duration(rttvar), time.Duration(gotSRTT), time.Duration(gotVar))
	}
}

// 窓の probe の間(persist)に SND.UNA を進める ACK を受けても、再送のタイマーの節は窓の probe の期限のままで、
// RTO を張らない(retransTimerOnAck)。RTO の後に失われた記録だけが残る間に相手が窓を 0 にすると persist に入り、
// その後に相手が前に届いていた分を確認する。
func TestAckInPersistKeepsTheProbeTimer(t *testing.T) {
	n := newTestNet(t, smallLimits())
	c, p := n.accepted(true, false)
	if _, err := c.Write(make([]byte, 3000)); err != nil {
		t.Fatal(err)
	}
	n.drain() // 相手は受けない
	n.advance(1100 * time.Millisecond)
	n.drain() // RTO の送り直しも失う
	p.wnd = 0
	p.ack(nil)
	n.drain()
	cs := &n.d.s.conns[c.c.id]
	for i := 0; i < 100; i++ {
		cs.mu.Lock()
		persist := cs.persist
		cs.mu.Unlock()
		if persist {
			break
		}
		n.advance(100 * time.Millisecond)
		n.drain()
	}
	cs.mu.Lock()
	persist, deadline, una := cs.persist, cs.tdl[tmrRetrans], cs.sndUna
	cs.mu.Unlock()
	if !persist || deadline == 0 {
		t.Fatalf("not in persist with an armed probe timer: persist %v deadline %d", persist, deadline)
	}
	p.rcv = una + 1000 // 前に届いていた分を確認する。窓は 0 のまま
	p.ack(nil)
	cs.mu.Lock()
	persist2, deadline2, una2, rtoAt := cs.persist, cs.tdl[tmrRetrans], cs.sndUna, cs.rtoAt
	cs.mu.Unlock()
	if una2 != una+1000 {
		t.Fatalf("SND.UNA %d after the ACK, want %d", una2, una+1000)
	}
	if !persist2 || deadline2 != deadline || rtoAt != 0 {
		t.Fatalf("after the ACK in persist: persist %v, retransmit node %d (was %d), RTO %d; want the probe timer kept and no RTO", persist2, deadline2, deadline, rtoAt)
	}
}
