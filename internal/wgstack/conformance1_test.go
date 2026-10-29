package wgstack

import (
	"testing"
	"time"
)

// TestCombinedFINACKIsAcknowledged は、自分の FIN の後に相手が自分の FIN を確認する FIN を 1 つの segment で
// 送ったとき、その場で ACK を返すことを確かめる。接続は TIME_WAIT の行に移るが、移る前に負った ACK を落とさない。
func TestCombinedFINACKIsAcknowledged(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	c.Close()
	outs := n.drain()
	if len(outs) != 1 || !outs[0].seg.has(flagFIN) {
		t.Fatalf("FIN %v", outs)
	}
	p.absorb(outs)
	p.fin() // FIN|ACK、自分の FIN を確認する
	outs = n.drain()
	if len(outs) != 1 || outs[0].seg.flags != flagACK || outs[0].seg.ack != p.snd {
		t.Fatalf("ACK for the combined FIN: %v", outs)
	}
	if outs[0].seg.opt.tsEcr != p.tsVal {
		t.Errorf("TSecr %d, want the FIN's TSval %d", outs[0].seg.opt.tsEcr, p.tsVal)
	}
	if st := n.d.Stats(); st.TWRows != 1 || st.Conns != 0 {
		t.Fatalf("stats %+v", st)
	}
	// 再送された FIN への ACK は、その FIN の TSval を返す
	n.advance(500 * time.Millisecond)
	s := p.seg(flagACK|flagFIN, nil)
	s.seq = p.snd - 1
	n.inject(s)
	outs = n.drain()
	if len(outs) != 1 || outs[0].seg.opt.tsEcr != s.tsVal {
		t.Fatalf("ACK for the retransmitted FIN %v, want TSecr %d", outs, s.tsVal)
	}
}
