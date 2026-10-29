package wgstack

import (
	"testing"
	"time"
)

// TIME_WAIT の行を使い直す RFC 6191 の SYN を、握手の途中の表の上限で捨てるときは行を外さず、相手が再送した
// SYN も前の接続の SND.NXT の 65537 先から ISS を受けることを確かめる。
func TestReuseISSKeptWhenTheReuseSYNIsRefused(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	go func() {
		c.Write(make([]byte, 1<<20))
		c.Close()
	}()
	for i := 0; i < 100000 && n.d.Stats().TWRows == 0; i++ {
		p.absorb(n.drain())
		p.ack(nil)
		if i%50 == 0 {
			n.advance(time.Millisecond)
		}
	}
	p.fin()
	n.drain()
	if n.d.Stats().TWRows != 1 {
		t.Fatal("no TIME_WAIT row")
	}
	oldNxt := p.rcv
	// 偽の送信元の SYN で、この待ち受けの握手の途中の行を上限まで埋める
	half := n.d.s.lim.synRows / 2
	for i := 0; i < half; i++ {
		n.inject(tseg{src: spoofed(i), sport: uint16(100 + i), dport: 80, seq: 1, flags: flagSYN, wnd: 1000, mss: 1380, ws: -1})
	}
	n.drain()
	n.advance(time.Second)
	p.tsVal += 1000
	syn := tseg{sport: 40000, dport: 80, seq: p.snd + 100000, flags: flagSYN, wnd: 65535, mss: 1380, ws: 7, ts: true, tsVal: p.tsVal}
	n.inject(syn)
	if outs := n.drain(); len(outs) != 0 {
		t.Logf("first reuse SYN answered: %v", outs)
	}
	t.Logf("TW rows after the dropped SYN %d, syn-full %d", n.d.Stats().TWRows, n.d.Stats().SynTableFull)
	// 洪水の行は SYN-ACK の再送を使い切って消える(相手の SYN の再送より前に空く場合)
	for i := 0; i < half; i++ {
		n.inject(tseg{src: spoofed(i), sport: uint16(100 + i), dport: 80, seq: 2, flags: flagRST, ws: -1})
	}
	t.Logf("syn rows after the RSTs %d", n.d.Stats().SynRows)
	n.drain()
	syn.tsVal++
	n.inject(syn) // 相手の SYN の再送
	t.Logf("syn rows after the retransmitted SYN %d, syn-full %d", n.d.Stats().SynRows, n.d.Stats().SynTableFull)
	var sa *out
	for _, o := range n.drain() {
		if o.seg.flags == flagSYN|flagACK && o.seg.tup.lport == 40000 {
			sa = &o
		}
	}
	if sa == nil {
		t.Fatal("no SYN-ACK for the retransmitted SYN")
	}
	t.Logf("old SND.NXT %d new ISS %d", oldNxt, sa.seg.seq)
	if seqLT(sa.seg.seq, oldNxt+65537) {
		t.Errorf("retransmitted reuse SYN got ISS %d, %d bytes behind the old SND.NXT %d", sa.seg.seq, int32(oldNxt-sa.seg.seq), oldNxt)
	}
}

// TestReuseSYNRefusedKeepsTheTimeWaitSlot は、枠に残る TIME_WAIT の接続を使い直す SYN を、握手の途中の表の
// 上限で捨てるときも、枠を TIME_WAIT のまま保つことを確かめる。
func TestReuseSYNRefusedKeepsTheTimeWaitSlot(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	c.CloseWrite()
	p.absorb(n.drain())
	p.ack(nil)
	p.fin()
	n.drain()
	cs := &n.d.s.conns[c.c.id]
	if cs.state != stTimeWait {
		t.Fatalf("state %v", cs.state)
	}
	for i := 0; i < n.d.s.lim.synRows/2; i++ {
		n.inject(tseg{src: spoofed(i), sport: uint16(100 + i), dport: 80, seq: 1, flags: flagSYN, wnd: 1000, mss: 1380, ws: -1})
	}
	n.drain()
	p.tsVal += 1000
	n.inject(tseg{sport: 40000, dport: 80, seq: p.snd + 100000, flags: flagSYN, wnd: 65535, mss: 1380, ws: 7, ts: true, tsVal: p.tsVal})
	if cs.state != stTimeWait {
		t.Fatalf("refused reuse SYN moved the slot to %v", cs.state)
	}
	if outs := n.drain(); len(outs) != 0 {
		t.Fatalf("answered a refused reuse SYN: %v", outs)
	}
}
