package wgstack

import (
	"net/netip"
	"testing"
	"time"
)

// 閉じた接続の FIN を窓が 0 の相手が受けず、相手が probe に応え続けても、Linux の tcp_orphan_retries と同じく
// 後退の回数で打ち切り、RST で枠を返すことを確かめる。
func TestOrphanHeldFINIsBoundedAgainstAZeroWindowPeer(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	p.wnd = 0
	p.ack(nil)
	c.Close()
	fins := 0
	for i := 0; i < 2*3600; i++ { // 2 時間
		n.advance(time.Second)
		for _, o := range n.drain() {
			if o.seg.has(flagRST) {
				if st := n.d.Stats(); st.Conns != 0 || !c.Delivered() {
					t.Fatalf("after the RST: %+v, delivered %v", st, c.Delivered())
				}
				if i > 120 {
					t.Errorf("orphan aborted only after %d s", i)
				}
				return
			}
			if o.seg.has(flagFIN) {
				fins++
			}
			p.ack(nil)
		}
	}
	st := n.d.Stats()
	t.Logf("after 2 h: conns %d, FINs sent %d, delivered %v, state %v", st.Conns, fins, c.Delivered(), n.d.s.conns[c.c.id].state)
	if st.Conns != 0 {
		t.Errorf("a closed connection still holds its slot after 2 h against a zero-window peer that answers probes")
	}
}

// 相手の FIN|ACK が自分の FIN を確認して行に移るとき、ACK は 1 つだけで、TSecr はその FIN の TSval であること。
func TestRowACKOnceEchoingTheFINTSval(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	c.Close()
	p.absorb(n.drain()) // DUT の FIN
	p.tsVal += 77
	s := p.seg(flagACK|flagFIN, nil)
	n.inject(s)
	p.snd++
	outs := n.drain()
	if len(outs) != 1 {
		t.Fatalf("want exactly one ACK, got %v", outs)
	}
	o := outs[0]
	if o.seg.ack != p.snd || !o.seg.opt.hasTS || o.seg.opt.tsEcr != s.tsVal {
		t.Fatalf("row ACK %v TSecr %d, want ack %d TSecr %d", o, o.seg.opt.tsEcr, p.snd, s.tsVal)
	}
	if n.d.Stats().TWRows != 1 {
		t.Fatal("no row")
	}
	// 古い TSval の再送 FIN:TS.Recent を戻さず ACK を返す
	old := p.seg(flagACK|flagFIN, nil)
	old.seq = p.snd - 1
	old.tsVal = s.tsVal - 10
	n.inject(old)
	outs = n.drain()
	if len(outs) != 1 || outs[0].seg.opt.tsEcr != s.tsVal {
		t.Fatalf("ACK to an older retransmitted FIN %v", outs)
	}
	// 新しい TSval の再送 FIN:TSecr はその値
	newer := p.seg(flagACK|flagFIN, nil)
	newer.seq = p.snd - 1
	n.inject(newer)
	outs = n.drain()
	if len(outs) != 1 || outs[0].seg.opt.tsEcr != newer.tsVal {
		t.Fatalf("ACK to a newer retransmitted FIN %v", outs)
	}
}

// 待ち受けを閉じた後に TIME_WAIT の 4 つ組へ RFC 6191 の SYN が来たとき、行の ACK を返して行を残し、握手の
// 途中の表の満杯に数えないことを確かめる。
func TestReuseSYNWithoutListenerGetsTheRowACK(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	c.Close()
	p.absorb(n.drain())
	p.fin()
	n.drain()
	l.Close()
	if _, err := n.d.ListenTCP(netip.AddrPortFrom(dutAddr, 81)); err != nil {
		t.Fatal(err)
	}
	before := n.d.Stats().SynTableFull
	p.tsVal += 1000
	n.inject(tseg{sport: 40000, dport: 80, seq: p.snd + 100000, flags: flagSYN, wnd: 65535, mss: 1380, ws: 7, ts: true, tsVal: p.tsVal})
	outs := n.drain()
	st := n.d.Stats()
	// Linux と同じく、待ち受けが無ければ行の ACK を返し、行を残す。握手の途中の表の満杯には数えない
	if len(outs) != 1 || outs[0].seg.flags != flagACK || st.TWRows != 1 || st.SynTableFull != before {
		t.Fatalf("reply %v; TW rows %d; SynTableFull +%d", outs, st.TWRows, st.SynTableFull-before)
	}
}
