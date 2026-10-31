package wgstack

import (
	"net/netip"
	"testing"
	"time"
)

// 閉じた接続の FIN を窓が 0 の相手が受けず、相手が probe に応え続けても、Linux と同じく後退の回数と RTO の
// 上限で打ち切り、RST で枠を返すことを確かめる。
func TestOrphanHeldFINIsBoundedAgainstAZeroWindowPeer(t *testing.T) {
	n := newTestNet(t, smallLimits())
	c, p := n.accepted(true, false)
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
				// Linux と同じく、後退を含めた RTO が 120 秒に届いた後の次の期限(最小の RTO で約 325 秒)まで打ち切らない
				if i < 300 || i > 400 {
					t.Errorf("orphan aborted after %d s, want about 325 s", i)
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
	c, p := n.accepted(true, false)
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

// flapWindow は、窓が 0 の間 probe に応え、gap ごとに約 10 KB だけ窓を開ける相手に 200,000 byte を送らせる。
// appClose が真なら書いた後に Close、偽なら CloseWrite する。届いた byte、RST を受けたか、最後の枠の数を返す。
func flapWindow(t *testing.T, gap time.Duration, appClose bool) (delivered int, reset bool, conns int) {
	n := newTestNet(t, smallLimits())
	c, p := n.accepted(true, false)
	const total = 200000
	c.Write(make([]byte, total))
	p.wnd = 0
	p.ack(nil)
	if appClose {
		c.Close()
	} else {
		c.CloseWrite()
	}
	for round := 0; round < 200 && delivered < total; round++ {
		for el := time.Duration(0); el < gap; el += 100 * time.Millisecond { // 窓は 0:probe に応える
			n.advance(100 * time.Millisecond)
			for _, o := range n.drain() {
				if o.seg.has(flagRST) {
					return delivered, true, n.d.Stats().Conns
				}
				delivered += len(p.absorb([]out{o}))
				p.ack(nil)
			}
		}
		p.wnd = 10000 >> 7 // 約 10 KB を開ける
		p.ack(nil)
		for i := 0; i < 50; i++ {
			outs := n.drain()
			for _, o := range outs {
				if o.seg.has(flagRST) {
					return delivered, true, n.d.Stats().Conns
				}
			}
			delivered += len(p.absorb(outs))
			if len(outs) == 0 {
				break
			}
		}
		p.wnd = 0
		p.ack(nil)
	}
	return delivered, false, n.d.Stats().Conns
}

// TestFlappingWindowDeliversTheTail は、窓が 0 と小さな窓を行き来する相手に、閉じた接続も閉じていない接続も
// 末尾を届け終えることを確かめる。窓が開くたびに後退が戻るので、閉じた接続も打ち切らない。窓が 0 の間が
// 約 325 秒を超えると、閉じた接続だけを打ち切る。
func TestFlappingWindowDeliversTheTail(t *testing.T) {
	for _, gap := range []time.Duration{20 * time.Second, 45 * time.Second, 60 * time.Second} {
		for _, appClose := range []bool{true, false} {
			delivered, reset, _ := flapWindow(t, gap, appClose)
			if reset || delivered != 200000 {
				t.Errorf("gap %v appClose %v: delivered %d, reset %v", gap, appClose, delivered, reset)
			}
		}
	}
	if _, reset, conns := flapWindow(t, 400*time.Second, true); !reset || conns != 0 {
		t.Errorf("closed connection with a 400 s zero window: reset %v, conns %d", reset, conns)
	}
	if _, reset, _ := flapWindow(t, 400*time.Second, false); reset {
		t.Error("an open connection was aborted during a 400 s zero window")
	}
}

// TestOpenConnNotOrphanLimited は、アプリケーションが閉じていない接続の窓の probe を、相手が応える間は
// 1 時間でも打ち切らないことを確かめる。
func TestOpenConnNotOrphanLimited(t *testing.T) {
	n := newTestNet(t, smallLimits())
	c, p := n.accepted(true, false)
	p.wnd = 0
	p.ack(nil)
	c.Write(make([]byte, 5000)) // 送れないデータを持つ
	for i := 0; i < 3600; i++ {
		n.advance(time.Second)
		for _, o := range n.drain() {
			if o.seg.has(flagRST) {
				t.Fatalf("an open connection was aborted after %d s", i)
			}
			p.ack(nil)
		}
	}
	if n.d.Stats().Conns != 1 || c.Delivered() {
		t.Fatalf("after 1 h: conns %d, delivered %v", n.d.Stats().Conns, c.Delivered())
	}
}

// TestOrphanAbortDeliveredAndSlot は、閉じた接続を窓の probe で打ち切った後、枠が返り、Delivered が真になり、
// 打ち切りが数えられることを確かめる。打ち切りは閉じた後に起き、後退を含めた RTO が上限に届く前には起きない。
func TestOrphanAbortDeliveredAndSlot(t *testing.T) {
	n := newTestNet(t, smallLimits())
	c, p := n.accepted(true, false)
	p.wnd = 0
	p.ack(nil)
	c.Write(make([]byte, 5000))
	n.advance(30 * time.Second) // 閉じる前の probe
	for range n.drain() {
		p.ack(nil)
	}
	c.Close()
	closedAt := n.clk.Now()
	var abortedAt time.Duration
	for i := 0; i < 3600 && abortedAt == 0; i++ {
		n.advance(time.Second)
		for _, o := range n.drain() {
			if o.seg.has(flagRST) {
				abortedAt = n.clk.Now()
			}
			p.ack(nil)
		}
	}
	st := n.d.Stats()
	if abortedAt == 0 || abortedAt <= closedAt || st.Conns != 0 || !c.Delivered() || st.ProbeAborts != 1 {
		t.Fatalf("closed at %v, aborted at %v: %+v, delivered %v", closedAt, abortedAt, st, c.Delivered())
	}
	if rto := n.d.s.conns[c.c.id].curRTO(); rto != 0 {
		t.Logf("slot reused, RTO %v", rto)
	}
}
