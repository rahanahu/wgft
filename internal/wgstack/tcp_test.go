package wgstack

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"
)

func listen(t testing.TB, n *testNet, port uint16) *TCPListener {
	t.Helper()
	l, err := n.d.ListenTCP(netip.AddrPortFrom(dutAddr, port))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestHandshakeOptions(t *testing.T) {
	n := newTestNet(t, smallLimits())
	listen(t, n, 80)
	p := n.handshake(40000, 80, true, true, true)
	o := p.synAck.seg.opt
	if !o.hasMSS || o.mss != testMTU-40 {
		t.Errorf("MSS %v %d, want %d", o.hasMSS, o.mss, testMTU-40)
	}
	if !o.sackOK || !o.hasTS || !o.hasWS || o.wscale != rcvWindowShft {
		t.Errorf("options %+v", o)
	}
	if o.tsEcr != 5000 {
		t.Errorf("TSecr %d, want 5000", o.tsEcr)
	}
	if w := p.synAck.seg.wnd; w != 64296 {
		t.Errorf("SYN-ACK window %d, want 64296", w)
	}
	if p.synAck.ip.header[6]&0x40 == 0 {
		t.Error("DF is not set")
	}
}

func TestHandshakeBare(t *testing.T) {
	n := newTestNet(t, smallLimits())
	listen(t, n, 80)
	n.inject(tseg{sport: 1, dport: 80, seq: 7, flags: flagSYN, wnd: 1000, ws: -1})
	outs := n.drain()
	if len(outs) != 1 {
		t.Fatalf("got %v", outs)
	}
	o := outs[0].seg.opt
	if o.hasTS || o.sackOK || o.hasWS || !o.hasMSS {
		t.Errorf("options %+v", o)
	}
	// 最後の ACK の後、MSS の無い相手には 536 で送る
	n.inject(tseg{sport: 1, dport: 80, seq: 8, ack: outs[0].seg.seq + 1, flags: flagACK, wnd: 65535, ws: -1})
	l := n.d.s.listeners[netip.AddrPortFrom(dutAddr, 80)]
	c := acceptOne(t, &TCPListener{l: l})
	if _, err := c.Write(make([]byte, 2000)); err != nil {
		t.Fatal(err)
	}
	outs = n.drain()
	if len(outs) == 0 || len(outs[0].seg.payload) != minMSS {
		t.Fatalf("first segment %v, want %d bytes", outs, minMSS)
	}
}

func TestDataBothWays(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, true, true)
	c := acceptOne(t, l)
	p.ack([]byte("hello"))
	buf := make([]byte, 100)
	k, err := c.Read(buf)
	if err != nil || string(buf[:k]) != "hello" {
		t.Fatalf("Read %q %v", buf[:k], err)
	}
	msg := bytes.Repeat([]byte("x"), 5000)
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := p.absorb(n.drain())
	if !bytes.Equal(got, msg) {
		t.Fatalf("peer got %d bytes, want %d", len(got), len(msg))
	}
	if c.RemoteAddr().String() != "10.9.0.2:40000" || c.LocalAddr().String() != "10.9.0.1:80" {
		t.Errorf("addresses %v %v", c.LocalAddr(), c.RemoteAddr())
	}
}

func TestDelayedAck(t *testing.T) {
	n := newTestNet(t, smallLimits())
	listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	n.drain()
	p.ack(make([]byte, 100))
	if outs := n.drain(); len(outs) != 0 {
		t.Fatalf("immediate ACK for one small segment: %v", outs)
	}
	n.advance(39 * time.Millisecond)
	if outs := n.drain(); len(outs) != 0 {
		t.Fatalf("ACK before the delayed ACK timer: %v", outs)
	}
	n.advance(time.Millisecond)
	outs := n.drain()
	if len(outs) != 1 || outs[0].seg.ack != p.snd {
		t.Fatalf("delayed ACK %v", outs)
	}
	// MSS 2 つ分で即座に ACK する
	full := make([]byte, testMTU-40-12)
	p.ack(full)
	if outs := n.drain(); len(outs) != 0 {
		t.Fatalf("ACK after one full segment: %v", outs)
	}
	p.ack(full)
	outs = n.drain()
	if len(outs) != 1 || outs[0].seg.ack != p.snd {
		t.Fatalf("ACK after two full segments: %v", outs)
	}
}

func TestOutOfOrderSACK(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, true, true)
	c := acceptOne(t, l)
	base := p.snd
	seg := func(off uint32, size int) {
		s := p.seg(flagACK, bytes.Repeat([]byte{byte(off)}, size))
		s.seq = base + off
		n.inject(s)
	}
	seg(1000, 100)
	outs := n.drain()
	if len(outs) != 1 || outs[0].seg.ack != base || outs[0].seg.opt.nsack != 1 || outs[0].seg.opt.sack[0] != (sackBlock{base + 1000, base + 1100}) {
		t.Fatalf("after first OOO: %v", outs)
	}
	seg(2000, 100)
	outs = n.drain()
	if len(outs) != 1 || outs[0].seg.opt.nsack != 2 || outs[0].seg.opt.sack[0] != (sackBlock{base + 2000, base + 2100}) {
		t.Fatalf("after second OOO: %v", outs)
	}
	seg(1100, 100) // 最初の区間を伸ばす
	outs = n.drain()
	if len(outs) != 1 || outs[0].seg.opt.sack[0] != (sackBlock{base + 1000, base + 1200}) {
		t.Fatalf("after extending: %v", outs)
	}
	// 穴を埋める
	seg(0, 1000)
	seg(1200, 800)
	outs = n.drain()
	last := outs[len(outs)-1]
	if last.seg.ack != base+2100 || last.seg.opt.nsack != 0 {
		t.Fatalf("after filling: %v", outs)
	}
	buf := make([]byte, 4000)
	k, _ := io.ReadAtLeast(c, buf, 2100)
	if k != 2100 {
		t.Fatalf("read %d", k)
	}
}

func TestRetransmitBackoff(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	c.Write([]byte("data"))
	first := n.drain()
	if len(first) != 1 {
		t.Fatal(first)
	}
	rto := time.Duration(n.d.s.conns[c.c.id].curRTO())
	if rto < rtoMin {
		t.Fatalf("RTO %v below the minimum", rto)
	}
	var gaps []time.Duration
	last := time.Duration(0)
	for i := 0; i < 4; i++ {
		var elapsed time.Duration
		for {
			n.advance(time.Millisecond)
			elapsed += time.Millisecond
			if outs := n.drain(); len(outs) > 0 {
				if outs[0].seg.seq != first[0].seg.seq || string(outs[0].seg.payload) != "data" {
					t.Fatalf("retransmission %v", outs)
				}
				break
			}
			if elapsed > 10*time.Second {
				t.Fatal("no retransmission")
			}
		}
		gaps = append(gaps, elapsed)
		if i > 0 && elapsed < 2*last-2*time.Millisecond {
			t.Errorf("gap %d %v is not double %v", i, elapsed, last)
		}
		last = elapsed
	}
	p.absorb(first)
	p.ack(nil)
	n.advance(5 * time.Second)
	if outs := n.drain(); len(outs) != 0 {
		t.Fatalf("sent after the ACK: %v", outs)
	}
	t.Logf("gaps %v", gaps)
}

func TestFastRetransmitNewReno(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	mss := testMTU - 40 - 12
	c.Write(make([]byte, 10*mss))
	outs := n.drain()
	if len(outs) != 10 {
		t.Fatalf("IW10: sent %d segments", len(outs))
	}
	// 2 つ目を失ったとして、1 つ目の確認と重複した ACK を 3 つ送る
	p.rcv = outs[0].seg.seq + uint32(mss)
	p.ack(nil)
	n.drain()
	for i := 0; i < 3; i++ {
		p.ack(nil)
	}
	got := n.drain()
	if len(got) == 0 || got[0].seg.seq != outs[1].seg.seq {
		t.Fatalf("fast retransmit %v", got)
	}
	cs := &n.d.s.conns[c.c.id]
	if !cs.inRecovery {
		t.Fatal("not in recovery")
	}
	// 部分の確認で次の穴を再送する
	p.rcv = outs[2].seg.seq
	p.ack(nil)
	got = n.drain()
	if len(got) == 0 || got[0].seg.seq != outs[2].seg.seq {
		t.Fatalf("partial ACK retransmit %v", got)
	}
	// 全部の確認で回復を終える
	p.rcv = outs[9].seg.seq + uint32(mss)
	p.ack(nil)
	n.drain()
	if cs.inRecovery {
		t.Fatal("still in recovery after the full ACK")
	}
}

func TestZeroWindowProbe(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	p.wnd = 0
	p.ack(nil)
	n.drain()
	c.Write([]byte("blocked"))
	if outs := n.drain(); len(outs) != 0 {
		t.Fatalf("sent into a zero window: %v", outs)
	}
	var probes []time.Duration
	var el time.Duration
	for len(probes) < 3 && el < 10*time.Second {
		n.advance(time.Millisecond)
		el += time.Millisecond
		for _, o := range n.drain() {
			if o.seg.seq != p.rcv-1 || len(o.seg.payload) != 0 {
				t.Fatalf("probe %v", o)
			}
			probes = append(probes, el)
			p.ack(nil) // 窓は 0 のまま応える
			n.drain()
		}
	}
	if len(probes) < 3 {
		t.Fatalf("probes %v", probes)
	}
	if g1, g2 := probes[1]-probes[0], probes[2]-probes[1]; g2 < 2*g1-2*time.Millisecond {
		t.Errorf("probe backoff %v %v", g1, g2)
	}
	p.wnd = 65535
	p.ack(nil)
	got := p.absorb(n.drain())
	if string(got) != "blocked" {
		t.Fatalf("after window opened: %q", got)
	}
}

func TestRFC5961(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	// 窓の内側で番号の合わない RST には challenge ACK
	s := p.seg(flagRST, nil)
	s.seq += 100
	n.inject(s)
	outs := n.drain()
	if len(outs) != 1 || outs[0].seg.flags != flagACK || outs[0].seg.ack != p.snd {
		t.Fatalf("challenge ACK for in-window RST: %v", outs)
	}
	// 窓の外の RST は無視
	s = p.seg(flagRST, nil)
	s.seq += 1 << 30
	n.inject(s)
	if outs := n.drain(); len(outs) != 0 {
		t.Fatalf("reply to out-of-window RST: %v", outs)
	}
	// 確立後の SYN には challenge ACK
	s = p.seg(flagSYN, nil)
	n.inject(s)
	outs = n.drain()
	if len(outs) != 1 || outs[0].seg.flags != flagACK {
		t.Fatalf("challenge ACK for SYN: %v", outs)
	}
	// 番号の合う RST で接続を終える
	n.inject(p.seg(flagRST, nil))
	if outs := n.drain(); len(outs) != 0 {
		t.Fatalf("reply to RST: %v", outs)
	}
	_, err := c.Read(make([]byte, 10))
	if !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("Read after RST: %v", err)
	}
}

func TestPAWS(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	s := p.seg(flagACK, []byte("old"))
	s.tsVal = 1 // 前の timestamp より古い
	n.inject(s)
	outs := n.drain()
	if len(outs) != 1 || outs[0].seg.ack != p.snd {
		t.Fatalf("PAWS reply %v", outs)
	}
	c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err := c.Read(make([]byte, 10)); !isTimeout(err) {
		t.Fatalf("PAWS-rejected data was delivered: %v", err)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func TestHalfCloseAndTimeWaitRow(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	c.Write([]byte("bye"))
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	outs := n.drain()
	got := p.absorb(outs)
	if string(got) != "bye" || !outs[len(outs)-1].seg.has(flagFIN) {
		t.Fatalf("data and FIN %v", outs)
	}
	// 相手は書き続け、FIN を送る
	p.ack([]byte("more"))
	p.fin()
	n.drain()
	cs := &n.d.s.conns[c.c.id]
	if cs.state != stTimeWait {
		t.Fatalf("state %v, want TIME_WAIT in the slot", cs.state)
	}
	buf := make([]byte, 10)
	k, err := c.Read(buf)
	if err != nil || string(buf[:k]) != "more" {
		t.Fatalf("Read %q %v", buf[:k], err)
	}
	if _, err := c.Read(buf); err != io.EOF {
		t.Fatalf("Read after FIN: %v", err)
	}
	if c.Delivered() {
		t.Fatal("delivered before Close")
	}
	c.Close()
	st := n.d.Stats()
	if st.Conns != 0 || st.TWRows != 1 {
		t.Fatalf("stats after Close %+v", st)
	}
	// 古い接続の値
	if !c.Delivered() {
		t.Error("stale handle is not delivered")
	}
	if _, err := c.Read(buf); !errors.Is(err, net.ErrClosed) {
		t.Errorf("stale Read %v", err)
	}
	if _, err := c.Write(buf); !errors.Is(err, net.ErrClosed) {
		t.Errorf("stale Write %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("stale Close %v", err)
	}
	// 行は再送された FIN に ACK を返す
	s := p.seg(flagACK|flagFIN, nil)
	s.seq = p.snd - 1
	n.inject(s)
	outs = n.drain()
	if len(outs) != 1 || outs[0].seg.ack != p.snd {
		t.Fatalf("TIME_WAIT row ACK %v", outs)
	}
	// RFC 6191:timestamp の大きい SYN は行を外して待ち受けに渡る
	syn := tseg{sport: 40000, dport: 80, seq: p.snd + 100000, flags: flagSYN, wnd: 65535, mss: 1380, ws: 7, ts: true, tsVal: p.tsVal + 10}
	n.inject(syn)
	outs = n.drain()
	if len(outs) != 1 || outs[0].seg.flags != flagSYN|flagACK {
		t.Fatalf("SYN reusing TIME_WAIT %v", outs)
	}
	if n.d.Stats().TWRows != 0 {
		t.Fatal("row not removed")
	}
	// 古い値の Abort は何もしない
	c.Abort()
	if outs := n.drain(); len(outs) != 0 {
		t.Fatalf("stale Abort sent %v", outs)
	}
}

func TestStaleAbortSendsRSTForRow(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	c.Close()
	p.absorb(n.drain())
	p.ack(nil) // FIN を確認する -> FIN_WAIT_2 の行
	if st := n.d.Stats(); st.TWRows != 1 || st.Conns != 0 {
		t.Fatalf("stats %+v", st)
	}
	c.Abort()
	outs := n.drain()
	if len(outs) != 1 || !outs[0].seg.has(flagRST) {
		t.Fatalf("stale Abort %v", outs)
	}
	if n.d.Stats().TWRows != 0 {
		t.Fatal("row not removed by Abort")
	}
}

func TestFinWait2RowDataRST(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	c.Close()
	p.absorb(n.drain())
	p.ack(nil)
	p.ack([]byte("late"))
	outs := n.drain()
	if len(outs) != 1 || !outs[0].seg.has(flagRST) {
		t.Fatalf("data to FIN_WAIT_2 row %v", outs)
	}
	if n.d.Stats().TWRows != 0 {
		t.Fatal("row not removed")
	}
}

func TestCloseWithUnreadDataSendsRST(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	p.ack([]byte("unread"))
	n.drain()
	c.Close()
	outs := n.drain()
	if len(outs) != 1 || !outs[0].seg.has(flagRST) {
		t.Fatalf("Close with unread data %v", outs)
	}
	if st := n.d.Stats(); st.Conns != 0 || st.TWRows != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestAbort(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	c.Abort()
	outs := n.drain()
	if len(outs) != 1 || outs[0].seg.flags != flagRST|flagACK || outs[0].seg.seq != p.rcv {
		t.Fatalf("Abort %v", outs)
	}
	if n.d.Stats().Conns != 0 {
		t.Fatal("slot not returned")
	}
	if !c.Delivered() {
		t.Fatal("not delivered after Abort")
	}
}

func TestMSSFloor(t *testing.T) {
	n := newTestNet(t, smallLimits())
	listen(t, n, 80)
	n.inject(tseg{sport: 1, dport: 80, seq: 1, flags: flagSYN, wnd: 1000, mss: 535, ws: -1})
	if outs := n.drain(); len(outs) != 0 {
		t.Fatalf("answered SYN with MSS 535: %v", outs)
	}
	if n.d.Stats().MSSFloorDrops != 1 {
		t.Fatal("not counted")
	}
	n.inject(tseg{sport: 2, dport: 80, seq: 1, flags: flagSYN, wnd: 1000, mss: 536, ws: -1})
	if outs := n.drain(); len(outs) != 1 {
		t.Fatalf("SYN with MSS 536: %v", outs)
	}
}

func TestClosedPortRST(t *testing.T) {
	n := newTestNet(t, smallLimits())
	n.inject(tseg{sport: 1, dport: 81, seq: 100, flags: flagSYN, wnd: 1000, ws: -1})
	outs := n.drain()
	if len(outs) != 1 || outs[0].seg.flags != flagRST|flagACK || outs[0].seg.ack != 101 {
		t.Fatalf("RST for closed port %v", outs)
	}
	n.inject(tseg{sport: 1, dport: 81, seq: 100, ack: 555, flags: flagACK, wnd: 1000, ws: -1})
	outs = n.drain()
	if len(outs) != 1 || outs[0].seg.flags != flagRST || outs[0].seg.seq != 555 {
		t.Fatalf("RST for ACK %v", outs)
	}
	n.inject(tseg{sport: 1, dport: 81, seq: 100, flags: flagRST, wnd: 1000, ws: -1})
	if outs := n.drain(); len(outs) != 0 {
		t.Fatalf("reply to RST %v", outs)
	}
}

func TestListenerCloseResets(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	n.handshake(40000, 80, true, false, true) // 待ち行列に入る
	n.inject(tseg{sport: 40001, dport: 80, seq: 1, flags: flagSYN, wnd: 1000, ws: -1})
	n.drain()
	if st := n.d.Stats(); st.Conns != 1 || st.SynRows != 1 || st.AcceptQueued != 1 {
		t.Fatalf("before Close %+v", st)
	}
	l.Close()
	outs := n.drain()
	if len(outs) != 2 || !outs[0].seg.has(flagRST) || !outs[1].seg.has(flagRST) {
		t.Fatalf("listener Close %v", outs)
	}
	if st := n.d.Stats(); st.Conns != 0 || st.SynRows != 0 || st.AcceptQueued != 0 {
		t.Fatalf("after Close %+v", st)
	}
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close %v", err)
	}
	// ポートはその場で空く
	listen(t, n, 80)
}

func TestAcceptQueueRSTRemoves(t *testing.T) {
	n := newTestNet(t, smallLimits())
	listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	n.inject(p.seg(flagRST, nil))
	if st := n.d.Stats(); st.Conns != 0 || st.AcceptQueued != 0 {
		t.Fatalf("after RST in the accept queue %+v", st)
	}
}

func TestSynAckRetransmitAndIW1(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	n.inject(tseg{sport: 9, dport: 80, seq: 1, flags: flagSYN, wnd: 65535, mss: 1380, ws: 7})
	first := n.drain()
	var times []time.Duration
	var el time.Duration
	for el < 70*time.Second {
		n.advance(100 * time.Millisecond)
		el += 100 * time.Millisecond
		for _, o := range n.drain() {
			if o.seg.flags != flagSYN|flagACK || o.seg.seq != first[0].seg.seq {
				t.Fatalf("retransmission %v", o)
			}
			times = append(times, el)
		}
	}
	want := []time.Duration{time.Second, 3 * time.Second, 7 * time.Second, 15 * time.Second, 31 * time.Second}
	if len(times) != len(want) {
		t.Fatalf("SYN-ACK retransmissions at %v, want %v", times, want)
	}
	for i := range want {
		if d := times[i] - want[i]; d < 0 || d > 100*time.Millisecond {
			t.Errorf("retransmission %d at %v, want %v", i, times[i], want[i])
		}
	}
	if n.d.Stats().SynRows != 0 {
		t.Fatal("row not removed after the retries")
	}
	// 再送した後に成立した接続の初期の窓は 1 segment
	n.inject(tseg{sport: 10, dport: 80, seq: 1, flags: flagSYN, wnd: 65535, mss: 1380, ws: 7})
	sa := n.drain()[0]
	n.advance(time.Second)
	n.drain()
	n.inject(tseg{sport: 10, dport: 80, seq: 2, ack: sa.seg.seq + 1, flags: flagACK, wnd: 1000, ws: -1})
	c := acceptOne(t, l)
	c.Write(make([]byte, 10000))
	if outs := n.drain(); len(outs) != 1 {
		t.Fatalf("initial window after SYN-ACK retransmit: %d segments", len(outs))
	}
}

func TestReadDeadlineAndEOF(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	_, err := c.Read(make([]byte, 10))
	if !isTimeout(err) || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read after deadline: %v", err)
	}
	c.SetReadDeadline(time.Time{})
	done := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 10))
		done <- err
	}()
	time.Sleep(10 * time.Millisecond)
	p.fin()
	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatalf("Read after FIN: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read did not wake")
	}
}

func TestDeviceContract(t *testing.T) {
	clk := NewManualClock()
	d, err := newDevice(Config{Addr: dutAddr, MTU: testMTU, Clock: clk, Rand: seededRand()}, smallLimits(), newBoostPool(boostSlots))
	if err != nil {
		t.Fatal(err)
	}
	if ev := <-d.Events(); ev != 1 {
		t.Fatalf("event %v", ev)
	}
	if d.BatchSize() != 1 || d.File() != nil {
		t.Fatal("BatchSize or File")
	}
	if m, _ := d.MTU(); m != testMTU {
		t.Fatal("MTU")
	}
	k, err := d.Write([][]byte{{}, {0x60, 0, 0, 0}, {0x45, 0}}, 0)
	if k != 2 || !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("Write %d %v", k, err)
	}
	l, _ := d.ListenTCP(netip.AddrPortFrom(dutAddr, 80))
	readErr := make(chan error, 1)
	go func() {
		_, err := d.Read([][]byte{make([]byte, 2000)}, []int{0}, 0)
		readErr <- err
	}()
	acceptErr := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		acceptErr <- err
	}()
	time.Sleep(10 * time.Millisecond)
	d.Close()
	if err := <-readErr; !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Read after Close %v", err)
	}
	if err := <-acceptErr; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close %v", err)
	}
	if _, ok := <-d.Events(); ok {
		t.Fatal("Events not closed")
	}
	if _, err := d.Write([][]byte{buildPeer(tseg{sport: 1, dport: 80, flags: flagSYN, ws: -1})}, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Write after Close %v", err)
	}
	d.Close()
}

func TestCloseWithPendingDataRetiresAfterDelivery(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	go func() {
		c.Write(make([]byte, 100000))
		c.Close()
	}()
	total := 0
	for i := 0; i < 2000 && n.d.Stats().TWRows == 0; i++ {
		got := p.absorb(n.drain())
		total += len(got)
		p.ack(nil)
		n.advance(time.Millisecond)
	}
	st := n.d.Stats()
	if total != 100000 || st.TWRows != 1 || st.Conns != 0 {
		t.Fatalf("delivered %d, stats %+v", total, st)
	}
	if !c.Delivered() {
		t.Fatal("not delivered")
	}
}

func TestFINIntoZeroWindowIsRetransmitted(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	p := n.handshake(40000, 80, true, false, true)
	c := acceptOne(t, l)
	n.drain()
	p.wnd = 0
	p.ack(nil)
	c.CloseWrite()
	outs := n.drain()
	if len(outs) != 1 || !outs[0].seg.has(flagFIN) {
		t.Fatalf("FIN into a zero window %v", outs)
	}
	// FIN を失ったとして、再送を待つ
	var got []out
	for i := 0; i < 5000 && len(got) == 0; i++ {
		n.advance(time.Millisecond)
		got = n.drain()
	}
	if len(got) == 0 || !got[0].seg.has(flagFIN) || got[0].seg.seq != outs[0].seg.seq {
		t.Fatalf("FIN not retransmitted: %v", got)
	}
}
