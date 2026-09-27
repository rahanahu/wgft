package nettun

import (
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// newKeepalivePairAccept は、待ち受ける側 (b) の stack だけを faketime の時計で作った tcpPair を
// 返す。accept した endpoint の keepalive のタイマーは b の時計で動く。a は実時間のままで、届いた
// probe に ACK を返す。
func newKeepalivePairAccept(t *testing.T) (*tcpPair, *faketime.ManualClock) {
	t.Helper()
	a, err := Create(netip.MustParseAddr("10.95.0.1"), 1420)
	if err != nil {
		t.Fatal(err)
	}
	clock := faketime.NewManualClock()
	stackClock = clock
	b, err := Create(netip.MustParseAddr("10.95.0.2"), 1420)
	stackClock = nil
	if err != nil {
		a.Close()
		t.Fatal(err)
	}
	p := &tcpPair{a: a, b: b, ab: newGate(), ba: newGate()}
	p.forwards = append(p.forwards, p.forward(a, b, p.ab), p.forward(b, a, p.ba))
	t.Cleanup(func() {
		p.ab.resume()
		p.ba.resume()
		a.Close()
		b.Close()
		for _, done := range p.forwards {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Error("TUN forwarder did not stop")
			}
		}
	})
	return p, clock
}

// TestKeepaliveAcceptSideKeepsALiveIdlePeer は、accept した endpoint の keepalive が、probe に ACK を
// 返す生きた相手を切らないことを確かめる(仕様 7 節「接続の寿命」、エージェントの側)。
func TestKeepaliveAcceptSideKeepsALiveIdlePeer(t *testing.T) {
	p, clock := newKeepalivePairAccept(t)
	ln := p.listen(t, 4000)
	c := p.dial(t, 4000)
	s := acceptOne(t, ln)
	defer c.Close()
	defer s.Close()
	if !s.endpoint().SocketOptions().GetKeepAlive() {
		t.Fatal("accepted endpoint: keepalive is off")
	}
	established := func() uint64 { return p.b.stack.Stats().TCP.CurrentEstablished.Value() }
	if established() != 1 {
		t.Fatalf("established %d; want 1", established())
	}
	// 相手 (a) の stack は実時間の時計で、窓の外の segment への ACK を 500 ms に 1 回に絞るので、
	// 往復の間に実時間で 1 秒置く (tcp_keepalive_test.go と同じ)。
	for i := 0; i < 3; i++ {
		if i > 0 {
			time.Sleep(time.Second)
		}
		sent, recv := segmentsSent(s), segmentsReceived(s)
		clock.Advance(tcp.DefaultKeepaliveIdle + time.Second)
		waitSent(t, s, sent+1)
		waitSegments(t, s, recv+1)
	}
	if established() != 1 || tcp.EndpointState(s.endpoint().State()) != tcp.StateEstablished {
		t.Fatalf("established %d state %s after the probes; want 1 and ESTABLISHED", established(), tcp.EndpointState(s.endpoint().State()))
	}
}

// TestKeepaliveAcceptSideDropsAVanishedPeer は、相手 (vpsd) が消えて probe に何も返らなければ、
// accept した endpoint が既定の回数の後に誤りで消え、閉じかけの数にも残らないことを確かめる。
func TestKeepaliveAcceptSideDropsAVanishedPeer(t *testing.T) {
	p, clock := newKeepalivePairAccept(t)
	ln := p.listen(t, 4000)
	c := p.dial(t, 4000)
	s := acceptOne(t, ln)
	defer c.Close()
	defer s.Close()
	// 相手からの packet を止めて、消えた vpsd を模す。
	p.ab.pause()
	sent := segmentsSent(s)
	clock.Advance(tcp.DefaultKeepaliveIdle + time.Second)
	waitSent(t, s, sent+1)
	for i := 0; i < tcp.DefaultKeepaliveCount+1; i++ {
		clock.Advance(tcp.DefaultKeepaliveInterval + time.Second)
		time.Sleep(10 * time.Millisecond)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && tcp.EndpointState(s.endpoint().State()) == tcp.StateEstablished {
		time.Sleep(5 * time.Millisecond)
	}
	if got := tcp.EndpointState(s.endpoint().State()); got == tcp.StateEstablished {
		t.Fatal("accepted endpoint still ESTABLISHED after the keepalive probes went unanswered")
	}
	buf := make([]byte, 1)
	s.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := s.Read(buf); err == nil {
		t.Fatal("read after the keepalive timeout returned no error")
	}
	if got := p.b.stack.Stats().TCP.CurrentEstablished.Value(); got != 0 {
		t.Fatalf("established %d; want 0", got)
	}
	if got := p.b.TCPClosing(); got != 0 {
		t.Fatalf("closing endpoints %d; want 0: a keepalive timeout frees the endpoint", got)
	}
}
