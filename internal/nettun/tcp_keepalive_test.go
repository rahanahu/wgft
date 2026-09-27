package nettun

import (
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// newKeepalivePair は、dial する側 (a) の stack だけを faketime の時計で作った tcpPair を返す。
// keepalive のタイマーは a の stack の時計で動くので、時計を進めれば数時間の idle を待たずに
// probe が出る。b は実時間の時計のままで、届いた probe に ACK を返す。
func newKeepalivePair(t *testing.T) (*tcpPair, *faketime.ManualClock) {
	t.Helper()
	clock := faketime.NewManualClock()
	stackClock = clock
	a, err := Create(netip.MustParseAddr("10.96.0.1"), 1420)
	stackClock = nil
	if err != nil {
		t.Fatal(err)
	}
	b, err := Create(netip.MustParseAddr("10.96.0.2"), 1420)
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

func segmentsReceived(c endpointConn) uint64 {
	return c.endpoint().Stats().(*tcp.Stats).SegmentsReceived.Value()
}

func segmentsSent(c endpointConn) uint64 {
	return c.endpoint().Stats().(*tcp.Stats).SegmentsSent.Value()
}

func waitSent(t *testing.T, c endpointConn, want uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if segmentsSent(c) >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("segments sent %d; want at least %d: no keepalive probe went out", segmentsSent(c), want)
}

func waitSegments(t *testing.T, c endpointConn, want uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if segmentsReceived(c) >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("segments received %d; want at least %d", segmentsReceived(c), want)
}

// TestKeepaliveKeepsALiveIdlePeer は、idle の後の probe に相手が ACK を返す限り、接続が ESTABLISHED の
// まま残ることを確かめる(仕様 7 節「接続の寿命」: keepalive は生きた相手を切らない)。
func TestKeepaliveKeepsALiveIdlePeer(t *testing.T) {
	p, clock := newKeepalivePair(t)
	ln := p.listen(t, 4000)
	c := p.dial(t, 4000)
	s := acceptOne(t, ln)
	defer s.Close()
	defer c.Close()
	established := func() uint64 { return p.a.stack.Stats().TCP.CurrentEstablished.Value() }
	if established() != 1 {
		t.Fatalf("established %d; want 1", established())
	}
	// idle の期限で probe が出て、相手の ACK が届く。ACK が届いた probe は接続が生きている証拠
	// なので、gVisor は次の probe を interval ではなく idle の後に出す。したがって毎回 idle の分だけ
	// 時計を進め、probe が出たこと (送信の数) と ACK が返ったこと (受信の数) を順に待つ。
	// 相手の stack は実時間の時計で動き、窓の外の segment への ACK を 1 endpoint あたり 500 ms に
	// 1 回に絞る (stack.TCPInvalidRateLimit の既定) ので、往復の間に実時間で 1 秒置く。
	for i := 0; i < 3; i++ {
		if i > 0 {
			time.Sleep(time.Second)
		}
		sent, recv := segmentsSent(c), segmentsReceived(c)
		clock.Advance(tcp.DefaultKeepaliveIdle + time.Second)
		waitSent(t, c, sent+1)
		waitSegments(t, c, recv+1)
	}
	if established() != 1 || tcp.EndpointState(c.endpoint().State()) != tcp.StateEstablished {
		t.Fatalf("established %d state %s after the probes; want 1 and ESTABLISHED", established(), tcp.EndpointState(c.endpoint().State()))
	}
}

// TestKeepaliveDropsAVanishedPeer は、probe に何も返らなければ、gVisor の既定の回数(9 回、75 秒
// 間隔)の後に接続が誤りで消え、閉じかけの数にも残らないことを確かめる(仕様 7 節「接続の寿命」)。
func TestKeepaliveDropsAVanishedPeer(t *testing.T) {
	p, clock := newKeepalivePair(t)
	ln := p.listen(t, 4000)
	c := p.dial(t, 4000)
	s := acceptOne(t, ln)
	defer s.Close()
	defer c.Close()
	// 相手からの packet を止めて、消えた相手を模す。
	p.ba.pause()
	// ACK の返らない probe は interval ごとに続き、count 回を超えると誤りになる。
	sent := segmentsSent(c)
	clock.Advance(tcp.DefaultKeepaliveIdle + time.Second)
	waitSent(t, c, sent+1)
	for i := 0; i < tcp.DefaultKeepaliveCount+1; i++ {
		clock.Advance(tcp.DefaultKeepaliveInterval + time.Second)
		time.Sleep(10 * time.Millisecond)
	}
	if got := segmentsSent(c); got < sent+uint64(tcp.DefaultKeepaliveCount) {
		t.Fatalf("segments sent %d; want at least %d probes on top of %d", got, tcp.DefaultKeepaliveCount, sent)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && tcp.EndpointState(c.endpoint().State()) == tcp.StateEstablished {
		time.Sleep(5 * time.Millisecond)
	}
	if got := tcp.EndpointState(c.endpoint().State()); got == tcp.StateEstablished {
		t.Fatal("endpoint still ESTABLISHED after the keepalive probes went unanswered")
	}
	buf := make([]byte, 1)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(buf); err == nil {
		t.Fatal("read after the keepalive timeout returned no error")
	}
	if got := p.a.stack.Stats().TCP.CurrentEstablished.Value(); got != 0 {
		t.Fatalf("established %d; want 0", got)
	}
	if got := p.a.TCPClosing(); got != 0 {
		t.Fatalf("closing endpoints %d; want 0: a keepalive timeout frees the endpoint", got)
	}
	var idle tcpip.KeepaliveIdleOption
	if err := c.endpoint().GetSockOpt(&idle); err != nil || time.Duration(idle) != tcp.DefaultKeepaliveIdle {
		t.Fatalf("keepalive idle %s err %v; want the default %s", time.Duration(idle), err, tcp.DefaultKeepaliveIdle)
	}
}
