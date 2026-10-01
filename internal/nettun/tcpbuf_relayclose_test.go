package nettun

import (
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// userTimeout は c の endpoint に置かれた user timeout を返す。
func userTimeout(t *testing.T, c net.Conn) time.Duration {
	t.Helper()
	var o tcpip.TCPUserTimeoutOption
	if err := connOf(c).ep.GetSockOpt(&o); err != nil {
		t.Fatalf("get user timeout: %v", err)
	}
	return time.Duration(o)
}

// shortRelayCloseTimeout は、この試験の間だけ relayCloseUserTimeout を d にする。
func shortRelayCloseTimeout(t *testing.T, d time.Duration) {
	old := relayCloseUserTimeout
	relayCloseUserTimeout = d
	t.Cleanup(func() { relayCloseUserTimeout = old })
}

// waitState は c の endpoint が want になるまで最長 d 待ち、最後の状態を返す。
func waitState(c net.Conn, want tcp.EndpointState, d time.Duration) tcp.EndpointState {
	end := time.Now().Add(d)
	for {
		st := state(c)
		if st == want || time.Now().After(end) {
			return st
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func registered(p *tcpPair, c net.Conn) bool {
	ep, _ := connOf(c).ep.(*tcp.Endpoint)
	for _, e := range p.b.stack.RegisteredEndpoints() {
		if e == stack.TransportEndpoint(ep) {
			return true
		}
	}
	return false
}

// user timeout を置くのは、中継の終わりの閉じ方で閉じる boost を持たない接続だけである。動いている接続、
// CloseWrite、通常の Close、boost を持つ接続には置かない。
func TestCloseAfterRelaySetsUserTimeoutOnlyOnFloor(t *testing.T) {
	p := newTCPPair(t, 1)

	live, liveS := p.dial(t)
	defer live.Close()
	defer liveS.Close()
	if d := userTimeout(t, liveS); d != 0 {
		t.Fatalf("live connection: user timeout %v, want 0", d)
	}
	liveS.(*TCPConn).CloseWrite()
	if d := userTimeout(t, liveS); d != 0 {
		t.Fatalf("after CloseWrite: user timeout %v, want 0", d)
	}

	c1, s1 := p.dial(t)
	defer c1.Close()
	s1.Close()
	if d := userTimeout(t, s1); d != 0 {
		t.Fatalf("after Close: user timeout %v, want 0", d)
	}

	c2, s2 := p.dial(t)
	defer c2.Close()
	if boosted(s2) {
		t.Fatal("setup: floor connection is boosted")
	}
	s2.(*TCPConn).CloseAfterRelay()
	if d := userTimeout(t, s2); d != relayCloseUserTimeout {
		t.Fatalf("floor connection after CloseAfterRelay: user timeout %v, want %v", d, relayCloseUserTimeout)
	}

	c3, s3 := p.dial(t)
	defer c3.Close()
	bulk(t, s3, c3, 2<<20)
	if !boosted(s3) {
		t.Fatal("setup: sender not boosted")
	}
	s3.(*TCPConn).CloseAfterRelay()
	if d := userTimeout(t, s3); d != 0 {
		t.Fatalf("boost holder after CloseAfterRelay: user timeout %v, want 0", d)
	}
}

// 読まない相手に送り残しを持って中継の終わりの閉じ方で閉じた floor の接続は、同じ停滞が続けば期限の後に
// ERROR になって stack から外れる。相手が読み始めると、受信のキューのデータの後に reset を受ける。
// 同じ形の boost の保有者は今までどおり残る。
func TestCloseAfterRelayEndsZeroWindowStall(t *testing.T) {
	shortRelayCloseTimeout(t, 2*time.Second)
	p := newTCPPair(t, 1)

	cb, sb := p.dial(t)
	defer cb.Close()
	bulk(t, sb, cb, 2<<20)
	if !boosted(sb) {
		t.Fatal("setup: boost holder not boosted")
	}
	fillNonReader(sb)

	c, s := p.dial(t)
	defer c.Close()
	if fillNonReader(s) == 0 || boosted(s) {
		t.Fatal("setup: floor connection did not fill or is boosted")
	}
	sb.(*TCPConn).CloseAfterRelay()
	s.(*TCPConn).CloseAfterRelay()
	if st := state(s); st != tcp.StateFinWait1 {
		t.Fatalf("setup: closed floor connection in %v, want FIN-WAIT1", st)
	}
	if st := waitState(s, tcp.StateError, 15*time.Second); st != tcp.StateError {
		t.Fatalf("floor connection with a stalled peer: %v after the timeout, want ERROR", st)
	}
	if registered(p, s) {
		t.Fatal("timed out endpoint is still registered")
	}
	if st := state(sb); st != tcp.StateFinWait1 {
		t.Fatalf("boost holder: %v, want it to stay in FIN-WAIT1", st)
	}
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := io.Copy(io.Discard, c)
	if err == nil || !strings.Contains(err.Error(), "reset") {
		t.Fatalf("peer read after the timeout: %v, want a reset", err)
	}
}

// 窓が開いたまま送ったデータが確認されない停滞にも効く。経路が届かない間に期限が過ぎると接続は ERROR に
// なり、経路が戻った後の相手は何も受け取らず、次に送ったものへの reset で知る。
func TestCloseAfterRelayEndsUnackedOpenWindow(t *testing.T) {
	shortRelayCloseTimeout(t, 2*time.Second)
	var blackhole atomic.Bool
	p := newTCPPairOpts(t, 0, nil, func([]byte) bool { return blackhole.Load() })
	c, s := p.dial(t)
	defer c.Close()

	blackhole.Store(true)
	if n, err := s.Write(make([]byte, 64<<10)); err != nil || n != 64<<10 {
		t.Fatalf("setup: write %d, %v", n, err)
	}
	s.(*TCPConn).CloseAfterRelay()
	if st := waitState(s, tcp.StateError, 15*time.Second); st != tcp.StateError {
		t.Fatalf("floor connection with unacknowledged data and an open window: %v, want ERROR", st)
	}
	blackhole.Store(false)

	got := make(chan error, 1)
	go func() {
		n, err := io.Copy(io.Discard, c)
		if n != 0 {
			err = io.ErrShortWrite // データを受け取った印。期待しない
		}
		got <- err
	}()
	time.Sleep(500 * time.Millisecond)
	if _, err := c.Write([]byte{'x'}); err != nil {
		t.Fatalf("peer write: %v", err)
	}
	select {
	case err := <-got:
		if err == nil || !strings.Contains(err.Error(), "reset") {
			t.Fatalf("peer after the timeout: %v, want a reset and no data", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("peer did not learn of the timeout from its next send")
	}
}
