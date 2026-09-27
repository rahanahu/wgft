package nettun

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// tcpPair は、2 つの Device を向きごとに止められる転送で背中合わせに繋ぐ。a が dial し、b が待ち受ける。
type tcpPair struct {
	a, b     *Device
	ab, ba   *gate // a → b、b → a の転送の門
	forwards []<-chan struct{}
}

// gate は転送の門。pause で閉じ、resume で開く。転送は packet ごとに門を通り、閉じている間は
// 開くまで待つ。open は開いている間は閉じた channel、閉じている間は開いた channel である。
type gate struct {
	mu   sync.Mutex
	open chan struct{}
}

func newGate() *gate {
	g := &gate{open: make(chan struct{})}
	close(g.open)
	return g
}

func (g *gate) pause() {
	g.mu.Lock()
	defer g.mu.Unlock()
	select {
	case <-g.open:
		g.open = make(chan struct{})
	default:
	}
}

func (g *gate) resume() {
	g.mu.Lock()
	defer g.mu.Unlock()
	select {
	case <-g.open:
	default:
		close(g.open)
	}
}

func (g *gate) pass() {
	g.mu.Lock()
	open := g.open
	g.mu.Unlock()
	<-open
}

func newTCPPair(t *testing.T) *tcpPair {
	t.Helper()
	a, err := Create(netip.MustParseAddr("10.98.0.1"), 1420)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Create(netip.MustParseAddr("10.98.0.2"), 1420)
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
	return p
}

func (p *tcpPair) forward(from, to *Device, g *gate) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		sizes := []int{0}
		for {
			n, err := from.Read([][]byte{buf}, sizes, 0)
			if err != nil || n != 1 {
				return
			}
			packet := append([]byte(nil), buf[:sizes[0]]...)
			g.pass()
			if _, err := to.Write([][]byte{packet}, 0); err != nil {
				return
			}
		}
	}()
	return done
}

func (p *tcpPair) listen(t *testing.T, port uint16) *TCPListener {
	t.Helper()
	ln, err := p.b.ListenTCP(netip.AddrPortFrom(p.b.local, port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

func (p *tcpPair) dial(t *testing.T, port uint16) *dialedConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := p.a.DialTCP(ctx, netip.AddrPortFrom(p.b.local, port))
	if err != nil {
		t.Fatal(err)
	}
	return c.(*dialedConn)
}

func acceptOne(t *testing.T, ln *TCPListener) *TCPConn {
	t.Helper()
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		ch <- result{c, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatal(r.err)
		}
		return r.c.(*TCPConn)
	case <-time.After(5 * time.Second):
		t.Fatal("accept timed out")
		return nil
	}
}

func waitState(t *testing.T, c endpointConn, want tcp.EndpointState) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if tcp.EndpointState(c.endpoint().State()) == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("endpoint state %s; want %s", tcp.EndpointState(c.endpoint().State()), want)
}

// readAll は c から EOF か誤りまで読む。
func readAll(c net.Conn) ([]byte, error) {
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	return io.ReadAll(c)
}

// timeWaitOnDialer は、a の側が能動的に閉じて TIME_WAIT に入る接続を 1 本作り、TIME_WAIT に
// 入ったところで返す。呼び出し側がその Close を試す。
func timeWaitOnDialer(t *testing.T, p *tcpPair, ln *TCPListener) *dialedConn {
	t.Helper()
	c := p.dial(t, 4000)
	s := acceptOne(t, ln)
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if data, err := readAll(s); err != nil || len(data) != 0 {
		t.Fatalf("server read: %q %v", data, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if data, err := readAll(c); err != nil || len(data) != 0 {
		t.Fatalf("client read: %q %v", data, err)
	}
	waitState(t, c, tcp.StateTimeWait)
	return c
}

func TestTCPClosingCapReleasesTimeWaitAtCapOnly(t *testing.T) {
	p := newTCPPair(t)
	ln := p.listen(t, 4000)
	const k = 3
	p.a.SetTCPClosingCap(k)

	// 天井の下では、TIME_WAIT の endpoint は Close の後も TIME_WAIT に残る(TCP の意味を変えない)。
	for i := 1; i < k; i++ {
		c := timeWaitOnDialer(t, p, ln)
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		if got := tcp.EndpointState(c.endpoint().State()); got != tcp.StateTimeWait {
			t.Fatalf("close %d below the cap: state %s; want TIME_WAIT", i, got)
		}
		if got := p.a.TCPClosing(); got != i {
			t.Fatalf("closing endpoints after close %d: %d; want %d", i, got, i)
		}
	}
	// 閉じかけの数が K に達すると(閉じる endpoint 自身も TIME_WAIT で数に入る)、その TIME_WAIT は
	// 直ちに解放される。
	c := timeWaitOnDialer(t, p, ln)
	if got := p.a.TCPClosing(); got != k {
		t.Fatalf("closing endpoints at the cap: %d; want %d", got, k)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if got := tcp.EndpointState(c.endpoint().State()); got == tcp.StateTimeWait {
		t.Fatal("close at the cap left the endpoint in TIME_WAIT")
	}
	if got := p.a.TCPClosing(); got != k-1 {
		t.Fatalf("closing endpoints after the release: %d; want %d", got, k-1)
	}
	tw, other := p.a.TCPClosingReleased()
	if tw != 1 || other != 0 {
		t.Fatalf("released: time-wait %d other %d; want 1 0", tw, other)
	}
	// 解放した endpoint をもう一度 Close しても害は無い。
	if err := c.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

// halfCloseRoundTrip は、要求を送って書き込み側を半閉じし応答を読む型の 1 往復を、b の側の Close の
// 直前まで進める。応答は b → a の転送を止めた状態で書くので、Close の時点で送信バッファに残る。
// 戻り値は client と、b の Close を呼ぶ関数である。
func halfCloseRoundTrip(t *testing.T, p *tcpPair, ln *TCPListener, response []byte) (*dialedConn, func()) {
	t.Helper()
	c := p.dial(t, 4000)
	s := acceptOne(t, ln)
	if _, err := c.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if data, err := readAll(s); err != nil || string(data) != "request" {
		t.Fatalf("server read: %q %v", data, err)
	}
	waitState(t, s, tcp.StateCloseWait)
	p.ba.pause()
	if _, err := s.Write(response); err != nil {
		t.Fatal(err)
	}
	if err := s.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	return c, func() {
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		p.ba.resume()
	}
}

func TestTCPClosingCapAtCapKeepsHalfClosedResponse(t *testing.T) {
	p := newTCPPair(t)
	ln := p.listen(t, 4000)
	// K = 1 なので、CLOSE_WAIT にある閉じる endpoint 自身で閉じかけの数は K に達する。
	// K の段は TIME_WAIT だけを解放するので、応答は配り切られる。
	p.b.SetTCPClosingCap(1)
	response := bytes.Repeat([]byte("r"), 64<<10)
	c, closeServer := halfCloseRoundTrip(t, p, ln, response)
	if got := p.b.TCPClosing(); got < 1 {
		t.Fatalf("closing endpoints before close: %d; want at least 1", got)
	}
	closeServer()
	data, err := readAll(c)
	if err != nil || !bytes.Equal(data, response) {
		t.Fatalf("client read %d bytes, err %v; want the full response of %d bytes and EOF", len(data), err, len(response))
	}
	c.Close()
	if tw, other := p.b.TCPClosingReleased(); other != 0 {
		t.Fatalf("released: time-wait %d other %d; want no release in other states", tw, other)
	}
}

func TestTCPClosingCapAtTwiceCapCutsHalfClosedResponse(t *testing.T) {
	p := newTCPPair(t)
	ln := p.listen(t, 4000)
	p.b.SetTCPClosingCap(1)
	// b の側に TIME_WAIT を 1 つ置く(b が能動的に閉じる)。閉じかけの数は、その TIME_WAIT と
	// 試す接続の CLOSE_WAIT で 2K = 2 に達する。
	c0 := p.dial(t, 4000)
	s0 := acceptOne(t, ln)
	if err := s0.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if data, err := readAll(c0); err != nil || len(data) != 0 {
		t.Fatalf("client read: %q %v", data, err)
	}
	if err := c0.Close(); err != nil {
		t.Fatal(err)
	}
	waitState(t, s0, tcp.StateTimeWait)
	// K の段に掛からないよう、この TIME_WAIT は Close せずに持ったままにする(b の閉じかけの数 1)。
	response := bytes.Repeat([]byte("r"), 256<<10)
	c, closeServer := halfCloseRoundTrip(t, p, ln, response)
	if got := p.b.TCPClosing(); got < 2 {
		t.Fatalf("closing endpoints before close: %d; want at least 2", got)
	}
	closeServer()
	data, err := readAll(c)
	if err == nil || len(data) >= len(response) {
		t.Fatalf("client read %d bytes, err %v; want a reset before the full response of %d bytes", len(data), err, len(response))
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Fatalf("client read error %T %v; want a net.OpError from the reset", err, err)
	}
	c.Close()
	if tw, other := p.b.TCPClosingReleased(); other != 1 {
		t.Fatalf("released: time-wait %d other %d; want exactly 1 release in another state", tw, other)
	}
	s0.Close()
}

func TestTCPClosingCapLogsOncePerMinute(t *testing.T) {
	lines := captureLog(t)
	p := newTCPPair(t)
	ln := p.listen(t, 4000)
	p.a.SetTCPClosingCap(1)
	for i := 0; i < 3; i++ {
		c := timeWaitOnDialer(t, p, ln)
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if tw, _ := p.a.TCPClosingReleased(); tw != 3 {
		t.Fatalf("released %d in TIME_WAIT; want 3", tw)
	}
	got := lines()
	if len(got) != 1 {
		t.Fatalf("log lines %d: %q; want exactly 1 within a minute", len(got), got)
	}
	for _, want := range []string{"closing TCP endpoints reached the cap of 1", "released 1 endpoints in TIME_WAIT", "0 in other closing states"} {
		if !strings.Contains(got[0], want) {
			t.Fatalf("log line %q lacks %q", got[0], want)
		}
	}
	if strings.ContainsAny(got[0], "()") {
		t.Fatalf("log line uses parentheses: %q", got[0])
	}
}

func TestDialTCPEnablesKeepaliveWithGVisorDefaults(t *testing.T) {
	p := newTCPPair(t)
	ln := p.listen(t, 4000)
	c := p.dial(t, 4000)
	s := acceptOne(t, ln)
	defer c.Close()
	defer s.Close()
	if !c.endpoint().SocketOptions().GetKeepAlive() {
		t.Fatal("dialed endpoint: keepalive is off")
	}
	if !s.endpoint().SocketOptions().GetKeepAlive() {
		t.Fatal("accepted endpoint: keepalive is off")
	}
	var idle tcpip.KeepaliveIdleOption
	if err := c.endpoint().GetSockOpt(&idle); err != nil {
		t.Fatal(err)
	}
	var interval tcpip.KeepaliveIntervalOption
	if err := c.endpoint().GetSockOpt(&interval); err != nil {
		t.Fatal(err)
	}
	count, err := c.endpoint().GetSockOptInt(tcpip.KeepaliveCountOption)
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(idle) != tcp.DefaultKeepaliveIdle || time.Duration(interval) != tcp.DefaultKeepaliveInterval || count != tcp.DefaultKeepaliveCount {
		t.Fatalf("keepalive idle %s interval %s count %d; want gVisor's defaults %s %s %d",
			time.Duration(idle), time.Duration(interval), count, tcp.DefaultKeepaliveIdle, tcp.DefaultKeepaliveInterval, tcp.DefaultKeepaliveCount)
	}
}

func TestDialTCPRefusedAndCancelled(t *testing.T) {
	p := newTCPPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// 待ち受けの無いポートは RST で拒まれ、gonet と同じ形の connect の誤りになる。
	_, err := p.a.DialTCP(ctx, netip.AddrPortFrom(p.b.local, 4001))
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "connect" {
		t.Fatalf("dial to a closed port: %T %v; want a connect net.OpError", err, err)
	}
	// SYN が届かない間に ctx が切れると、ctx の誤りで戻り endpoint は残らない。
	p.ab.pause()
	before := p.a.TCPClosing()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	_, err = p.a.DialTCP(ctx2, netip.AddrPortFrom(p.b.local, 4001))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled dial: %v; want context.DeadlineExceeded", err)
	}
	p.ab.resume()
	if got := p.a.TCPClosing(); got != before {
		t.Fatalf("closing endpoints after a cancelled dial: %d; want %d", got, before)
	}
}

func TestSetTCPClosingCapZeroUsesDefault(t *testing.T) {
	d, err := Create(netip.MustParseAddr("10.98.0.9"), 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if got := d.TCPClosingCap(); got != DefaultTCPClosingCap {
		t.Fatalf("cap of a new Device %d; want %d", got, DefaultTCPClosingCap)
	}
	d.SetTCPClosingCap(7)
	if got := d.TCPClosingCap(); got != 7 {
		t.Fatalf("cap %d; want 7", got)
	}
	d.SetTCPClosingCap(0)
	if got := d.TCPClosingCap(); got != DefaultTCPClosingCap {
		t.Fatalf("cap after 0 %d; want the default %d", got, DefaultTCPClosingCap)
	}
}

// endpointConn は、accept 側の *TCPConn と dial 側の *dialedConn に共通の、endpoint を読める接続。
type endpointConn interface {
	net.Conn
	endpoint() tcpip.Endpoint
}

// TestDialedConnHasNoAbortAndClosesWithFIN は、dial した接続が Abort を持たず(中継の cutConn が
// RST に落とさない)、天井の下の Close が graceful(相手は EOF を見る)であることを固定する
// (仕様 7 節: vpsd が中継を切るときの netstack の側は今までどおり Close)。
func TestDialedConnHasNoAbortAndClosesWithFIN(t *testing.T) {
	p := newTCPPair(t)
	ln := p.listen(t, 4000)
	c := p.dial(t, 4000)
	s := acceptOne(t, ln)
	defer s.Close()
	if _, ok := any(c).(interface{ Abort() }); ok {
		t.Fatal("the dialed connection has Abort; the relay would cut it with RST")
	}
	if _, err := c.Write([]byte("bye")); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := readAll(s)
	if err != nil || string(data) != "bye" {
		t.Fatalf("server read %q, %v; want the data and a clean EOF from a graceful close", data, err)
	}
}

// TestTCPClosingCapDoesNotCountAClosedEndpoint は、2K の段が connected でない endpoint(既に解放
// 済みのもの)の Close を解放に数えないことを固定する。
func TestTCPClosingCapDoesNotCountAClosedEndpoint(t *testing.T) {
	p := newTCPPair(t)
	ln := p.listen(t, 4000)
	p.a.SetTCPClosingCap(1)
	released := timeWaitOnDialer(t, p, ln)
	if err := released.Close(); err != nil { // D = 1 >= K: released at once
		t.Fatal(err)
	}
	if tw, other := p.a.TCPClosingReleased(); tw != 1 || other != 0 {
		t.Fatalf("released: time-wait %d other %d; want 1 0", tw, other)
	}
	// 2 本を TIME_WAIT に置いたまま (Close せず) D = 2 = 2K にし、解放済みの endpoint をもう一度 Close する。
	held1 := timeWaitOnDialer(t, p, ln)
	held2 := timeWaitOnDialer(t, p, ln)
	if got := p.a.TCPClosing(); got != 2 {
		t.Fatalf("closing endpoints %d; want 2", got)
	}
	if err := released.Close(); err != nil {
		t.Fatal(err)
	}
	if tw, other := p.a.TCPClosingReleased(); tw != 1 || other != 0 {
		t.Fatalf("released after closing a closed endpoint at 2K: time-wait %d other %d; want 1 0", tw, other)
	}
	held1.Close()
	held2.Close()
}
