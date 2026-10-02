package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// The tests in this file pin how a relayed TCP connection ends in the server's userspace mode,
// for each cause and direction: what the public client and the agent each observe, and when the
// relay returns the flow's accounting (the rule's flow slot in the pool and the per-source slot of
// the Admission Policy). The public side is a kernel socket on the loopback, as in vpsd; the side
// toward the agent is a netstack conn, as nettun.DialTCP returns it in vpsd.

// endObs is what one side observes when it reads after the cause: the peer closed (EOF), the
// peer reset the connection, or nothing yet (the read deadline passed).
type endObs string

const (
	obsEOF   endObs = "EOF"
	obsReset endObs = "reset"
	obsOpen  endObs = "open"
)

// observe reads c for up to d and names how the read ended. Data read before the end is dropped.
func observe(c net.Conn, d time.Duration) endObs {
	c.SetReadDeadline(time.Now().Add(d))
	defer c.SetReadDeadline(time.Time{})
	b := make([]byte, 512)
	for {
		_, err := c.Read(b)
		switch {
		case err == nil:
			continue
		case errors.Is(err, io.EOF):
			return obsEOF
		case errors.Is(err, os.ErrDeadlineExceeded):
			return obsOpen
		default:
			return obsReset
		}
	}
}

// endingRig is one relayed connection in the server's userspace mode, with both of its ends in
// the test's hands: client is the public client, agent the agent's end of the relay's netstack
// conn.
type endingRig struct {
	m        *Manager
	k        Key
	pool     *resource.Pool
	releases atomic.Int32
	client   *net.TCPConn
	agent    net.Conn
}

func newEndingRig(t *testing.T) *endingRig {
	t.Helper()
	clientDev, agentNet := netstackPair(t)
	const agentPort = 7006
	ln, err := agentNet.dev.ListenTCP(netip.AddrPortFrom(cutAgentAddr, agentPort))
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		for {
			select {
			case c := <-accepted:
				c.Close()
			default:
				return
			}
		}
	})
	lb := &loopback{}
	port := reserveTCP(t, lb)
	r := &endingRig{k: Key{proto.TCP, port}, pool: resource.NewPool(8)}
	var armed atomic.Bool
	dialed := make(chan net.Conn, 1)
	r.m = New(lb, Options{
		TCPPool: r.pool,
		Logf:    testLogf(t),
		Admit: func(string, netip.Addr, int) (func(), bool) {
			return func() { r.releases.Add(1) }, true
		},
		Dial: func(network, addr string) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := clientDev.DialTCP(ctx, netip.MustParseAddrPort(addr))
			// the reachability probe when the listener opens is not armed
			if err == nil && armed.CompareAndSwap(true, false) {
				dialed <- c
			}
			return c, err
		},
	})
	t.Cleanup(r.m.Close)
	r.m.Apply(map[Key]Desired{r.k: {netip.AddrPortFrom(cutAgentAddr, agentPort).String(), "r1"}})
	if st := statusOf(t, r.m, r.k); !st.Listening {
		t.Fatalf("the listener did not open: %v", st.Err)
	}
	armed.Store(true)
	c, err := net.DialTCP("tcp4", nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	r.client = c
	var up net.Conn
	select {
	case up = <-dialed:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay did not dial the agent")
	}
	// the agent's end of the relayed conn is the one accepted from the relay's local address;
	// the others are the reachability probes
	deadline := time.After(5 * time.Second)
	for r.agent == nil {
		select {
		case a := <-accepted:
			if ra := a.RemoteAddr(); ra != nil && ra.String() == up.LocalAddr().String() {
				r.agent = a
			} else {
				a.Close()
			}
		case <-deadline:
			t.Fatal("the agent did not accept the relay's connection")
		}
	}
	t.Cleanup(func() { r.agent.Close() })
	// both directions carry data before the cause
	r.send(t, r.client, r.agent, "ping")
	r.send(t, r.agent, r.client, "pong")
	r.wantHeld(t, "before the cause")
	return r
}

// send writes s on from and checks that it arrives on to.
func (r *endingRig) send(t *testing.T, from, to net.Conn, s string) {
	t.Helper()
	if _, err := from.Write([]byte(s)); err != nil {
		t.Fatalf("write %q: %v", s, err)
	}
	to.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer to.SetReadDeadline(time.Time{})
	b := make([]byte, len(s))
	if _, err := io.ReadFull(to, b); err != nil || string(b) != s {
		t.Fatalf("relayed %q, want %q: %v", b, s, err)
	}
}

func (r *endingRig) accounting() string {
	return fmt.Sprintf("flows %d, pool in use %d, per-source releases %d",
		r.flows(), r.pool.InUse(), r.releases.Load())
}

// flows is the listener's flow count, or 0 once the listener is gone (Manager.Close).
func (r *endingRig) flows() int {
	for _, s := range r.m.Status() {
		if s.Key == r.k {
			return s.Flows
		}
	}
	return 0
}

// wantHeld checks that the relay still holds the flow's accounting.
func (r *endingRig) wantHeld(t *testing.T, when string) {
	t.Helper()
	if r.flows() != 1 || r.pool.InUse() != 1 || r.releases.Load() != 0 {
		t.Fatalf("%s: the relay does not hold the flow: %s", when, r.accounting())
	}
}

// wantReturned waits until the relay has returned the flow's accounting, each slot once.
func (r *endingRig) wantReturned(t *testing.T, when string) {
	t.Helper()
	waitUntil(t, func() string {
		return fmt.Sprintf("%s: the relay did not return the flow: %s", when, r.accounting())
	}, func() bool {
		return r.flows() == 0 && r.pool.InUse() == 0 && r.releases.Load() == 1
	})
	time.Sleep(50 * time.Millisecond)
	if got := r.releases.Load(); got != 1 {
		t.Errorf("%s: per-source release called %d times, want 1", when, got)
	}
}

// heldFor is how long a check that the relay still holds a flow waits first.
const heldFor = 200 * time.Millisecond

func resetTCP(c *net.TCPConn) {
	c.SetLinger(0)
	c.Close()
}

// wantObs checks what one side observed.
func wantObs(t *testing.T, side string, got, want endObs) {
	t.Helper()
	if got != want {
		t.Errorf("%s observed %s, want %s", side, got, want)
	}
}

// A relayed connection that ends with an EOF in one direction stays half-closed: the other side
// sees EOF, the other direction still carries data, and the relay holds the flow until the other
// side closes too. A reset on either side, or a cut by the relay itself, ends the flow at once.
// The client-reset case pins the current behaviour; the decision recorded in
// TestTCPClientResetReachesTheAgentAsReset changes only what the agent observes in that case.
func TestTCPEndingByCauseAndDirection(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T, r *endingRig)
	}{
		{"client half-close", func(t *testing.T, r *endingRig) {
			r.client.CloseWrite()
			wantObs(t, "agent", observe(r.agent, 5*time.Second), obsEOF)
			time.Sleep(heldFor)
			r.wantHeld(t, "after the client's half-close")
			r.send(t, r.agent, r.client, "back")
			r.agent.Close()
			wantObs(t, "client", observe(r.client, 5*time.Second), obsEOF)
			r.wantReturned(t, "after the agent closed too")
		}},
		{"client close", func(t *testing.T, r *endingRig) {
			r.client.Close()
			wantObs(t, "agent", observe(r.agent, 5*time.Second), obsEOF)
			time.Sleep(heldFor)
			r.wantHeld(t, "after the client's close while the agent stays open")
			r.agent.Close()
			r.wantReturned(t, "after the agent closed too")
		}},
		{"client reset", func(t *testing.T, r *endingRig) {
			resetTCP(r.client)
			r.wantReturned(t, "after the client's reset, while the agent stays open")
			// current behaviour; the decided behaviour is a reset (see
			// TestTCPClientResetReachesTheAgentAsReset)
			wantObs(t, "agent", observe(r.agent, 5*time.Second), obsEOF)
		}},
		{"agent half-close", func(t *testing.T, r *endingRig) {
			r.agent.(interface{ CloseWrite() error }).CloseWrite()
			wantObs(t, "client", observe(r.client, 5*time.Second), obsEOF)
			time.Sleep(heldFor)
			r.wantHeld(t, "after the agent's half-close")
			r.send(t, r.client, r.agent, "up")
			r.client.Close()
			wantObs(t, "agent", observe(r.agent, 5*time.Second), obsEOF)
			r.wantReturned(t, "after the client closed too")
		}},
		{"agent close", func(t *testing.T, r *endingRig) {
			r.agent.Close()
			wantObs(t, "client", observe(r.client, 5*time.Second), obsEOF)
			time.Sleep(heldFor)
			r.wantHeld(t, "after the agent's close while the client stays open")
			r.client.Close()
			r.wantReturned(t, "after the client closed too")
		}},
		{"agent reset", func(t *testing.T, r *endingRig) {
			r.agent.(aborter).Abort()
			r.wantReturned(t, "after the agent's reset, while the client stays open")
			wantObs(t, "client", observe(r.client, 5*time.Second), obsEOF)
		}},
		{"rule removed", func(t *testing.T, r *endingRig) {
			r.m.Apply(nil)
			r.wantReturned(t, "after the rule was removed")
			wantObs(t, "agent", observe(r.agent, 5*time.Second), obsReset)
			wantObs(t, "client", observe(r.client, 5*time.Second), obsEOF)
		}},
		{"source no longer allowed", func(t *testing.T, r *endingRig) {
			if n := r.m.CloseSessions(func(string, netip.Addr) bool { return false }); n != 1 {
				t.Errorf("CloseSessions = %d, want 1", n)
			}
			r.wantReturned(t, "after the source was cut")
			wantObs(t, "agent", observe(r.agent, 5*time.Second), obsReset)
			wantObs(t, "client", observe(r.client, 5*time.Second), obsEOF)
		}},
		{"shutdown", func(t *testing.T, r *endingRig) {
			r.m.Close()
			r.wantReturned(t, "after Manager.Close")
			wantObs(t, "agent", observe(r.agent, 5*time.Second), obsReset)
			wantObs(t, "client", observe(r.client, 5*time.Second), obsEOF)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.run(t, newEndingRig(t))
		})
	}
}

// Decided behaviour, not yet implemented: when the public client resets its connection, the
// relay resets its connection to the agent instead of closing it, so the agent's relay ends the
// flow even if its target never closes after a FIN. The current code closes the agent's side
// normally and the agent observes EOF, so this test fails if enabled.
func TestTCPClientResetReachesTheAgentAsReset(t *testing.T) {
	t.Skip("expected to change: the relay does not yet pass a client's reset on to the agent")
	r := newEndingRig(t)
	resetTCP(r.client)
	r.wantReturned(t, "after the client's reset, while the agent stays open")
	wantObs(t, "agent", observe(r.agent, 5*time.Second), obsReset)
}

// agentEndingRig is one relayed connection in the agent's role: the relay listens on the tunnel's
// netstack, where the server's connection arrives, and dials its target with a kernel socket.
// server is the server's end of the tunnel conn, target the target's end of the relay's conn.
type agentEndingRig struct {
	endingRig
	server net.Conn
	target net.Conn
}

func newAgentEndingRig(t *testing.T) *agentEndingRig {
	t.Helper()
	serverDev, agentNet := netstackPair(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		for {
			select {
			case c := <-accepted:
				c.Close()
			default:
				return
			}
		}
	})
	const port = 7007
	r := &agentEndingRig{endingRig: endingRig{k: Key{proto.TCP, port}, pool: resource.NewPool(8)}}
	var armed atomic.Bool
	dialed := make(chan net.Conn, 1)
	r.m = New(agentNet, Options{
		TCPPool: r.pool,
		Logf:    testLogf(t),
		Admit: func(string, netip.Addr, int) (func(), bool) {
			return func() { r.releases.Add(1) }, true
		},
		Dial: func(network, addr string) (net.Conn, error) {
			c, err := net.DialTimeout(network, addr, 5*time.Second)
			// the reachability probe when the listener opens is not armed
			if err == nil && armed.CompareAndSwap(true, false) {
				dialed <- c
			}
			return c, err
		},
	})
	t.Cleanup(r.m.Close)
	r.m.Apply(map[Key]Desired{r.k: {ln.Addr().String(), "r1"}})
	if st := statusOf(t, r.m, r.k); !st.Listening {
		t.Fatalf("the listener did not open: %v", st.Err)
	}
	armed.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := serverDev.DialTCP(ctx, netip.AddrPortFrom(cutAgentAddr, port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	r.server = c
	var up net.Conn
	select {
	case up = <-dialed:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay did not dial the target")
	}
	deadline := time.After(5 * time.Second)
	for r.target == nil {
		select {
		case a := <-accepted:
			if a.RemoteAddr().String() == up.LocalAddr().String() {
				r.target = a
			} else {
				a.Close()
			}
		case <-deadline:
			t.Fatal("the target did not accept the relay's connection")
		}
	}
	t.Cleanup(func() { r.target.Close() })
	r.send(t, r.server, r.target, "ping")
	r.send(t, r.target, r.server, "pong")
	r.wantHeld(t, "before the cause")
	return r
}

// The agent's relay ends a connection the same way when the server's side ends it: a FIN from the
// server is a half-close toward the target, and a reset from the server ends the flow at once and
// closes the target's connection normally, so the target sees EOF.
func TestTCPAgentEndingFromTheServer(t *testing.T) {
	t.Run("server close", func(t *testing.T) {
		r := newAgentEndingRig(t)
		r.server.Close()
		wantObs(t, "target", observe(r.target, 5*time.Second), obsEOF)
		time.Sleep(heldFor)
		r.wantHeld(t, "after the server's close while the target stays open")
		r.target.Close()
		r.wantReturned(t, "after the target closed too")
	})
	t.Run("server reset", func(t *testing.T) {
		r := newAgentEndingRig(t)
		r.server.(aborter).Abort()
		r.wantReturned(t, "after the server's reset, while the target stays open")
		wantObs(t, "target", observe(r.target, 5*time.Second), obsEOF)
	})
}
