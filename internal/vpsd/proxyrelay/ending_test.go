package proxyrelay

import (
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
)

// The tests in this file pin how a relayed connection ends, for each cause and direction: what
// the public client and the agent each observe, and when the relay returns the flow's accounting
// (the pool slot and the per-source slot). They run with both kinds of connection to the agent:
// a kernel socket, as in kernel mode, where the relay copies with splice, and a stand-in for the
// netstack conn of userspace mode, which has Abort and CloseWrite and no SetLinger, and which the
// relay copies through its own buffers.

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

// netstackUp stands for the server's netstack conn to the agent in userspace mode
// (*nettun.TCPConn): Abort resets the underlying loopback socket, and it has no SetLinger.
type netstackUp struct {
	net.Conn
	tc *net.TCPConn
}

func (c *netstackUp) Abort() {
	c.tc.SetLinger(0)
	c.tc.Close()
}

func (c *netstackUp) CloseWrite() error { return c.tc.CloseWrite() }

// endingRig is one relayed connection with both of its ends in the test's hands: client is the
// public client, agent the agent's end of the relay's connection to the agent.
type endingRig struct {
	m        *Manager
	pool     *resource.Pool
	releases atomic.Int32
	client   *net.TCPConn
	agent    *net.TCPConn
}

const endingPort = 8443

func newEndingRig(t *testing.T, netstack bool) *endingRig {
	t.Helper()
	agentLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { agentLn.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := agentLn.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	pubLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &endingRig{pool: resource.NewPool(8)}
	r.m = New(Options{
		Listen: func(uint16) (net.Listener, error) { return pubLn, nil },
		Dial: func(string) (net.Conn, error) {
			c, err := net.Dial("tcp4", agentLn.Addr().String())
			if err != nil || !netstack {
				return c, err
			}
			return &netstackUp{Conn: c, tc: c.(*net.TCPConn)}, nil
		},
		Logf: testLogf(t),
		Pool: r.pool,
		Admit: func(string, netip.Addr) (func(), bool) {
			return func() { r.releases.Add(1) }, true
		},
	})
	t.Cleanup(r.m.Close)
	r.m.Apply([]Rule{agentRule("r", endingPort, "home", "10.200.0.2", nil)})
	c, err := net.DialTimeout("tcp4", pubLn.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	r.client = c.(*net.TCPConn)
	select {
	case a := <-accepted:
		r.agent = a.(*net.TCPConn)
	case <-time.After(5 * time.Second):
		t.Fatal("the relay did not connect to the agent")
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
	return fmt.Sprintf("pool in use %d, per-source releases %d", r.pool.InUse(), r.releases.Load())
}

// wantHeld checks that the relay still holds the flow's accounting.
func (r *endingRig) wantHeld(t *testing.T, when string) {
	t.Helper()
	if r.pool.InUse() != 1 || r.releases.Load() != 0 {
		t.Fatalf("%s: the relay does not hold the flow: %s", when, r.accounting())
	}
}

// wantReturned waits until the relay has returned the flow's accounting, each slot once.
func (r *endingRig) wantReturned(t *testing.T, when string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for r.pool.InUse() != 0 || r.releases.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("%s: the relay did not return the flow: %s", when, r.accounting())
		}
		time.Sleep(5 * time.Millisecond)
	}
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
// TestClientResetReachesTheAgentAsReset changes only what the agent observes in that case.
func TestEndingByCauseAndDirection(t *testing.T) {
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
			// TestClientResetReachesTheAgentAsReset)
			wantObs(t, "agent", observe(r.agent, 5*time.Second), obsEOF)
		}},
		{"agent half-close", func(t *testing.T, r *endingRig) {
			r.agent.CloseWrite()
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
			resetTCP(r.agent)
			r.wantReturned(t, "after the agent's reset, while the client stays open")
			wantObs(t, "client", observe(r.client, 5*time.Second), obsEOF)
		}},
		{"rule removed", func(t *testing.T, r *endingRig) {
			r.m.Apply(nil)
			r.wantReturned(t, "after the rule was removed")
			wantObs(t, "agent", observe(r.agent, 5*time.Second), obsReset)
			wantObs(t, "client", observe(r.client, 5*time.Second), obsEOF)
		}},
		{"source restriction", func(t *testing.T, r *endingRig) {
			r.m.Apply([]Rule{agentRule("r", endingPort, "home", "10.200.0.2", []string{"127.0.0.1/32"})})
			r.wantReturned(t, "after the source was cut")
			wantObs(t, "agent", observe(r.agent, 5*time.Second), obsReset)
			wantObs(t, "client", observe(r.client, 5*time.Second), obsEOF)
		}},
		{"CloseAgent", func(t *testing.T, r *endingRig) {
			r.m.CloseAgent("home")
			r.wantReturned(t, "after the agent was removed")
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
	for _, mode := range []struct {
		name     string
		netstack bool
	}{{"kernel upstream", false}, {"netstack upstream", true}} {
		t.Run(mode.name, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					tc.run(t, newEndingRig(t, mode.netstack))
				})
			}
		})
	}
}

// Decided behaviour, not yet implemented: when the public client resets its connection, the
// relay resets its connection to the agent instead of closing it, so the agent's relay ends the
// flow even if its target never closes after a FIN. The current code closes the agent's side
// normally and the agent observes EOF, so this test fails if enabled.
func TestClientResetReachesTheAgentAsReset(t *testing.T) {
	t.Skip("expected to change: the relay does not yet pass a client's reset on to the agent")
	for _, mode := range []struct {
		name     string
		netstack bool
	}{{"kernel upstream", false}, {"netstack upstream", true}} {
		t.Run(mode.name, func(t *testing.T) {
			r := newEndingRig(t, mode.netstack)
			resetTCP(r.client)
			r.wantReturned(t, "after the client's reset, while the agent stays open")
			wantObs(t, "agent", observe(r.agent, 5*time.Second), obsReset)
		})
	}
}
