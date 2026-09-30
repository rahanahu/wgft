package relay

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/rahanahu/wgft/internal/nettun"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// silentPeer accepts connections on ln, reads until the read fails and never writes or closes,
// like a target or an agent that keeps its side open after EOF. accepted receives the remote
// address of each accepted connection, and ends its remote address and the error that ended its
// reads.
type silentPeer struct {
	accepted chan string
	ends     chan peerEnd
}

type peerEnd struct {
	from string
	err  error
}

func serveSilent(t *testing.T, ln net.Listener) *silentPeer {
	t.Helper()
	p := &silentPeer{accepted: make(chan string, 16), ends: make(chan peerEnd, 16)}
	conns := make(chan net.Conn, 8)
	t.Cleanup(func() {
		ln.Close()
		for {
			select {
			case c := <-conns:
				c.Close()
			default:
				return
			}
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// read the address at once: a netstack conn has none once it has ended, which a
			// reachability probe may have done already
			var from string
			if a := c.RemoteAddr(); a != nil {
				from = a.String()
			}
			conns <- c
			p.accepted <- from
			go func() {
				_, err := io.Copy(io.Discard, c)
				if err == nil {
					err = io.EOF
				}
				select {
				case p.ends <- peerEnd{from, err}:
				default:
				}
			}()
		}
	}()
	return p
}

func (p *silentPeer) waitAccepted(t *testing.T) {
	t.Helper()
	select {
	case <-p.accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay never connected to the peer")
	}
}

// waitAcceptedFrom waits until the peer has accepted the connection from the address from.
func (p *silentPeer) waitAcceptedFrom(from string) bool {
	timeout := time.After(5 * time.Second)
	for {
		select {
		case a := <-p.accepted:
			if a == from {
				return true
			}
		case <-timeout:
			return false
		}
	}
}

// endOf waits for the connection from the address from to end and returns the error that ended
// it. It skips the others, such as the relay's reachability probe (checkTarget).
func (p *silentPeer) endOf(t *testing.T, from string) error {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case e := <-p.ends:
			if e.from == from {
				return e.err
			}
		case <-timeout:
			t.Fatalf("the connection from %s is still open", from)
		}
	}
}

// waitUntil polls done until it is true, or fails with what after 5 seconds.
func waitUntil(t *testing.T, what func() string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatal(what())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The server cuts a relayed connection with a reset toward the agent (design.md 6.2 節). The
// agent's relay must end the session then, although its target keeps its side open and says
// nothing: close the target connection and return the flow slot and the per-source slot. A relay
// that treats the reset like a FIN only half-closes the target connection and keeps reading from
// it, so the session and both slots stay until the target closes.
func TestTCPResetFromTheTunnelEndsTheSession(t *testing.T) {
	const port = 7004
	k := Key{proto.TCP, port}
	agent, err := nettun.Create(cutAgentAddr, 1420)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		agent.Close()
		agent.Wait()
	})
	peer := newRawPeer(agent, cutClientAddr, netip.AddrPortFrom(cutAgentAddr, port))
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := serveSilent(t, ln)
	pool := resource.NewPool(8)
	var released atomic.Int32
	m := New(netstackNet{dev: agent, addr: cutAgentAddr}, Options{
		TCPPool: pool,
		Logf:    testLogf(t),
		Admit: func(string, netip.Addr, int) (func(), bool) {
			return func() { released.Add(1) }, true
		},
	})
	defer m.Close()
	m.Apply(map[Key]Desired{k: {ln.Addr().String(), "r1"}})
	if st := statusOf(t, m, k); !st.Listening {
		t.Fatalf("the listener did not open: %v", st.Err)
	}

	next := peer.handshake(t, 40011)
	target.waitAccepted(t)
	waitUntil(t, func() string { return "the relay did not register the session" }, func() bool {
		return statusOf(t, m, k).Sessions == 2
	})
	peer.send(t, 40011, next, 0, header.TCPFlagRst)

	waitUntil(t, func() string {
		st := statusOf(t, m, k)
		return fmt.Sprintf("the reset did not end the session: sessions %d, flows %d, pool in use %d, per-source releases %d",
			st.Sessions, st.Flows, pool.InUse(), released.Load())
	}, func() bool {
		st := statusOf(t, m, k)
		return st.Sessions == 0 && st.Flows == 0 && pool.InUse() == 0 && released.Load() == 1
	})
	time.Sleep(50 * time.Millisecond)
	if got := released.Load(); got != 1 {
		t.Errorf("per-source release called %d times, want 1", got)
	}
}

// In the server's userspace mode the relay dials the agent through the netstack. When the relay
// cuts such a session (a source-restriction change through CloseSessions, or the rule removed),
// the agent must see a reset, not a FIN: the agent's relay treats a FIN as a half-close and keeps
// its target connection and slots while the target stays open (design.md 6.2 節, 6.3 節). A cut
// that comes while the relay is still dialling the agent must reset the conn the dial returns:
// relaying it would let netpipe close it with a FIN on the public side's read failure.
func TestTCPCutReachesTheAgentAsReset(t *testing.T) {
	closeSessions := func(m *Manager) {
		if n := m.CloseSessions(func(string, netip.Addr) bool { return false }); n != 1 {
			t.Errorf("CloseSessions = %d, want 1", n)
		}
	}
	for _, tc := range []struct {
		name string
		// dialing stops the connection's goroutine in its dial to the agent while cut runs
		dialing bool
		cut     func(m *Manager)
	}{
		{"CloseSessions", false, closeSessions},
		{"CloseSessions while dialing", true, closeSessions},
		{"rule removed", false, func(m *Manager) { m.Apply(nil) }},
		{"rule removed while dialing", true, func(m *Manager) { m.Apply(nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, agentNet := netstackPair(t)
			const agentPort = 7005
			ln, err := agentNet.dev.ListenTCP(netip.AddrPortFrom(cutAgentAddr, agentPort))
			if err != nil {
				t.Fatal(err)
			}
			agentSide := serveSilent(t, ln)
			lb := &loopback{}
			port := reserveTCP(t, lb)
			var (
				armed   atomic.Bool
				entered = make(chan struct{})
				proceed = make(chan struct{})
				session = make(chan net.Conn, 1)
			)
			resume := sync.OnceFunc(func() { close(proceed) })
			t.Cleanup(resume)
			m := New(lb, Options{
				Logf: testLogf(t),
				Dial: func(network, addr string) (net.Conn, error) {
					// the reachability probe when the listener opens is not armed
					relayed := armed.CompareAndSwap(true, false)
					if relayed {
						close(entered)
						<-proceed
					}
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					c, err := client.DialTCP(ctx, netip.MustParseAddrPort(addr))
					if relayed && err == nil {
						// hand the conn to the relay only once the agent has accepted it, so a reset
						// right after the dial reaches a conn the agent holds. Without this wait, the
						// agent at times never reported a conn reset while it was still in the
						// netstack's accept queue
						if !agentSide.waitAcceptedFrom(c.LocalAddr().String()) {
							t.Error("the agent did not accept the relay's connection")
						}
						session <- c
					}
					return c, err
				},
			})
			defer m.Close()
			m.Apply(map[Key]Desired{{proto.TCP, port}: {netip.AddrPortFrom(cutAgentAddr, agentPort).String(), "r1"}})
			armed.Store(true)
			c, err := net.DialTCP("tcp4", nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("the relay did not dial the agent")
			}
			if !tc.dialing {
				resume()
				k := Key{proto.TCP, port}
				waitUntil(t, func() string { return "the relay did not register the session" }, func() bool {
					return statusOf(t, m, k).Sessions == 2
				})
			}

			tc.cut(m)
			resume()

			var up net.Conn
			select {
			case up = <-session:
			case <-time.After(5 * time.Second):
				t.Fatal("the relay's dial to the agent did not return")
			}
			if err := agentSide.endOf(t, up.LocalAddr().String()); !isCutByReset(err) {
				t.Fatalf("the agent side of the cut session ended with %v, want a reset", err)
			}
		})
	}
}
