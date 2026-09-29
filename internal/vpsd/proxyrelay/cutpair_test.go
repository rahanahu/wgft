package proxyrelay

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/resource"
)

// closeTracked records whether the relay closed its connection to the agent.
type closeTracked struct {
	*net.TCPConn
	closed atomic.Bool
}

func (c *closeTracked) Close() error {
	c.closed.Store(true)
	return c.TCPConn.Close()
}

// halfOpenAgent echoes what it reads and never closes its side, not even after reading the
// relay's FIN. A relay that cuts only the public side of a connection keeps the upstream
// connection to such an agent until the test cleans up.
func halfOpenAgent(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			go func() {
				b := make([]byte, 512)
				for {
					n, err := c.Read(b)
					if n > 0 {
						c.Write(b[:n])
					}
					if err != nil {
						return // never closes
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// cutRig runs a Manager whose public ports are loopback listeners and whose agents never close
// after EOF. It records every upstream connection and every per-source release. Once armed, the
// next dial to an agent stops until resume.
type cutRig struct {
	m        *Manager
	pool     *resource.Pool
	releases atomic.Int32
	armed    atomic.Bool
	entered  chan struct{}
	proceed  chan struct{}
	mu       sync.Mutex
	addrs    map[uint16]string // public port -> loopback listener
	agents   map[string]string // agent address:port -> fake agent
	ups      []*closeTracked
}

func newCutRig(t *testing.T, busy map[uint16]bool) *cutRig {
	t.Helper()
	r := &cutRig{
		pool:    resource.NewPool(8),
		addrs:   map[uint16]string{},
		entered: make(chan struct{}),
		proceed: make(chan struct{}),
		agents: map[string]string{
			"10.200.0.2:8443": halfOpenAgent(t),
			"10.200.0.3:8443": halfOpenAgent(t),
		},
	}
	t.Cleanup(func() {
		r.resume()
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, c := range r.ups {
			c.Close()
		}
	})
	r.m = New(Options{
		Listen: func(port uint16) (net.Listener, error) {
			if busy[port] {
				return nil, errors.New("address already in use")
			}
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err == nil {
				r.mu.Lock()
				r.addrs[port] = ln.Addr().String()
				r.mu.Unlock()
			}
			return ln, err
		},
		Dial: func(addr string) (net.Conn, error) {
			r.mu.Lock()
			dst, ok := r.agents[addr]
			r.mu.Unlock()
			if !ok {
				return nil, errors.New("no agent at " + addr)
			}
			if r.armed.CompareAndSwap(true, false) {
				close(r.entered)
				<-r.proceed
			}
			c, err := net.Dial("tcp4", dst)
			if err != nil {
				return nil, err
			}
			tracked := &closeTracked{TCPConn: c.(*net.TCPConn)}
			r.mu.Lock()
			r.ups = append(r.ups, tracked)
			r.mu.Unlock()
			return tracked, nil
		},
		Logf: testLogf(t),
		Pool: r.pool,
		Admit: func(string, netip.Addr) (func(), bool) {
			return func() { r.releases.Add(1) }, true
		},
	})
	t.Cleanup(r.m.Close)
	return r
}

func (r *cutRig) resume() {
	select {
	case <-r.proceed:
	default:
		close(r.proceed)
	}
}

// connect opens a connection to port. If dialing is true, it returns once the relay is stopped
// in its dial to the agent; otherwise it checks that the connection reaches the agent.
func (r *cutRig) connect(t *testing.T, port uint16, dialing bool) net.Conn {
	t.Helper()
	r.mu.Lock()
	addr := r.addrs[port]
	r.mu.Unlock()
	r.armed.Store(dialing)
	c, err := net.DialTimeout("tcp4", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if dialing {
		select {
		case <-r.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("the relay did not dial the agent")
		}
		return c
	}
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 2)
	if _, err := c.Read(b); err != nil || string(b) != "hi" {
		t.Fatalf("no relay before the change: %q, %v", b, err)
	}
	c.SetDeadline(time.Time{})
	return c
}

// tracked is the number of relayed connections the listeners and the retiring listeners hold.
func (r *cutRig) tracked() int {
	r.m.mu.Lock()
	defer r.m.mu.Unlock()
	n := 0
	for _, l := range append(mapValues(r.m.ls), r.m.retiring...) {
		l.mu.Lock()
		n += len(l.conns)
		l.mu.Unlock()
	}
	return n
}

func mapValues(m map[uint16]*listener) []*listener {
	out := make([]*listener, 0, len(m))
	for _, l := range m {
		out = append(out, l)
	}
	return out
}

// waitCut checks that the relay closed both sides of the one relayed connection, returned its
// budget slot and released its per-source slot exactly once.
func (r *cutRig) waitCut(t *testing.T, client net.Conn) {
	t.Helper()
	if !closedByPeer(client) {
		t.Error("the client connection was not cut")
	}
	state := func() (ok bool, desc string) {
		// tracked takes the Manager's locks; Prepare calls Listen, which takes r.mu, under them
		tracked := r.tracked()
		r.mu.Lock()
		ups := len(r.ups)
		closed := ups == 1 && r.ups[0].closed.Load()
		r.mu.Unlock()
		desc = fmt.Sprintf("upstreams %d, upstream closed %v, tracked %d, pool in use %d, per-source releases %d",
			ups, closed, tracked, r.pool.InUse(), r.releases.Load())
		return closed && tracked == 0 && r.pool.InUse() == 0 && r.releases.Load() == 1, desc
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		ok, desc := state()
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the relay was not cut on both sides: %s", desc)
		}
		time.Sleep(5 * time.Millisecond)
	}
	// the cleanup runs once: wait a little and check that no slot was returned twice
	time.Sleep(50 * time.Millisecond)
	if got := r.releases.Load(); got != 1 {
		t.Errorf("per-source release called %d times, want 1", got)
	}
	if got := r.pool.InUse(); got != 0 {
		t.Errorf("pool in use = %d, want 0", got)
	}
}

// Every operation that cuts a relayed connection closes both its public connection and its
// upstream connection to the agent (design.md 6.2 節「進行中の中継を閉じる契機」, 7a.3 節 Retire).
// Closing only the public side makes netpipe send FIN upstream and keep reading from the agent, so
// an agent that never closes after EOF keeps the upstream connection, the budget slot and the
// per-source slot until it closes. A connection that is still dialling when its listener closes
// or its target changes is not tracked yet; it closes both sides when it finds that out.
func TestCutClosesUpstream(t *testing.T) {
	const port = 8443
	home := agentRule("r", port, "home", "10.200.0.2", nil)
	for _, tc := range []struct {
		name string
		// dialing stops the connection in its dial to the agent while cut runs
		dialing bool
		cut     func(t *testing.T, r *cutRig)
		// retiring is the ports RetiringPorts must report after the cut
		retiring []uint16
	}{
		{name: "rule removed", cut: func(t *testing.T, r *cutRig) {
			r.m.Apply(nil)
		}},
		{name: "rule removed while dialing", dialing: true, cut: func(t *testing.T, r *cutRig) {
			r.m.Apply(nil)
		}},
		{name: "Manager.Close", cut: func(t *testing.T, r *cutRig) {
			r.m.Close()
		}},
		{name: "CloseAgent", cut: func(t *testing.T, r *cutRig) {
			r.m.CloseAgent("home")
		}},
		{name: "retarget", cut: func(t *testing.T, r *cutRig) {
			r.m.Apply([]Rule{agentRule("r", port, "home2", "10.200.0.3", nil)})
		}},
		{name: "retarget while dialing", dialing: true, cut: func(t *testing.T, r *cutRig) {
			r.m.Apply([]Rule{agentRule("r", port, "home2", "10.200.0.3", nil)})
		}},
		{name: "source restriction", cut: func(t *testing.T, r *cutRig) {
			r.m.Apply([]Rule{agentRule("r", port, "home", "10.200.0.2", []string{"127.0.0.1/32"})})
		}},
		{name: "retire refuses the source", retiring: []uint16{port}, cut: func(t *testing.T, r *cutRig) {
			// the rule moves to a port that cannot be bound: fail-closed, retiring its listener
			p := r.m.Prepare([]Rule{agentRule("r", 9443, "home", "10.200.0.2", nil)})
			if p.Failed()["r"] == nil {
				t.Fatal("want r to fail")
			}
			p.Commit(map[string]func(netip.Addr) bool{"r": func(netip.Addr) bool { return false }})
		}},
		{name: "retiring re-check refuses the source", cut: func(t *testing.T, r *cutRig) {
			next := []Rule{agentRule("r", 9443, "home", "10.200.0.2", nil)}
			r.m.Prepare(next).Commit(map[string]func(netip.Addr) bool{"r": func(netip.Addr) bool { return true }})
			if got := r.m.RetiringPorts(); !reflect.DeepEqual(got, []uint16{port}) {
				t.Fatalf("RetiringPorts = %v, want [%d]", got, port)
			}
			r.m.Prepare(next).Commit(map[string]func(netip.Addr) bool{"r": func(netip.Addr) bool { return false }})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newCutRig(t, map[uint16]bool{9443: true})
			r.m.Apply([]Rule{home})
			client := r.connect(t, port, tc.dialing)
			tc.cut(t, r)
			r.resume()
			r.waitCut(t, client)
			// a retiring listener with no connection left closes at the re-check (design.md 7a.3 節)
			if got := r.m.RetiringPorts(); len(got) != len(tc.retiring) || (len(got) > 0 && !reflect.DeepEqual(got, tc.retiring)) {
				t.Errorf("RetiringPorts = %v, want %v", got, tc.retiring)
			}
		})
	}
}

// A retiring listener keeps the connections its re-check still admits, with both sides open.
func TestRetiringKeepsAdmittedUpstream(t *testing.T) {
	r := newCutRig(t, map[uint16]bool{9443: true})
	r.m.Apply([]Rule{agentRule("r", 8443, "home", "10.200.0.2", nil)})
	client := r.connect(t, 8443, false)
	next := []Rule{agentRule("r", 9443, "home", "10.200.0.2", nil)}
	keep := map[string]func(netip.Addr) bool{"r": func(netip.Addr) bool { return true }}
	r.m.Prepare(next).Commit(keep)
	r.m.Prepare(next).Commit(keep)
	client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 2)
	if _, err := client.Read(b); err != nil || string(b) != "ok" {
		t.Errorf("a retained connection stopped relaying: %q, %v", b, err)
	}
	r.mu.Lock()
	upClosed := r.ups[0].closed.Load()
	r.mu.Unlock()
	if upClosed {
		t.Error("the upstream of a retained connection was closed")
	}
	if got := r.m.RetiringPorts(); !reflect.DeepEqual(got, []uint16{8443}) {
		t.Errorf("RetiringPorts = %v, want [8443]", got)
	}
	if got := r.pool.InUse(); got != 1 {
		t.Errorf("pool in use = %d, want 1", got)
	}
}
