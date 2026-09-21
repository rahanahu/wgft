package proxyrelay

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// retargetHarness opens each declared port on its own loopback listener, like relayHarness, and
// routes Dial by the declared agent address, so a test can tell which agent a connection reaches.
type retargetHarness struct {
	m      *Manager
	mu     sync.Mutex
	addrs  map[uint16]string // 公開ポート -> loopback の待ち受け
	agents map[string]string // エージェントのアドレス:ポート -> 偽のエージェントの loopback
	logs   []string
	// dialing は dial に入ったことを知らせ、gate が閉じている間は dial をそこで止める。
	dialing chan string
	gate    chan struct{}
}

func newRetargetHarness(t *testing.T, agents map[string]string) *retargetHarness {
	t.Helper()
	h := &retargetHarness{addrs: map[uint16]string{}, agents: agents, dialing: make(chan string, 8)}
	log := testLogf(t)
	h.m = New(Options{
		Listen: func(port uint16) (net.Listener, error) {
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err == nil {
				h.mu.Lock()
				h.addrs[port] = ln.Addr().String()
				h.mu.Unlock()
			}
			return ln, err
		},
		Dial: func(addr string) (net.Conn, error) {
			h.mu.Lock()
			dst, ok := h.agents[addr]
			gate := h.gate
			h.mu.Unlock()
			if !ok {
				return nil, errors.New("no agent at " + addr)
			}
			select {
			case h.dialing <- addr:
			default:
			}
			if gate != nil {
				<-gate
			}
			return net.Dial("tcp", dst)
		},
		Logf: func(format string, args ...any) {
			h.mu.Lock()
			h.logs = append(h.logs, fmt.Sprintf(format, args...))
			h.mu.Unlock()
			log(format, args...)
		},
	})
	t.Cleanup(h.m.Close)
	return h
}

func (h *retargetHarness) dial(t *testing.T, port uint16, src string) (net.Conn, error) {
	t.Helper()
	h.mu.Lock()
	addr := h.addrs[port]
	h.mu.Unlock()
	d := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}}
	return d.Dial("tcp4", addr)
}

// logged reports whether any log line holds sub.
func (h *retargetHarness) logged(sub string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, l := range h.logs {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

// agentRule is ruleOn with an explicit agent address, agent name and source policy.
func agentRule(id string, port uint16, agent string, addr string, deny []string) Rule {
	r := rule(false, deny, nil)
	r.ID, r.ListenPort, r.Agent = id, port, agent
	r.AgentAddr, r.AgentPort = netip.MustParseAddr(addr), port
	return r
}

// A rule that keeps its listen port but points at another agent has a new effective target
// (design.md 6.2 節, 7 節「実効宛先が違う:閉じてから開く。セッションは切れる」). The established
// connections of that listener reach the OLD agent, because each of them dialled its upstream at
// accept time, so Commit must close them all.
func TestRetargetClosesEstablishedConnections(t *testing.T) {
	old, next := lineAgent(t), lineAgent(t)
	h := newRetargetHarness(t, map[string]string{"10.200.0.2:8443": old, "10.200.0.3:8443": next})
	h.m.Apply([]Rule{agentRule("r", 8443, "home", "10.200.0.2", nil)})

	c, err := h.dial(t, 8443, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !echoOK(c, "a") {
		t.Fatal("the connection does not relay before the change")
	}

	// the same rule, same listen port, now on the second agent
	h.m.Apply([]Rule{agentRule("r", 8443, "home2", "10.200.0.3", nil)})
	if !closedByPeer(c) {
		t.Error("a connection to the old agent was kept after the rule was repointed to another agent")
	}
	if !h.logged("retargeted; rule r; closed 1 connections") {
		t.Errorf("no log line reports the retarget and the number of closed connections: %v", h.logs)
	}
	// the listener keeps its port and now relays to the new agent
	c2, err := h.dial(t, 8443, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if !echoOK(c2, "b") {
		t.Error("the listener does not relay to the new agent after the retarget")
	}
}

// A change of the source policy alone is not a change of the effective target: the connections the
// new policy still admits keep relaying, and only the refused ones are closed (design.md 6.2 節
// 「接続元制限の変更:条件を満たさなくなった接続元の中継を閉じる」).
func TestSourcePolicyChangeKeepsAdmittedConnections(t *testing.T) {
	old := lineAgent(t)
	h := newRetargetHarness(t, map[string]string{"10.200.0.2:8443": old})
	h.m.Apply([]Rule{agentRule("r", 8443, "home", "10.200.0.2", nil)})

	kept, err := h.dial(t, 8443, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer kept.Close()
	denied, err := h.dial(t, 8443, "127.0.0.2")
	if err != nil {
		t.Skipf("cannot use 127.0.0.2 as a source here: %v", err)
	}
	defer denied.Close()
	if !echoOK(kept, "a") || !echoOK(denied, "b") {
		t.Fatal("the connections do not relay before the change")
	}

	h.m.Apply([]Rule{agentRule("r", 8443, "home", "10.200.0.2", []string{"127.0.0.2/32"})})
	if !closedByPeer(denied) {
		t.Error("a connection from a newly denied source was kept")
	}
	if !echoOK(kept, "c") {
		t.Error("a connection the new policy still admits was cut")
	}
	if h.logged("retargeted") {
		t.Errorf("a source policy change must not count as a retarget: %v", h.logs)
	}
}

// A connection that is still opening its upstream while the target changes must not relay either:
// it dialled the old agent, and the tracked set does not hold it yet.
func TestRetargetClosesConnectionsStillDialling(t *testing.T) {
	old, next := lineAgent(t), lineAgent(t)
	h := newRetargetHarness(t, map[string]string{"10.200.0.2:8443": old, "10.200.0.3:8443": next})
	h.mu.Lock()
	h.gate = make(chan struct{})
	h.mu.Unlock()
	h.m.Apply([]Rule{agentRule("r", 8443, "home", "10.200.0.2", nil)})

	c, err := h.dial(t, 8443, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case addr := <-h.dialing:
		if addr != "10.200.0.2:8443" {
			t.Fatalf("the connection dialled %s, want the old agent", addr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the relay did not dial the agent")
	}
	// the rule moves while that connection is still dialling
	h.m.Apply([]Rule{agentRule("r", 8443, "home2", "10.200.0.3", nil)})
	h.mu.Lock()
	gate := h.gate
	h.mu.Unlock()
	close(gate) // the dial to the old agent completes now
	if !closedByPeer(c) {
		t.Error("a connection that had dialled the old agent kept relaying after the retarget")
	}
}

// flakyListener fails its first fails accepts with an error that is not net.ErrClosed, the way a
// process out of file descriptors does, and then behaves like the listener it wraps.
type flakyListener struct {
	net.Listener
	mu    sync.Mutex
	fails int
	calls int
}

func (f *flakyListener) Accept() (net.Conn, error) {
	f.mu.Lock()
	f.calls++
	if f.fails > 0 {
		f.fails--
		f.mu.Unlock()
		return nil, errors.New("accept: too many open files")
	}
	f.mu.Unlock()
	return f.Listener.Accept()
}

func (f *flakyListener) accepts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// An accept error that is not net.ErrClosed must not end the accept loop: the socket stays bound,
// Prepare does not reopen a port that is already in m.ls, so a listener that gave up would stay
// bound and deaf until vpsd restarts. The failure is logged and the listener retries.
func TestAcceptErrorKeepsServing(t *testing.T) {
	agentAddr := lineAgent(t)
	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fl := &flakyListener{Listener: raw, fails: 3}
	var mu sync.Mutex
	var logs []string
	log := testLogf(t)
	m := New(Options{
		Listen: func(uint16) (net.Listener, error) { return fl, nil },
		Dial:   func(string) (net.Conn, error) { return net.Dial("tcp", agentAddr) },
		Logf: func(format string, args ...any) {
			mu.Lock()
			logs = append(logs, fmt.Sprintf(format, args...))
			mu.Unlock()
			log(format, args...)
		},
	})
	t.Cleanup(m.Close)
	m.Apply([]Rule{agentRule("r", 8443, "home", "10.200.0.2", nil)})

	deadline := time.Now().Add(5 * time.Second)
	for fl.accepts() < 4 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := fl.accepts(); got < 4 {
		t.Fatalf("accept was called %d times, want the loop to retry after each failure", got)
	}
	c, err := net.DialTimeout("tcp", raw.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !echoOK(c, "a") {
		t.Error("the listener does not relay after the accept failures")
	}
	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, l := range logs {
		if strings.Contains(l, "accept failed") {
			found = true
		}
	}
	if !found {
		t.Errorf("the accept failure was not logged: %v", logs)
	}
}
