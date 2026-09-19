package proxyrelay

import (
	"bufio"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"
)

// lineAgent is a plain TCP agent that answers every line with "echo:" and the line, for as long
// as the connection lasts.
func lineAgent(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if _, err := c.Write([]byte("echo:" + line)); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// relayHarness opens each declared port on its own loopback listener and dials the fake agent.
// Ports in busy fail to bind.
type relayHarness struct {
	m     *Manager
	mu    sync.Mutex
	addrs map[uint16]string
}

func newRelayHarness(t *testing.T, agentAddr string, busy map[uint16]bool) *relayHarness {
	t.Helper()
	h := &relayHarness{addrs: map[uint16]string{}}
	h.m = New(Options{
		Listen: func(port uint16) (net.Listener, error) {
			if busy[port] {
				return nil, errors.New("address already in use")
			}
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err == nil {
				h.mu.Lock()
				h.addrs[port] = ln.Addr().String()
				h.mu.Unlock()
			}
			return ln, err
		},
		Dial: func(string) (net.Conn, error) { return net.Dial("tcp", agentAddr) },
		Logf: testLogf(t),
	})
	t.Cleanup(h.m.Close)
	return h
}

// dial connects to the public side of port from the loopback source address src.
func (h *relayHarness) dial(t *testing.T, port uint16, src string) (net.Conn, error) {
	t.Helper()
	h.mu.Lock()
	addr := h.addrs[port]
	h.mu.Unlock()
	d := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}}
	return d.Dial("tcp4", addr)
}

func echoOK(c net.Conn, msg string) bool {
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte(msg + "\n")); err != nil {
		return false
	}
	got, err := bufio.NewReader(c).ReadString('\n')
	return err == nil && got == "echo:"+msg+"\n"
}

// closedByPeer reports whether the relay closed c (a read ends with EOF or a reset, not a timeout).
func closedByPeer(c net.Conn) bool {
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := c.Read(make([]byte, 1))
	var ne net.Error
	return err != nil && !(errors.As(err, &ne) && ne.Timeout())
}

// A rule whose replacement cannot bind is fail-closed (design.md 7a.3 節): StopAccepting closes
// only its listening socket, so established connections keep relaying while new ones are refused;
// Retire then closes only the connections its new declaration refuses (a new source_deny).
func TestStopAcceptingKeepsEstablishedAndRetireClosesDenied(t *testing.T) {
	h := newRelayHarness(t, lineAgent(t), map[uint16]bool{9443: true})
	h.m.Apply([]Rule{ruleOn("r", 8443)})

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

	// r moves to 9443, which cannot be bound, and its new declaration denies 127.0.0.2
	p := h.m.Prepare([]Rule{ruleOn("r", 9443)})
	if err := p.Failed()["r"]; err == nil {
		t.Fatalf("Failed = %v, want r", p.Failed())
	}
	if got := p.Listening(); len(got) != 0 {
		t.Errorf("Listening = %v, want nothing (the old port is being retired, the new one failed)", got)
	}
	deny := netip.MustParsePrefix("127.0.0.2/32")
	p.Commit(map[string]func(netip.Addr) bool{"r": func(src netip.Addr) bool { return !deny.Contains(src) }})

	if !echoOK(kept, "c") {
		t.Error("an established connection the new declaration admits was cut")
	}
	if !closedByPeer(denied) {
		t.Error("an established connection from a newly denied source was kept")
	}
	if c, err := h.dial(t, 8443, "127.0.0.1"); err == nil {
		c.Close()
		t.Error("the retiring listener still accepts new connections")
	}
	if got := h.m.RetiringPorts(); !reflect.DeepEqual(got, []uint16{8443}) {
		t.Errorf("RetiringPorts = %v, want [8443]", got)
	}

	// Deleting the rule cuts what is left, as deletion always does.
	h.m.Prepare(nil).Commit(nil)
	if !closedByPeer(kept) {
		t.Error("deleting a retiring rule must close its established connections")
	}
	if got := h.m.RetiringPorts(); len(got) != 0 {
		t.Errorf("RetiringPorts = %v after the delete, want none", got)
	}
}

// Without retiring (a delete or a disable), Commit keeps today's behaviour: the listener and its
// established connections are closed.
func TestCommitWithoutRetiringCutsEstablished(t *testing.T) {
	h := newRelayHarness(t, lineAgent(t), nil)
	h.m.Apply([]Rule{ruleOn("r", 8443)})
	c, err := h.dial(t, 8443, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !echoOK(c, "a") {
		t.Fatal("no relay before the delete")
	}
	h.m.Prepare(nil).Commit(nil)
	if !closedByPeer(c) {
		t.Error("deleting the rule must close its established connection")
	}
}
