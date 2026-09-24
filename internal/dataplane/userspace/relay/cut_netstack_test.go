package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/nettun"
	"github.com/rahanahu/wgft/proto"
)

// netstackNet opens the relay's listeners on a gVisor netstack, the way the agent's tunnel does
// (tunnel.Tunnel.ListenTCP/ListenUDP), so the tests below see the netstack's own port rules:
// an endpoint left in TIME_WAIT or FIN_WAIT_2 keeps its local port, and a new listener on that
// port fails with "port is in use".
type netstackNet struct {
	dev  *nettun.Device
	addr netip.Addr
}

func (n netstackNet) ListenTCP(port uint16) (net.Listener, error) {
	return n.dev.ListenTCP(netip.AddrPortFrom(n.addr, port))
}

func (n netstackNet) ListenUDP(port uint16) (net.PacketConn, error) {
	return n.dev.ListenUDP(netip.AddrPortFrom(n.addr, port))
}

var (
	cutClientAddr = netip.MustParseAddr("10.99.0.1")
	cutAgentAddr  = netip.MustParseAddr("10.99.0.2")
)

// netstackPair joins two netstack devices back to back: packets one writes out are delivered to
// the other, in place of WireGuard. The client dials from the first; the relay listens on the second.
func netstackPair(t *testing.T) (*nettun.Device, netstackNet) {
	t.Helper()
	client, err := nettun.Create(cutClientAddr, 1420)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := nettun.Create(cutAgentAddr, 1420)
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	pump := func(src, dst *nettun.Device) {
		bufs := [][]byte{make([]byte, 65535)}
		sizes := []int{0}
		for {
			n, err := src.Read(bufs, sizes, 0)
			if err != nil {
				return
			}
			if n == 1 {
				dst.Write([][]byte{bufs[0][:sizes[0]]}, 0)
			}
		}
	}
	go pump(client, agent)
	go pump(agent, client)
	t.Cleanup(func() {
		// Stop both stacks: Close aborts every endpoint and Wait removes the NICs, after which
		// nothing writes to the devices. Device.Close is not called: it closes the channel that
		// WriteNotify sends on, and the race detector reports that close against sends made
		// earlier from the stack's goroutines. The two pumps stay blocked in Read.
		for _, d := range []*nettun.Device{client, agent} {
			d.Stack().Close()
		}
		for _, d := range []*nettun.Device{client, agent} {
			d.Stack().Wait()
		}
	})
	return client, netstackNet{dev: agent, addr: cutAgentAddr}
}

// dialNetstackEcho connects from the client's netstack to the relay's port and checks one echo.
func dialNetstackEcho(t *testing.T, client *nettun.Device, port uint16) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := client.DialTCP(ctx, netip.AddrPortFrom(cutAgentAddr, port))
	if err != nil {
		t.Fatalf("dial the relay on the netstack: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if got, err := echoLine(c, "hello"); err != nil || got != "hello\n" {
		t.Fatalf("echo through the relay: %q, %v", got, err)
	}
	return c
}

// isCutByReset is whether a read on a cut session failed the way a reset makes it fail: neither
// a graceful close (EOF) nor the read deadline expiring (the session still open).
func isCutByReset(err error) bool {
	return err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrDeadlineExceeded)
}

// A TCP session the relay cuts on purpose (the rule disabled and re-enabled at once, or the
// target changed) must leave the netstack port free at once, so the listener opens again in the
// same Apply. A graceful Close would leave the agent's endpoint in FIN_WAIT_2 here, because the
// client never closes its side, and the new listener would fail with "port is in use" until
// the hold ends (design.md 7 節). The client sees a reset rather than EOF.
func TestTCPForcedCutFreesTheNetstackPortAtOnce(t *testing.T) {
	const port = 7000
	k := Key{proto.TCP, port}
	cases := []struct {
		name string
		cut  func(m *Manager, target, other string)
		// toOther is whether the rule points at the other target after the cut
		toOther bool
	}{
		{"disable and re-enable", func(m *Manager, target, _ string) {
			m.Apply(nil)
			m.Apply(map[Key]Desired{k: {target, "r1"}})
		}, false},
		{"target change reopens", func(m *Manager, _, other string) {
			m.Apply(map[Key]Desired{k: {other, "r1"}})
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, agent := netstackPair(t)
			target, other := tcpEcho(t), tcpEcho(t)
			m := New(agent, Options{Logf: t.Logf})
			defer m.Close()
			m.Apply(map[Key]Desired{k: {target, "r1"}})
			c := dialNetstackEcho(t, client, port)

			tc.cut(m, target, other)

			st := statusOf(t, m, k)
			if !st.Listening {
				t.Fatalf("the listener did not open again right after the cut: %v", st.Err)
			}
			want := target
			if tc.toOther {
				want = other
			}
			if st.Target != want {
				t.Fatalf("target after the cut = %s, want %s", st.Target, want)
			}
			dialNetstackEcho(t, client, port)

			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := c.Read(make([]byte, 1)); !isCutByReset(err) {
				t.Fatalf("the cut session should end with a reset, not a graceful close or a timeout; got %v", err)
			}
		})
	}
}

// A UDP listener has no TIME_WAIT: after the rule is disabled with a live session, the same
// port opens again at once.
func TestUDPCloseFreesTheNetstackPortAtOnce(t *testing.T) {
	const port = 7001
	k := Key{proto.UDP, port}
	client, agent := netstackPair(t)
	target, _ := udpEcho(t)
	m := New(agent, Options{Logf: t.Logf})
	defer m.Close()
	want := map[Key]Desired{k: {target, "r1"}}
	echo := func() {
		t.Helper()
		c, err := client.DialUDP(netip.AddrPortFrom(cutAgentAddr, port))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 16)
		if n, err := c.Read(b); err != nil || string(b[:n]) != "ping" {
			t.Fatalf("echo through the relay: %q, %v", b[:n], err)
		}
	}
	m.Apply(want)
	echo()
	m.Apply(nil)
	m.Apply(want)
	if st := statusOf(t, m, k); !st.Listening {
		t.Fatalf("the UDP listener did not open again right after the close: %v", st.Err)
	}
	echo()
}

// acceptSignal wraps a Network so that the test knows the relay's accept loop has taken a
// connection off its listener.
type acceptSignal struct {
	Network
	accepted chan struct{}
}

func (a acceptSignal) ListenTCP(port uint16) (net.Listener, error) {
	ln, err := a.Network.ListenTCP(port)
	if err != nil {
		return nil, err
	}
	return signalListener{ln, a.accepted}, nil
}

type signalListener struct {
	net.Listener
	accepted chan struct{}
}

func (l signalListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		select {
		case l.accepted <- struct{}{}:
		default:
		}
	}
	return c, err
}

// A connection accepted while Apply holds m.mu waits in the accept loop (ruleOf) until Apply
// returns, so the listener's close cannot see it. It must not be registered and piped to the old
// target afterwards: it would hold the netstack port, and the listener opened for the new target
// could not bind until the client went away. The accept loop cuts it instead, so the next retry
// opens the listener and the client sees a reset.
func TestTCPConnAcceptedDuringCloseIsCut(t *testing.T) {
	const port = 7002
	k := Key{proto.TCP, port}
	client, agent := netstackPair(t)
	target, other := tcpEcho(t), tcpEcho(t)
	accepted := make(chan struct{}, 1)
	m := New(acceptSignal{agent, accepted}, Options{Logf: t.Logf})
	defer m.Close()
	m.Apply(map[Key]Desired{k: {target, "r1"}})

	// the same steps as Apply's reopen, with the accept landing while m.mu is held
	m.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := client.DialTCP(ctx, netip.AddrPortFrom(cutAgentAddr, port))
	if err != nil {
		m.mu.Unlock()
		t.Fatalf("dial the relay on the netstack: %v", err)
	}
	defer c.Close()
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		m.mu.Unlock()
		t.Fatal("the relay never accepted the connection")
	}
	m.closeLocked(k)
	m.openLocked(k, Desired{other, "r1"})
	m.mu.Unlock()

	// The listener for the new target could not bind while the accepted connection still held
	// the port; the retry (every 30s in the agent) opens it once the accept loop has cut it.
	deadline := time.Now().Add(3 * time.Second)
	var st Status
	for {
		m.Retry()
		if st = statusOf(t, m, k); st.Listening || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !st.Listening || st.Target != other {
		t.Fatalf("the listener for the new target did not open: listening=%v target=%s err=%v", st.Listening, st.Target, st.Err)
	}
	dialNetstackEcho(t, client, port)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); !isCutByReset(err) {
		t.Fatalf("the connection accepted during the close should be reset; got %v", err)
	}
}
