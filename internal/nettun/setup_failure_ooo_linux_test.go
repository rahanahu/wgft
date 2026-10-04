//go:build linux && lab

package nettun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rahanahu/wgft/internal/dataplane/userspace/relay"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/internal/vpsd/proxyrelay"
	"github.com/rahanahu/wgft/proto"
)

// These setup-error paths used to close a real out-of-order-only receive queue before measuring
// it. Keep the raw segment and kernel settings inside the disposable VM's private namespace.
func TestSetupFailureOutOfOrderKernelData(t *testing.T) {
	if os.Getenv("WGFT_TEST_IN_NETNS") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestSetupFailureOutOfOrderKernelData$", "-test.v", "-test.count=1")
		cmd.Env = append(os.Environ(), "WGFT_TEST_IN_NETNS=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET, UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}}
		out, err := cmd.CombinedOutput()
		t.Logf("in a new user and network namespace:\n%s", out)
		if err != nil {
			t.Fatalf("undetermined or failed in the required namespace: %v", err)
		}
		return
	}
	setupNetns(t)
	for _, kind := range []string{"relay dial", "proxy dial", "proxy header"} {
		t.Run(kind, func(t *testing.T) { established(t, func(t *testing.T) error { return setupFailureOOOScene(t, kind) }) })
	}
}

type setupFailureListener struct {
	net.Listener
	accepted chan *net.TCPConn
}

func (l setupFailureListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepted <- c.(*net.TCPConn)
	}
	return c, err
}

type setupFailureNetwork struct{ ln net.Listener }

func (n setupFailureNetwork) ListenTCP(uint16) (net.Listener, error) { return n.ln, nil }
func (n setupFailureNetwork) ListenUDP(uint16) (net.PacketConn, error) {
	return nil, errors.New("unused UDP listener")
}

func setupFailureOOOScene(t *testing.T, kind string) error {
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	lport := uint16(ln.Addr().(*net.TCPAddr).Port)
	accepted := make(chan *net.TCPConn, 1)
	wrapped := setupFailureListener{ln, accepted}
	entered, proceed := make(chan struct{}), make(chan struct{})
	var once sync.Once
	resume := func() { once.Do(func() { close(proceed) }) }
	defer resume()
	pool := resource.NewPool(8)
	var held, releases, doubles atomic.Int32
	var pport uint16
	observed := make(chan []int, 1)
	policy := func() (func(), bool) {
		held.Add(1)
		var returned atomic.Bool
		return func() {
			if !returned.CompareAndSwap(false, true) {
				doubles.Add(1)
			}
			observed <- pairMemory(t, lport, pport)
			held.Add(-1)
			releases.Add(1)
		}, true
	}
	dial := func() (net.Conn, error) { close(entered); <-proceed; return nil, errors.New("dial failure") }
	if kind == "relay dial" {
		m := relay.New(setupFailureNetwork{wrapped}, relay.Options{TCPPool: pool, Logf: func(string, ...any) {}, Dial: func(string, string) (net.Conn, error) { return dial() }, Admit: func(string, netip.Addr, int) (func(), bool) { return policy() }})
		defer m.Close()
		m.Prepare(map[relay.Key]relay.Desired{{Proto: proto.TCP, Port: lport}: {Target: "127.0.0.1:1", RuleID: "rule"}}).Commit(nil)
	} else {
		if kind == "proxy header" {
			p, _, _ := newRelayEndPair(t, 1)
			dial = func() (net.Conn, error) {
				close(entered)
				<-proceed
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				up, err := p.a.DialTCP(ctx, netip.AddrPortFrom(p.b.local, 9000))
				if err != nil {
					return nil, err
				}
				peer, err := p.ln.Accept()
				if err != nil {
					t.Fatal(err)
				}
				defer peer.Close()
				up.Close()
				return up, nil
			}
		}
		m := proxyrelay.New(proxyrelay.Options{Listen: func(uint16) (net.Listener, error) { return wrapped, nil }, Dial: func(string) (net.Conn, error) { return dial() }, Pool: pool, HoldUntilDelivered: true, FloorAtAccept: true, Admit: func(string, netip.Addr) (func(), bool) { return policy() }, Logf: func(string, ...any) {}})
		defer m.Close()
		m.Apply([]proxyrelay.Rule{{ID: "rule", Agent: "agent", ListenPort: lport, AgentAddr: netip.MustParseAddr("127.0.0.1"), AgentPort: 1, ProxyProtocol: kind == "proxy header"}})
	}
	// Managers must remain alive through the scene; their deferred closes run only on return.
	client, err := net.DialTCP("tcp4", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	pport = uint16(client.LocalAddr().(*net.TCPAddr).Port)
	var c *net.TCPConn
	select {
	case c = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("no accepted socket")
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("setup Dial did not begin")
	}
	snd, rcv := seqs(t, client)
	sendOutOfOrder(t, pport, lport, snd, rcv, 1000, 500)
	if _, err := holdWait(time.Second, func() bool { return rmemAlloc(c) > 0 }); err != nil {
		return fmt.Errorf("OOO did not reach accepted socket")
	}
	q, mem := inq(c), rmemAlloc(c)
	if q != 0 || mem <= 0 {
		return fmt.Errorf("SIOCINQ %d, RMEM_ALLOC %d; want0 and above0", q, mem)
	}
	if pool.InUse() != 1 || held.Load() != 1 {
		t.Fatal("established socket lacks both charges")
	}
	t.Logf("before setup error: SIOCINQ=%d RMEM_ALLOC=%d", q, mem)
	resume()
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, readErr := io.Copy(io.Discard, client)
	var atRelease []int
	select {
	case atRelease = <-observed:
	case <-time.After(5 * time.Second):
		t.Fatal("no release-boundary memory observation")
	}
	for _, n := range atRelease {
		if n > 0 {
			t.Fatalf("accepted socket retained %d bytes when K returned", n)
		}
	}
	if _, err := holdWait(3*time.Second, func() bool { return pool.InUse() == 0 && held.Load() == 0 }); err != nil {
		t.Fatal(err)
	}
	after := pairMemory(t, lport, pport)
	for _, n := range after {
		if n > 0 {
			t.Fatalf("accepted socket retained %d bytes after both slots returned", n)
		}
	}
	t.Logf("at policy release after K: receive memory=%v; after both releases=%v; peer reset=%v", atRelease, after, errors.Is(readErr, unix.ECONNRESET))
	if releases.Load() != 1 || doubles.Load() != 0 || pool.Ledger().DoubleReleases != 0 {
		t.Fatalf("release count %d, ticket doubles%d, pool doubles%d", releases.Load(), doubles.Load(), pool.Ledger().DoubleReleases)
	}
	return nil
}
