//go:build linux

package nettun

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/rahanahu/wgft/internal/dataplane/userspace/relay"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// The tests in this file pin how the userspace relay accounts for a connection after the relay has
// ended, while the connection still holds data on its way to a peer (design.md 7 節「中継が終わった
// 後の末尾の配送」): the pair keeps its Resource Guard slot and, in the server's role, its
// per-source slot until the data is delivered, the paths that cut relays also cut such pairs at
// once, and the number of such pairs is bounded by the flow budget. Each test drives the real relay
// in the agent's role (the relay listens on the netstack and dials a kernel target) or the
// server's role (the relay listens on the kernel loopback and dials over the netstack).
//
// "The netstack side" is a tail held by the relay's netstack connection: data goes from the
// kernel end through the relay to the netstack peer, which does not read. "The kernel side" is a
// tail held by the relay's kernel socket: data goes from the netstack peer to the kernel end,
// which does not read.

// holdEnv is one relay with its pool and the test's ends of each relayed pair.
type holdEnv struct {
	t        *testing.T
	agent    bool // the relay's role
	p        *tcpPair
	relayDev *Device
	peerDev  *Device
	drop     *atomic.Bool
	win      *relayEndWindow
	m        *relay.Manager
	pool     *resource.Pool
	releases atomic.Int32 // per-source releases
	srcInUse atomic.Int32 // per-source slots held
	srcLimit atomic.Int32 // per-source limit the test's Admit enforces; 0 is none
	doubles  atomic.Int32 // per-source tickets released more than once
	logs     *holdLog
	armed    atomic.Bool
	ports    map[string]uint16

	nsAcc  chan net.Conn // the relay's netstack conns (agent: accepted; server: dialed)
	kAcc   chan net.Conn // the relay's kernel conns (agent: dialed; server: accepted)
	peerC  chan net.Conn // server: the agent's accepted ends on the peer Device
	tgtC   chan net.Conn // agent: the target's accepted ends on the loopback
	tgtLn  net.Listener
	kfix   func(*net.TCPConn) // run on each relay kernel conn as it is captured
	kfixMu sync.Mutex
}

type holdLog struct {
	mu    sync.Mutex
	lines []string
	ended bool
	t     *testing.T
}

func (l *holdLog) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := fmt.Sprintf(format, args...)
	l.lines = append(l.lines, s)
	if !l.ended {
		l.t.Log(s)
	}
}

func (l *holdLog) has(sub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.lines {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// holdPair is one relayed connection: relayNS and relayK are the relay's own conns, peer is the
// netstack peer's end and kend the kernel end (the public client in the server's role, the target
// in the agent's).
type holdPair struct {
	key     relay.Key
	relayNS *tcpConn
	relayK  *net.TCPConn
	peer    net.Conn
	kend    *net.TCPConn
	flow    [2]uint16
}

type captureListener struct {
	net.Listener
	env *holdEnv
}

func (l captureListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.env.capturedKernel(c)
	}
	return c, err
}

type holdServerNet struct{ env *holdEnv }

func (n holdServerNet) ListenTCP(port uint16) (net.Listener, error) {
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		return nil, err
	}
	return captureListener{ln, n.env}, nil
}

func (holdServerNet) ListenUDP(port uint16) (net.PacketConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
}

func (e *holdEnv) capturedKernel(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	e.kfixMu.Lock()
	fix := e.kfix
	e.kfixMu.Unlock()
	if fix != nil {
		fix(tc)
	}
	select {
	case e.kAcc <- c:
	default:
	}
}

// newHoldEnv starts a relay in the given role with a pool of total flows and one listener per
// rule name.
func newHoldEnv(t *testing.T, agent bool, total int, rules ...string) *holdEnv {
	t.Helper()
	relayHost := byte(1)
	if agent {
		relayHost = 2
	}
	p, drop, win := newRelayEndPair(t, relayHost)
	e := &holdEnv{t: t, agent: agent, p: p, drop: drop, win: win, pool: resource.NewPool(total),
		logs: &holdLog{t: t}, ports: map[string]uint16{},
		nsAcc: make(chan net.Conn, 64), kAcc: make(chan net.Conn, 64), peerC: make(chan net.Conn, 64), tgtC: make(chan net.Conn, 64)}
	t.Cleanup(func() {
		e.logs.mu.Lock()
		e.logs.ended = true
		e.logs.mu.Unlock()
	})
	opts := relay.Options{TCPPool: e.pool, Logf: e.logs.logf}
	want := map[relay.Key]relay.Desired{}
	if agent {
		e.relayDev, e.peerDev = p.b, p.a
		tln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		e.tgtLn = tln
		t.Cleanup(func() { tln.Close() })
		go func() {
			for {
				c, err := tln.Accept()
				if err != nil {
					return
				}
				e.tgtC <- c
			}
		}()
		opts.Dial = func(network, addr string) (net.Conn, error) {
			c, err := net.DialTimeout(network, addr, 5*time.Second)
			if err == nil && e.armed.Load() {
				e.capturedKernel(c)
			}
			return c, err
		}
		e.m = relay.New(relayEndNet{p.b, e.nsAcc}, opts)
		for i, r := range rules {
			port := uint16(7500 + i)
			e.ports[r] = port
			want[relay.Key{Proto: proto.TCP, Port: port}] = relay.Desired{Target: tln.Addr().String(), RuleID: r}
		}
	} else {
		e.relayDev, e.peerDev = p.a, p.b
		go func() {
			for {
				c, err := p.ln.Accept()
				if err != nil {
					return
				}
				e.peerC <- c
			}
		}()
		opts.Admit = func(string, netip.Addr, int) (func(), bool) {
			if l := e.srcLimit.Load(); l > 0 && e.srcInUse.Load() >= l {
				return nil, false
			}
			e.srcInUse.Add(1)
			var once atomic.Bool
			return func() {
				e.releases.Add(1)
				if !once.CompareAndSwap(false, true) {
					e.doubles.Add(1)
					return
				}
				e.srcInUse.Add(-1)
			}, true
		}
		opts.Dial = func(network, addr string) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := p.a.DialTCP(ctx, netip.MustParseAddrPort(addr))
			if err == nil && e.armed.Load() {
				e.nsAcc <- c
			}
			return c, err
		}
		e.m = relay.New(holdServerNet{e}, opts)
		for _, r := range rules {
			l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			port := uint16(l.Addr().(*net.TCPAddr).Port)
			l.Close()
			e.ports[r] = port
			want[relay.Key{Proto: proto.TCP, Port: port}] = relay.Desired{Target: netip.AddrPortFrom(p.b.local, 9000).String(), RuleID: r}
		}
	}
	t.Cleanup(e.m.Close)
	e.m.Apply(want)
	for _, r := range rules {
		if st := e.status(e.key(r)); !st.Listening {
			t.Fatalf("listener for %s did not open: %v", r, st.Err)
		}
	}
	e.armed.Store(true)
	return e
}

func (e *holdEnv) key(rule string) relay.Key { return relay.Key{Proto: proto.TCP, Port: e.ports[rule]} }

func (e *holdEnv) status(k relay.Key) relay.Status {
	for _, s := range e.m.Status() {
		if s.Key == k {
			return s
		}
	}
	return relay.Status{}
}

// open makes one relayed connection on rule. It returns nil if the relay refused the connection
// before relaying it (it reset the kernel end in the server's role, or the netstack peer in the
// agent's).
func (e *holdEnv) open(rule string) *holdPair {
	t := e.t
	t.Helper()
	k := e.key(rule)
	pr := &holdPair{key: k}
	if e.agent {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		peer, err := e.peerDev.DialTCP(ctx, netip.AddrPortFrom(e.relayDev.local, k.Port))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { peer.Close() })
		pr.peer = peer
		select {
		case c := <-e.nsAcc:
			pr.relayNS = connOf(c)
		case <-time.After(5 * time.Second):
			t.Fatal("the relay did not accept the peer's connection")
		}
		select {
		case c := <-e.kAcc:
			pr.relayK = c.(*net.TCPConn)
		case <-time.After(2 * time.Second):
			// refused before dialing: the relay reset its netstack conn
			return nil
		}
		pr.kend = matchAccepted(t, e.tgtC, pr.relayK.LocalAddr().String()).(*net.TCPConn)
	} else {
		src, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", k.Port), 5*time.Second)
		if errors.Is(err, unix.ECONNRESET) {
			// the relay reset the connection before the handshake was seen through: refused
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { src.Close() })
		pr.kend = src.(*net.TCPConn)
		select {
		case c := <-e.kAcc:
			pr.relayK = c.(*net.TCPConn)
		case <-time.After(5 * time.Second):
			t.Fatal("the relay did not accept the client's connection")
		}
		select {
		case c := <-e.nsAcc:
			pr.relayNS = connOf(c)
		case <-time.After(2 * time.Second):
			return nil
		}
		pr.peer = matchAccepted(t, e.peerC, pr.relayNS.LocalAddr().String())
	}
	pr.flow = flowOf(t, pr.relayNS)
	return pr
}

// tailSide says which of the relay's conns is left holding the tail.
type tailSide int

const (
	netstackTail tailSide = iota
	kernelTail
)

func (s tailSide) String() string {
	if s == netstackTail {
		return "netstack side"
	}
	return "kernel side"
}

func holdData(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = relayEndByte(i)
	}
	return b
}

const (
	holdNetstackSize = 192 << 10
	holdKernelSize   = 256 << 10
)

// leaveTail makes the relay end pr while its conn on side holds data that the reader has not
// read: the reader half-closes first and does not read, the writer sends size bytes and
// half-closes. It returns an error naming why the scene was not established, if it was not.
func (e *holdEnv) leaveTail(pr *holdPair, side tailSide, size int) error {
	writer, reader := net.Conn(pr.kend), pr.peer
	if side == kernelTail {
		writer, reader = pr.peer, pr.kend
		pr.kend.SetReadBuffer(32 << 10)
	}
	if err := reader.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		return err
	}
	go func() {
		writer.SetWriteDeadline(time.Now().Add(10 * time.Second))
		writer.Write(holdData(size))
		writer.(interface{ CloseWrite() error }).CloseWrite()
	}()
	if err := e.waitEnded(pr, 5*time.Second); err != nil {
		return err
	}
	switch side {
	case netstackTail:
		if off := e.win.offeredEnd(pr.flow); off < 0 || off >= int64(size) {
			return fmt.Errorf("the peer had offered room up to %d of %d bytes when the relay ended, so no tail was left", off, size)
		}
	case kernelTail:
		if q := outq(pr.relayK); q <= 0 {
			return fmt.Errorf("the relay's kernel socket had %d bytes queued when the relay ended", q)
		}
	}
	return nil
}

// waitEnded waits until the relay no longer relays pr: the netstack conn was closed by the relay
// and the listener's sessions no longer count the pair.
func (e *holdEnv) waitEnded(pr *holdPair, d time.Duration) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if pr.relayNS.closed.Load() && e.status(pr.key).Sessions == 0 {
			return nil
		}
		time.Sleep(2 * time.Millisecond)
	}
	return fmt.Errorf("the relay did not end the pair within %v (sessions %d)", d, e.status(pr.key).Sessions)
}

// outq is the relay's kernel socket's SIOCOUTQ, or -1 if it cannot be read (closed).
func outq(c *net.TCPConn) int {
	rc, err := c.SyscallConn()
	if err != nil {
		return -1
	}
	n := -1
	if rc.Control(func(fd uintptr) {
		if v, err := unix.IoctlGetInt(int(fd), unix.SIOCOUTQ); err == nil {
			n = v
		}
	}) != nil {
		return -1
	}
	return n
}

// kernelState is the relay's kernel socket's TCP_INFO state, or -1 if it cannot be read.
func kernelState(c *net.TCPConn) int {
	rc, err := c.SyscallConn()
	if err != nil {
		return -1
	}
	st := -1
	if rc.Control(func(fd uintptr) {
		if info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO); err == nil {
			st = int(info.State)
		}
	}) != nil {
		return -1
	}
	return st
}

// holdReadAll reads c until EOF, checking every byte against holdData, pausing after each chunk when
// slow, and returns how many bytes it read and how reading ended (nil for EOF after size bytes).
func holdReadAll(c net.Conn, size int, deadline time.Time, slow bool) (int, error) {
	c.SetReadDeadline(deadline)
	buf := make([]byte, relayEndChunk)
	n := 0
	for {
		m, err := c.Read(buf)
		for i := 0; i < m; i++ {
			if buf[i] != relayEndByte(n+i) {
				return n + i, fmt.Errorf("byte %d is %d, want %d", n+i, buf[i], relayEndByte(n+i))
			}
		}
		n += m
		if errors.Is(err, io.EOF) {
			if n != size {
				return n, fmt.Errorf("EOF after %d of %d bytes", n, size)
			}
			return n, nil
		}
		if err != nil {
			return n, err
		}
		if slow {
			time.Sleep(relayEndPause)
		}
	}
}

// holdWait waits up to d for cond and returns how long it took, or an error.
func holdWait(d time.Duration, cond func() bool) (time.Duration, error) {
	start := time.Now()
	for !cond() {
		if time.Since(start) > d {
			return time.Since(start), fmt.Errorf("not within %v", d)
		}
		time.Sleep(2 * time.Millisecond)
	}
	return time.Since(start), nil
}

// established runs a scene up to three times, as the pre-registration says, and fails the test
// as undetermined if it is never established.
func established(t *testing.T, scene func(t *testing.T) error) {
	t.Helper()
	var last error
	for i := 0; i < 3; i++ {
		var notEstablished error
		ok := t.Run(fmt.Sprintf("try%d", i+1), func(t *testing.T) {
			if err := scene(t); err != nil {
				notEstablished = err
				t.Skipf("not established: %v", err)
			}
		})
		if !ok || notEstablished == nil {
			return
		}
		last = notEstablished
	}
	t.Fatalf("undetermined: the scene was not established in 3 runs: %v", last)
}

// N1 and N1i': after the relay ends with a tail on either side, the pair keeps its flow slot while
// the reader does not read, and in the server's role its per-source slot too. When the reader
// reads, the tail and EOF arrive and both slots are returned, each once.
func TestRelayHoldCountsTheTail(t *testing.T) {
	for _, agent := range []bool{true, false} {
		for _, side := range []tailSide{netstackTail, kernelTail} {
			role := "server"
			if agent {
				role = "agent"
			}
			t.Run(role+"/"+side.String(), func(t *testing.T) {
				established(t, func(t *testing.T) error {
					e := newHoldEnv(t, agent, 8, "r1")
					pr := e.open("r1")
					if pr == nil {
						t.Fatal("the relay refused the first connection")
					}
					size := holdNetstackSize
					reader := pr.peer
					if side == kernelTail {
						size, reader = holdKernelSize, pr.kend
					}
					if err := e.leaveTail(pr, side, size); err != nil {
						return err
					}
					holdUntil := time.Now().Add(5 * time.Second)
					for time.Now().Before(holdUntil) {
						st := e.status(pr.key)
						if st.Flows != 1 || st.Sessions != 0 {
							t.Fatalf("while the tail is held: flows %d, sessions %d; want 1 and 0", st.Flows, st.Sessions)
						}
						// the per-source slot is held for as long as K (owner's decision of 2026-10-04,
						// which replaced returning it when the relay ends)
						if !agent && (e.releases.Load() != 0 || e.srcInUse.Load() != 1) {
							t.Fatalf("while the tail is held: per-source releases %d, slots held %d; want 0 and 1", e.releases.Load(), e.srcInUse.Load())
						}
						time.Sleep(50 * time.Millisecond)
					}
					n, err := holdReadAll(reader, size, time.Now().Add(10*time.Second), false)
					if err != nil {
						t.Fatalf("the reader did not get the tail and EOF: read %d: %v", n, err)
					}
					d, err := holdWait(3*time.Second, func() bool {
						return e.pool.InUse() == 0 && e.status(pr.key).Flows == 0 && e.srcInUse.Load() == 0
					})
					if err != nil {
						t.Fatalf("the flow slot was not returned after the reader read everything: %v", err)
					}
					t.Logf("slot returned %v after the reader finished", d.Round(time.Millisecond))
					time.Sleep(100 * time.Millisecond)
					if !agent && (e.releases.Load() != 1 || e.doubles.Load() != 0) {
						t.Fatalf("per-source releases %d, double releases %d; want 1 and 0", e.releases.Load(), e.doubles.Load())
					}
					if d := e.pool.Ledger().DoubleReleases; d != 0 {
						t.Fatalf("pool double releases %d", d)
					}
					return nil
				})
			})
		}
	}
}

// R3: a reader on the kernel side that keeps reading slowly gets every byte and EOF after the
// relay ended with a tail in its kernel socket.
func TestRelayHoldDeliversKernelTailToSlowReader(t *testing.T) {
	for _, agent := range []bool{true, false} {
		role := "server"
		if agent {
			role = "agent"
		}
		t.Run(role, func(t *testing.T) {
			established(t, func(t *testing.T) error {
				e := newHoldEnv(t, agent, 8, "r1")
				pr := e.open("r1")
				if pr == nil {
					t.Fatal("refused")
				}
				start := time.Now()
				if err := e.leaveTail(pr, kernelTail, holdKernelSize); err != nil {
					return err
				}
				n, err := holdReadAll(pr.kend, holdKernelSize, start.Add(8*time.Second), true)
				if err != nil {
					t.Fatalf("read %d of %d: %v", n, holdKernelSize, err)
				}
				if _, err := holdWait(3*time.Second, func() bool { return e.pool.InUse() == 0 }); err != nil {
					t.Fatalf("slot not returned: %v", err)
				}
				return nil
			})
		})
	}
}

// N2: the paths that cut relays also cut a pair whose tail is being delivered, at once.
func TestRelayHoldCutPathsFreeThePair(t *testing.T) {
	cuts := []struct {
		name string
		cut  func(e *holdEnv)
	}{
		{"port removed", func(e *holdEnv) { e.m.Apply(map[relay.Key]relay.Desired{}) }},
		{"manager closed", func(e *holdEnv) { e.m.Close() }},
		{"source swept", func(e *holdEnv) {
			e.m.CloseSessions(func(string, netip.Addr) bool { return false })
		}},
	}
	for _, agent := range []bool{true, false} {
		for _, side := range []tailSide{netstackTail, kernelTail} {
			for _, c := range cuts {
				role := "server"
				if agent {
					role = "agent"
				}
				t.Run(role+"/"+side.String()+"/"+c.name, func(t *testing.T) {
					established(t, func(t *testing.T) error {
						e := newHoldEnv(t, agent, 8, "r1")
						pr := e.open("r1")
						if pr == nil {
							t.Fatal("refused")
						}
						size := holdNetstackSize
						if side == kernelTail {
							size = holdKernelSize
						}
						if err := e.leaveTail(pr, side, size); err != nil {
							return err
						}
						// long enough that the wait checks again only every 2 s, so a cut that does not
						// wake it would miss the 500 ms below
						time.Sleep(4 * time.Second)
						if e.pool.InUse() != 1 {
							return fmt.Errorf("the hold was not in place before the cut: in use %d", e.pool.InUse())
						}
						c.cut(e)
						d, err := holdWait(500*time.Millisecond, func() bool { return e.pool.InUse() == 0 })
						if err != nil {
							t.Fatalf("the slot was not returned within 500 ms of the cut: in use %d", e.pool.InUse())
						}
						t.Logf("slot returned %v after the cut", d.Round(time.Millisecond))
						if st := tcp.EndpointState(pr.relayNS.ep.State()); st != tcp.StateError && st != tcp.StateClose {
							t.Fatalf("the relay's netstack conn is %v after the cut, want reset", st)
						}
						for _, ep := range tcpip.GetDanglingEndpoints() {
							if ep == pr.relayNS.ep {
								t.Fatal("the relay's netstack endpoint is still dangling after the cut")
							}
						}
						return nil
					})
				})
			}
		}
	}
}

// N5: a peer that resets the connection while the tail is held ends the hold.
func TestRelayHoldPeerReset(t *testing.T) {
	for _, agent := range []bool{true, false} {
		for _, side := range []tailSide{netstackTail, kernelTail} {
			role := "server"
			if agent {
				role = "agent"
			}
			t.Run(role+"/"+side.String(), func(t *testing.T) {
				established(t, func(t *testing.T) error {
					e := newHoldEnv(t, agent, 8, "r1")
					pr := e.open("r1")
					if pr == nil {
						t.Fatal("refused")
					}
					size := holdNetstackSize
					if side == kernelTail {
						size = holdKernelSize
					}
					if err := e.leaveTail(pr, side, size); err != nil {
						return err
					}
					time.Sleep(200 * time.Millisecond)
					if e.pool.InUse() != 1 {
						return fmt.Errorf("hold not in place: in use %d", e.pool.InUse())
					}
					if side == netstackTail {
						pr.peer.(interface{ Abort() }).Abort()
					} else {
						pr.kend.SetLinger(0)
						pr.kend.Close()
					}
					d, err := holdWait(3*time.Second, func() bool { return e.pool.InUse() == 0 })
					if err != nil {
						t.Fatalf("the slot was not returned within 3 s of the reset: %v", err)
					}
					t.Logf("slot returned %v after the reset", d.Round(time.Millisecond))
					return nil
				})
			})
		}
	}
}

// N6, a substitute check: a peer that stops responding. The kernel side gets a short
// TCP_USER_TIMEOUT on the relay's socket only in this test, so that Linux itself aborts it; the
// netstack side gets a small TCPMaxRetriesOption on the relay's stack only in this test, so that
// gVisor itself aborts it. The real times are not checked here.
func TestRelayHoldUnresponsivePeer(t *testing.T) {
	for _, agent := range []bool{true, false} {
		for _, side := range []tailSide{netstackTail, kernelTail} {
			role := "server"
			if agent {
				role = "agent"
			}
			t.Run(role+"/"+side.String(), func(t *testing.T) {
				established(t, func(t *testing.T) error {
					e := newHoldEnv(t, agent, 8, "r1")
					if side == kernelTail {
						e.kfixMu.Lock()
						e.kfix = func(tc *net.TCPConn) {
							rc, _ := tc.SyscallConn()
							rc.Control(func(fd uintptr) {
								unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, 1000)
							})
						}
						e.kfixMu.Unlock()
					} else {
						retries := tcpip.TCPMaxRetriesOption(3)
						if err := e.relayDev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &retries); err != nil {
							t.Fatal(err)
						}
					}
					pr := e.open("r1")
					if pr == nil {
						t.Fatal("refused")
					}
					size := holdNetstackSize
					if side == kernelTail {
						size = holdKernelSize
					}
					if err := e.leaveTail(pr, side, size); err != nil {
						return err
					}
					var aborted time.Time
					if side == netstackTail {
						e.drop.Store(true)
						if _, err := holdWait(90*time.Second, func() bool {
							return tcp.EndpointState(pr.relayNS.ep.State()) == tcp.StateError
						}); err != nil {
							t.Fatalf("gVisor did not abort the relay's conn: %v", err)
						}
						aborted = time.Now()
					} else {
						if _, err := holdWait(30*time.Second, func() bool {
							st := kernelState(pr.relayK)
							return st == 7 || st == -1
						}); err != nil {
							t.Fatalf("Linux did not abort the relay's socket: %v", err)
						}
						aborted = time.Now()
					}
					if _, err := holdWait(3*time.Second, func() bool { return e.pool.InUse() == 0 }); err != nil {
						t.Fatalf("the slot was not returned within 3 s of the abort: %v", err)
					}
					t.Logf("aborted and returned; substitute check, real time not checked (%v)", time.Since(aborted).Round(time.Millisecond))
					return nil
				})
			})
		}
	}
}

// N7: in the agent's role, a target that resets leaves the relay's netstack conn with a tail in
// FIN_WAIT_1; the pair is counted until the peer reads it.
func TestRelayHoldTargetReset(t *testing.T) {
	established(t, func(t *testing.T) error {
		e := newHoldEnv(t, true, 8, "r1")
		pr := e.open("r1")
		if pr == nil {
			t.Fatal("refused")
		}
		go pr.kend.Write(holdData(holdNetstackSize))
		// let the relay take everything out of the target's socket before the reset
		time.Sleep(500 * time.Millisecond)
		pr.kend.SetLinger(0)
		pr.kend.Close()
		if err := e.waitEnded(pr, 5*time.Second); err != nil {
			return err
		}
		if off := e.win.offeredEnd(pr.flow); off < 0 || off >= holdNetstackSize {
			return fmt.Errorf("no tail: offered up to %d", off)
		}
		time.Sleep(2 * time.Second)
		if st := e.status(pr.key); st.Flows != 1 {
			t.Fatalf("flows %d while the tail is held, want 1", st.Flows)
		}
		n, err := holdReadAll(pr.peer, holdNetstackSize, time.Now().Add(10*time.Second), false)
		if err != nil {
			t.Fatalf("read %d: %v", n, err)
		}
		if _, err := holdWait(3*time.Second, func() bool { return e.pool.InUse() == 0 }); err != nil {
			t.Fatalf("slot not returned: %v", err)
		}
		return nil
	})
}

// N8 and N11: a relay netstack conn in FIN_WAIT_2 returns the slot only when its receive memory
// is 0. The non-zero receive memory is a substitute for out-of-order data: the boost pool's
// receive-memory hook reports it. Two exits are covered in the agent's role: the target resets
// without data (the relay closes the conn after the relay ends) and the dial to the target fails
// (the relay closes the accepted conn without relaying).
func TestRelayHoldFinWait2(t *testing.T) {
	for _, exit := range []string{"target reset", "dial failed"} {
		for _, mem := range []string{"memory 0", "memory forced"} {
			t.Run(exit+"/"+mem, func(t *testing.T) {
				established(t, func(t *testing.T) error {
					e := newHoldEnv(t, true, 8, "r1")
					var forced atomic.Bool
					if mem == "memory forced" {
						forced.Store(true)
						e.relayDev.pool.recvMemHook = func(ep tcpip.Endpoint) (int, bool) {
							if forced.Load() {
								return 1, true
							}
							return 0, true
						}
					}
					var relayNS *tcpConn
					var key relay.Key
					if exit == "dial failed" {
						e.tgtLn.Close()
						key = e.key("r1")
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()
						peer, err := e.peerDev.DialTCP(ctx, netip.AddrPortFrom(e.relayDev.local, key.Port))
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { peer.Close() })
						select {
						case c := <-e.nsAcc:
							relayNS = connOf(c)
						case <-time.After(5 * time.Second):
							t.Fatal("not accepted")
						}
					} else {
						pr := e.open("r1")
						if pr == nil {
							t.Fatal("refused")
						}
						relayNS, key = pr.relayNS, pr.key
						pr.kend.SetLinger(0)
						pr.kend.Close()
					}
					if _, err := holdWait(5*time.Second, func() bool {
						return tcp.EndpointState(relayNS.ep.State()) == tcp.StateFinWait2
					}); err != nil {
						return fmt.Errorf("FIN_WAIT_2 not entered: %v", tcp.EndpointState(relayNS.ep.State()))
					}
					entered := time.Now()
					if mem == "memory 0" {
						if _, err := holdWait(3*time.Second, func() bool { return e.pool.InUse() == 0 }); err != nil {
							t.Fatalf("the slot was not returned in FIN_WAIT_2 with receive memory 0: %v", err)
						}
						t.Logf("returned %v after FIN_WAIT_2", time.Since(entered).Round(time.Millisecond))
						return nil
					}
					time.Sleep(3 * time.Second)
					if e.pool.InUse() != 1 || e.status(key).Flows != 1 {
						t.Fatalf("the slot was returned in FIN_WAIT_2 with non-zero receive memory: in use %d", e.pool.InUse())
					}
					forced.Store(false)
					if _, err := holdWait(3*time.Second, func() bool { return e.pool.InUse() == 0 }); err != nil {
						t.Fatalf("the slot was not returned once the receive memory was 0: %v", err)
					}
					return nil
				})
			})
		}
	}
}

// N3: with the pool full of r1's tails, r1 is refused and r2, which has its minimum, still
// relays a small transfer in normal time.
func TestRelayHoldCapRefusesOnlyTheFullRule(t *testing.T) {
	established(t, func(t *testing.T) error {
		e := newHoldEnv(t, false, 8, "r1", "r2")
		base := smallTransfer(t, e, "r2")
		held := 0
		refused := false
		for i := 0; i < 8 && !refused; i++ {
			pr := e.open("r1")
			if pr == nil {
				refused = true
				break
			}
			if err := e.leaveTail(pr, netstackTail, holdNetstackSize); err != nil {
				return err
			}
			held++
		}
		if !refused || held == 0 {
			return fmt.Errorf("r1 held %d tails and was refused: %v", held, refused)
		}
		if !e.logs.has("refusing new connections") {
			t.Fatal("the refusal was not logged")
		}
		got := smallTransfer(t, e, "r2")
		t.Logf("r1 held %d tails; r2's transfer %v, without holds %v", held, got, base)
		if got > 2*base+20*time.Millisecond {
			t.Fatalf("r2's transfer took %v, more than twice %v", got, base)
		}
		return nil
	})
}

// smallTransfer sends 64 KiB from the kernel end to the peer and back on a new pair of rule and
// returns how long the round trip took.
func smallTransfer(t *testing.T, e *holdEnv, rule string) time.Duration {
	t.Helper()
	pr := e.open(rule)
	if pr == nil {
		t.Fatalf("%s was refused", rule)
	}
	data := holdData(64 << 10)
	start := time.Now()
	go pr.kend.Write(data)
	buf := make([]byte, len(data))
	pr.peer.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(pr.peer, buf); err != nil {
		t.Fatal(err)
	}
	go pr.peer.Write(buf)
	back := make([]byte, len(data))
	pr.kend.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(pr.kend, back); err != nil {
		t.Fatal(err)
	}
	d := time.Since(start)
	pr.kend.Close()
	pr.peer.Close()
	return d
}

// heldNetstack counts the relay Device's closed TCP endpoints that are not finished: those that
// still hold a tail or their FIN.
func heldNetstack(dev *Device) int {
	n := 0
	for _, ep := range tcpip.GetDanglingEndpoints() {
		addr, err := ep.GetLocalAddress()
		if err != nil || addr.Addr != tcpip.AddrFromSlice(dev.local.AsSlice()) {
			continue
		}
		switch tcp.EndpointState(ep.State()) {
		case tcp.StateTimeWait, tcp.StateClose, tcp.StateError:
		default:
			n++
		}
	}
	return n
}

// kernelOrphans counts loopback TCP sockets with local or remote port port that no process owns
// (inode 0) in FIN_WAIT1, CLOSING or LAST_ACK.
func kernelOrphans(t *testing.T, port uint16) int {
	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan()
	n := 0
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 10 {
			continue
		}
		lp, _ := strconv.ParseUint(fs[1][strings.Index(fs[1], ":")+1:], 16, 16)
		if uint16(lp) != port {
			continue
		}
		switch fs[3] {
		case "04", "0B", "09":
		default:
			continue
		}
		if fs[9] == "0" {
			n++
		}
	}
	return n
}

// N4: repeating the "leave a tail" operation 3K times never leaves more than K pairs holding a
// tail, on either side, and all are released when the readers read.
func TestRelayHoldCountIsBounded(t *testing.T) {
	const k = 4
	for _, side := range []tailSide{netstackTail, kernelTail} {
		t.Run(side.String(), func(t *testing.T) {
			established(t, func(t *testing.T) error {
				e := newHoldEnv(t, false, k, "r1")
				port := e.ports["r1"]
				var readers []net.Conn
				var held []*holdPair
				refusals := 0
				size := holdNetstackSize
				if side == kernelTail {
					size = holdKernelSize
				}
				for i := 0; i < 3*k; i++ {
					pr := e.open("r1")
					if pr == nil {
						refusals++
					} else {
						if err := e.leaveTail(pr, side, size); err != nil {
							return err
						}
						if side == netstackTail {
							readers = append(readers, pr.peer)
						} else {
							readers = append(readers, pr.kend)
						}
						held = append(held, pr)
					}
					held := heldNetstack(e.relayDev) + kernelOrphans(t, port)
					if held > k || e.pool.InUse() > k {
						t.Fatalf("after %d attempts: %d tails held outside the process or by closed endpoints, %d in use; want at most %d", i+1, held, e.pool.InUse(), k)
					}
				}
				if len(readers) != k || refusals == 0 {
					return fmt.Errorf("held %d of %d with %d refusals", len(readers), k, refusals)
				}
				// After a long zero window the sender probes at backed-off intervals of up to 120 s; if
				// a busy host drops the reader's window update, the data resumes only at the next
				// probe, so the readers get more than that
				for i, r := range readers {
					if n, err := holdReadAll(r, size, time.Now().Add(150*time.Second), false); err != nil {
						pr := held[i]
						t.Fatalf("reader %d read %d: %v; the relay's kernel socket: state %d, queued %d; its netstack conn: %v",
							i, n, err, kernelState(pr.relayK), outq(pr.relayK), tcp.EndpointState(pr.relayNS.ep.State()))
					}
				}
				if _, err := holdWait(3*time.Second, func() bool { return e.pool.InUse() == 0 }); err != nil {
					t.Fatalf("not all released: in use %d", e.pool.InUse())
				}
				return nil
			})
		})
	}
}

// N9: many pairs waiting for their tails do not hold locks that stop unrelated work, and closing
// the manager ends every wait.
func TestRelayHoldDoesNotStallTheProcess(t *testing.T) {
	established(t, func(t *testing.T) error {
		e := newHoldEnv(t, false, 40, "r1", "r2")
		base := smallTransfer(t, e, "r2")
		held := 0
		for i := 0; i < 16; i++ {
			pr := e.open("r1")
			if pr == nil {
				break
			}
			if err := e.leaveTail(pr, netstackTail, holdNetstackSize); err != nil {
				return err
			}
			held++
		}
		if held != 16 {
			return fmt.Errorf("held %d of 16", held)
		}
		want := map[relay.Key]relay.Desired{}
		for _, r := range []string{"r1", "r2"} {
			want[e.key(r)] = relay.Desired{Target: netip.AddrPortFrom(e.p.b.local, 9000).String(), RuleID: r}
		}
		extra := relay.Key{Proto: proto.TCP, Port: 7999}
		// the reachability probes of the listener that Apply opens are not relayed pairs
		e.armed.Store(false)
		for i := 0; i < 20; i++ {
			start := time.Now()
			e.m.Status()
			if d := time.Since(start); d > 100*time.Millisecond {
				t.Fatalf("Status took %v", d)
			}
			w := map[relay.Key]relay.Desired{}
			for k, v := range want {
				w[k] = v
			}
			if i%2 == 0 {
				w[extra] = relay.Desired{Target: netip.AddrPortFrom(e.p.b.local, 9000).String(), RuleID: "r3"}
			}
			start = time.Now()
			e.m.Apply(w)
			if d := time.Since(start); d > 100*time.Millisecond {
				t.Fatalf("Apply took %v", d)
			}
		}
		time.Sleep(200 * time.Millisecond)
		for _, ch := range []chan net.Conn{e.nsAcc, e.peerC, e.kAcc} {
			for len(ch) > 0 {
				(<-ch).Close()
			}
		}
		e.armed.Store(true)
		if got := smallTransfer(t, e, "r2"); got > 2*base+20*time.Millisecond {
			t.Fatalf("r2's transfer took %v, more than twice %v", got, base)
		}
		// r2's pair of the transfer above returns its slot once both ends have closed it
		if _, err := holdWait(time.Second, func() bool { return e.pool.InUse() == 16 }); err != nil {
			t.Fatalf("in use %d before closing, want 16", e.pool.InUse())
		}
		e.m.Close()
		if _, err := holdWait(500*time.Millisecond, func() bool { return e.pool.InUse() == 0 }); err != nil {
			t.Fatalf("the waits did not end within 500 ms of Close: in use %d", e.pool.InUse())
		}
		return nil
	})
}

// Not pre-registered, added with the change: a Retiring listener (design.md 7a.3 節) stays until
// the pair whose tail it is delivering has delivered it, and its next re-check closes it then.
func TestRelayHoldRetiringWaitsForTheTail(t *testing.T) {
	established(t, func(t *testing.T) error {
		e := newHoldEnv(t, false, 8, "r1")
		pr := e.open("r1")
		if pr == nil {
			t.Fatal("refused")
		}
		if err := e.leaveTail(pr, netstackTail, holdNetstackSize); err != nil {
			return err
		}
		keep := map[string]func(netip.Addr) bool{"r1": func(netip.Addr) bool { return true }}
		// the rule leaves the declaration but is retiring: the listener stops accepting and stays
		e.m.Prepare(map[relay.Key]relay.Desired{}).Commit(keep)
		e.m.Prepare(map[relay.Key]relay.Desired{}).Commit(keep)
		if got := e.m.Retiring(); len(got) != 1 {
			t.Fatalf("Retiring = %v while the tail is held, want the listener", got)
		}
		if n, err := holdReadAll(pr.peer, holdNetstackSize, time.Now().Add(10*time.Second), false); err != nil {
			t.Fatalf("read %d: %v", n, err)
		}
		if _, err := holdWait(3*time.Second, func() bool { return e.pool.InUse() == 0 }); err != nil {
			t.Fatalf("slot not returned: %v", err)
		}
		e.m.Prepare(map[relay.Key]relay.Desired{}).Commit(keep)
		if got := e.m.Retiring(); len(got) != 0 {
			t.Fatalf("Retiring = %v after the tail was delivered, want none", got)
		}
		return nil
	})
}

// N12: with a per-source limit, one source that leaves its whole quota of tails being delivered is
// refused further connections until its peers read them; then K and the per-source count return to
// 0, each released once.
func TestRelayHoldKeepsThePerSourceLimit(t *testing.T) {
	const limit = 3
	for _, side := range []tailSide{netstackTail, kernelTail} {
		t.Run(side.String(), func(t *testing.T) {
			established(t, func(t *testing.T) error {
				e := newHoldEnv(t, false, 16, "r1")
				e.srcLimit.Store(limit)
				size := holdNetstackSize
				if side == kernelTail {
					size = holdKernelSize
				}
				var readers []net.Conn
				for i := 0; i < limit; i++ {
					pr := e.open("r1")
					if pr == nil {
						return fmt.Errorf("connection %d of the quota was refused", i+1)
					}
					if err := e.leaveTail(pr, side, size); err != nil {
						return err
					}
					if side == netstackTail {
						readers = append(readers, pr.peer)
					} else {
						readers = append(readers, pr.kend)
					}
				}
				time.Sleep(200 * time.Millisecond)
				if e.srcInUse.Load() != limit || e.pool.InUse() != limit {
					t.Fatalf("with %d tails held: per-source %d, K %d; want %d each", limit, e.srcInUse.Load(), e.pool.InUse(), limit)
				}
				for i := 0; i < 2; i++ {
					if pr := e.open("r1"); pr != nil {
						t.Fatalf("a connection beyond the per-source limit was relayed while %d tails were held", limit)
					}
				}
				if e.pool.InUse() != limit {
					t.Fatalf("K %d after the refused connections, want %d", e.pool.InUse(), limit)
				}
				for _, r := range readers {
					if n, err := holdReadAll(r, size, time.Now().Add(150*time.Second), false); err != nil {
						t.Fatalf("read %d: %v", n, err)
					}
				}
				if _, err := holdWait(3*time.Second, func() bool { return e.pool.InUse() == 0 && e.srcInUse.Load() == 0 }); err != nil {
					t.Fatalf("not returned: K %d, per-source %d", e.pool.InUse(), e.srcInUse.Load())
				}
				time.Sleep(100 * time.Millisecond)
				if e.releases.Load() != limit || e.doubles.Load() != 0 || e.pool.Ledger().DoubleReleases != 0 {
					t.Fatalf("per-source releases %d (doubles %d), pool double releases %d; want %d, 0, 0",
						e.releases.Load(), e.doubles.Load(), e.pool.Ledger().DoubleReleases, limit)
				}
				return nil
			})
		})
	}
}
