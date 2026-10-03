//go:build linux

package proxyrelay

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rahanahu/wgft/internal/resource"
)

// The tests in this file pin how the Relay rule relay accounts for a connection after it has
// ended while the public socket still holds data for a client that does not read (design.md 7 節
// 「中継が終わった後の末尾の配送」). In userspace mode (HoldUntilDelivered) the pair keeps its
// pool slot and its per-source slot until the data is delivered and returns them together, and
// the paths that cut relays cut such a pair at once. In kernel mode the relay returns both slots
// when it ends, as before.

type holdRig struct {
	m        *Manager
	pool     *resource.Pool
	releases atomic.Int32
	client   *net.TCPConn
	agent    *net.TCPConn
	public   chan *net.TCPConn // the relay's accepted public sockets
	port     uint16
}

type captureLn struct {
	net.Listener
	got chan *net.TCPConn
}

func (l captureLn) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if tc, ok := c.(*net.TCPConn); ok && err == nil {
		select {
		case l.got <- tc:
		default:
		}
	}
	return c, err
}

const holdSize = 256 << 10

func newHoldRig(t *testing.T, userspace bool) *holdRig {
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
	r := &holdRig{pool: resource.NewPool(8), public: make(chan *net.TCPConn, 4), port: uint16(pubLn.Addr().(*net.TCPAddr).Port)}
	r.m = New(Options{
		Listen: func(uint16) (net.Listener, error) { return captureLn{pubLn, r.public}, nil },
		Dial: func(string) (net.Conn, error) {
			c, err := net.Dial("tcp4", agentLn.Addr().String())
			if err != nil || !userspace {
				return c, err
			}
			return &netstackUp{Conn: c, tc: c.(*net.TCPConn)}, nil
		},
		HoldUntilDelivered: userspace,
		Logf:               testLogf(t),
		Pool:               r.pool,
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
	return r
}

// leaveTail ends the relay while the public socket holds data the client does not read. It
// returns the relay's public socket.
func (r *holdRig) leaveTail(t *testing.T) (*net.TCPConn, error) {
	var pub *net.TCPConn
	select {
	case pub = <-r.public:
	case <-time.After(5 * time.Second):
		t.Fatal("no public socket captured")
	}
	r.client.SetReadBuffer(16 << 10)
	r.client.CloseWrite()
	go func() {
		data := make([]byte, holdSize)
		for i := range data {
			data[i] = byte(i % 251)
		}
		r.agent.SetWriteDeadline(time.Now().Add(10 * time.Second))
		r.agent.Write(data)
		r.agent.CloseWrite()
	}()
	// the relay has ended once the pair is delivering its tail (userspace mode) or has returned
	// its slots (kernel mode)
	deadline := time.Now().Add(5 * time.Second)
	for r.releases.Load() == 0 && r.delivering() == 0 {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("the relay did not end within 5 s")
		}
		time.Sleep(2 * time.Millisecond)
	}
	return pub, nil
}

// delivering is how many pairs of the manager's listeners are delivering their tail.
func (r *holdRig) delivering() int {
	r.m.mu.Lock()
	defer r.m.mu.Unlock()
	n := 0
	for _, l := range r.m.ls {
		l.mu.Lock()
		n += len(l.delivering)
		l.mu.Unlock()
	}
	return n
}

func holdOutq(c *net.TCPConn) int {
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

func holdWaitFor(d time.Duration, cond func() bool) error {
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			return fmt.Errorf("not within %v", d)
		}
		time.Sleep(2 * time.Millisecond)
	}
	return nil
}

// holdEstablished runs a scene up to three times and fails as undetermined if it is never
// established.
func holdEstablished(t *testing.T, scene func(t *testing.T) error) {
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

// N1 and N1i' in userspace mode: the pool slot and the per-source slot are held while the client
// does not read; the client then gets every byte and EOF, and both slots are returned, once.
func TestHoldCountsTheTail(t *testing.T) {
	holdEstablished(t, func(t *testing.T) error {
		r := newHoldRig(t, true)
		pub, err := r.leaveTail(t)
		if err != nil {
			return err
		}
		if q := holdOutq(pub); q <= 0 {
			return fmt.Errorf("no tail in the public socket when the relay ended: %d", q)
		}
		until := time.Now().Add(5 * time.Second)
		for time.Now().Before(until) {
			// the per-source slot is held for as long as the pool slot (owner's decision of
			// 2026-10-04, which replaced returning it when the relay ends)
			if r.pool.InUse() != 1 || r.releases.Load() != 0 {
				t.Fatalf("while the tail is held: %d in use, %d per-source releases; want 1 and 0", r.pool.InUse(), r.releases.Load())
			}
			time.Sleep(50 * time.Millisecond)
		}
		r.client.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := io.Copy(io.Discard, r.client)
		if err != nil || n != holdSize {
			t.Fatalf("the client read %d of %d: %v", n, holdSize, err)
		}
		if err := holdWaitFor(3*time.Second, func() bool { return r.pool.InUse() == 0 && r.releases.Load() == 1 }); err != nil {
			t.Fatalf("the slots were not returned: %d in use, %d per-source releases", r.pool.InUse(), r.releases.Load())
		}
		time.Sleep(100 * time.Millisecond)
		if r.releases.Load() != 1 || r.pool.Ledger().DoubleReleases != 0 {
			t.Fatalf("per-source releases %d, pool double releases %d; want 1 and 0", r.releases.Load(), r.pool.Ledger().DoubleReleases)
		}
		return nil
	})
}

// N2 and N5 in userspace mode: the paths that cut relays, and a reset from the client, free a pair
// whose tail is being delivered.
func TestHoldCutsAndResetFreeThePair(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit time.Duration
		cut   func(r *holdRig)
	}{
		{"rule removed", 500 * time.Millisecond, func(r *holdRig) { r.m.Apply(nil) }},
		{"manager closed", 500 * time.Millisecond, func(r *holdRig) { r.m.Close() }},
		{"source restriction", 500 * time.Millisecond, func(r *holdRig) {
			r.m.Apply([]Rule{agentRule("r", endingPort, "home", "10.200.0.2", []string{"127.0.0.1/32"})})
		}},
		{"retargeted", 500 * time.Millisecond, func(r *holdRig) {
			r.m.Apply([]Rule{agentRule("r", endingPort, "home", "10.200.0.3", nil)})
		}},
		{"client reset", 3 * time.Second, func(r *holdRig) {
			r.client.SetLinger(0)
			r.client.Close()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			holdEstablished(t, func(t *testing.T) error {
				r := newHoldRig(t, true)
				pub, err := r.leaveTail(t)
				if err != nil {
					return err
				}
				if q := holdOutq(pub); q <= 0 {
					return fmt.Errorf("no tail: %d", q)
				}
				// long enough that the wait checks again only every 2 s, so a cut that does not wake
				// it would miss the 500 ms limit
				time.Sleep(4 * time.Second)
				if r.pool.InUse() != 1 {
					return fmt.Errorf("hold not in place: %d in use", r.pool.InUse())
				}
				start := time.Now()
				tc.cut(r)
				if err := holdWaitFor(tc.limit, func() bool { return r.pool.InUse() == 0 }); err != nil {
					t.Fatalf("the pool slot was not returned within %v of the cut", tc.limit)
				}
				t.Logf("returned %v after the cut", time.Since(start).Round(time.Millisecond))
				return nil
			})
		})
	}
}

// publicOrphanWithData reports whether a loopback socket with local port port, owned by no
// process, still has data in its send queue.
func publicOrphanWithData(t *testing.T, port uint16) bool {
	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan()
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 10 {
			continue
		}
		lp, _ := strconv.ParseUint(fs[1][strings.Index(fs[1], ":")+1:], 16, 16)
		if uint16(lp) != port || fs[9] != "0" {
			continue
		}
		tx, _ := strconv.ParseUint(fs[4][:strings.Index(fs[4], ":")], 16, 32)
		if tx > 0 {
			return true
		}
	}
	return false
}

// R5: in kernel mode the relay returns both slots when it ends, although the public socket still
// holds data the client has not read, as before this change.
func TestKernelModeReturnsSlotsAtTheEnd(t *testing.T) {
	holdEstablished(t, func(t *testing.T) error {
		r := newHoldRig(t, false)
		if _, err := r.leaveTail(t); err != nil {
			return err
		}
		ended := time.Now()
		if err := holdWaitFor(time.Second, func() bool { return r.pool.InUse() == 0 }); err != nil {
			t.Fatalf("kernel mode did not return the pool slot within 1 s of the relay's end: %d in use", r.pool.InUse())
		}
		t.Logf("returned %v after the end", time.Since(ended).Round(time.Millisecond))
		if !publicOrphanWithData(t, r.port) {
			return fmt.Errorf("no orphaned public socket with data: the scene had no tail")
		}
		return nil
	})
}

// A Retiring relay (design.md 7a.3 節) keeps a pair whose tail is being delivered while its
// declaration keeps the source, and closes only once the tail is delivered; a re-check that refuses
// the source cuts the pair at once.
func TestHoldRetiringWaitsForTheTail(t *testing.T) {
	for _, keepSource := range []bool{true, false} {
		name := "source kept"
		if !keepSource {
			name = "source refused"
		}
		t.Run(name, func(t *testing.T) {
			holdEstablished(t, func(t *testing.T) error {
				r := newHoldRig(t, true)
				pub, err := r.leaveTail(t)
				if err != nil {
					return err
				}
				if q := holdOutq(pub); q <= 0 {
					return fmt.Errorf("no tail: %d", q)
				}
				keepAll := map[string]func(netip.Addr) bool{"r": func(netip.Addr) bool { return true }}
				// the rule leaves the declaration but is retiring: the relay stops accepting and stays
				r.m.Prepare(nil).Commit(keepAll)
				if got := r.m.RetiringPorts(); len(got) != 1 {
					t.Fatalf("RetiringPorts = %v after retiring, want the relay", got)
				}
				if !keepSource {
					refuse := map[string]func(netip.Addr) bool{"r": func(netip.Addr) bool { return false }}
					r.m.Prepare(nil).Commit(refuse)
					if err := holdWaitFor(500*time.Millisecond, func() bool { return r.pool.InUse() == 0 }); err != nil {
						t.Fatalf("the re-check that refuses the source did not cut the delivering pair: %d in use", r.pool.InUse())
					}
					if got := r.m.RetiringPorts(); len(got) != 0 {
						t.Fatalf("RetiringPorts = %v after the pair was cut, want none", got)
					}
					return nil
				}
				// a re-check while the tail is held keeps the relay
				r.m.Prepare(nil).Commit(keepAll)
				if got := r.m.RetiringPorts(); len(got) != 1 || r.pool.InUse() != 1 {
					t.Fatalf("while the tail is held: RetiringPorts = %v, %d in use; want the relay and 1", got, r.pool.InUse())
				}
				r.client.SetReadDeadline(time.Now().Add(10 * time.Second))
				if n, err := io.Copy(io.Discard, r.client); err != nil || n != holdSize {
					t.Fatalf("the client read %d of %d: %v", n, holdSize, err)
				}
				if err := holdWaitFor(3*time.Second, func() bool { return r.pool.InUse() == 0 }); err != nil {
					t.Fatalf("slots not returned: %d in use", r.pool.InUse())
				}
				r.m.Prepare(nil).Commit(keepAll)
				if got := r.m.RetiringPorts(); len(got) != 0 {
					t.Fatalf("RetiringPorts = %v after the tail was delivered, want none", got)
				}
				return nil
			})
		})
	}
}
