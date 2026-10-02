package nettun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/dataplane/userspace/relay"
	"github.com/rahanahu/wgft/proto"
)

// The tests in this file pin two conditions on how the userspace relay ends a TCP connection
// whose last data is still on its way to a peer that reads slowly. They are regression
// conditions: they pass on the current code, and any change to how the relay closes, holds or
// ends such a connection must keep them passing.
//
//   - A peer that keeps reading receives every byte the relay accepted, and then EOF, also when
//     the relay finished writing and closed its netstack connection before the peer had read it.
//   - A short outage toward that peer, far shorter than gVisor's retransmission give-up, does not
//     lose data: the transfer recovers and completes, whether the outage falls before or after
//     the relay ends.
//
// They drive the real relay (relay.Manager and netpipe) in both of its roles, so the relay's
// netstack connection is on either side of netpipe.Pipe. They live in this package so the test
// chooses the boost pool of the relay's Device: with no slot the relay's connection stays at the
// floor, so its unsent data is no longer counted once the relay has returned the flow; with one
// slot it is a boost holder.

const (
	// relayEndSize is what the source sends through the relay. At the floor the relay's send
	// queue and the peer's receive queue hold a few hundred KiB together, so the relay finishes
	// writing, and closes, while a third or more of this is still on its way to the peer.
	relayEndSize = 768 << 10
	// relayEndChunk and relayEndPause make the peer read about 320 KiB/s, so the whole
	// transfer takes about 2.4 s.
	relayEndChunk = 8 << 10
	relayEndPause = 25 * time.Millisecond
	// relayEndOutage is how long packets from the relay's Device are dropped. gVisor gives up
	// only after many backed-off retransmissions, minutes at the earliest.
	relayEndOutage = 1500 * time.Millisecond
	// relayEndBudget bounds the whole transfer, outage included, from the source's first write.
	relayEndBudget = 8 * time.Second
)

// relayEndByte is the byte at offset i of what the source sends, so the peer checks the order
// and content as well as the count.
func relayEndByte(i int) byte { return byte(i % 251) }

func relayEndData() []byte {
	b := make([]byte, relayEndSize)
	for i := range b {
		b[i] = relayEndByte(i)
	}
	return b
}

// relayEndNet opens the relay's listeners on a Device and passes each accepted connection on.
type relayEndNet struct {
	dev *Device
	acc chan net.Conn
}

func (n relayEndNet) ListenTCP(port uint16) (net.Listener, error) {
	ln, err := n.dev.ListenTCP(netip.AddrPortFrom(n.dev.local, port))
	if err != nil {
		return nil, err
	}
	return relayEndListener{ln, n.acc}, nil
}

func (n relayEndNet) ListenUDP(port uint16) (net.PacketConn, error) {
	return n.dev.ListenUDP(netip.AddrPortFrom(n.dev.local, port))
}

type relayEndListener struct {
	net.Listener
	acc chan net.Conn
}

func (l relayEndListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		select {
		case l.acc <- c:
		default:
		}
	}
	return c, err
}

// relayEndLoopback opens the relay's listeners on the kernel's loopback, as vpsd's public side.
type relayEndLoopback struct{}

func (relayEndLoopback) ListenTCP(port uint16) (net.Listener, error) {
	return net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
}

func (relayEndLoopback) ListenUDP(port uint16) (net.PacketConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
}

// relayEndRig is one relayed connection. Data flows from source, through the relay and its
// netstack connection relayConn, to peer over the netstack. drop drops every packet the
// relay's Device sends while it is true.
type relayEndRig struct {
	relayConn *tcpConn
	peer      net.Conn
	source    net.Conn
	drop      *atomic.Bool
}

func relayEndLogf(t *testing.T) func(string, ...any) {
	var mu sync.Mutex
	ended := false
	t.Cleanup(func() {
		mu.Lock()
		ended = true
		mu.Unlock()
	})
	return func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		if !ended {
			t.Logf(format, args...)
		}
	}
}

// newRelayEndPair joins two Devices and drops the packets that the Device with the given last
// address byte sends while drop is true. a (host 1) and b (host 2) both start without boost slots.
func newRelayEndPair(t *testing.T, dropFrom byte) (*tcpPair, *atomic.Bool) {
	drop := new(atomic.Bool)
	p := newTCPPairOpts(t, 0, nil, func(pkt []byte) bool {
		return drop.Load() && len(pkt) >= 20 && pkt[15] == dropFrom
	})
	return p, drop
}

// newAgentRelayEnd is the agent's role: the relay listens on the netstack (b) and dials a kernel
// target on the loopback. The peer is the server's end on a; the source is the target.
func newAgentRelayEnd(t *testing.T, slots int) *relayEndRig {
	t.Helper()
	p, drop := newRelayEndPair(t, 2)
	p.b.pool = newBoostPool(slots)
	tln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tln.Close() })
	tacc := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := tln.Accept()
			if err != nil {
				return
			}
			tacc <- c
		}
	}()
	var armed atomic.Bool
	dialed := make(chan net.Conn, 1)
	acc := make(chan net.Conn, 1)
	m := relay.New(relayEndNet{p.b, acc}, relay.Options{
		Logf: relayEndLogf(t),
		Dial: func(network, addr string) (net.Conn, error) {
			c, err := net.DialTimeout(network, addr, 5*time.Second)
			// the reachability probe when the listener opens is not armed
			if err == nil && armed.CompareAndSwap(true, false) {
				dialed <- c
			}
			return c, err
		},
	})
	t.Cleanup(m.Close)
	k := relay.Key{Proto: proto.TCP, Port: 7400}
	m.Apply(map[relay.Key]relay.Desired{k: {Target: tln.Addr().String(), RuleID: "r1"}})
	armed.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	peer, err := p.a.DialTCP(ctx, netip.AddrPortFrom(p.b.local, k.Port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	r := &relayEndRig{peer: peer, drop: drop}
	select {
	case c := <-acc:
		r.relayConn = connOf(c)
	case <-time.After(5 * time.Second):
		t.Fatal("the relay did not accept the peer's connection")
	}
	var up net.Conn
	select {
	case up = <-dialed:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay did not dial the target")
	}
	r.source = matchAccepted(t, tacc, up.LocalAddr().String())
	return r
}

// newServerRelayEnd is the server's role: the relay listens on the kernel's loopback and dials
// the agent over the netstack (a). The source is the public client; the peer is the agent's end
// on b.
func newServerRelayEnd(t *testing.T, slots int) *relayEndRig {
	t.Helper()
	p, drop := newRelayEndPair(t, 1)
	p.a.pool = newBoostPool(slots)
	aacc := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := p.ln.Accept()
			if err != nil {
				return
			}
			aacc <- c
		}
	}()
	var armed atomic.Bool
	dialed := make(chan net.Conn, 1)
	m := relay.New(relayEndLoopback{}, relay.Options{
		Logf: relayEndLogf(t),
		Dial: func(network, addr string) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := p.a.DialTCP(ctx, netip.MustParseAddrPort(addr))
			if err == nil && armed.CompareAndSwap(true, false) {
				dialed <- c
			}
			return c, err
		},
	})
	t.Cleanup(m.Close)
	// a free port on the loopback for the relay's listener
	l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	k := relay.Key{Proto: proto.TCP, Port: port}
	m.Apply(map[relay.Key]relay.Desired{k: {Target: netip.AddrPortFrom(p.b.local, 9000).String(), RuleID: "r1"}})
	armed.Store(true)
	src, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { src.Close() })
	r := &relayEndRig{source: src, drop: drop}
	var d net.Conn
	select {
	case d = <-dialed:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay did not dial the agent")
	}
	r.relayConn = connOf(d)
	r.peer = matchAccepted(t, aacc, d.LocalAddr().String())
	return r
}

// matchAccepted returns the connection from acc whose remote address is remote, closing the
// others (the reachability probe's).
func matchAccepted(t *testing.T, acc chan net.Conn, remote string) net.Conn {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case c := <-acc:
			if c.RemoteAddr().String() == remote {
				t.Cleanup(func() { c.Close() })
				return c
			}
			c.Close()
		case <-deadline:
			t.Fatalf("no accepted connection from %s", remote)
			return nil
		}
	}
}

// relayEndRead is what the peer read and how its reading ended.
type relayEndRead struct {
	n   int
	err error // nil means EOF after exactly relayEndSize bytes
}

// readSlowly reads the peer until EOF or the deadline, relayEndChunk at a time with a pause
// after each read, checking every byte. read is updated as bytes arrive.
func readSlowly(c net.Conn, deadline time.Time, read *atomic.Int64) relayEndRead {
	c.SetReadDeadline(deadline)
	buf := make([]byte, relayEndChunk)
	n := 0
	for {
		m, err := c.Read(buf)
		for i := 0; i < m; i++ {
			if buf[i] != relayEndByte(n+i) {
				return relayEndRead{n + i, fmt.Errorf("byte %d is %d, want %d", n+i, buf[i], relayEndByte(n+i))}
			}
		}
		n += m
		read.Store(int64(n))
		if errors.Is(err, io.EOF) {
			if n != relayEndSize {
				return relayEndRead{n, fmt.Errorf("EOF after %d of %d bytes", n, relayEndSize)}
			}
			return relayEndRead{n, nil}
		}
		if err != nil {
			return relayEndRead{n, err}
		}
		if n > relayEndSize {
			return relayEndRead{n, fmt.Errorf("read %d bytes, more than the %d sent", n, relayEndSize)}
		}
		time.Sleep(relayEndPause)
	}
}

// outageAt says when packets from the relay's Device are dropped for relayEndOutage.
type outageAt int

const (
	noOutage outageAt = iota
	// outageBeforeEnd starts once the peer has read 64 KiB, while the relay still has data to
	// write.
	outageBeforeEnd
	// outageAfterEnd starts as soon as the relay has finished writing.
	outageAfterEnd
)

// relayFinished is whether the relay has finished writing to its netstack connection: it has
// half-closed it after the source's EOF, or closed or aborted it. Today the relay closes the
// connection right after the half-close, because the other direction has already ended.
func relayFinished(c *tcpConn) bool {
	c.cmu.Lock()
	defer c.cmu.Unlock()
	return c.sndShut || c.closing
}

// runRelayEnd sends relayEndSize bytes from the source through the relay to the peer, which
// reads slowly, and checks that the peer receives all of it and then EOF. It also checks the
// scene: the relay finished writing while the peer still had data to receive, and an outage fell
// where the scene says.
func runRelayEnd(t *testing.T, r *relayEndRig, outage outageAt) {
	t.Helper()
	// The direction from the peer toward the source carries nothing: the peer half-closes it
	// first, so the relay ends the connection once it has written everything the source sent.
	if err := r.peer.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	deadline := start.Add(relayEndBudget)
	r.source.SetWriteDeadline(deadline)
	go func() {
		r.source.Write(relayEndData())
		r.source.(interface{ CloseWrite() error }).CloseWrite()
	}()

	var read atomic.Int64
	got := make(chan relayEndRead, 1)
	go func() { got <- readSlowly(r.peer, deadline, &read) }()

	// readAtEnd is how much the peer had read when the relay finished writing, or -1 if it had
	// not by the deadline. The goroutine also runs the outage.
	var (
		readAtEnd         = int64(-1)
		outageFrom        time.Time
		outageTo          time.Time
		endedBeforeOutage bool
	)
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		dropFor := func() {
			endedBeforeOutage = relayFinished(r.relayConn)
			outageFrom = time.Now()
			r.drop.Store(true)
			time.Sleep(relayEndOutage)
			r.drop.Store(false)
			outageTo = time.Now()
		}
		for time.Now().Before(deadline) {
			if relayFinished(r.relayConn) {
				readAtEnd = read.Load()
				if outage == outageAfterEnd {
					dropFor()
				}
				return
			}
			if outage == outageBeforeEnd && outageFrom.IsZero() && read.Load() >= 64<<10 {
				dropFor()
				continue
			}
			time.Sleep(time.Millisecond)
		}
	}()

	res := <-got
	<-watched
	t.Logf("peer read %d bytes in %v, end: %v; the relay finished writing when the peer had read %d; outage %v; relay's side closed: %v",
		res.n, time.Since(start).Round(time.Millisecond), res.err, readAtEnd, outageTo.Sub(outageFrom).Round(time.Millisecond), r.relayConn.closed.Load())
	if res.err != nil {
		t.Fatalf("the peer did not receive all %d bytes and then EOF: read %d, then %v", relayEndSize, res.n, res.err)
	}
	if readAtEnd < 0 {
		t.Fatal("setup: the relay did not finish writing by the deadline")
	}
	if readAtEnd >= relayEndSize {
		t.Fatalf("setup: the relay finished writing only after the peer had read everything (%d bytes), so nothing was left to deliver after the relay's end", readAtEnd)
	}
	if outage != noOutage && outageTo.IsZero() {
		t.Fatal("setup: the outage did not happen")
	}
	if outage == outageBeforeEnd && endedBeforeOutage {
		t.Fatal("setup: the relay had already finished writing when the outage began")
	}
}

// A peer that keeps reading slowly receives every byte the relay accepted, and then EOF, also
// after the relay has finished writing and closed its netstack connection. The relay's
// connection is at the floor (no boost slot) or a boost holder, in the agent's role (the relay's
// netstack connection is the first argument of netpipe.Pipe) and the server's (the second).
func TestRelayEndDeliversToSlowReader(t *testing.T) {
	for _, role := range []struct {
		name string
		rig  func(*testing.T, int) *relayEndRig
	}{{"agent", newAgentRelayEnd}, {"server", newServerRelayEnd}} {
		for _, slots := range []int{0, 1} {
			name := role.name + "/floor"
			if slots > 0 {
				name = role.name + "/boost"
			}
			t.Run(name, func(t *testing.T) {
				r := role.rig(t, slots)
				runRelayEnd(t, r, noOutage)
			})
		}
	}
}

// A short outage toward the peer, before or after the relay ends, does not lose data: the
// transfer recovers and the peer, which keeps reading, receives every byte and then EOF. The
// relay's connection is at the floor, in both roles.
func TestRelayEndRecoversFromShortOutage(t *testing.T) {
	for _, role := range []struct {
		name string
		rig  func(*testing.T, int) *relayEndRig
	}{{"agent", newAgentRelayEnd}, {"server", newServerRelayEnd}} {
		for _, o := range []struct {
			name string
			at   outageAt
		}{{"before the end", outageBeforeEnd}, {"after the end", outageAfterEnd}} {
			t.Run(role.name+"/"+o.name, func(t *testing.T) {
				r := role.rig(t, 0)
				runRelayEnd(t, r, o.at)
			})
		}
	}
}
