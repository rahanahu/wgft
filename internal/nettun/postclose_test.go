package nettun

import (
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// These tests pin the post-close table: a Device keeps at most a fixed number of closed TCP
// endpoints, evicts the oldest with a reset when it is full, drops rows that reach CLOSED or
// ERROR, and keeps endpoints that a relay still holds for delivery out of it.

// newPostClosePair joins two Devices whose dialing side has a post-close table of size rows.
// A nonzero timeWait shortens the dialing side's TIME_WAIT.
func newPostClosePair(t *testing.T, size int, timeWait time.Duration) *tcpPair {
	t.Helper()
	p := newTCPPair(t, 16)
	p.a.postClose = newPostCloseTable(size)
	if timeWait > 0 {
		opt := tcpip.TCPTimeWaitTimeoutOption(timeWait)
		if err := p.a.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// closeFirst dials, closes the dialed side first and then the accepted side, so the dialed
// endpoint ends in TIME_WAIT. It returns the dialed endpoint.
func closeFirst(t *testing.T, p *tcpPair) tcpip.Endpoint {
	t.Helper()
	c, s := p.dial(t)
	ep := connOf(c).ep
	c.Close()
	s.Close()
	return ep
}

func stateOf(ep tcpip.Endpoint) tcp.EndpointState { return tcp.EndpointState(ep.State()) }

// The value is derived from the 128 MiB budget and 10 KiB a row, not tuned.
func TestPostCloseEntriesDerivation(t *testing.T) {
	if postCloseEntries != 13107 {
		t.Fatalf("postCloseEntries = %d, want 13107", postCloseEntries)
	}
}

// A full table resets its oldest rows in insertion order, never holds more than its size,
// counts the evictions and logs them at most once a minute.
func TestPostCloseEvictsOldestFirst(t *testing.T) {
	lines := captureLog(t)
	const size = 4
	p := newPostClosePair(t, size, 0)
	var eps []tcpip.Endpoint
	for i := 0; i < size+3; i++ {
		eps = append(eps, closeFirst(t, p))
		if n := p.a.postClose.len(); n > size {
			t.Fatalf("table holds %d rows, more than %d", n, size)
		}
	}
	for i, ep := range eps {
		if i < 3 {
			if st := stateOf(ep); st != tcp.StateError {
				t.Fatalf("evicted endpoint %d is %v, want ERROR after the reset", i, st)
			}
			continue
		}
		waitFor(t, 5*time.Second, "TIME_WAIT", func() bool { return stateOf(ep) == tcp.StateTimeWait })
	}
	if n := p.a.postClose.evicted.Load(); n != 3 {
		t.Fatalf("evicted = %d, want 3", n)
	}
	var evictLines int
	for _, l := range lines() {
		if strings.Contains(l, "reset closed TCP connections") {
			evictLines++
		}
	}
	if evictLines != 1 {
		t.Fatalf("logged the evictions %d times, want once: %q", evictLines, lines())
	}
}

// An eviction resets the peer and frees the port: the same 4-tuple connects again at once.
func TestPostCloseEvictionFreesThePort(t *testing.T) {
	p := newPostClosePair(t, 1, 0)
	c, s := p.dial(t)
	ep := connOf(c).ep
	local, _ := ep.GetLocalAddress()
	c.Close()
	s.Close()
	waitFor(t, 5*time.Second, "TIME_WAIT", func() bool { return stateOf(ep) == tcp.StateTimeWait })
	if err := bindLocal(p, local); err == nil {
		t.Fatal("a TIME_WAIT port could be bound again before the eviction")
	}
	closeFirst(t, p) // evicts ep
	if st := stateOf(ep); st != tcp.StateError {
		t.Fatalf("evicted endpoint is %v, want ERROR", st)
	}
	if err := bindLocal(p, local); err != nil {
		t.Fatalf("the evicted endpoint's port is still in use: %v", err)
	}
}

func bindLocal(p *tcpPair, local tcpip.FullAddress) tcpip.Error {
	ep, err := p.a.stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &waiter.Queue{})
	if err != nil {
		return err
	}
	defer ep.Close()
	return ep.Bind(tcpip.FullAddress{NIC: 1, Addr: local.Addr, Port: local.Port})
}

// Rows leave when their endpoint reaches CLOSED or ERROR, and the order of the rest is kept.
func TestPostCloseSweepKeepsOrder(t *testing.T) {
	p := newPostClosePair(t, 4, 0)
	var eps []tcpip.Endpoint
	for i := 0; i < 4; i++ {
		eps = append(eps, closeFirst(t, p))
	}
	eps[1].Abort()
	p.a.postClose.sweep()
	if n := p.a.postClose.len(); n != 3 {
		t.Fatalf("after the sweep the table holds %d rows, want 3", n)
	}
	closeFirst(t, p) // fills the freed row
	closeFirst(t, p) // evicts eps[0], the oldest
	if stateOf(eps[0]) != tcp.StateError {
		t.Fatal("the oldest row was not evicted")
	}
	for _, i := range []int{2, 3} {
		if st := stateOf(eps[i]); st == tcp.StateError {
			t.Fatalf("row %d was evicted before the oldest", i)
		}
	}
	if n := p.a.postClose.evicted.Load(); n != 1 {
		t.Fatalf("evicted = %d, want 1", n)
	}
}

// After the load stops, the Device's own sweeper empties the table within the TIME_WAIT period,
// without rebuilding the Device, and new connections still work.
func TestPostCloseDrainsAfterTimeWait(t *testing.T) {
	const timeWait = 500 * time.Millisecond
	p := newPostClosePair(t, 8, timeWait)
	for i := 0; i < 20; i++ {
		closeFirst(t, p)
	}
	if n := p.a.postClose.len(); n == 0 || n > 8 {
		t.Fatalf("table holds %d rows under load, want 1..8", n)
	}
	waitFor(t, timeWait+3*time.Second, "the table to drain", func() bool { return p.a.postClose.len() == 0 })
	c, s := p.dial(t)
	bulk(t, c, s, 64<<10)
	c.Close()
	s.Close()
}

// While the table is full and evicting, an established flow keeps working in both directions.
func TestPostCloseOtherFlowWhileFull(t *testing.T) {
	p := newPostClosePair(t, 2, 0)
	long, peer := p.dial(t)
	defer long.Close()
	defer peer.Close()
	for i := 0; i < 10; i++ {
		closeFirst(t, p)
		bulk(t, long, peer, 32<<10)
		bulk(t, peer, long, 32<<10)
	}
	if n := p.a.postClose.evicted.Load(); n == 0 {
		t.Fatal("the table never evicted, so it was never full")
	}
	if st := stateOf(connOf(long).ep); st != tcp.StateEstablished {
		t.Fatalf("the open flow is %v, want ESTABLISHED", st)
	}
}

// A connection closed for delivery stays out of the table, so an eviction cannot reset a tail
// that a relay is still delivering; its final Close puts it in.
func TestPostCloseHeldForDeliveryIsNotEvicted(t *testing.T) {
	p := newPostClosePair(t, 1, 0)
	c, s := p.dial(t)
	held := c.(*TCPConn)
	held.CloseForDelivery()
	s.Close()
	for i := 0; i < 3; i++ {
		closeFirst(t, p)
	}
	if st := stateOf(held.ep); st == tcp.StateError {
		t.Fatal("an eviction reset a connection held for delivery")
	}
	waitFor(t, 5*time.Second, "delivery", held.Delivered)
	before := p.a.postClose.evicted.Load()
	held.Close()
	closeFirst(t, p) // evicts the connection that was just released
	if st := stateOf(held.ep); st != tcp.StateError {
		t.Fatalf("the released connection is %v, want ERROR after its eviction", st)
	}
	if got := p.a.postClose.evicted.Load() - before; got != 2 {
		t.Fatalf("evicted %d after the release, want 2", got)
	}
}

// Device.Close does not wait on the table, and a Close after it adds nothing.
func TestPostCloseDeviceClose(t *testing.T) {
	p := newPostClosePair(t, 4, 0)
	for i := 0; i < 4; i++ {
		closeFirst(t, p)
	}
	late, peer := p.dial(t)
	within(t, goDone(func() { p.a.Close() }), 5*time.Second, "Device.Close with a full post-close table")
	late.Close()
	peer.Close()
	if n := p.a.postClose.len(); n != 0 {
		t.Fatalf("a closed Device's table holds %d rows", n)
	}
}

// One row costs at most the 10 KiB that postCloseEntries assumes, in TIME_WAIT and in FIN_WAIT_2
// with no receive memory, also after the connection carried data. Before the write path dropped
// its reader, gVisor's endpoint kept the caller's last write buffer and a row cost about 42 KiB.
func TestPostCloseRowHeap(t *testing.T) {
	if testing.Short() {
		t.Skip("measures the heap")
	}
	for _, finWait2 := range []bool{false, true} {
		per := rowHeap(t, 1000, finWait2)
		t.Logf("finWait2=%v: live heap per row %.2f KiB", finWait2, per/1024)
		if per > 10<<10 {
			t.Fatalf("finWait2=%v: a row costs %.2f KiB, more than the 10 KiB that postCloseEntries assumes", finWait2, per/1024)
		}
	}
}

// rowHeap returns the live heap per row of n dialed connections that carried 64 KiB each way and
// then closed first. For FIN_WAIT_2, the accepted side is reset with its reset dropped, so the
// dialed side keeps nothing to receive and its peer keeps nothing.
func rowHeap(t *testing.T, n int, finWait2 bool) float64 {
	var dropRST atomic.Bool
	p := newTCPPairOpts(t, 16, nil, func(pkt []byte) bool {
		ip := header.IPv4(pkt)
		if !dropRST.Load() || len(pkt) < header.IPv4MinimumSize || ip.TransportProtocol() != header.TCPProtocolNumber {
			return false
		}
		tp := header.TCP(ip.Payload())
		return len(tp) >= header.TCPMinimumSize && tp.Flags()&header.TCPFlagRst != 0
	})
	p.a.postClose = newPostCloseTable(n + 16)
	warm, warmPeer := p.dial(t)
	bulk(t, warm, warmPeer, 64<<10)
	warm.Close()
	warmPeer.Close()
	base := liveHeap()
	eps := make([]tcpip.Endpoint, 0, n)
	peers := make([]net.Conn, 0, n)
	for i := 0; i < n; i++ {
		c, s := p.dial(t)
		bulk(t, c, s, 64<<10)
		bulk(t, s, c, 64<<10)
		eps = append(eps, connOf(c).ep)
		peers = append(peers, s)
		c.Close()
	}
	want := tcp.StateTimeWait
	if finWait2 {
		want = tcp.StateFinWait2
		for _, ep := range eps {
			waitFor(t, 10*time.Second, "FIN_WAIT_2", func() bool { return stateOf(ep) == want })
		}
		dropRST.Store(true)
		for _, s := range peers {
			s.(*TCPConn).Abort()
		}
	} else {
		for _, s := range peers {
			s.Close()
		}
	}
	peers = nil
	for _, ep := range eps {
		waitFor(t, 10*time.Second, want.String(), func() bool { return stateOf(ep) == want })
	}
	// 受けた側の LAST_ACK の行は、CLOSED になった後の sweep で外れる
	waitFor(t, 10*time.Second, "the accepted side's rows to leave", func() bool {
		p.b.postClose.sweep()
		return p.b.postClose.len() <= 1
	})
	eps = nil
	per := float64(int64(liveHeap())-int64(base)) / float64(n)
	if got := p.a.postClose.len(); got != n+1 {
		t.Fatalf("the table holds %d rows, want %d", got, n+1)
	}
	return per
}

func liveHeap() uint64 {
	var m runtime.MemStats
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}
