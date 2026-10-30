package nettun

import (
	"context"
	"encoding/binary"
	"math/rand/v2"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// sackOption is two NOPs and one SACK block.
func sackOption(start, end uint32) []byte {
	b := []byte{header.TCPOptionNOP, header.TCPOptionNOP, header.TCPOptionSACK, 10, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[4:], start)
	binary.BigEndian.PutUint32(b[8:], end)
	return b
}

// ackPeer is a hand-written TCP peer of a Device: it completes the handshake
// with SACK permitted and acknowledges every data segment while acking is set.
type ackPeer struct {
	d          *Device
	remote     netip.AddrPort
	local      netip.AddrPort
	irs        uint32
	acking     atomic.Bool
	maxEnd     atomic.Uint32 // highest sequence number the Device sent
	lastAck    atomic.Uint32 // highest acknowledgment the peer sent
	outbound   atomic.Int64  // segments the Device sent
	conn       net.Conn
	written    atomic.Int64
	stopWriter chan struct{}
}

func newAckPeer(t *testing.T) *ackPeer {
	t.Helper()
	p := &ackPeer{d: ingressDevice(t), remote: netip.AddrPortFrom(ingressRemote, 7400), irs: 9000, stopWriter: make(chan struct{})}
	p.acking.Store(true)
	syn := make(chan header.TCP, 1)
	go func() {
		buf := make([]byte, 70000)
		sizes := []int{0}
		for {
			n, err := p.d.Read([][]byte{buf}, sizes, 0)
			if err != nil || n != 1 {
				return
			}
			ip := header.IPv4(buf[:sizes[0]])
			if ip.Protocol() != uint8(header.TCPProtocolNumber) {
				continue
			}
			tcp := header.TCP(ip[ip.HeaderLength():])
			if tcp.Flags().Contains(header.TCPFlagSyn) {
				select {
				case syn <- append(header.TCP(nil), tcp...):
				default:
				}
				continue
			}
			p.outbound.Add(1)
			end := tcp.SequenceNumber() + uint32(len(tcp)-int(tcp.DataOffset()))
			if int32(end-p.maxEnd.Load()) > 0 {
				p.maxEnd.Store(end)
			}
			// Like a receiver that has everything up to maxEnd, acknowledge
			// the highest byte, also for a retransmission.
			if p.acking.Load() && end != tcp.SequenceNumber() {
				p.ack(p.maxEnd.Load(), nil)
			}
		}
	}()
	done := make(chan error, 1)
	go func() {
		c, err := p.d.DialTCP(context.Background(), p.remote)
		p.conn = c
		done <- err
	}()
	s := <-syn
	p.local = netip.AddrPortFrom(ingressLocal, s.SourcePort())
	p.maxEnd.Store(s.SequenceNumber() + 1)
	p.lastAck.Store(s.SequenceNumber() + 1)
	opts := append(mssOption(536), header.TCPOptionNOP, header.TCPOptionSACKPermitted, 2, header.TCPOptionNOP, header.TCPOptionWS, 3, 7)
	sendIngress(t, p.d, tcpSegment(p.remote, p.local, header.TCPFlagSyn|header.TCPFlagAck, p.irs, s.SequenceNumber()+1, opts))
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { close(p.stopWriter); p.conn.(*TCPConn).Abort() })
	go func() {
		b := make([]byte, 32<<10)
		for {
			select {
			case <-p.stopWriter:
				return
			default:
			}
			n, err := p.conn.Write(b)
			p.written.Add(int64(n))
			if err != nil {
				return
			}
		}
	}()
	return p
}

func (p *ackPeer) ack(ack uint32, opts []byte) {
	p.d.Write([][]byte{tcpSegment(p.remote, p.local, header.TCPFlagAck, p.irs+1, ack, opts)}, 0)
	if int32(ack-p.lastAck.Load()) > 0 {
		p.lastAck.Store(ack)
	}
}

// The reproduction: a peer that keeps the Device's data unacknowledged and
// sends duplicate or one-byte-advancing ACKs with a SACK block. Without the
// budget each ACK costs time in proportion to the segments in flight and the
// endpoint's queue grows by about 0.75 KiB per ACK.
// 並列にしない: liveHeap で heap の増え方を測るので、他の試験の確保と解放が測定に混ざる。
func TestAckBudgetBoundsAckFlood(t *testing.T) {
	for _, tc := range []struct {
		name    string
		advance bool
	}{{"duplicate", false}, {"advancing", true}} {
		t.Run(tc.name, func(t *testing.T) {
			p := newAckPeer(t)
			ep := p.conn.(*TCPConn).ep
			// Stop acknowledging once the window is open, so that the
			// Device fills it with segments that stay unacknowledged.
			deadline := time.Now().Add(20 * time.Second)
			for {
				var info tcpip.TCPInfoOption
				ep.GetSockOpt(&info)
				if info.CcState == tcpip.Open && info.SndCwnd >= 1024 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("the window did not open: %+v", info)
				}
				time.Sleep(time.Millisecond)
			}
			p.acking.Store(false)
			deadline = time.Now().Add(5 * time.Second)
			for p.maxEnd.Load()-p.lastAck.Load() < 256<<10 {
				if time.Now().After(deadline) {
					var info tcpip.TCPInfoOption
					ep.GetSockOpt(&info)
					t.Fatalf("only %d bytes in flight; written %d; %+v", p.maxEnd.Load()-p.lastAck.Load(), p.written.Load(), info)
				}
				time.Sleep(10 * time.Millisecond)
			}
			time.Sleep(200 * time.Millisecond)
			limit := connLimit(p.conn.(*TCPConn).tcpConn)
			base := liveHeap()
			una, hi := p.lastAck.Load(), p.maxEnd.Load()
			out0, drop0 := p.outbound.Load(), p.d.acks.dropped.Load()
			const flood = 200000
			for i := 0; i < flood; i++ {
				if tc.advance {
					una++
				}
				p.ack(una, sackOption(hi-1072, hi-536))
			}
			admitted := flood - int64(p.d.acks.dropped.Load()-drop0)
			sent := p.outbound.Load() - out0
			t.Logf("in flight %d KiB, limit %d, admitted %d, the Device sent %d segments during the flood",
				(hi-p.lastAck.Load())>>10, limit, admitted, sent)
			if admitted > int64(limit)+sent {
				t.Fatalf("admitted %d ACKs without data, more than the limit %d and the %d segments sent", admitted, limit, sent)
			}
			// 200,000 queued ACKs hold about 150 MiB; the budget keeps it near limit × 0.75 KiB.
			if grown := int64(liveHeap()) - int64(base); grown > 32<<20 {
				t.Fatalf("live heap grew by %d MiB during the flood", grown>>20)
			}
			// The connection recovers once the peer acknowledges again. The
			// peer has spent its budget, so its next ACK passes only after the
			// Device retransmits.
			p.acking.Store(true)
			p.ack(p.maxEnd.Load(), nil)
			w := p.written.Load()
			deadline = time.Now().Add(30 * time.Second)
			for p.written.Load() < w+(1<<20) {
				if time.Now().After(deadline) {
					t.Fatalf("the transfer did not resume: %d bytes written after the flood", p.written.Load()-w)
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

// Normal transfers in both directions over a lossy link recover and never
// meet the budget.
func TestAckBudgetLossyTransfersRecover(t *testing.T) {
	var mu sync.Mutex
	rng := rand.New(rand.NewPCG(1, 2))
	drop := func([]byte) bool {
		mu.Lock()
		defer mu.Unlock()
		return rng.Float64() < 0.02
	}
	p := newTCPPairOpts(t, 16, nil, drop)
	c, s := p.dial(t)
	defer c.Close()
	defer s.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, dir := range [][2]net.Conn{{c, s}, {s, c}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- bulkErr(dir[0], dir[1], 8<<20)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if a, b := p.a.acks.dropped.Load(), p.b.acks.dropped.Load(); a != 0 || b != 0 {
		t.Fatalf("the budget dropped ACKs of normal transfers: %d and %d", a, b)
	}
}

// The accounting of one connection: which segments use the budget, the
// refill by outbound segments and its limit, and the sweep.
func TestAckBudgetAccounting(t *testing.T) {
	p := newTCPPair(t, 0)
	c, s := p.dial(t)
	defer s.Close()
	ep := connOf(c).ep
	la, _ := ep.GetLocalAddress()
	local := netip.AddrPortFrom(p.a.local, la.Port)
	remote := netip.AddrPortFrom(p.b.local, 9000)
	in := func(flags header.TCPFlags, payload int) []byte {
		pkt := tcpSegment(remote, local, flags, 1, 1, nil)
		if payload > 0 {
			pkt = append(pkt, make([]byte, payload)...)
			binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
		}
		return pkt
	}
	out := tcpSegment(local, remote, header.TCPFlagAck, 1, 1, nil)
	acks := p.a.acks
	tokens := func() int {
		acks.mu.Lock()
		defer acks.mu.Unlock()
		f := acks.flows[ackFlowKey{remote: remote.Addr().As4(), remotePort: remote.Port(), localPort: local.Port()}]
		if f == nil {
			return -1
		}
		return f.tokens
	}
	limit := connLimit(connOf(c))
	if limit != tcpSendFloor/ackSegmentFloor+ackBurst {
		t.Fatalf("limit %d", limit)
	}
	// The pair is idle, but the stack may still send or receive a segment
	// right after the handshake; wait until the count settles.
	time.Sleep(100 * time.Millisecond)
	start := tokens()
	if start < limit-4 || start > limit {
		t.Fatalf("a new connection starts with %d of %d", start, limit)
	}
	for i := 0; i < start; i++ {
		if !acks.admit(in(header.TCPFlagAck, 0)) {
			t.Fatalf("ACK %d of %d dropped", i, start)
		}
	}
	for _, tc := range []struct {
		name  string
		pkt   []byte
		admit bool
	}{
		{"ACK without data", in(header.TCPFlagAck, 0), false},
		{"FIN", in(header.TCPFlagAck|header.TCPFlagFin, 0), false},
		{"PSH", in(header.TCPFlagAck|header.TCPFlagPsh, 0), false},
		{"data", in(header.TCPFlagAck, 1), true},
		{"RST", in(header.TCPFlagAck|header.TCPFlagRst, 0), true},
		{"SYN", in(header.TCPFlagSyn|header.TCPFlagAck, 0), true},
		{"no ACK flag", in(0, 0), true},
		{"other connection", tcpSegment(netip.AddrPortFrom(p.b.local, 9001), local, header.TCPFlagAck, 1, 1, nil), true},
		{"other destination", tcpSegment(remote, netip.AddrPortFrom(p.b.local, local.Port()), header.TCPFlagAck, 1, 1, nil), true},
		{"UDP", ingressUDP(nil, 1, 2), true},
	} {
		if got := acks.admit(tc.pkt); got != tc.admit {
			t.Errorf("%s: admit = %v", tc.name, got)
		}
	}
	dropped := acks.dropped.Load()
	if dropped != 3 {
		t.Fatalf("dropped %d", dropped)
	}
	acks.outbound(out)
	acks.outbound(out)
	for i, want := range []bool{true, true, false} {
		if got := acks.admit(in(header.TCPFlagAck, 0)); got != want {
			t.Fatalf("after two outbound segments, ACK %d: admit = %v", i, got)
		}
	}
	for i := 0; i < 2*limit; i++ {
		acks.outbound(out)
	}
	if got := tokens(); got != limit {
		t.Fatalf("refilled to %d, limit %d", got, limit)
	}
	c.(*TCPConn).Abort()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		acks.sweep()
		if tokens() == -1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("an aborted connection keeps its row")
		}
	}
	if !acks.admit(in(header.TCPFlagAck, 0)) {
		t.Fatal("an ACK for a connection without a row was dropped")
	}
}

// connLimit is the budget limit of connection c.
func connLimit(c *tcpConn) int { return ackLimit(c.ep, c.boosted) }

// rowTokens returns the tokens of the row for key k, or -1 without a row.
func rowTokens(b *ackBudgets, k ackFlowKey) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if f := b.flows[k]; f != nil {
		return f.tokens
	}
	return -1
}

// flowKeys returns the row keys of a dialed connection c on its Device and
// of the accepted connection s on the listening Device.
func flowKeys(c, s net.Conn) (dialed, accepted ackFlowKey) {
	ca, sa := c.LocalAddr().(*net.TCPAddr).AddrPort(), s.LocalAddr().(*net.TCPAddr).AddrPort()
	dialed = ackFlowKey{remote: sa.Addr().As4(), remotePort: sa.Port(), localPort: ca.Port()}
	accepted = ackFlowKey{remote: ca.Addr().As4(), remotePort: ca.Port(), localPort: sa.Port()}
	return dialed, accepted
}

// emptyACK is an ACK without data from the peer of the connection that the
// row key k describes on a Device at local.
func emptyACK(local [4]byte, k ackFlowKey) []byte {
	return tcpSegment(netip.AddrPortFrom(netip.AddrFrom4(k.remote), k.remotePort),
		netip.AddrPortFrom(netip.AddrFrom4(local), k.localPort), header.TCPFlagAck, 1, 1, nil)
}

// A connection that leaves boost, by demote or by delivering everything after
// its close, drops to the floor limit, and tokens it earned under boost do not
// let more ACKs through than the floor limit.
// 並列にしない: demote は tcpIdleReclaim を壁時計で待って保有者を floor に戻すので、tcpIdleReclaim の
// 回収を壁時計で確かめるほかの試験と同じく、他の試験の負荷を混ぜない。
func TestAckBudgetFollowsBoost(t *testing.T) {
	floorLimit := tcpSendFloor/ackSegmentFloor + ackBurst
	boostLimit := tcpBoostSize/ackSegmentFloor + ackBurst
	boostAndRefill := func(t *testing.T, p *tcpPair) (net.Conn, net.Conn, ackFlowKey) {
		c, s := p.dial(t)
		bulk(t, c, s, 4<<20)
		if !boosted(c) {
			t.Fatal("setup: the dialed connection is not boosted")
		}
		if got := connLimit(connOf(c)); got != boostLimit {
			t.Fatalf("boosted limit %d, want %d", got, boostLimit)
		}
		k, _ := flowKeys(c, s)
		// The connection's own segments to the TUN refill its budget.
		out := tcpSegment(netip.AddrPortFrom(netip.AddrFrom4(p.a.acks.local), k.localPort),
			netip.AddrPortFrom(netip.AddrFrom4(k.remote), k.remotePort), header.TCPFlagAck, 1, 1, nil)
		for i := 0; i < 2*boostLimit; i++ {
			p.a.acks.outbound(out)
		}
		if got := rowTokens(p.a.acks, k); got != boostLimit {
			t.Fatalf("refilled to %d under boost, want %d", got, boostLimit)
		}
		return c, s, k
	}
	admitted := func(p *tcpPair, k ackFlowKey) int {
		in := emptyACK(p.a.acks.local, k)
		n := 0
		for n <= boostLimit && p.a.acks.admit(in) {
			n++
		}
		return n
	}
	t.Run("demote", func(t *testing.T) {
		p := newTCPPair(t, 1)
		c, s, k := boostAndRefill(t, p)
		defer c.Close()
		defer s.Close()
		time.Sleep(tcpIdleReclaim + 200*time.Millisecond)
		if !connOf(c).demote(time.Now()) {
			t.Fatal("setup: the idle holder did not return to the floor")
		}
		if got := connLimit(connOf(c)); got != floorLimit {
			t.Fatalf("limit after demote %d, want %d", got, floorLimit)
		}
		if n := admitted(p, k); n > floorLimit {
			t.Fatalf("admitted %d ACKs without data after demote, floor limit %d", n, floorLimit)
		}
	})
	t.Run("delivered", func(t *testing.T) {
		p := newTCPPair(t, 1)
		c, s, k := boostAndRefill(t, p)
		// Each segment the connection sends to the TUN adds one token, so the count below meets
		// the floor limit only when nothing is sent during it. The accepted side closes after it
		// has acknowledged the dialed side's FIN, so neither side closes simultaneously, and the
		// count waits until the accepted side is CLOSED: the dialed side's last ACK has then
		// passed the TUN.
		c.Close()
		waitFor(t, 10*time.Second, "the dialed side's FIN to be acknowledged", func() bool { return finAcked(connOf(c).ep) })
		s.Close()
		waitFor(t, 10*time.Second, "the close to settle", func() bool {
			return stateOf(connOf(c).ep) == tcp.StateTimeWait && stateOf(connOf(s).ep) == tcp.StateClose
		})
		if got := rowTokens(p.a.acks, k); got < 0 {
			t.Skip("the row left before the check; the endpoint is already CLOSED")
		}
		if got := connLimit(connOf(c)); got != floorLimit {
			t.Fatalf("limit after delivery %d, want %d", got, floorLimit)
		}
		if n := admitted(p, k); n > floorLimit {
			t.Fatalf("admitted %d ACKs without data after delivery, floor limit %d", n, floorLimit)
		}
	})
}

// An accepted connection has a row from Accept and its budget drops ACKs
// without data past the limit.
func TestAckBudgetAcceptedConnection(t *testing.T) {
	p := newTCPPair(t, 0)
	c, s := p.dial(t)
	defer c.Close()
	defer s.Close()
	_, k := flowKeys(c, s)
	limit := connLimit(connOf(s))
	time.Sleep(100 * time.Millisecond)
	if got := rowTokens(p.b.acks, k); got < limit-4 || got > limit {
		t.Fatalf("the accepted connection's row has %d tokens, want about %d", got, limit)
	}
	in := emptyACK(p.b.acks.local, k)
	drop0 := p.b.acks.dropped.Load()
	n := 0
	for i := 0; i < limit+100; i++ {
		if p.b.acks.admit(in) {
			n++
		}
	}
	if n > limit || p.b.acks.dropped.Load()-drop0 < 100 {
		t.Fatalf("admitted %d of %d ACKs without data, limit %d", n, limit+100, limit)
	}
}

// The Device's own sweeper removes the rows of connections that end; no
// test calls sweep here.
func TestAckBudgetSweeperRemovesRows(t *testing.T) {
	t.Parallel()
	p := newTCPPair(t, 0)
	c, s := p.dial(t)
	defer s.Close()
	dk, ak := flowKeys(c, s)
	if rowTokens(p.a.acks, dk) < 0 || rowTokens(p.b.acks, ak) < 0 {
		t.Fatal("setup: a connection has no row")
	}
	c.(*TCPConn).Abort()
	waitFor(t, 5*time.Second, "the sweeper to remove both rows", func() bool {
		return rowTokens(p.a.acks, dk) < 0 && rowTokens(p.b.acks, ak) < 0
	})
}

// A row keeps only the endpoint and the boost flag: a closed connection's
// tcpConn, with its write history, is collectable while the row is still in
// the table for the endpoint's TIME_WAIT.
func TestAckBudgetRowDoesNotHoldConn(t *testing.T) {
	// No boost slots: a slot holder stays referenced by the pool until
	// another connection takes the slot.
	p := newTCPPair(t, 0)
	c, s := p.dial(t)
	bulk(t, c, s, 1<<20)
	k, _ := flowKeys(c, s)
	freed := make(chan struct{})
	runtime.AddCleanup(connOf(c), func(ch chan struct{}) { close(ch) }, freed)
	c.Close()
	s.Close()
	c = nil
	deadline := time.Now().Add(10 * time.Second)
	for {
		runtime.GC()
		select {
		case <-freed:
			if rowTokens(p.a.acks, k) < 0 {
				t.Fatal("the row left before the check; the test needs the row in TIME_WAIT")
			}
			return
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the closed connection was not collected while its row remains")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
