package relay

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/rahanahu/wgft/internal/nettun"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// holdFirstNet wraps a Network so that the first connection its TCP listener accepts is handed to
// the test before the relay's accept loop sees it. The test resets the connection from the client
// side and releases it once the reset has reached the netstack, the way a busy accept loop picks up
// a connection that its client reset while it waited in the accept queue.
type holdFirstNet struct {
	Network
	taken   chan *endTracked
	release chan struct{}
}

func (h holdFirstNet) ListenTCP(port uint16) (net.Listener, error) {
	ln, err := h.Network.ListenTCP(port)
	if err != nil {
		return nil, err
	}
	return &holdFirstListener{Listener: ln, taken: h.taken, release: h.release}, nil
}

type holdFirstListener struct {
	net.Listener
	once    sync.Once
	taken   chan *endTracked
	release chan struct{}
}

// endTracked records whether the relay ended a netstack connection, by Abort or Close.
type endTracked struct {
	net.Conn
	ended atomic.Bool
}

func (c *endTracked) Abort() {
	c.ended.Store(true)
	c.Conn.(aborter).Abort()
}

func (c *endTracked) Close() error {
	c.ended.Store(true)
	return c.Conn.Close()
}

func (l *holdFirstListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	first := false
	l.once.Do(func() { first = true })
	if first {
		tc := &endTracked{Conn: c}
		l.taken <- tc
		<-l.release
		return tc, nil
	}
	return c, nil
}

// rawPeer plays the client side of TCP by hand on a netstack device: the test writes the client's
// segments into the device and reads the netstack's replies from it, in place of WireGuard.
type rawPeer struct {
	dev  *nettun.Device
	src  netip.Addr
	dst  netip.AddrPort
	pkts chan []byte
}

func newRawPeer(dev *nettun.Device, src netip.Addr, dst netip.AddrPort) *rawPeer {
	p := &rawPeer{dev: dev, src: src, dst: dst, pkts: make(chan []byte, 64)}
	go func() {
		bufs := [][]byte{make([]byte, 65535)}
		sizes := []int{0}
		for {
			n, err := dev.Read(bufs, sizes, 0)
			if err != nil {
				return
			}
			if n == 1 {
				select {
				case p.pkts <- append([]byte(nil), bufs[0][:sizes[0]]...):
				default:
				}
			}
		}
	}()
	return p
}

func (p *rawPeer) send(t *testing.T, srcPort uint16, seq, ack uint32, flags header.TCPFlags) {
	t.Helper()
	b := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)
	ip := header.IPv4(b)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(b)), TTL: 64, Protocol: uint8(tcp.ProtocolNumber),
		SrcAddr: tcpip.AddrFromSlice(p.src.AsSlice()), DstAddr: tcpip.AddrFromSlice(p.dst.Addr().AsSlice()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	h := header.TCP(b[header.IPv4MinimumSize:])
	h.Encode(&header.TCPFields{
		SrcPort: srcPort, DstPort: p.dst.Port(), SeqNum: seq, AckNum: ack,
		DataOffset: header.TCPMinimumSize, Flags: flags, WindowSize: 65535,
	})
	xsum := header.PseudoHeaderChecksum(tcp.ProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(), header.TCPMinimumSize)
	h.SetChecksum(^h.CalculateChecksum(xsum))
	if _, err := p.dev.Write([][]byte{b}, 0); err != nil {
		t.Fatalf("write a segment into the netstack: %v", err)
	}
}

// handshake completes a three-way handshake from srcPort and returns the client's next sequence
// number. The connection then waits in the listener's accept queue.
func (p *rawPeer) handshake(t *testing.T, srcPort uint16) uint32 {
	t.Helper()
	const isn = 1000
	p.send(t, srcPort, isn, 0, header.TCPFlagSyn)
	deadline := time.After(5 * time.Second)
	for {
		select {
		case b := <-p.pkts:
			ip := header.IPv4(b)
			if len(b) < header.IPv4MinimumSize || ip.TransportProtocol() != tcp.ProtocolNumber {
				continue
			}
			h := header.TCP(ip.Payload())
			if h.DestinationPort() != srcPort || h.Flags() != header.TCPFlagSyn|header.TCPFlagAck {
				continue
			}
			p.send(t, srcPort, isn+1, h.SequenceNumber()+1, header.TCPFlagAck)
			return isn + 1
		case <-deadline:
			t.Fatalf("no SYN-ACK from the netstack for port %d", srcPort)
		}
	}
}

// A client can complete the handshake and reset the connection before the relay's accept loop gets
// to it, for example while the loop works through a burst of connections. gVisor keeps such a
// connection in the accept queue and Accept returns it, and gonet's RemoteAddr returns nil because
// the endpoint is no longer connected. The accept loop must refuse the connection without taking a
// flow slot or asking the Admission Policy, and keep accepting. Before the fix, addrOf called
// String on the nil address and the panic ended the agent.
func TestTCPConnResetBeforeAcceptIsRefused(t *testing.T) {
	const port = 7003
	k := Key{proto.TCP, port}
	agent, err := nettun.Create(cutAgentAddr, 1420)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		agent.Close()
		agent.Wait()
	})
	peer := newRawPeer(agent, cutClientAddr, netip.AddrPortFrom(cutAgentAddr, port))

	var (
		mu       sync.Mutex
		admitted []netip.Addr
		released int
		logs     []string
	)
	logf := testLogf(t)
	hold := holdFirstNet{
		Network: netstackNet{dev: agent, addr: cutAgentAddr},
		taken:   make(chan *endTracked, 1),
		release: make(chan struct{}),
	}
	pool := resource.NewPool(8)
	m := New(hold, Options{
		TCPPool: pool,
		Logf: func(format string, args ...any) {
			mu.Lock()
			logs = append(logs, fmt.Sprintf(format, args...))
			mu.Unlock()
			logf(format, args...)
		},
		Admit: func(ruleID string, src netip.Addr, size int) (func(), bool) {
			mu.Lock()
			defer mu.Unlock()
			admitted = append(admitted, src)
			return func() {
				mu.Lock()
				released++
				mu.Unlock()
			}, true
		},
	})
	defer m.Close()
	defer func() {
		select {
		case <-hold.release:
		default:
			close(hold.release)
		}
	}()
	m.Apply(map[Key]Desired{k: {tcpEcho(t), "r1"}})
	if st := statusOf(t, m, k); !st.Listening {
		t.Fatalf("the listener did not open: %v", st.Err)
	}
	m.mu.Lock()
	l := m.listeners[k]
	m.mu.Unlock()

	next := peer.handshake(t, 40001)
	var c *endTracked
	select {
	case c = <-hold.taken:
	case <-time.After(5 * time.Second):
		t.Fatal("the listener never accepted the connection")
	}
	peer.send(t, 40001, next, 0, header.TCPFlagRst)
	deadline := time.Now().Add(5 * time.Second)
	for c.RemoteAddr() != nil {
		if time.Now().After(deadline) {
			t.Fatal("the reset never reached the accepted connection")
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(hold.release)

	// The accept loop keeps running: the next connection reaches the Admission Policy with its
	// source address.
	next = peer.handshake(t, 40002)
	waitFor := func(what string, done func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !done() {
			if time.Now().After(deadline) {
				t.Fatal(what)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitFor("the accept loop did not take the next connection", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(admitted) > 0
	})
	// Reset the second connection too. Its relay ends and returns its slots, so every slot is
	// free again only if the first connection took none.
	peer.send(t, 40002, next, 0, header.TCPFlagRst)
	waitFor("the slots were not returned after both connections ended", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return pool.InUse() == 0 && released == 1 && l.sessions() == 0
	})

	mu.Lock()
	defer mu.Unlock()
	if len(admitted) != 1 || admitted[0] != cutClientAddr {
		t.Errorf("admitted sources = %v, want only %s for the second connection", admitted, cutClientAddr)
	}
	if !c.ended.Load() {
		t.Error("the refused connection was not closed")
	}
	refusedLogged := false
	for _, line := range logs {
		if strings.Contains(line, "remote address is unknown") {
			refusedLogged = true
		}
	}
	if !refusedLogged {
		t.Errorf("no log line for the refused connection; logs: %q", logs)
	}
}
