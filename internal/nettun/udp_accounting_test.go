package nettun

import (
	"bytes"
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const accountingPort = 32000

var accountingLocal = netip.MustParseAddr("10.99.0.1")
var accountingRemote = netip.MustParseAddr("10.99.0.2")

type udpCounters struct {
	received uint64
	closed   uint64
	overflow uint64
	checksum uint64
}

func snapshotUDPStats(s *tcpip.TransportEndpointStats) udpCounters {
	return udpCounters{
		received: s.PacketsReceived.Value(),
		closed:   s.ReceiveErrors.ClosedReceiver.Value(),
		overflow: s.ReceiveErrors.ReceiveBufferOverflow.Value(),
		checksum: s.ReceiveErrors.ChecksumErrors.Value(),
	}
}

func (s udpCounters) acceptedSince(before udpCounters) uint64 {
	return s.received - before.received - (s.closed - before.closed) - (s.overflow - before.overflow)
}

func newAccountingEndpoint(t *testing.T) (*Device, tcpip.Endpoint, *tcpip.TransportEndpointStats) {
	t.Helper()
	dev, err := Create(accountingLocal, 1420)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dev.Close() })
	ep, terr := dev.stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, new(waiter.Queue))
	if terr != nil {
		t.Fatalf("NewEndpoint: %v", terr)
	}
	t.Cleanup(ep.Close)
	if terr := ep.Bind(fullAddr(netip.AddrPortFrom(accountingLocal, accountingPort))); terr != nil {
		t.Fatalf("Bind: %v", terr)
	}
	s, ok := ep.Stats().(*tcpip.TransportEndpointStats)
	if !ok {
		t.Fatalf("UDP Stats type = %T", ep.Stats())
	}
	return dev, ep, s
}

// UDP のチェックサムを 0 にした IPv4 datagram を作る。IPv4 では 0 はチェックサム省略を示す。
func accountingDatagram(payload []byte, udpLength uint16, udpChecksum uint16) []byte {
	if udpLength == 0 {
		udpLength = uint16(header.UDPMinimumSize + len(payload))
	}
	p := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
	ip := header.IPv4(p[:header.IPv4MinimumSize])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(p)),
		TTL:         64,
		Protocol:    uint8(udp.ProtocolNumber),
		SrcAddr:     tcpip.AddrFromSlice(accountingRemote.AsSlice()),
		DstAddr:     tcpip.AddrFromSlice(accountingLocal.AsSlice()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	u := header.UDP(p[header.IPv4MinimumSize:])
	u.Encode(&header.UDPFields{SrcPort: 41000, DstPort: accountingPort, Length: udpLength, Checksum: udpChecksum})
	copy(p[header.IPv4MinimumSize+header.UDPMinimumSize:], payload)
	return p
}

func injectAccountingDatagram(t *testing.T, dev *Device, p []byte) {
	t.Helper()
	n, err := dev.Write([][]byte{p}, 0)
	if err != nil || n != 1 {
		t.Fatalf("Device.Write = (%d, %v)", n, err)
	}
}

func readAccountingDatagram(ep tcpip.Endpoint, size int) (tcpip.ReadResult, []byte, tcpip.Error) {
	b := make([]byte, size)
	w := tcpip.SliceWriter(b)
	res, err := ep.Read(&w, tcpip.ReadOptions{})
	return res, b, err
}

func TestUDPAccountingAcceptedAndReadTotal(t *testing.T) {
	dev, ep, stats := newAccountingEndpoint(t)
	before := snapshotUDPStats(stats)
	payload := []byte("four")
	injectAccountingDatagram(t, dev, accountingDatagram(payload, 0, 0))
	after := snapshotUDPStats(stats)
	if got := after.acceptedSince(before); got != 1 {
		t.Fatalf("accepted counter delta = %d, want 1; before=%+v after=%+v", got, before, after)
	}
	res, b, err := readAccountingDatagram(ep, 16)
	if err != nil || res.Total != len(payload) || res.Count != len(payload) || !bytes.Equal(b[:res.Count], payload) {
		t.Fatalf("Read = (%+v, %q, %v), want full payload", res, b, err)
	}
	if _, _, err := readAccountingDatagram(ep, 16); err == nil {
		t.Fatal("empty receive queue returned a datagram")
	} else if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
		t.Fatalf("empty receive queue error = %v, want ErrWouldBlock", err)
	}
}

func TestUDPAccountingOverflow(t *testing.T) {
	dev, ep, stats := newAccountingEndpoint(t)
	p := accountingDatagram(make([]byte, 800), 0, 0)
	ep.SocketOptions().SetReceiveBufferSize(int64(2*(len(p)+stack.PacketBufferStructSize)), false)
	before := snapshotUDPStats(stats)
	for i := 0; i < 3; i++ {
		injectAccountingDatagram(t, dev, p)
	}
	after := snapshotUDPStats(stats)
	if got := after.acceptedSince(before); got != 2 || after.overflow-before.overflow != 1 {
		t.Fatalf("overflow counters: accepted=%d, overflow=%d", got, after.overflow-before.overflow)
	}
	for i := 0; i < 2; i++ {
		res, _, err := readAccountingDatagram(ep, 800)
		if err != nil || res.Total != 800 {
			t.Fatalf("Read after overflow = (%+v, %v)", res, err)
		}
	}
	if _, _, err := readAccountingDatagram(ep, 1); err == nil {
		t.Fatal("overflowed third datagram was queued")
	}
}

func TestUDPAccountingChecksumAndClosedReceiver(t *testing.T) {
	dev, ep, stats := newAccountingEndpoint(t)
	before := snapshotUDPStats(stats)
	injectAccountingDatagram(t, dev, accountingDatagram([]byte("bad"), 0, 1))
	after := snapshotUDPStats(stats)
	if after.acceptedSince(before) != 0 || after.checksum-before.checksum != 1 {
		t.Fatalf("bad checksum counters: before=%+v after=%+v", before, after)
	}
	// Read shutdown keeps the bound endpoint registered even if it returns ErrNotConnected.
	_ = ep.Shutdown(tcpip.ShutdownRead)
	before = snapshotUDPStats(stats)
	injectAccountingDatagram(t, dev, accountingDatagram([]byte("closed"), 0, 0))
	after = snapshotUDPStats(stats)
	if after.acceptedSince(before) != 0 || after.closed-before.closed != 1 {
		t.Fatalf("closed receiver counters: before=%+v after=%+v", before, after)
	}
}

func TestUDPAccountingInputLengthAndShortRead(t *testing.T) {
	dev, ep, stats := newAccountingEndpoint(t)
	payload := []byte("four")
	before := snapshotUDPStats(stats)
	// UDP length は 1 バイト分と主張するが、IPv4 total length は 4 バイト分を含む。
	injectAccountingDatagram(t, dev, accountingDatagram(payload, header.UDPMinimumSize+1, 0))
	if got := snapshotUDPStats(stats).acceptedSince(before); got != 1 {
		t.Fatalf("short UDP length accepted delta = %d, want 1", got)
	}
	res, b, err := readAccountingDatagram(ep, 2)
	if err != nil || res.Total != 1 || res.Count != 1 || !bytes.Equal(b[:res.Count], payload[:1]) {
		t.Fatalf("short Read = (%+v, %q, %v), want Count 1 and Total 1", res, b, err)
	}
	if _, _, err := readAccountingDatagram(ep, 1); err == nil {
		t.Fatal("truncated datagram remained queued")
	}
}

func TestUDPAccountingZeroPayloadAndRebind(t *testing.T) {
	dev, ep, stats := newAccountingEndpoint(t)
	before := snapshotUDPStats(stats)
	injectAccountingDatagram(t, dev, accountingDatagram(nil, 0, 0))
	if got := snapshotUDPStats(stats).acceptedSince(before); got != 1 {
		t.Fatalf("zero payload accepted delta = %d, want 1", got)
	}
	res, _, err := readAccountingDatagram(ep, 1)
	if err != nil || res.Total != 0 || res.Count != 0 {
		t.Fatalf("zero payload Read = (%+v, %v)", res, err)
	}
	ep.Close()
	var wq waiter.Queue
	next, terr := dev.stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if terr != nil {
		t.Fatalf("new endpoint after close: %v", terr)
	}
	defer next.Close()
	if terr := next.Bind(fullAddr(netip.AddrPortFrom(accountingLocal, accountingPort))); terr != nil {
		t.Fatalf("rebind: %v", terr)
	}
	nextStats := next.Stats().(*tcpip.TransportEndpointStats)
	injectAccountingDatagram(t, dev, accountingDatagram([]byte("new"), 0, 0))
	if got := snapshotUDPStats(nextStats).received; got != 1 {
		t.Fatalf("new endpoint received = %d, want 1", got)
	}
	if got := snapshotUDPStats(stats).received; got != 1 {
		t.Fatalf("old endpoint received changed to %d", got)
	}
}

func TestUDPAccountingHandleLocalBypassesTUNWrite(t *testing.T) {
	dev, ep, stats := newAccountingEndpoint(t)
	before := snapshotUDPStats(stats)
	c, err := dev.DialUDP(netip.AddrPortFrom(accountingLocal, accountingPort))
	if err != nil {
		t.Fatalf("self DialUDP: %v", err)
	}
	defer c.Close()
	if n, err := c.Write([]byte("self")); err != nil || n != 4 {
		t.Fatalf("self UDP Write = (%d, %v)", n, err)
	}
	if got := snapshotUDPStats(stats).acceptedSince(before); got != 1 {
		t.Fatalf("self UDP received delta = %d, want 1", got)
	}
	res, b, readErr := readAccountingDatagram(ep, 4)
	if readErr != nil || res.Total != 4 || !bytes.Equal(b, []byte("self")) {
		t.Fatalf("self UDP Read = (%+v, %q, %v)", res, b, readErr)
	}
	if got := dev.ep.NumQueued(); got != 0 {
		t.Fatalf("self UDP left %d packets in TUN output queue", got)
	}
}
