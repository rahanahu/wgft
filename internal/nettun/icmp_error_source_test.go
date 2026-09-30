package nettun

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// peerNet は vpsd のユーザー空間モードの形を模す。srv は server の Device、agent は被害者の
// エージェントの Device で、2 つの間は Read と Write で packet を渡す。other は同じ server の別の
// ピア(攻撃者のエージェント)のアドレスで、wireguard-go はその /32 を AllowedIPs とするので、
// 外側の送信元が other の packet はそのまま srv の Write に届く。
type peerNet struct {
	srv, agent *Device
	other      netip.Addr
	maxTCP     atomic.Int64 // srv から agent への TCP の segment の最大の payload
	holdSYN    atomic.Bool  // 立っている間は srv から agent への SYN を捨て、送信元のポートを synPort に残す
	synPort    atomic.Int32
}

var peerNetN atomic.Int32

func newPeerNet(t *testing.T) *peerNet {
	t.Helper()
	n := peerNetN.Add(1)
	addr := func(host byte) netip.Addr { return netip.AddrFrom4([4]byte{10, 98, byte(n), host}) }
	srv, err := Create(addr(1), 1420)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := Create(addr(3), 1420)
	if err != nil {
		t.Fatal(err)
	}
	p := &peerNet{srv: srv, agent: agent, other: addr(2)}
	var wg sync.WaitGroup
	fwd := func(from, to *Device, record bool) {
		defer wg.Done()
		buf := make([]byte, 1520)
		sizes := []int{0}
		for {
			n, err := from.Read([][]byte{buf}, sizes, 0)
			if err != nil || n != 1 {
				return
			}
			pkt := buf[:sizes[0]]
			if record && len(pkt) >= header.IPv4MinimumSize && pkt[9] == uint8(header.TCPProtocolNumber) {
				ip := header.IPv4(pkt)
				tcp := header.TCP(pkt[ip.HeaderLength():])
				if p.holdSYN.Load() && tcp.Flags().Contains(header.TCPFlagSyn) {
					p.synPort.Store(int32(tcp.SourcePort()))
					continue
				}
				if pl := int64(ip.TotalLength()) - int64(ip.HeaderLength()) - int64(tcp.DataOffset()); pl > p.maxTCP.Load() {
					p.maxTCP.Store(pl)
				}
			}
			to.Write([][]byte{pkt}, 0)
		}
	}
	wg.Add(2)
	go fwd(srv, agent, true)
	go fwd(agent, srv, false)
	t.Cleanup(func() {
		srv.Close()
		agent.Close()
		wg.Wait()
	})
	return p
}

// icmpv4Error builds an ICMPv4 error of type typ and code from outerSrc to
// outerDst. It quotes an IPv4 header from quoteSrc to quoteDst with protocol
// proto and the first 8 bytes of the transport header (the two ports). field
// is the second 32-bit word of the ICMP header; for Fragmentation Needed its
// low 16 bits are the next-hop MTU.
func icmpv4Error(typ header.ICMPv4Type, code header.ICMPv4Code, field uint32, outerSrc, outerDst, quoteSrc, quoteDst netip.Addr, proto tcpip.TransportProtocolNumber, sport, dport uint16) []byte {
	quote := make([]byte, header.IPv4MinimumSize+8)
	qh := header.IPv4(quote)
	qh.Encode(&header.IPv4Fields{
		TotalLength: 1400, ID: 7, TTL: 64, Protocol: uint8(proto), Flags: header.IPv4FlagDontFragment,
		SrcAddr: tcpip.AddrFromSlice(quoteSrc.AsSlice()), DstAddr: tcpip.AddrFromSlice(quoteDst.AsSlice()),
	})
	qh.SetChecksum(^qh.CalculateChecksum())
	binary.BigEndian.PutUint16(quote[header.IPv4MinimumSize:], sport)
	binary.BigEndian.PutUint16(quote[header.IPv4MinimumSize+2:], dport)
	icmp := make([]byte, header.ICMPv4MinimumSize+len(quote))
	icmp[0], icmp[1] = byte(typ), byte(code)
	binary.BigEndian.PutUint32(icmp[4:8], field)
	copy(icmp[header.ICMPv4MinimumSize:], quote)
	binary.BigEndian.PutUint16(icmp[2:4], ^checksum.Checksum(icmp, 0))
	out := make([]byte, header.IPv4MinimumSize+len(icmp))
	oh := header.IPv4(out)
	oh.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(out)), ID: 9, TTL: 64, Protocol: uint8(header.ICMPv4ProtocolNumber),
		SrcAddr: tcpip.AddrFromSlice(outerSrc.AsSlice()), DstAddr: tcpip.AddrFromSlice(outerDst.AsSlice()),
	})
	oh.SetChecksum(^oh.CalculateChecksum())
	copy(out[header.IPv4MinimumSize:], icmp)
	return out
}

// udpSession opens the srv side of a relay UDP session to the agent and
// returns it with a round trip that reports the session's error.
func (p *peerNet) udpSession(t *testing.T) (c net.Conn, echo func() error) {
	t.Helper()
	target := netip.AddrPortFrom(p.agent.local, 5000)
	ln, err := p.agent.ListenUDP(target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	c, err = p.srv.DialUDP(target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	echo = func() error {
		if _, err := c.Write([]byte("ping")); err != nil {
			return err
		}
		buf := make([]byte, 64)
		ln.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, from, err := ln.ReadFrom(buf)
		if err != nil {
			t.Fatalf("agent read: %v", err)
		}
		if _, err := ln.WriteTo(buf[:n], from); err != nil {
			t.Fatalf("agent write: %v", err)
		}
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = c.Read(buf)
		return err
	}
	if err := echo(); err != nil {
		t.Fatalf("echo before any ICMP: %v", err)
	}
	return c, echo
}

func (p *peerNet) portUnreachable(outerSrc netip.Addr, c net.Conn) []byte {
	return icmpv4Error(header.ICMPv4DstUnreachable, header.ICMPv4PortUnreachable, 0, outerSrc, p.srv.local,
		p.srv.local, p.agent.local, header.UDPProtocolNumber, uint16(c.LocalAddr().(*net.UDPAddr).Port), 5000)
}

func isRefused(err error) bool {
	return err != nil && strings.Contains(err.Error(), "connection was refused")
}

// A Port Unreachable from another peer quoting the server's UDP session to
// the agent does not reach the session; the same error from the agent itself
// still ends it, as before.
func TestICMPErrorFromAnotherPeerKeepsUDPSession(t *testing.T) {
	p := newPeerNet(t)
	c, echo := p.udpSession(t)
	sendIngress(t, p.srv, p.portUnreachable(p.other, c))
	time.Sleep(20 * time.Millisecond)
	if err := echo(); err != nil {
		t.Fatalf("a Port Unreachable from another peer reached the session: %v", err)
	}

	sendIngress(t, p.srv, p.portUnreachable(p.agent.local, c))
	time.Sleep(20 * time.Millisecond)
	if err := echo(); !isRefused(err) {
		t.Fatalf("a Port Unreachable from the quoted destination: session error = %v; want connection refused", err)
	}
}

// A forged ICMP error cut into fragments is checked after reassembly: the
// first fragment carries only the ICMP header, so nothing before reassembly
// can see the quoted destination.
func TestICMPErrorFromAnotherPeerCheckedAfterReassembly(t *testing.T) {
	p := newPeerNet(t)
	c, echo := p.udpSession(t)
	forged := p.portUnreachable(p.other, c)
	binary.BigEndian.PutUint16(forged[4:6], 4243) // a nonzero ID for reassembly
	h := header.IPv4(forged)
	h.SetChecksum(0)
	h.SetChecksum(^h.CalculateChecksum())
	first, second := splitIngressIPv4(forged, header.ICMPv4MinimumSize)
	sendIngress(t, p.srv, first)
	sendIngress(t, p.srv, second)
	time.Sleep(20 * time.Millisecond)
	if err := echo(); err != nil {
		t.Fatalf("a fragmented Port Unreachable from another peer reached the session: %v", err)
	}

	legit := p.portUnreachable(p.agent.local, c)
	binary.BigEndian.PutUint16(legit[4:6], 4244)
	h = header.IPv4(legit)
	h.SetChecksum(0)
	h.SetChecksum(^h.CalculateChecksum())
	first, second = splitIngressIPv4(legit, header.ICMPv4MinimumSize)
	sendIngress(t, p.srv, first)
	sendIngress(t, p.srv, second)
	time.Sleep(20 * time.Millisecond)
	if err := echo(); !isRefused(err) {
		t.Fatalf("a fragmented Port Unreachable from the quoted destination: session error = %v; want connection refused", err)
	}
}

// tcpSession connects srv to the agent, drains everything the agent
// receives, and returns the srv side with a function that sends n bytes and
// reports the largest TCP payload the srv sent meanwhile.
func (p *peerNet) tcpSession(t *testing.T) (c net.Conn, send func(n int) int64) {
	t.Helper()
	ln, err := p.agent.ListenTCP(netip.AddrPortFrom(p.agent.local, 7000))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	received := make(chan int64, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		n, _ := io.Copy(io.Discard, conn)
		conn.Close()
		received <- n
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err = p.srv.DialTCP(ctx, netip.AddrPortFrom(p.agent.local, 7000))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	send = func(n int) int64 {
		time.Sleep(50 * time.Millisecond) // let earlier segments drain before the reset
		p.maxTCP.Store(0)
		c.SetWriteDeadline(time.Now().Add(20 * time.Second))
		if _, err := c.Write(make([]byte, n)); err != nil {
			t.Fatalf("write: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
		return p.maxTCP.Load()
	}
	return c, send
}

func (p *peerNet) fragNeeded(outerSrc netip.Addr, c net.Conn, mtu uint16) []byte {
	return icmpv4Error(header.ICMPv4DstUnreachable, header.ICMPv4FragmentationNeeded, uint32(mtu), outerSrc, p.srv.local,
		p.srv.local, p.agent.local, header.TCPProtocolNumber, uint16(c.LocalAddr().(*net.TCPAddr).Port), 7000)
}

// A Fragmentation Needed from another peer does not shrink the server's TCP
// segments to the agent. One from the agent itself does, down to the floor
// and no further.
func TestICMPFragNeededFromAnotherPeerKeepsTCPSegments(t *testing.T) {
	p := newPeerNet(t)
	c, send := p.tcpSession(t)
	before := send(64 << 10)
	if before < 1000 {
		t.Fatalf("largest payload before any ICMP = %d; want a full segment", before)
	}

	// From another peer: neither an MTU above the floor nor one below it
	// reaches the connection.
	for _, mtu := range []uint16{1000, 68} {
		sendIngress(t, p.srv, p.fragNeeded(p.other, c, mtu))
		if got := send(16 << 10); got != before {
			t.Fatalf("after Fragmentation Needed with MTU %d from another peer: largest payload = %d; want %d", mtu, got, before)
		}
	}

	// From the quoted destination, but below the floor.
	sendIngress(t, p.srv, p.fragNeeded(p.agent.local, c, icmpv4FragNeededMinMTU-1))
	if got := send(16 << 10); got != before {
		t.Fatalf("after Fragmentation Needed with MTU %d from the agent: largest payload = %d; want %d", icmpv4FragNeededMinMTU-1, got, before)
	}

	// A legitimate one lowers the segments.
	sendIngress(t, p.srv, p.fragNeeded(p.agent.local, c, 1000))
	if got := send(64 << 10); got <= 0 || got > 1000-40 {
		t.Fatalf("after Fragmentation Needed with MTU 1000 from the agent: largest payload = %d; want 1..960", got)
	}

	// Exactly the floor is honored.
	sendIngress(t, p.srv, p.fragNeeded(p.agent.local, c, icmpv4FragNeededMinMTU))
	if got := send(64 << 10); got <= 0 || got > icmpv4FragNeededMinMTU-40 {
		t.Fatalf("after Fragmentation Needed with MTU %d from the agent: largest payload = %d; want 1..%d", icmpv4FragNeededMinMTU, got, icmpv4FragNeededMinMTU-40)
	}
}

// A Host Unreachable from another peer does not abort the server's TCP
// connect to the agent. The first SYN is held back so that the error reaches
// the endpoint while it is still connecting; the retransmitted SYN then
// completes the connect.
func TestICMPErrorFromAnotherPeerKeepsTCPConnect(t *testing.T) {
	p := newPeerNet(t)
	target := netip.AddrPortFrom(p.agent.local, 7100)
	ln, err := p.agent.ListenTCP(target)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if conn, err := ln.Accept(); err == nil {
			conn.Close()
		}
	}()
	p.holdSYN.Store(true)
	type result struct {
		c   net.Conn
		err error
	}
	done := make(chan result, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := p.srv.DialTCP(ctx, target)
		done <- result{c, err}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for p.synPort.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no SYN from the server")
		}
		time.Sleep(time.Millisecond)
	}
	sendIngress(t, p.srv, icmpv4Error(header.ICMPv4DstUnreachable, header.ICMPv4HostUnreachable, 0, p.other, p.srv.local,
		p.srv.local, p.agent.local, header.TCPProtocolNumber, uint16(p.synPort.Load()), 7100))
	p.holdSYN.Store(false)
	r := <-done
	if r.err != nil {
		t.Fatalf("connect after a Host Unreachable from another peer: %v", r.err)
	}
	r.c.Close()
}

// admitICMPv4Error by message: every ICMP error type is checked against the
// quoted destination, the MTU floor applies only to Fragmentation Needed, and
// messages that are not errors pass whatever their source.
func TestAdmitICMPv4Error(t *testing.T) {
	local := netip.MustParseAddr("10.97.0.1")
	peer := netip.MustParseAddr("10.97.0.3")
	other := netip.MustParseAddr("10.97.0.2")
	build := func(typ header.ICMPv4Type, code header.ICMPv4Code, field uint32, src netip.Addr) []byte {
		return icmpv4Error(typ, code, field, src, local, local, peer, header.UDPProtocolNumber, 40000, 5000)
	}
	errorTypes := []struct {
		typ  header.ICMPv4Type
		code header.ICMPv4Code
	}{
		{header.ICMPv4DstUnreachable, header.ICMPv4NetUnreachable},
		{header.ICMPv4DstUnreachable, header.ICMPv4HostUnreachable},
		{header.ICMPv4DstUnreachable, header.ICMPv4PortUnreachable},
		{header.ICMPv4DstUnreachable, header.ICMPv4FragmentationNeeded},
		{header.ICMPv4SrcQuench, 0},
		{header.ICMPv4Redirect, 1},
		{header.ICMPv4TimeExceeded, header.ICMPv4TTLExceeded},
		{header.ICMPv4ParamProblem, 0},
	}
	for _, e := range errorTypes {
		field := uint32(1400)
		if got := admitICMPv4Error(build(e.typ, e.code, field, other)); got {
			t.Errorf("type %d code %d from another peer: admitted", e.typ, e.code)
		}
		if got := admitICMPv4Error(build(e.typ, e.code, field, peer)); !got {
			t.Errorf("type %d code %d from the quoted destination: dropped", e.typ, e.code)
		}
	}

	// The floor reads the next-hop MTU of Fragmentation Needed only; other
	// codes leave the field unused and may carry any value there.
	for _, c := range []struct {
		code header.ICMPv4Code
		mtu  uint32
		want bool
	}{
		{header.ICMPv4FragmentationNeeded, 0, false},
		{header.ICMPv4FragmentationNeeded, 68, false},
		{header.ICMPv4FragmentationNeeded, icmpv4FragNeededMinMTU - 1, false},
		{header.ICMPv4FragmentationNeeded, icmpv4FragNeededMinMTU, true},
		{header.ICMPv4FragmentationNeeded, 0xffff0000 | icmpv4FragNeededMinMTU, true},
		{header.ICMPv4FragmentationNeeded, 0x02000000 | 68, false},
		{header.ICMPv4PortUnreachable, 0, true},
		{header.ICMPv4PortUnreachable, 68, true},
		{header.ICMPv4HostUnreachable, 1, true},
	} {
		if got := admitICMPv4Error(build(header.ICMPv4DstUnreachable, c.code, c.mtu, peer)); got != c.want {
			t.Errorf("code %d field %#x from the quoted destination: admitted = %v; want %v", c.code, c.mtu, got, c.want)
		}
	}
	if !admitICMPv4Error(build(header.ICMPv4TimeExceeded, 0, 68, peer)) {
		t.Error("Time Exceeded with 68 in the unused field: dropped")
	}

	// Messages that are not errors pass from anyone.
	for _, typ := range []header.ICMPv4Type{header.ICMPv4EchoReply, header.ICMPv4Echo, header.ICMPv4Timestamp} {
		if !admitICMPv4Error(build(typ, 0, 0, other)) {
			t.Errorf("type %d from another peer: dropped", typ)
		}
	}

	// An error too short to quote a destination is dropped; a packet too
	// short to hold an ICMP header and a packet that is not ICMP pass on to
	// gVisor, which handles them as before.
	full := build(header.ICMPv4DstUnreachable, header.ICMPv4PortUnreachable, 0, peer)
	for n := header.IPv4MinimumSize + header.ICMPv4MinimumSize; n < header.IPv4MinimumSize+header.ICMPv4MinimumSize+header.IPv4MinimumSize; n++ {
		if admitICMPv4Error(full[:n]) {
			t.Errorf("Port Unreachable cut to %d bytes: admitted", n)
		}
	}
	if !admitICMPv4Error(full[:header.IPv4MinimumSize+header.ICMPv4MinimumSize-1]) {
		t.Error("ICMP shorter than its header: dropped")
	}
	if !admitICMPv4Error(ingressUDP([]byte("x"), 1, 2)) {
		t.Error("UDP: dropped")
	}

	// The outer header length comes from IHL: with options the ICMP header
	// starts later.
	opt := make([]byte, 4+len(full))
	copy(opt, full[:header.IPv4MinimumSize])
	opt[0] = 0x46
	opt[header.IPv4MinimumSize] = byte(header.IPv4OptionNOPType)
	opt[header.IPv4MinimumSize+1] = byte(header.IPv4OptionNOPType)
	opt[header.IPv4MinimumSize+2] = byte(header.IPv4OptionNOPType)
	opt[header.IPv4MinimumSize+3] = byte(header.IPv4OptionListEndType)
	copy(opt[header.IPv4MinimumSize+4:], full[header.IPv4MinimumSize:])
	if !admitICMPv4Error(opt) {
		t.Error("Port Unreachable from the quoted destination with outer options: dropped")
	}
	copy(opt[12:16], other.AsSlice())
	if admitICMPv4Error(opt) {
		t.Error("Port Unreachable from another peer with outer options: admitted")
	}
}
