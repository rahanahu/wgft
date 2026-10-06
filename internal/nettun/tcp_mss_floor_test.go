package nettun

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// These tests pin the MSS floor at the TUN ingress: a SYN or SYN-ACK whose
// MSS option is below 536 never reaches gVisor, is counted and logged, and
// every other handshake, including one without an MSS option, still forms a
// connection.

// mssOption is a well-formed MSS option.
func mssOption(mss uint16) []byte {
	return []byte{header.TCPOptionMSS, 4, byte(mss >> 8), byte(mss)}
}

// tcpSegment builds a complete IPv4 TCP segment with valid checksums. opts is
// padded with EOL to a multiple of 4 bytes.
func tcpSegment(src, dst netip.AddrPort, flags header.TCPFlags, seq, ack uint32, opts []byte) []byte {
	for len(opts)%4 != 0 {
		opts = append(opts, header.TCPOptionEOL)
	}
	tcpLen := header.TCPMinimumSize + len(opts)
	p := make([]byte, header.IPv4MinimumSize+tcpLen)
	ip := header.IPv4(p)
	srcAddr, dstAddr := tcpip.AddrFromSlice(src.Addr().AsSlice()), tcpip.AddrFromSlice(dst.Addr().AsSlice())
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(p)),
		ID:          7,
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	tcp := header.TCP(p[header.IPv4MinimumSize:])
	tcp.Encode(&header.TCPFields{
		SrcPort:    src.Port(),
		DstPort:    dst.Port(),
		SeqNum:     seq,
		AckNum:     ack,
		DataOffset: uint8(tcpLen),
		Flags:      flags,
		WindowSize: 65535,
	})
	copy(tcp[header.TCPMinimumSize:], opts)
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, srcAddr, dstAddr, uint16(tcpLen))
	tcp.SetChecksum(^checksum.Checksum(tcp, xsum))
	return p
}

func TestTCPSynMSSBelowFloor(t *testing.T) {
	src := netip.MustParseAddrPort("10.98.0.2:40000")
	dst := netip.MustParseAddrPort("10.98.0.1:443")
	syn, synAck := header.TCPFlagSyn, header.TCPFlagSyn|header.TCPFlagAck
	cases := []struct {
		name   string
		packet []byte
		want   bool
	}{
		{"SYN MSS 48", tcpSegment(src, dst, syn, 1, 0, mssOption(48)), true},
		{"SYN MSS 1, which gVisor raises to 48", tcpSegment(src, dst, syn, 1, 0, mssOption(1)), true},
		{"SYN MSS 535", tcpSegment(src, dst, syn, 1, 0, mssOption(535)), true},
		{"SYN MSS 536", tcpSegment(src, dst, syn, 1, 0, mssOption(536)), false},
		{"SYN MSS 1460", tcpSegment(src, dst, syn, 1, 0, mssOption(1460)), false},
		{"SYN without options", tcpSegment(src, dst, syn, 1, 0, nil), false},
		{"SYN with options but no MSS", tcpSegment(src, dst, syn, 1, 0, []byte{header.TCPOptionNOP, header.TCPOptionNOP, header.TCPOptionSACKPermitted, 2}), false},
		{"SYN MSS 0, which gVisor treats as absent", tcpSegment(src, dst, syn, 1, 0, mssOption(0)), false},
		{"SYN MSS 48 after NOPs", tcpSegment(src, dst, syn, 1, 0, append([]byte{header.TCPOptionNOP, header.TCPOptionNOP}, mssOption(48)...)), true},
		{"SYN MSS option of the wrong length", tcpSegment(src, dst, syn, 1, 0, []byte{header.TCPOptionMSS, 3, 0, 48}), false},
		{"SYN MSS 48 behind a malformed option, where gVisor stops", tcpSegment(src, dst, syn, 1, 0, append([]byte{30, 1}, mssOption(48)...)), false},
		{"SYN MSS 48 then a malformed option", tcpSegment(src, dst, syn, 1, 0, append(mssOption(48), 30, 1)), true},
		{"SYN MSS 1460 then 48, where gVisor keeps the last", tcpSegment(src, dst, syn, 1, 0, append(mssOption(1460), mssOption(48)...)), true},
		{"SYN MSS 48 then 1460, where gVisor keeps the last", tcpSegment(src, dst, syn, 1, 0, append(mssOption(48), mssOption(1460)...)), false},
		{"SYN-ACK MSS 48", tcpSegment(src, dst, synAck, 1, 2, mssOption(48)), true},
		{"SYN-ACK MSS 536", tcpSegment(src, dst, synAck, 1, 2, mssOption(536)), false},
		{"ACK carrying an MSS option of 48", tcpSegment(src, dst, header.TCPFlagAck, 1, 2, mssOption(48)), false},
	}
	for _, c := range cases {
		if got := tcpSynMSSBelowFloor(c.packet); got != c.want {
			t.Errorf("%s: tcpSynMSSBelowFloor = %v, want %v", c.name, got, c.want)
		}
	}

	// IPv4 options move the TCP header.
	withIPOptions := func(p []byte) []byte {
		q := append(append(append([]byte(nil), p[:20]...), byte(header.IPv4OptionNOPType), byte(header.IPv4OptionNOPType), byte(header.IPv4OptionNOPType), byte(header.IPv4OptionListEndType)), p[20:]...)
		q[0] = 0x46
		binary.BigEndian.PutUint16(q[2:4], uint16(len(q)))
		ipv4SetChecksum(q[:24])
		return q
	}
	if !tcpSynMSSBelowFloor(withIPOptions(tcpSegment(src, dst, syn, 1, 0, mssOption(48)))) {
		t.Error("a SYN with MSS 48 behind IPv4 options must be below the floor")
	}

	// Malformed headers pass on to gVisor, which drops them.
	low := tcpSegment(src, dst, syn, 1, 0, mssOption(48))
	shortOffset := append([]byte(nil), low...)
	shortOffset[20+12] = 4 << 4 // data offset 16 bytes
	longOffset := append([]byte(nil), low...)
	longOffset[20+12] = 15 << 4 // data offset past the segment
	truncated := low[:len(low)-2]
	udpLike := append([]byte(nil), low...)
	udpLike[9] = uint8(header.UDPProtocolNumber)
	for name, p := range map[string][]byte{
		"data offset below 20": shortOffset, "data offset past the end": longOffset,
		"Total Length past the packet": truncated, "not TCP": udpLike, "too short for IPv4": low[:12],
		"too short for TCP": low[:header.IPv4MinimumSize+10],
	} {
		if tcpSynMSSBelowFloor(p) {
			t.Errorf("%s: a malformed packet must pass to gVisor", name)
		}
	}
}

// devicePackets reads every packet the Device sends until it closes.
func devicePackets(t *testing.T, d *Device) <-chan []byte {
	t.Helper()
	ch := make(chan []byte, 64)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(ch)
		buf := make([]byte, 2048)
		sizes := []int{0}
		for {
			n, err := d.Read([][]byte{buf}, sizes, 0)
			if err != nil || n != 1 {
				return
			}
			select {
			case ch <- append([]byte(nil), buf[:sizes[0]]...):
			case <-stop:
				return
			}
		}
	}()
	t.Cleanup(func() { close(stop); d.Close(); wg.Wait() })
	return ch
}

// nextTCP waits for the next TCP segment the Device sends with all of flags set.
func nextTCP(t *testing.T, ch <-chan []byte, flags header.TCPFlags, within time.Duration) header.TCP {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case p, ok := <-ch:
			if !ok {
				t.Fatal("the Device closed")
			}
			ip := header.IPv4(p)
			if ip.Protocol() != uint8(header.TCPProtocolNumber) {
				continue
			}
			tcp := header.TCP(p[ip.HeaderLength():])
			if tcp.Flags().Contains(flags) {
				return tcp
			}
		case <-deadline:
			t.Fatalf("no TCP segment with flags %v within %v", flags, within)
		}
	}
}

// noTCP fails if the Device sends any TCP segment within d.
func noTCP(t *testing.T, ch <-chan []byte, d time.Duration) {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case p := <-ch:
			if header.IPv4(p).Protocol() == uint8(header.TCPProtocolNumber) {
				t.Fatalf("the Device answered a dropped handshake: % x", p)
			}
		case <-deadline:
			return
		}
	}
}

// A SYN below the floor never reaches gVisor: no SYN-ACK, no accepted
// connection. It is counted, and the first drop is logged.
func TestDeviceDropsSynBelowMSSFloor(t *testing.T) {
	logs := captureLog(t)
	d := ingressDevice(t)
	out := devicePackets(t, d)
	listen := netip.AddrPortFrom(ingressLocal, 7300)
	ln, err := d.ListenTCP(listen)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	received := func() uint64 { return d.stack.Stats().IP.PacketsReceived.Value() }

	for i, mss := range []uint16{48, 535} {
		before := received()
		sendIngress(t, d, tcpSegment(netip.AddrPortFrom(ingressRemote, uint16(41000+i)), listen, header.TCPFlagSyn, 1000, 0, mssOption(mss)))
		if got := d.synMSS.dropped.Load(); got != uint64(i+1) {
			t.Fatalf("after a SYN with MSS %d: %d dropped, want %d", mss, got, i+1)
		}
		if received() != before {
			t.Fatalf("a SYN with MSS %d reached gVisor", mss)
		}
	}
	noTCP(t, out, 300*time.Millisecond)
	select {
	case c := <-accepted:
		c.Close()
		t.Fatal("a SYN below the MSS floor formed a connection")
	default:
	}
	lines := logs()
	if len(lines) != 1 || !strings.Contains(lines[0], "MSS below 536") || !strings.Contains(lines[0], "1 dropped") ||
		!strings.Contains(lines[0], ingressRemote.String()+":41000") || strings.ContainsAny(lines[0], "()") {
		t.Fatalf("drop log = %q; want one line for the first drop, without parentheses", lines)
	}

	for i, opts := range [][]byte{mssOption(536), nil} {
		src := netip.AddrPortFrom(ingressRemote, uint16(42000+i))
		sendIngress(t, d, tcpSegment(src, listen, header.TCPFlagSyn, 5000, 0, opts))
		synAck := nextTCP(t, out, header.TCPFlagSyn|header.TCPFlagAck, 2*time.Second)
		if synAck.DestinationPort() != src.Port() || synAck.AckNumber() != 5001 {
			t.Fatalf("SYN-ACK to port %d acking %d; want port %d acking 5001", synAck.DestinationPort(), synAck.AckNumber(), src.Port())
		}
		sendIngress(t, d, tcpSegment(src, listen, header.TCPFlagAck, 5001, synAck.SequenceNumber()+1, nil))
		select {
		case c := <-accepted:
			c.Close()
		case <-time.After(2 * time.Second):
			t.Fatalf("handshake %d at or above the floor formed no connection", i)
		}
	}
	if got := d.synMSS.dropped.Load(); got != 2 {
		t.Fatalf("accepted handshakes changed the drop count to %d", got)
	}
	if len(logs()) != 1 {
		t.Fatalf("drop log = %q; want one line a minute", logs())
	}
}

// On the dialing side, as on vpsd's userspace netstack, a SYN-ACK below the
// floor is dropped and the dial keeps waiting; a SYN-ACK at the floor then
// completes it.
func TestDeviceDropsSynAckBelowMSSFloor(t *testing.T) {
	captureLog(t)
	d := ingressDevice(t)
	out := devicePackets(t, d)
	remote := netip.AddrPortFrom(ingressRemote, 7400)
	type result struct {
		c   net.Conn
		err error
	}
	done := make(chan result, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := d.DialTCP(ctx, remote)
		done <- result{c, err}
	}()
	syn := nextTCP(t, out, header.TCPFlagSyn, 2*time.Second)
	if syn.Flags().Contains(header.TCPFlagAck) {
		t.Fatalf("first segment of a dial has flags %v", syn.Flags())
	}
	local := netip.AddrPortFrom(ingressLocal, syn.SourcePort())
	before := d.stack.Stats().IP.PacketsReceived.Value()
	sendIngress(t, d, tcpSegment(remote, local, header.TCPFlagSyn|header.TCPFlagAck, 9000, syn.SequenceNumber()+1, mssOption(48)))
	if got := d.synMSS.dropped.Load(); got != 1 {
		t.Fatalf("after a SYN-ACK with MSS 48: %d dropped, want 1", got)
	}
	if d.stack.Stats().IP.PacketsReceived.Value() != before {
		t.Fatal("a SYN-ACK with MSS 48 reached gVisor")
	}
	select {
	case r := <-done:
		t.Fatalf("the dial ended after a SYN-ACK below the floor: %v", r.err)
	case <-time.After(300 * time.Millisecond):
	}
	sendIngress(t, d, tcpSegment(remote, local, header.TCPFlagSyn|header.TCPFlagAck, 9000, syn.SequenceNumber()+1, mssOption(536)))
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("dial after a SYN-ACK at the floor: %v", r.err)
		}
		r.c.(*TCPConn).Abort()
	case <-time.After(5 * time.Second):
		t.Fatal("a SYN-ACK at the floor did not complete the dial")
	}
	if got := d.synMSS.dropped.Load(); got != 1 {
		t.Fatalf("a SYN-ACK at the floor changed the drop count to %d", got)
	}
}

// Two netstacks connect and move data both ways with nothing dropped, at the
// default MTU and at wgft's smallest MTU of 576, where gVisor advertises an
// MSS of exactly 536.
func TestMSSFloorKeepsNetstackConnections(t *testing.T) {
	for _, mtu := range []int{1420, 576} {
		var mu sync.Mutex
		var advertised []uint16
		watch := func(p []byte) bool {
			ip := header.IPv4(p)
			if ip.Protocol() != uint8(header.TCPProtocolNumber) {
				return false
			}
			tcp := header.TCP(p[ip.HeaderLength():])
			if tcp.Flags().Contains(header.TCPFlagSyn) {
				opts := header.ParseSynOptions(tcp.Options(), tcp.Flags().Contains(header.TCPFlagAck))
				mu.Lock()
				advertised = append(advertised, opts.MSS)
				mu.Unlock()
			}
			return false
		}
		p := newTCPPairMTU(t, 1, mtu, nil, watch)
		c, s := p.dial(t)
		bulk(t, c, s, 1<<20)
		bulk(t, s, c, 1<<20)
		c.Close()
		s.Close()
		if a, b := p.a.synMSS.dropped.Load(), p.b.synMSS.dropped.Load(); a != 0 || b != 0 {
			t.Fatalf("MTU %d: %d and %d handshakes dropped", mtu, a, b)
		}
		mu.Lock()
		want := uint16(mtu - header.IPv4MinimumSize - header.TCPMinimumSize)
		if len(advertised) < 2 {
			t.Fatalf("MTU %d: saw %d SYN segments, want the SYN and the SYN-ACK", mtu, len(advertised))
		}
		for _, mss := range advertised {
			if mss != want {
				t.Fatalf("MTU %d: a handshake advertised MSS %d, want %d", mtu, mss, want)
			}
		}
		mu.Unlock()
	}
}

// A SYN that arrives in fragments is checked after reassembly: the MSS option
// sits in the second fragment, behind the flags in the first.
func TestDeviceChecksFragmentedSynAfterReassembly(t *testing.T) {
	captureLog(t)
	d := ingressDevice(t)
	out := devicePackets(t, d)
	listen := netip.AddrPortFrom(ingressLocal, 7500)
	ln, err := d.ListenTCP(listen)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	low := netip.AddrPortFrom(ingressRemote, 43000)
	first, last := splitIngressIPv4(tcpSegment(low, listen, header.TCPFlagSyn, 1000, 0, mssOption(48)), 16)
	sendIngress(t, d, first)
	if got := d.synMSS.dropped.Load(); got != 0 {
		t.Fatalf("a first fragment alone changed the drop count to %d", got)
	}
	sendIngress(t, d, last)
	if got := d.synMSS.dropped.Load(); got != 1 {
		t.Fatalf("after a fragmented SYN with MSS 48: %d dropped, want 1", got)
	}
	noTCP(t, out, 300*time.Millisecond)

	ok := netip.AddrPortFrom(ingressRemote, 43001)
	first, last = splitIngressIPv4(tcpSegment(ok, listen, header.TCPFlagSyn, 2000, 0, mssOption(536)), 16)
	sendIngress(t, d, first)
	sendIngress(t, d, last)
	synAck := nextTCP(t, out, header.TCPFlagSyn|header.TCPFlagAck, 2*time.Second)
	if synAck.DestinationPort() != ok.Port() || synAck.AckNumber() != 2001 {
		t.Fatalf("SYN-ACK to port %d acking %d; want port %d acking 2001", synAck.DestinationPort(), synAck.AckNumber(), ok.Port())
	}
	if got := d.synMSS.dropped.Load(); got != 1 {
		t.Fatalf("a fragmented SYN at the floor changed the drop count to %d", got)
	}
}
