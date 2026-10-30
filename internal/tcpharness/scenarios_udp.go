package tcpharness

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// The UDP family: wgstack's UDP and reassembly, stage 2 of wgstack.md, against the same
// testbench as TCP. The DUT's socket is unconnected, the way wgft's relay receives UDP.

// ListenUDP opens a UDP socket on the DUT and closes it at the end of the scenario.
func (h *H) ListenUDP(port uint16) net.PacketConn {
	h.T.Helper()
	c, err := h.DUT.ListenUDP(port)
	if err != nil {
		h.T.Fatalf("listen on UDP %d: %v", port, err)
	}
	h.T.Cleanup(func() { c.Close() })
	return c
}

// InjectIP hands one IPv4 packet to the DUT.
func (h *H) InjectIP(p IPv4) {
	h.T.Helper()
	h.T.Logf("-> %v", p)
	if err := h.DUT.Inject(p.Marshal()); err != nil {
		h.T.Fatalf("inject %v: %v", p, err)
	}
}

// Packet returns the first IPv4 packet the DUT emits within d that match accepts. Other packets
// are logged and dropped, and a packet larger than the MTU fails the scenario as in Peer.Next.
func (h *H) Packet(d time.Duration, match func(IPv4) bool) (IPv4, bool) {
	deadline := h.Now().Add(d)
	for {
		pkt, ok := h.next(max(deadline.Sub(h.Now()), 0))
		if !ok {
			return IPv4{}, false
		}
		if len(pkt) > h.DUT.MTU() {
			h.T.Errorf("FAIL  emitted packet on %s: at most the MTU of %d bytes; got: %d bytes", h.engine.Name, h.DUT.MTU(), len(pkt))
		}
		p, err := ParseIPv4(pkt)
		if err != nil {
			h.T.Logf("emitted packet ignored: %v: % x", err, pkt[:min(len(pkt), 40)])
			continue
		}
		if match(p) {
			h.T.Logf("<- %v", p)
			return p, true
		}
		h.T.Logf("packet ignored: %v", p)
	}
}

// readDatagram reads one datagram from c within d of real time; the DUT's sockets keep real-time
// deadlines on every engine.
func readDatagram(c net.PacketConn, d time.Duration) ([]byte, netip.AddrPort, error) {
	buf := make([]byte, 70000)
	c.SetReadDeadline(time.Now().Add(d))
	n, from, err := c.ReadFrom(buf)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	ua, ok := from.(*net.UDPAddr)
	if !ok {
		return buf[:n], netip.AddrPort{}, fmt.Errorf("source is a %T", from)
	}
	return buf[:n], ua.AddrPort(), nil
}

func toPeer(p IPv4) bool { return p.Src == DUTAddr && p.Dst == PeerAddr }

// udpFrom is the testbench's UDP endpoint for a scenario; port is distinct per scenario.
func udpFrom(port uint16) netip.AddrPort { return netip.AddrPortFrom(PeerAddr, port) }

// udpDatagram checks delivery, the source address, checksums and the reply.
func udpDatagram(h *H) {
	const port = 5301
	c := h.ListenUDP(port)
	dst := netip.AddrPortFrom(DUTAddr, port)
	src := udpFrom(41001)

	msg := pattern(100, 0x11)
	h.InjectIP(UDPPacket(src, dst, 101, msg))
	got, from, err := readDatagram(c, time.Second)
	h.Check("delivered", err == nil && bytes.Equal(got, msg), "the application reads the 100-byte datagram",
		fmt.Sprintf("%d bytes, equal %v, error %s", len(got), bytes.Equal(got, msg), errKind(err)))
	h.Check("source", from == src, "ReadFrom names the testbench's address and port",
		yesNo(from == src, "the sender", "another address"))

	// A datagram with a wrong checksum is dropped; the next good one is the next read.
	bad := UDPPacket(src, dst, 102, pattern(100, 0x22))
	bad.Payload[8] ^= 0xff
	h.InjectIP(bad)
	good := pattern(100, 0x33)
	h.InjectIP(UDPPacket(src, dst, 103, good))
	got, _, err = readDatagram(c, time.Second)
	h.Check("bad-checksum-dropped", err == nil && bytes.Equal(got, good), "a datagram with a wrong checksum is dropped",
		yesNo(err == nil && bytes.Equal(got, good), "only the good datagram", fmt.Sprintf("%d bytes, error %s", len(got), errKind(err))))

	// RFC 768: a zero checksum means the sender computed none.
	none := UDPPacket(src, dst, 104, pattern(100, 0x44))
	none.Payload[6], none.Payload[7] = 0, 0
	h.InjectIP(none)
	got, _, err = readDatagram(c, time.Second)
	h.Check("no-checksum", err == nil && bytes.Equal(got, none.Payload[8:]), "a datagram without a checksum is delivered",
		fmt.Sprintf("%d bytes, error %s", len(got), errKind(err)))

	reply := pattern(200, 0x55)
	if _, err := c.WriteTo(reply, net.UDPAddrFromAddrPort(src)); err != nil {
		h.T.Fatalf("WriteTo: %v", err)
	}
	p, ok := h.Packet(time.Second, func(p IPv4) bool { return toPeer(p) && p.Proto == ProtoUDP })
	u, perr := ParseUDP(p)
	h.Check("reply", ok && perr == nil && u.Checksum != 0 && u.Src == dst && u.Dst == src && bytes.Equal(u.Payload, reply),
		"the reply leaves from the socket's port to the sender with a valid, nonzero checksum, as Linux and gVisor send",
		replyDesc(ok, perr, u, reply))
	if ok {
		h.Check("reply.df-clear", !p.DF, "wgstack.md, UDP is sent without DF", yesNo(p.DF, "DF set", "DF clear"))
		h.Measure("reply-ttl", p.TTL)
	}
}

func replyDesc(ok bool, err error, u UDP, want []byte) string {
	switch {
	case !ok:
		return "no reply"
	case err != nil:
		return err.Error()
	case u.Checksum == 0:
		return "no checksum"
	case !bytes.Equal(u.Payload, want):
		return fmt.Sprintf("%d bytes, different", len(u.Payload))
	}
	return "valid reply"
}

// udpLarge sends the largest UDP datagram IPv4 carries in MTU-sized fragments, and has the
// application send it back.
func udpLarge(h *H) {
	const port = 5302
	const size = 65507
	c := h.ListenUDP(port)
	dst := netip.AddrPortFrom(DUTAddr, port)
	src := udpFrom(41002)
	msg := pattern(size, 0x66)
	whole := UDPPacket(src, dst, 201, msg)
	var cuts []int
	for off := 1400; off < len(whole.Payload); off += 1400 {
		cuts = append(cuts, off)
	}
	for _, f := range Fragments(whole, cuts...) {
		h.InjectIP(f)
	}
	got, _, err := readDatagram(c, 2*time.Second)
	h.Check("delivered", err == nil && bytes.Equal(got, msg), "the application reads all 65,507 bytes",
		fmt.Sprintf("%d bytes, equal %v, error %s", len(got), bytes.Equal(got, msg), errKind(err)))

	if _, err := c.WriteTo(msg, net.UDPAddrFromAddrPort(src)); err != nil {
		h.Check("reply.written", false, "WriteTo takes 65,507 bytes", errKind(err))
	} else {
		r := newReassembler()
		frags, df, zeroID := 0, false, false
		var back IPv4
		done := false
		deadline := h.Now().Add(3 * time.Second)
		for !done {
			p, ok := h.Packet(max(deadline.Sub(h.Now()), 0), func(p IPv4) bool { return toPeer(p) && p.Proto == ProtoUDP })
			if !ok {
				break
			}
			frags++
			df = df || p.DF
			zeroID = zeroID || p.ID == 0
			back, done = r.add(p)
		}
		u, perr := ParseUDP(back)
		h.Check("reply.reassembles", done && perr == nil && u.Checksum != 0 && bytes.Equal(u.Payload, msg),
			"the fragments of the reply reassemble into the 65,507 bytes with a valid, nonzero checksum",
			replyDesc(done, perr, u, msg))
		h.Check("reply.df-clear", !df, "no fragment carries DF", yesNo(df, "DF set", "DF clear"))
		h.Check("reply.id-nonzero", !zeroID, "the fragments carry a nonzero IP ID", yesNo(zeroID, "ID 0", "nonzero"))
		h.Measure("reply-fragments", frags)
	}

	_, err = c.WriteTo(make([]byte, size+1), net.UDPAddrFromAddrPort(src))
	h.Check("oversize-refused", err != nil, "WriteTo refuses 65,508 bytes", errKind(err))
}

// fragmented is a datagram of n payload bytes to the DUT's port, split at 1000 and 2000.
func fragmented(src, dst netip.AddrPort, id uint16, n int, salt byte) ([]byte, []IPv4) {
	msg := pattern(n, salt)
	return msg, Fragments(UDPPacket(src, dst, id, msg), 1000, 2000)
}

// udpReassembly checks reassembly with fragments in order, out of order, duplicated and
// overlapping.
func udpReassembly(h *H) {
	const port = 5303
	c := h.ListenUDP(port)
	dst := netip.AddrPortFrom(DUTAddr, port)
	src := udpFrom(41003)
	expect := func(id string, what string, want []byte) {
		h.T.Helper()
		got, _, err := readDatagram(c, time.Second)
		h.Check(id, err == nil && bytes.Equal(got, want), what,
			yesNo(err == nil && bytes.Equal(got, want), "delivered", fmt.Sprintf("%d bytes, error %s", len(got), errKind(err))))
	}
	none := func(id string, what string) {
		h.T.Helper()
		got, _, err := readDatagram(c, 300*time.Millisecond)
		h.Check(id, err != nil, what, yesNo(err != nil, "nothing", fmt.Sprintf("a datagram of %d bytes", len(got))))
	}

	msg, fs := fragmented(src, dst, 301, 3000, 0x71)
	for _, f := range fs {
		h.InjectIP(f)
	}
	expect("in-order", "three fragments in order reassemble", msg)

	msg, fs = fragmented(src, dst, 302, 3000, 0x72)
	for i := len(fs) - 1; i >= 0; i-- {
		h.InjectIP(fs[i])
	}
	expect("out-of-order", "three fragments in reverse order reassemble", msg)

	msg, fs = fragmented(src, dst, 303, 3000, 0x73)
	h.InjectIP(fs[0])
	h.InjectIP(fs[1])
	h.InjectIP(fs[1])
	h.InjectIP(fs[2])
	expect("duplicate", "an exact duplicate fragment does not stop reassembly", msg)
	none("duplicate.once", "the datagram is delivered once")

	// The second fragment starts 8 bytes inside the first, with the same bytes there.
	_, fs = fragmented(src, dst, 304, 3000, 0x74)
	whole := UDPPacket(src, dst, 304, pattern(3000, 0x74))
	h.InjectIP(fs[0])
	h.InjectIP(Frag(whole, 992, 2000))
	h.InjectIP(fs[2])
	none("overlap-dropped", "packet-validation.md and Linux since 4.19: an overlapping fragment drops the datagram")
	// The missing piece, exactly: a stack that dropped only the overlapping fragment completes the
	// datagram now; one that dropped the datagram, as Linux kills the queue
	// (v6.1:net/ipv4/ip_fragment.c:383-391), has only the later pieces left and delivers nothing.
	h.InjectIP(fs[1])
	none("overlap-drops-datagram", "the overlap dropped the whole datagram, not only the overlapping fragment")

	msg, fs = fragmented(src, dst, 305, 3000, 0x75)
	for _, f := range fs {
		h.InjectIP(f)
	}
	expect("after", "a later datagram still reassembles", msg)
}

// udpReassemblyTimeout leaves two datagrams incomplete: one has its first fragment, the other
// only its second. RFC 792 and RFC 1122 3.3.2: the timeout sends Time Exceeded, code 1, for the
// first only.
func udpReassemblyTimeout(h *H) {
	const port = 5304
	c := h.ListenUDP(port)
	dst := netip.AddrPortFrom(DUTAddr, port)
	src := udpFrom(41004)
	_, a := fragmented(src, dst, 401, 3000, 0x81)
	_, b := fragmented(src, dst, 402, 3000, 0x82)
	h.InjectIP(a[0])
	h.InjectIP(b[1])
	start := h.Now()
	isTE := func(p IPv4) bool {
		if !toPeer(p) || p.Proto != ProtoICMP {
			return false
		}
		m, err := ParseICMP(p)
		return err == nil && m.Type == ICMPTimeExceeded
	}
	p, ok := h.Packet(35*time.Second, isTE)
	waited := h.Now().Sub(start)
	m, _ := ParseICMP(p)
	q, qok := ParseQuote(m.Body)
	h.Check("time-exceeded", ok && m.Code == CodeReassemblyTime && qok && q.ID == 401 && q.Src == PeerAddr && q.Dst == DUTAddr && q.Proto == ProtoUDP,
		"within 35 s, Time Exceeded code 1 quotes the datagram that has its first fragment",
		yesNo(ok, fmt.Sprintf("code %d quoting ID %d", m.Code, q.ID), "no Time Exceeded"))
	if ok {
		h.Measure("time-exceeded-after-ms", waited.Milliseconds())
		h.Check("time-exceeded.not-early", waited >= 25*time.Second,
			"the incomplete datagram is kept about 30 s, the lifetime of packet-validation.md and Linux's ipfrag_time, before Time Exceeded",
			fmt.Sprintf("after %.0f s", waited.Seconds()))
		h.Measure("time-exceeded-quote-bytes", q.Bytes)
		h.Check("time-exceeded.quote", qok && q.Offset == 0 && len(q.Payload) >= 8, "the quote is the first fragment's header and at least 8 bytes of it",
			fmt.Sprintf("offset %d, %d payload bytes", q.Offset, len(q.Payload)))
	}
	p, ok = h.Packet(3*time.Second, isTE)
	m, _ = ParseICMP(p)
	q, _ = ParseQuote(m.Body)
	h.Check("no-first-no-icmp", !ok, "nothing is sent for the datagram without its first fragment",
		yesNo(ok, fmt.Sprintf("Time Exceeded quoting ID %d", q.ID), "nothing"))
	_, _, err := readDatagram(c, 100*time.Millisecond)
	h.Check("not-delivered", err != nil, "neither datagram reaches the application", errKind(err))
}

// udpClosedPort sends to a port without a socket and to one whose socket has closed. Linux and
// wgstack.md answer with Port Unreachable.
func udpClosedPort(h *H) {
	const port = 5305
	src := udpFrom(41005)
	isPU := func(p IPv4) bool {
		if !toPeer(p) || p.Proto != ProtoICMP {
			return false
		}
		m, err := ParseICMP(p)
		return err == nil && m.Type == ICMPUnreachable
	}
	check := func(id string, dport uint16, ipid uint16, what string) {
		h.T.Helper()
		h.InjectIP(UDPPacket(src, netip.AddrPortFrom(DUTAddr, dport), ipid, pattern(64, 0x91)))
		p, ok := h.Packet(time.Second, isPU)
		m, _ := ParseICMP(p)
		q, qok := ParseQuote(m.Body)
		quoted := qok && q.ID == ipid && q.Src == PeerAddr && q.Dst == DUTAddr && q.Proto == ProtoUDP && len(q.Payload) >= 8 &&
			bytes.Equal(q.Payload[:4], UDPPacket(src, netip.AddrPortFrom(DUTAddr, dport), 0, nil).Payload[:4])
		h.Check(id, ok && m.Code == CodePortUnreachable && quoted, what,
			yesNo(ok, fmt.Sprintf("code %d, quote matches %v", m.Code, quoted), "no Port Unreachable"))
		if ok {
			h.Measure(id+"-quote-bytes", q.Bytes)
		}
	}
	check("port-unreachable", port, 501, "a datagram to a port without a socket draws Port Unreachable quoting it")
	c := h.ListenUDP(port + 1)
	c.Close()
	check("after-close", port+1, 502, "a datagram to a closed socket's port draws Port Unreachable")
}
