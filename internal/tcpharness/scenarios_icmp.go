package tcpharness

import (
	"bytes"
	"fmt"
	"net/netip"
	"time"
)

// The ICMP family: echo, and the ICMP errors TCP acts on, as wgstack.md's UDP, ICMP and
// reassembly section and packet-validation.md describe them.

// echo sends an echo request with payload, split at cuts when there are any, and returns the
// reassembled reply.
func echo(h *H, ipid uint16, ident, seq uint16, payload []byte, cuts ...int) (m ICMP, frags int, df, ok bool) {
	h.T.Helper()
	req := ICMPPacket(PeerAddr, DUTAddr, ipid, ICMP{Type: ICMPEchoRequest, Rest: uint32(ident)<<16 | uint32(seq), Body: payload})
	for _, f := range Fragments(req, cuts...) {
		h.InjectIP(f)
	}
	r := newReassembler()
	deadline := h.Now().Add(time.Second)
	for {
		p, got := h.Packet(max(deadline.Sub(h.Now()), 0), func(p IPv4) bool { return toPeer(p) && p.Proto == ProtoICMP })
		if !got {
			return ICMP{}, frags, df, false
		}
		frags++
		df = df || p.DF
		if whole, done := r.add(p); done {
			m, err := ParseICMP(whole)
			if err != nil {
				h.T.Logf("reply ignored: %v", err)
				continue
			}
			return m, frags, df, true
		}
	}
}

func echoDesc(m ICMP, ok bool, ident, seq uint16, payload []byte) (bool, string) {
	good := ok && m.Type == ICMPEchoReply && m.Code == 0 && m.Rest == uint32(ident)<<16|uint32(seq) && bytes.Equal(m.Body, payload)
	if !ok {
		return false, "no reply"
	}
	return good, fmt.Sprintf("type %d code %d, same identifier and sequence %v, %d of %d bytes equal %v",
		m.Type, m.Code, m.Rest == uint32(ident)<<16|uint32(seq), len(m.Body), len(payload), bytes.Equal(m.Body, payload))
}

// icmpEcho checks echo replies: a small request, one that fills the MTU, one larger than the
// MTU that arrives in fragments, and one with a wrong checksum. wgstack.md lists the reply to the
// one larger than the MTU among the choices not checked against Linux.
func icmpEcho(h *H) {
	small := pattern(56, 0xa1)
	m, _, df, ok := echo(h, 601, 0x1234, 1, small)
	good, got := echoDesc(m, ok, 0x1234, 1, small)
	h.Check("reply", good, "an echo request draws a reply with its identifier, sequence and data", got)
	if ok {
		// Linux answers from a socket whose path MTU discovery is off, IP_PMTUDISC_DONT
		// (v6.1:net/ipv4/icmp.c:1499), so its replies carry no DF
		h.Check("reply.df-clear", !df, "as Linux, the reply carries no DF", yesNo(df, "DF set", "DF clear"))
	}

	full := pattern(h.DUT.MTU()-28, 0xa2)
	m, frags, _, ok := echo(h, 602, 0x1234, 2, full)
	good, got = echoDesc(m, ok, 0x1234, 2, full)
	h.Check("full-mtu", good && frags == 1, "a request that fills the MTU draws one unfragmented reply",
		fmt.Sprintf("%s, %d packets", got, frags))

	big := pattern(3000, 0xa3)
	m, frags, _, ok = echo(h, 603, 0x1234, 3, big, 1400, 2800)
	good, got = echoDesc(m, ok, 0x1234, 3, big)
	h.Check("oversized", good, "RFC 1122 3.2.2.6: a request reassembled from fragments draws the whole reply, fragmented as the MTU needs", got)
	if ok {
		h.Measure("oversized-reply-packets", frags)
	}

	bad := ICMPPacket(PeerAddr, DUTAddr, 604, ICMP{Type: ICMPEchoRequest, Rest: 0x12340004, Body: pattern(56, 0xa4)})
	bad.Payload[10] ^= 0xff
	h.InjectIP(bad)
	_, ok = h.Packet(300*time.Millisecond, func(p IPv4) bool { return toPeer(p) && p.Proto == ProtoICMP })
	h.Check("bad-checksum", !ok, "a request with a wrong checksum draws nothing", yesNo(ok, "a reply", "nothing"))
}

// pmtuFlight opens a connection, has the DUT send four full segments and acknowledges the first
// two, so SND.UNA is the third segment's start and SND.NXT the fourth's end.
func pmtuFlight(h *H, port uint16) (*Peer, Conn, []Segment) {
	h.T.Helper()
	l := h.Listen(port)
	p, _, c := h.Connect(l, port, StandardSYN())
	segs, _ := flight(h, p, c, 4, byte(port))
	// The handshake's RTT is near zero, so a tail loss probe may follow the flight at once; it is
	// taken here, before the error, and not counted as a packet sent after it.
	burst(p)
	p.RcvNxt = segs[1].Seq + uint32(len(segs[1].Payload))
	p.SendAck()
	return p, c, segs
}

// pmtuAfter injects the ICMP error icmp, collects what the DUT sends for 200 ms, acknowledges
// the whole flight and has the application write four segments more. It returns the largest
// packet the DUT sends after the error, and whether a packet of the new data carried DF.
func pmtuAfter(h *H, p *Peer, c Conn, segs []Segment, icmp []byte) (int, bool) {
	h.T.Helper()
	h.T.Logf("-> ICMP error % x", icmp[:min(len(icmp), 28)])
	if err := h.DUT.Inject(icmp); err != nil {
		h.T.Fatalf("inject: %v", err)
	}
	largest := 0
	deadline := h.Now().Add(200 * time.Millisecond)
	for {
		s, ok := p.Next(max(deadline.Sub(h.Now()), 0))
		if !ok {
			break
		}
		if isData(s) {
			largest = max(largest, len(s.Marshal()))
		}
	}
	h.Measure("resent-largest", largest)
	last := segs[len(segs)-1]
	p.RcvNxt = last.Seq + uint32(len(last.Payload))
	p.SendAck()
	if _, err := c.Write(pattern(4*segSize(p), 0xb1)); err != nil {
		h.T.Fatalf("write: %v", err)
	}
	df := false
	more, _ := burst(p)
	for _, s := range more {
		largest = max(largest, len(s.Marshal()))
		df = df || s.DF
	}
	h.Require("second-flight", len(more) > 0, "the application's second write leaves", fmt.Sprintf("%d segments", len(more)))
	return largest, df
}

// The next-hop MTU the accepted errors carry, and how the checks describe a result.
const pmtuLow = 1000

func pmtuDesc(largest int) string {
	if largest <= pmtuLow {
		return fmt.Sprintf("applied: largest packet %d bytes", largest)
	}
	return fmt.Sprintf("ignored: largest packet %d bytes", largest)
}

// icmpFragNeeded lowers the path MTU with a well-formed Fragmentation Needed that quotes an
// unacknowledged segment: RFC 1191 and RFC 5927 accept it.
func icmpFragNeeded(h *H) {
	p, c, segs := pmtuFlight(h, 8101)
	largest, _ := pmtuAfter(h, p, c, segs, FragNeeded(PeerAddr, segs[2].Marshal(), pmtuLow))
	h.Check("applied", largest <= pmtuLow, "every packet after the error fits the MTU of 1000 it names", pmtuDesc(largest))
}

// icmpFragNeededAcked quotes a segment the testbench already acknowledged. RFC 5927 4.1 and
// wgstack.md accept the error only when the quoted sequence number is in [SND.UNA, SND.NXT].
func icmpFragNeededAcked(h *H) {
	p, c, segs := pmtuFlight(h, 8102)
	largest, _ := pmtuAfter(h, p, c, segs, FragNeeded(PeerAddr, segs[0].Marshal(), pmtuLow))
	h.Check("ignored", largest > pmtuLow, "an error quoting acknowledged data leaves the MTU alone", pmtuDesc(largest))
}

// icmpFragNeededUnsent quotes a sequence number beyond SND.NXT.
func icmpFragNeededUnsent(h *H) {
	p, c, segs := pmtuFlight(h, 8103)
	q := segs[3]
	q.Seq += 100000
	largest, _ := pmtuAfter(h, p, c, segs, FragNeeded(PeerAddr, q.Marshal(), pmtuLow))
	h.Check("ignored", largest > pmtuLow, "an error quoting data never sent leaves the MTU alone", pmtuDesc(largest))
}

// icmpFragNeededSource sends a well-formed error from an address other than the quoted
// datagram's destination. packet-validation.md, the ICMP error ingress: no router sits inside
// the tunnel, so only the peer itself sends a valid error.
func icmpFragNeededSource(h *H) {
	p, c, segs := pmtuFlight(h, 8104)
	router := netip.MustParseAddr("10.200.0.9")
	largest, _ := pmtuAfter(h, p, c, segs, FragNeeded(router, segs[2].Marshal(), pmtuLow))
	h.Check("ignored", largest > pmtuLow, "an error from another source than the quoted destination leaves the MTU alone", pmtuDesc(largest))
}

// icmpFragNeededOtherFlow quotes a flow the DUT does not have: the testbench's port plus one.
func icmpFragNeededOtherFlow(h *H) {
	p, c, segs := pmtuFlight(h, 8105)
	q := segs[2]
	q.Dst = netip.AddrPortFrom(q.Dst.Addr(), q.Dst.Port()+1)
	largest, _ := pmtuAfter(h, p, c, segs, FragNeeded(PeerAddr, q.Marshal(), pmtuLow))
	h.Check("ignored", largest > pmtuLow, "an error quoting another flow leaves this connection's MTU alone", pmtuDesc(largest))
}

// icmpFragNeededFloor names a next-hop MTU of 300, below Linux's min_pmtu of 552.
// packet-validation.md: wgft drops the error; Linux sets the path MTU to 552 and clears DF.
func icmpFragNeededFloor(h *H) {
	p, c, segs := pmtuFlight(h, 8106)
	largest, df := pmtuAfter(h, p, c, segs, FragNeeded(PeerAddr, segs[2].Marshal(), 300))
	h.Check("floor", largest >= 552, "no packet shrinks below Linux's min_pmtu of 552", fmt.Sprintf("largest packet %d bytes", largest))
	h.Check("ignored", largest > pmtuLow, "packet-validation.md: the error below the floor is dropped", pmtuDesc(largest))
	h.Measure("df-after", df)
}
