package tcpharness

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sort"
)

// The UDP and ICMP scenarios work on whole IPv4 packets, fragments included, so the testbench
// has its own codec for them beside the TCP Segment.

// IP protocol numbers.
const (
	ProtoICMP = 1
	ProtoTCP  = 6
	ProtoUDP  = 17
)

// IPv4 is one IPv4 packet with a 20-byte header.
type IPv4 struct {
	Src, Dst netip.Addr
	Proto    uint8
	ID       uint16
	DF, MF   bool
	Offset   int // the fragment offset in bytes
	TTL      uint8
	Payload  []byte // what follows the header, up to Total Length
}

// Fragment reports whether p is a fragment of a larger datagram.
func (p IPv4) Fragment() bool { return p.MF || p.Offset > 0 }

func (p IPv4) String() string {
	s := fmt.Sprintf("%s > %s proto=%d id=%d len=%d", p.Src, p.Dst, p.Proto, p.ID, 20+len(p.Payload))
	if p.Fragment() {
		s += fmt.Sprintf(" frag=%d", p.Offset)
		if p.MF {
			s += "+"
		}
	}
	if p.DF {
		s += " DF"
	}
	return s
}

// Marshal encodes p with a valid header checksum. A zero TTL becomes 64.
func (p IPv4) Marshal() []byte {
	pkt := make([]byte, 20+len(p.Payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:], p.ID)
	frag := uint16(p.Offset / 8)
	if p.DF {
		frag |= 0x4000
	}
	if p.MF {
		frag |= 0x2000
	}
	binary.BigEndian.PutUint16(pkt[6:], frag)
	pkt[8] = p.TTL
	if pkt[8] == 0 {
		pkt[8] = 64
	}
	pkt[9] = p.Proto
	src, dst := p.Src.As4(), p.Dst.As4()
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[10:], fold(checksum(0, pkt[:20])))
	copy(pkt[20:], p.Payload)
	return pkt
}

// ParseIPv4 decodes an IPv4 packet and verifies its header checksum. Options are skipped.
func ParseIPv4(pkt []byte) (IPv4, error) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return IPv4{}, errors.New("not IPv4")
	}
	ihl := int(pkt[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(pkt[2:]))
	if ihl < 20 || total < ihl || total > len(pkt) {
		return IPv4{}, errors.New("malformed IPv4 header")
	}
	if fold(checksum(0, pkt[:ihl])) != 0 {
		return IPv4{}, errors.New("bad IPv4 header checksum")
	}
	frag := binary.BigEndian.Uint16(pkt[6:])
	return IPv4{
		Src:     netip.AddrFrom4([4]byte(pkt[12:16])),
		Dst:     netip.AddrFrom4([4]byte(pkt[16:20])),
		Proto:   pkt[9],
		ID:      binary.BigEndian.Uint16(pkt[4:]),
		DF:      frag&0x4000 != 0,
		MF:      frag&0x2000 != 0,
		Offset:  int(frag&0x1fff) * 8,
		TTL:     pkt[8],
		Payload: append([]byte(nil), pkt[ihl:total]...),
	}, nil
}

// Fragments splits p's payload at the given byte offsets, each a multiple of 8, into fragments
// in order. Overlapping or duplicate fragments are built by hand from Frag.
func Fragments(p IPv4, cuts ...int) []IPv4 {
	var out []IPv4
	start := 0
	for _, c := range append(cuts, len(p.Payload)) {
		out = append(out, Frag(p, start, c))
		start = c
	}
	return out
}

// Frag is the fragment of p that carries p's payload bytes [from, to); MF is set unless to is the
// end of the payload.
func Frag(p IPv4, from, to int) IPv4 {
	f := p
	f.Offset = from
	f.MF = to < len(p.Payload)
	f.Payload = append([]byte(nil), p.Payload[from:to]...)
	return f
}

// UDP is one UDP datagram.
type UDP struct {
	Src, Dst netip.AddrPort
	Payload  []byte
	Checksum uint16 // the header's field; 0 means the sender computed none
}

// UDPPacket builds an unfragmented IPv4 packet that carries payload from src to dst with a valid
// UDP checksum.
func UDPPacket(src, dst netip.AddrPort, id uint16, payload []byte) IPv4 {
	u := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(u[0:], src.Port())
	binary.BigEndian.PutUint16(u[2:], dst.Port())
	binary.BigEndian.PutUint16(u[4:], uint16(len(u)))
	copy(u[8:], payload)
	sum := fold(checksum(udpPseudo(src.Addr(), dst.Addr(), len(u)), u))
	if sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(u[6:], sum)
	return IPv4{Src: src.Addr(), Dst: dst.Addr(), Proto: ProtoUDP, ID: id, Payload: u}
}

func udpPseudo(src, dst netip.Addr, n int) uint32 {
	s, d := src.As4(), dst.As4()
	sum := checksum(0, s[:])
	sum = checksum(sum, d[:])
	return sum + ProtoUDP + uint32(n)
}

// ParseUDP decodes the UDP datagram of an unfragmented or reassembled packet and verifies its
// checksum when it has one.
func ParseUDP(p IPv4) (UDP, error) {
	if p.Proto != ProtoUDP || p.Fragment() {
		return UDP{}, errors.New("not a whole UDP datagram")
	}
	b := p.Payload
	if len(b) < 8 {
		return UDP{}, errors.New("short UDP header")
	}
	n := int(binary.BigEndian.Uint16(b[4:]))
	if n < 8 || n > len(b) {
		return UDP{}, fmt.Errorf("UDP length %d in a payload of %d bytes", n, len(b))
	}
	b = b[:n]
	if binary.BigEndian.Uint16(b[6:]) != 0 && fold(checksum(udpPseudo(p.Src, p.Dst, n), b)) != 0 {
		return UDP{}, errors.New("bad UDP checksum")
	}
	return UDP{
		Src:      netip.AddrPortFrom(p.Src, binary.BigEndian.Uint16(b[0:])),
		Dst:      netip.AddrPortFrom(p.Dst, binary.BigEndian.Uint16(b[2:])),
		Payload:  append([]byte(nil), b[8:]...),
		Checksum: binary.BigEndian.Uint16(b[6:]),
	}, nil
}

// ICMP types and codes the scenarios use.
const (
	ICMPEchoReply    = 0
	ICMPUnreachable  = 3
	ICMPEchoRequest  = 8
	ICMPTimeExceeded = 11

	CodePortUnreachable = 3
	CodeFragNeeded      = 4
	CodeReassemblyTime  = 1
)

// ICMP is one ICMP message: Rest is the four bytes after the checksum, the identifier and
// sequence number of an echo or the next-hop MTU of Fragmentation Needed.
type ICMP struct {
	Type, Code uint8
	Rest       uint32
	Body       []byte
}

// ICMPPacket builds an unfragmented IPv4 packet carrying m with a valid checksum.
func ICMPPacket(src, dst netip.Addr, id uint16, m ICMP) IPv4 {
	b := make([]byte, 8+len(m.Body))
	b[0], b[1] = m.Type, m.Code
	binary.BigEndian.PutUint32(b[4:], m.Rest)
	copy(b[8:], m.Body)
	binary.BigEndian.PutUint16(b[2:], fold(checksum(0, b)))
	return IPv4{Src: src, Dst: dst, Proto: ProtoICMP, ID: id, Payload: b}
}

// ParseICMP decodes the ICMP message of an unfragmented or reassembled packet and verifies its
// checksum.
func ParseICMP(p IPv4) (ICMP, error) {
	if p.Proto != ProtoICMP || p.Fragment() {
		return ICMP{}, errors.New("not a whole ICMP message")
	}
	b := p.Payload
	if len(b) < 8 {
		return ICMP{}, errors.New("short ICMP header")
	}
	if fold(checksum(0, b)) != 0 {
		return ICMP{}, errors.New("bad ICMP checksum")
	}
	return ICMP{Type: b[0], Code: b[1], Rest: binary.BigEndian.Uint32(b[4:]), Body: append([]byte(nil), b[8:]...)}, nil
}

// Quote is the start of the datagram an ICMP error quotes: its IPv4 header fields and the bytes
// of its payload the error carries.
type Quote struct {
	IPv4
	Bytes int // the length of the quote, header included
}

// ParseQuote reads the quoted datagram of an ICMP error's body. The quoted header's checksum is
// not checked, since a router may have changed the TTL.
func ParseQuote(body []byte) (Quote, bool) {
	if len(body) < 20 || body[0]>>4 != 4 {
		return Quote{}, false
	}
	ihl := int(body[0]&0x0f) * 4
	if ihl < 20 || len(body) < ihl {
		return Quote{}, false
	}
	frag := binary.BigEndian.Uint16(body[6:])
	return Quote{IPv4: IPv4{
		Src:     netip.AddrFrom4([4]byte(body[12:16])),
		Dst:     netip.AddrFrom4([4]byte(body[16:20])),
		Proto:   body[9],
		ID:      binary.BigEndian.Uint16(body[4:]),
		DF:      frag&0x4000 != 0,
		MF:      frag&0x2000 != 0,
		Offset:  int(frag&0x1fff) * 8,
		TTL:     body[8],
		Payload: append([]byte(nil), body[ihl:]...),
	}, Bytes: len(body)}, true
}

// reassembler puts the DUT's fragments back together, the way the testbench's own stack would.
type reassembler struct {
	parts map[uint16][]IPv4
}

func newReassembler() *reassembler { return &reassembler{parts: map[uint16][]IPv4{}} }

// add takes one packet and returns the whole datagram once every fragment of it is in. An
// unfragmented packet is returned as it is.
func (r *reassembler) add(p IPv4) (IPv4, bool) {
	if !p.Fragment() {
		return p, true
	}
	fs := append(r.parts[p.ID], p)
	r.parts[p.ID] = fs
	sort.Slice(fs, func(i, j int) bool { return fs[i].Offset < fs[j].Offset })
	if fs[len(fs)-1].MF {
		return IPv4{}, false
	}
	end := 0
	for _, f := range fs {
		if f.Offset != end {
			return IPv4{}, false
		}
		end += len(f.Payload)
	}
	whole := fs[0]
	whole.MF, whole.Offset, whole.Payload = false, 0, nil
	for _, f := range fs {
		whole.Payload = append(whole.Payload, f.Payload...)
	}
	delete(r.parts, p.ID)
	return whole, true
}
