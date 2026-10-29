package tcpharness

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// The testbench encodes and decodes its own IPv4 and TCP headers instead of reusing a stack's
// header package, so a bug shared by the engine under test and the codec cannot hide itself.

// TCP flags.
const (
	FlagFIN uint8 = 1 << iota
	FlagSYN
	FlagRST
	FlagPSH
	FlagACK
	FlagURG
	FlagECE
	FlagCWR
)

// FlagString names the set flags, such as "SYN|ACK".
func FlagString(f uint8) string {
	names := []string{"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"}
	var out []string
	for i, n := range names {
		if f&(1<<i) != 0 {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return "none"
	}
	return strings.Join(out, "|")
}

// SACKBlock is one SACK block, [Left, Right) in sequence space (RFC 2018).
type SACKBlock struct{ Left, Right uint32 }

// Timestamps is the TCP timestamps option (RFC 7323).
type Timestamps struct{ Val, Ecr uint32 }

// Options holds the TCP options the harness reads and writes. A nil pointer or a negative WS
// means the option is absent.
type Options struct {
	MSS           *uint16
	WS            int // window scale shift; -1 when absent
	SACKPermitted bool
	TS            *Timestamps
	SACK          []SACKBlock
}

// NoOptions is an Options value with every option absent.
func NoOptions() Options { return Options{WS: -1} }

// Segment is one IPv4 TCP segment as the testbench sees it.
type Segment struct {
	Src, Dst netip.AddrPort
	Seq, Ack uint32
	Flags    uint8
	Window   uint16 // the raw header field, unscaled
	Opts     Options
	Payload  []byte
	TTL      uint8
	DF       bool
}

// Has reports whether every flag in f is set.
func (s Segment) Has(f uint8) bool { return s.Flags&f == f }

// Len is the segment's length in sequence space: the payload plus SYN and FIN.
func (s Segment) Len() uint32 {
	n := uint32(len(s.Payload))
	if s.Has(FlagSYN) {
		n++
	}
	if s.Has(FlagFIN) {
		n++
	}
	return n
}

func (s Segment) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s > %s [%s] seq=%d ack=%d win=%d len=%d", s.Src, s.Dst, FlagString(s.Flags), s.Seq, s.Ack, s.Window, len(s.Payload))
	if s.Opts.MSS != nil {
		fmt.Fprintf(&b, " mss=%d", *s.Opts.MSS)
	}
	if s.Opts.WS >= 0 {
		fmt.Fprintf(&b, " ws=%d", s.Opts.WS)
	}
	if s.Opts.SACKPermitted {
		b.WriteString(" sackOK")
	}
	if s.Opts.TS != nil {
		fmt.Fprintf(&b, " ts=%d/%d", s.Opts.TS.Val, s.Opts.TS.Ecr)
	}
	for _, blk := range s.Opts.SACK {
		fmt.Fprintf(&b, " sack=[%d,%d)", blk.Left, blk.Right)
	}
	return b.String()
}

func marshalOptions(o Options) []byte {
	var b []byte
	if o.MSS != nil {
		b = append(b, 2, 4, byte(*o.MSS>>8), byte(*o.MSS))
	}
	if o.SACKPermitted {
		b = append(b, 1, 1, 4, 2) // NOP NOP SACK-permitted
	}
	if o.TS != nil {
		b = append(b, 1, 1, 8, 10)
		b = binary.BigEndian.AppendUint32(b, o.TS.Val)
		b = binary.BigEndian.AppendUint32(b, o.TS.Ecr)
	}
	if o.WS >= 0 {
		b = append(b, 1, 3, 3, byte(o.WS)) // NOP WS
	}
	if len(o.SACK) > 0 {
		b = append(b, 1, 1, 5, byte(2+8*len(o.SACK)))
		for _, blk := range o.SACK {
			b = binary.BigEndian.AppendUint32(b, blk.Left)
			b = binary.BigEndian.AppendUint32(b, blk.Right)
		}
	}
	for len(b)%4 != 0 {
		b = append(b, 0) // EOL padding
	}
	if len(b) > 40 {
		panic(fmt.Sprintf("tcpharness: %d bytes of TCP options exceed 40", len(b)))
	}
	return b
}

func parseOptions(b []byte) (Options, error) {
	o := NoOptions()
	for len(b) > 0 {
		switch b[0] {
		case 0:
			return o, nil
		case 1:
			b = b[1:]
			continue
		}
		if len(b) < 2 || int(b[1]) < 2 || int(b[1]) > len(b) {
			return o, errors.New("malformed TCP option")
		}
		kind, body := b[0], b[2:b[1]]
		switch {
		case kind == 2 && len(body) == 2:
			v := binary.BigEndian.Uint16(body)
			o.MSS = &v
		case kind == 3 && len(body) == 1:
			o.WS = int(body[0])
		case kind == 4 && len(body) == 0:
			o.SACKPermitted = true
		case kind == 8 && len(body) == 8:
			o.TS = &Timestamps{Val: binary.BigEndian.Uint32(body), Ecr: binary.BigEndian.Uint32(body[4:])}
		case kind == 5 && len(body)%8 == 0:
			for i := 0; i < len(body); i += 8 {
				o.SACK = append(o.SACK, SACKBlock{binary.BigEndian.Uint32(body[i:]), binary.BigEndian.Uint32(body[i+4:])})
			}
		}
		b = b[b[1]:]
	}
	return o, nil
}

func checksum(sum uint32, b []byte) uint32 {
	for len(b) >= 2 {
		sum += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

func fold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func pseudoHeader(src, dst [4]byte, tcpLen int) uint32 {
	s := checksum(0, src[:])
	s = checksum(s, dst[:])
	return s + 6 + uint32(tcpLen)
}

// Marshal encodes s as an IPv4 packet with valid checksums. A zero TTL becomes 64.
func (s Segment) Marshal() []byte {
	opts := marshalOptions(s.Opts)
	tcpLen := 20 + len(opts) + len(s.Payload)
	pkt := make([]byte, 20+tcpLen)
	ip := pkt[:20]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(len(pkt)))
	if s.DF {
		ip[6] = 0x40
	}
	ip[8] = s.TTL
	if ip[8] == 0 {
		ip[8] = 64
	}
	ip[9] = 6
	src, dst := s.Src.Addr().As4(), s.Dst.Addr().As4()
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	binary.BigEndian.PutUint16(ip[10:], fold(checksum(0, ip)))

	t := pkt[20:]
	binary.BigEndian.PutUint16(t[0:], s.Src.Port())
	binary.BigEndian.PutUint16(t[2:], s.Dst.Port())
	binary.BigEndian.PutUint32(t[4:], s.Seq)
	binary.BigEndian.PutUint32(t[8:], s.Ack)
	t[12] = byte((20 + len(opts)) / 4 << 4)
	t[13] = s.Flags
	binary.BigEndian.PutUint16(t[14:], s.Window)
	copy(t[20:], opts)
	copy(t[20+len(opts):], s.Payload)
	binary.BigEndian.PutUint16(t[16:], fold(checksum(pseudoHeader(src, dst, tcpLen), t)))
	return pkt
}

// ErrNotTCP is returned by Parse for a well-formed packet that is not IPv4 TCP.
var ErrNotTCP = errors.New("not an IPv4 TCP packet")

// Parse decodes an IPv4 TCP packet and verifies both checksums. A fragment is an error: the
// engines under test emit none at the harness's MTU.
func Parse(pkt []byte) (Segment, error) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return Segment{}, ErrNotTCP
	}
	ihl := int(pkt[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(pkt[2:]))
	if ihl < 20 || total < ihl || total > len(pkt) {
		return Segment{}, errors.New("malformed IPv4 header")
	}
	if pkt[9] != 6 {
		return Segment{}, ErrNotTCP
	}
	if fold(checksum(0, pkt[:ihl])) != 0 {
		return Segment{}, errors.New("bad IPv4 header checksum")
	}
	if binary.BigEndian.Uint16(pkt[6:])&0x3fff != 0 {
		return Segment{}, errors.New("IPv4 fragment")
	}
	var src, dst [4]byte
	copy(src[:], pkt[12:16])
	copy(dst[:], pkt[16:20])
	t := pkt[ihl:total]
	if len(t) < 20 {
		return Segment{}, errors.New("short TCP header")
	}
	off := int(t[12]>>4) * 4
	if off < 20 || off > len(t) {
		return Segment{}, errors.New("bad TCP data offset")
	}
	if fold(checksum(pseudoHeader(src, dst, len(t)), t)) != 0 {
		return Segment{}, errors.New("bad TCP checksum")
	}
	opts, err := parseOptions(t[20:off])
	if err != nil {
		return Segment{}, err
	}
	return Segment{
		Src:     netip.AddrPortFrom(netip.AddrFrom4(src), binary.BigEndian.Uint16(t[0:])),
		Dst:     netip.AddrPortFrom(netip.AddrFrom4(dst), binary.BigEndian.Uint16(t[2:])),
		Seq:     binary.BigEndian.Uint32(t[4:]),
		Ack:     binary.BigEndian.Uint32(t[8:]),
		Flags:   t[13],
		Window:  binary.BigEndian.Uint16(t[14:]),
		Opts:    opts,
		Payload: append([]byte(nil), t[off:]...),
		TTL:     pkt[8],
		DF:      pkt[6]&0x40 != 0,
	}, nil
}
