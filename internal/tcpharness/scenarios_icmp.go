package tcpharness

import (
	"bytes"
	"fmt"
	"time"
)

// The helpers of the ICMP family, echo and the ICMP errors TCP acts on, as wgstack.md's UDP, ICMP
// and reassembly section and packet-validation.md describe them. The scenarios themselves are
// scripts under scripts/, which call these through the script language.

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

// The next-hop MTU the accepted errors carry, and how the checks describe a result.
const pmtuLow = 1000

func pmtuDesc(largest int) string {
	if largest <= pmtuLow {
		return fmt.Sprintf("applied: largest packet %d bytes", largest)
	}
	return fmt.Sprintf("ignored: largest packet %d bytes", largest)
}
