package nettun

// The pinned gVisor IPv4 implementation exposes OnReassemblyTimeout through
// NetworkProtocolInstance. This adapter rebuilds only the PacketBuffer view
// needed by that callback; gVisor still chooses route, source, quote, checksum
// and ICMP suppression/rate limiting. Parameter Problem uses a separate path.

import (
	"bytes"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// emitReassemblyTimeout and emitOptionParameterProblem take no lock. They
// read the immutable local address and call the stack, whose ICMP output is
// a nonblocking write into the finite channel queue.
func (t *Device) emitReassemblyTimeout(n ipv4FragmentNotice) bool {
	if !n.HasFirst || n.QuoteLen < 28 {
		return false
	}
	quote := n.Quote[:n.QuoteLen]
	hlen := int(quote[0]&15) * 4
	if hlen < 20 || hlen > 60 || len(quote) < hlen+8 || !ipv4ChecksumOK(quote[:hlen]) ||
		quote[6]&0x1f != 0 || quote[7] != 0 ||
		!bytes.Equal(quote[16:20], t.local.AsSlice()) {
		return false
	}
	proto := t.stack.NetworkProtocolInstance(ipv4.ProtocolNumber)
	handler, ok := proto.(interface{ OnReassemblyTimeout(*stack.PacketBuffer) })
	if !ok {
		return false
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(quote)})
	defer pkt.DecRef()
	pkt.NICID = 1
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	pkt.NetworkPacketInfo.LocalAddressBroadcast = bytes.Equal(quote[16:20], []byte{255, 255, 255, 255})
	if _, ok := pkt.NetworkHeader().Consume(hlen); !ok {
		return false
	}
	if quote[9] == uint8(header.ICMPv4ProtocolNumber) {
		if _, ok := pkt.TransportHeader().Consume(8); !ok {
			return false
		}
	}
	handler.OnReassemblyTimeout(pkt)
	return true
}

// The status is deliberately separate from TUN acceptance. A suppressed ICMP
// or a route failure is a network-layer outcome, not an unimplemented handoff.
type icmpOptionOutcome uint8

const (
	icmpOptionUnavailable icmpOptionOutcome = iota
	icmpOptionSent
	icmpOptionSuppressed
	icmpOptionFailed
)

// emitOptionParameterProblem handles malformed options on the offending
// fragment. The offending packet is still owned by Device.Write, so the
// quote can be copied synchronously up to gVisor's 576/route-MTU bound without
// increasing the retained reassembly notice budget.
func (t *Device) emitOptionParameterProblem(n ipv4FragmentNotice, offending []byte) icmpOptionOutcome {
	if n.Pointer < 20 || len(offending) < header.IPv4MinimumSize {
		return icmpOptionUnavailable
	}
	var saved []byte
	if n.HasFirst {
		if n.QuoteLen < header.IPv4MinimumSize {
			return icmpOptionUnavailable
		}
		saved = n.Quote[:n.QuoteLen]
	} else {
		// No first-fragment quote exists for a malformed option on a later
		// fragment. Use that same offending fragment during this Write call.
		saved = offending
	}
	hlen := int(saved[0]&15) * 4
	if hlen < 20 || hlen > 60 || len(saved) < hlen || len(offending) < hlen || int(n.Pointer) >= hlen {
		return icmpOptionUnavailable
	}
	// The fixed stack can quote an actual payload shorter than eight bytes.
	// A fragment with no payload is dropped before it checks options.
	if len(saved) == hlen || len(offending) == hlen {
		return icmpOptionSuppressed
	}
	quotePrefixLen := hlen + header.ICMPv4MinimumErrorPayloadSize
	if quotePrefixLen > len(saved) {
		quotePrefixLen = len(saved)
	}
	if len(offending) < quotePrefixLen {
		return icmpOptionUnavailable
	}
	// A copied-option shape conflict can carry the saved first quote although
	// the offending input was later. Only the exact original first is eligible.
	if (n.HasFirst && (!bytes.Equal(offending[:quotePrefixLen], saved[:quotePrefixLen]) ||
		offending[6]&0x1f != 0 || offending[7] != 0)) ||
		!ipv4ChecksumOK(saved[:hlen]) ||
		int(header.IPv4(offending).TotalLength()) != len(offending) {
		return icmpOptionUnavailable
	}
	if bytes.Equal(saved[12:16], []byte{0, 0, 0, 0}) ||
		saved[16]&0xf0 == 0xe0 || bytes.Equal(saved[16:20], []byte{255, 255, 255, 255}) ||
		!bytes.Equal(saved[16:20], t.local.AsSlice()) {
		return icmpOptionSuppressed
	}
	if saved[9] == byte(header.ICMPv4ProtocolNumber) {
		switch header.ICMPv4Type(saved[hlen]) {
		case header.ICMPv4EchoReply, header.ICMPv4Echo,
			header.ICMPv4Timestamp, header.ICMPv4TimestampReply,
			header.ICMPv4InfoRequest, header.ICMPv4InfoReply:
		default:
			return icmpOptionSuppressed
		}
	}
	route, err := t.stack.FindRoute(1, tcpip.AddrFromSlice(saved[16:20]), tcpip.AddrFromSlice(saved[12:16]), ipv4.ProtocolNumber, false)
	if err != nil {
		return icmpOptionFailed
	}
	defer route.Release()
	sent := t.stack.Stats().ICMP.V4.PacketsSent
	if !t.stack.AllowICMPMessage() {
		sent.RateLimited.Increment()
		return icmpOptionSuppressed
	}
	mtu := int(route.MTU())
	const maxIPData = header.IPv4MinimumProcessableDatagramSize - header.IPv4MinimumSize
	if mtu > maxIPData {
		mtu = maxIPData
	}
	available := mtu - header.ICMPv4MinimumSize
	if available < hlen+header.ICMPv4MinimumErrorPayloadSize {
		return icmpOptionSuppressed
	}
	quoteLen := len(offending)
	if quoteLen > available {
		quoteLen = available
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(route.MaxHeaderLength()) + header.ICMPv4MinimumSize,
		Payload:            buffer.MakeWithData(offending[:quoteLen]),
	})
	defer pkt.DecRef()
	pkt.TransportProtocolNumber = header.ICMPv4ProtocolNumber
	icmp := header.ICMPv4(pkt.TransportHeader().Push(header.ICMPv4MinimumSize))
	icmp.SetType(header.ICMPv4ParamProblem)
	icmp.SetCode(header.ICMPv4UnusedCode)
	icmp.SetPointer(n.Pointer)
	icmp.SetChecksum(header.ICMPv4Checksum(icmp, pkt.Data().Checksum()))
	if err := route.WritePacket(stack.NetworkHeaderParams{Protocol: header.ICMPv4ProtocolNumber, TTL: route.DefaultTTL(), TOS: stack.DefaultTOS}, pkt); err != nil {
		sent.Dropped.Increment()
		return icmpOptionFailed
	}
	sent.ParamProblem.Increment()
	return icmpOptionSent
}
