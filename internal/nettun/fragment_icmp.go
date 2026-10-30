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
func (t *Device) emitReassemblyTimeout(n ipv4FragmentNotice) {
	quote, ok := n.TimeoutQuote(t.local.As4())
	if !ok {
		return
	}
	hlen := int(quote[0]&15) * 4
	proto := t.stack.NetworkProtocolInstance(ipv4.ProtocolNumber)
	handler, ok := proto.(interface{ OnReassemblyTimeout(*stack.PacketBuffer) })
	if !ok {
		return
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(quote)})
	defer pkt.DecRef()
	pkt.NICID = 1
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	pkt.NetworkPacketInfo.LocalAddressBroadcast = bytes.Equal(quote[16:20], []byte{255, 255, 255, 255})
	if _, ok := pkt.NetworkHeader().Consume(hlen); !ok {
		return
	}
	if quote[9] == uint8(header.ICMPv4ProtocolNumber) {
		if _, ok := pkt.TransportHeader().Consume(8); !ok {
			return
		}
	}
	handler.OnReassemblyTimeout(pkt)
}

// emitOptionParameterProblem handles malformed options on the offending
// fragment. The offending packet is still owned by Device.Write, so the
// quote can be copied synchronously up to gVisor's 576/route-MTU bound without
// increasing the retained reassembly notice budget.
func (t *Device) emitOptionParameterProblem(n ipv4FragmentNotice, offending []byte) {
	hlen, ok := n.ParamProblemOK(offending, t.local.As4())
	if !ok {
		return
	}
	saved := offending
	if n.HasFirst {
		saved = n.Quote[:n.QuoteLen]
	}
	route, err := t.stack.FindRoute(1, tcpip.AddrFromSlice(saved[16:20]), tcpip.AddrFromSlice(saved[12:16]), ipv4.ProtocolNumber, false)
	if err != nil {
		return
	}
	defer route.Release()
	sent := t.stack.Stats().ICMP.V4.PacketsSent
	if !t.stack.AllowICMPMessage() {
		sent.RateLimited.Increment()
		return
	}
	mtu := int(route.MTU())
	const maxIPData = header.IPv4MinimumProcessableDatagramSize - header.IPv4MinimumSize
	if mtu > maxIPData {
		mtu = maxIPData
	}
	available := mtu - header.ICMPv4MinimumSize
	if available < hlen+header.ICMPv4MinimumErrorPayloadSize {
		return
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
		return
	}
	sent.ParamProblem.Increment()
}
