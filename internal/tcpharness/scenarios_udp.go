package tcpharness

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// The helpers of the UDP family: wgstack's UDP and reassembly, stage 2 of wgstack.md, against the
// same testbench as TCP. The DUT's socket is unconnected, the way wgft's relay receives UDP. The
// scenarios themselves are scripts under scripts/.

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

// replyDesc describes a UDP reply for a check's observation.
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
