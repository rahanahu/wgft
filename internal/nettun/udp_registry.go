package nettun

// UDP の登録表。Device の UDP endpoint はすべてここで作り、会計に登録してから使う(設計文書 7 節)。
// 登録表の外で作った UDP endpoint は予約なしで datagram を受け取り、会計の不変条件を壊すので、
// Device は gVisor の stack を外に出さない。

import (
	"errors"
	"math"
	"net"
	"net/netip"
	"os"

	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// errDeviceClosed is returned by the UDP constructors and writes after the
// Device is closed.
var errDeviceClosed = net.ErrClosed

type udpRegistry struct {
	accounting *udpAccounting
	// Test-only observation in closeAll after the endpoints are listed and
	// the lock is released, before any of them is closed. Nil in the Device.
	closeListedHook func()
}

func newUDPRegistry(dev *Device, local netip.Addr, maxBytes, maxPackets, overhead int) (*udpRegistry, error) {
	t := newUDPAccounting(dev, local, maxBytes, maxPackets, overhead)
	if t.fault != nil {
		return nil, t.fault
	}
	return &udpRegistry{accounting: t}, nil
}

// open owns the entire NewEndpoint -> Bind/Connect -> table insertion path
// under the accounting lock, so no delivery can observe a bound endpoint that
// is not yet registered. gVisor's port reservation ends inside Bind/Connect,
// so this interval is short and does not wait for any delivery in flight.
func (r *udpRegistry) open(local, remote *netip.AddrPort) (*rawUDPAdapter, error) {
	t := r.accounting
	if local != nil && (local.Addr() != t.local || local.Port() == 0) {
		return nil, errors.New("registry requires exact local IPv4 address and nonzero port")
	}
	if remote != nil && (!remote.Addr().Is4() || remote.Port() == 0) {
		return nil, errors.New("registry requires IPv4 remote address and nonzero port")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.device.closed.Load() {
		return nil, errDeviceClosed
	}
	if t.fault != nil {
		return nil, t.fault
	}
	c, err := newRawUDPAdapter(t.device, local, remote)
	if err != nil {
		return nil, err
	}
	if err := t.attachLocked(c); err != nil {
		c.ep.Close()
		return nil, err
	}
	// gVisor は packet 全体と PacketBuffer 自体を受信キューに算入する。
	// 会計の byte/件数上限が先に効くよう、その最大の追加費用を確保する。
	// mu を持ったまま設定するので、設定前に datagram は届かない。
	c.ep.SocketOptions().SetReceiveBufferSize(t.endpointReceiveBufferSize(), false)
	return c, nil
}

func (t *udpAccounting) endpointReceiveBufferSize() int64 {
	perPacket := int64(header.IPv4MaximumHeaderSize + header.UDPMinimumSize + stack.PacketBufferStructSize)
	base := int64(t.maxEndpointBytes)
	if int64(t.maxEndpointPackets) > (math.MaxInt64-base)/perPacket {
		return math.MaxInt64
	}
	return base + int64(t.maxEndpointPackets)*perPacket
}

func (r *udpRegistry) listen(port uint16) (*rawUDPAdapter, error) {
	local := netip.AddrPortFrom(r.accounting.local, port)
	return r.open(&local, nil)
}

func (r *udpRegistry) dial(remote netip.AddrPort) (*rawUDPAdapter, error) {
	return r.open(nil, &remote)
}

// inject accepts only complete unfragmented local IPv4 unicast UDP. The
// registry chooses the candidate by its actual bound port. A connected peer
// mismatch still goes through gVisor so its existing rejection/ICMP semantics
// are preserved; public endpoint Stats decide whether the reservation sticks.
//
// A managed port takes the reserve (mu), deliver (receiver opMu), settle (mu)
// shape. If the generation found under mu is closed or replaced before its
// opMu is taken, the reservation is refunded and the port is looked up again,
// so a datagram that races a Close and a rebind reaches the new generation
// reserved, or gVisor's ICMP when the port is gone.
func (r *udpRegistry) inject(datagram []byte) (bool, error) {
	t := r.accounting
	if t.device.closed.Load() {
		return false, os.ErrClosed
	}
	if len(datagram) < header.IPv4MinimumSize {
		return false, errors.New("incomplete IPv4 datagram")
	}
	ip := header.IPv4(datagram)
	if !ip.IsValid(len(datagram)) || int(ip.TotalLength()) != len(datagram) || ip.More() || ip.FragmentOffset() != 0 ||
		ip.Protocol() != uint8(udp.ProtocolNumber) || int(ip.TotalLength()) < int(ip.HeaderLength())+header.UDPMinimumSize {
		return false, errors.New("registry accepts only complete IPv4 UDP datagrams")
	}
	rawDest := ip.DestinationAddress()
	dest, ok := netip.AddrFromSlice(rawDest.AsSlice())
	if !ok || !dest.Is4() || dest.IsMulticast() || dest.IsUnspecified() || dest != t.local {
		return false, errors.New("registry accepts only local IPv4 unicast")
	}
	udpHeader := header.UDP(datagram[int(ip.HeaderLength()):])
	available := len(datagram) - int(ip.HeaderLength())
	udpLength := int(udpHeader.Length())
	if udpLength < header.UDPMinimumSize || udpLength > available {
		return false, nil
	}
	port := udpHeader.DestinationPort()
	payload := udpLength - header.UDPMinimumSize
	charged := available - header.UDPMinimumSize
	for {
		t.mu.Lock()
		if t.fault != nil {
			t.mu.Unlock()
			return false, t.fault
		}
		receiver := t.localPorts[port]
		if receiver == nil {
			// The registry owns the whole Device's UDP endpoint creation, so
			// nobody listens here and gVisor answers with Port Unreachable.
			// This stays under mu: open registers under the same lock, so a
			// port registered concurrently cannot receive this datagram
			// unreserved. The path is nonblocking and takes no other lock.
			if t.sendUnmanagedHook != nil {
				t.sendUnmanagedHook()
			}
			injectInbound(t.device.ep, datagram)
			t.mu.Unlock()
			return false, nil
		}
		g := t.generations[receiver]
		res, why := t.reserveWithChargeLocked(g, payload, charged)
		t.mu.Unlock()
		if why != udpReserved {
			t.noteRefusal(why)
			return false, nil
		}
		kept, stale, err := t.accountedSend(receiver, g, res, func() { injectInbound(t.device.ep, datagram) })
		if stale {
			continue
		}
		if err != nil {
			t.reportFault()
		}
		return kept, err
	}
}

func (r *udpRegistry) usage() (bytes, packets int, fault error) {
	t := r.accounting
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.usedBytes, t.usedPackets, t.fault
}

func (r *udpRegistry) endpoint(port uint16) *rawUDPAdapter {
	t := r.accounting
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.localPorts[port]
}

// closeAll marks the Device closed and lists the endpoints under the lock
// that open uses, so no endpoint is registered after the list is taken. Each
// Close then takes its own endpoint lock; none is held here.
func (r *udpRegistry) closeAll() {
	mu := &r.accounting.mu
	mu.Lock()
	r.accounting.device.closed.Store(true)
	endpoints := make([]*rawUDPAdapter, 0, len(r.accounting.generations))
	for c := range r.accounting.generations {
		endpoints = append(endpoints, c)
	}
	mu.Unlock()
	if r.closeListedHook != nil {
		r.closeListedHook()
	}
	for _, c := range endpoints {
		_ = c.Close()
	}
}
