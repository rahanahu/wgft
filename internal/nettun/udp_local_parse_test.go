package nettun

import (
	"encoding/binary"
	"errors"
	"math/rand"
	"net/netip"
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// inject parses datagram the way writeIPv4 does and hands it to injectLocal.
// Tests use it to put an arbitrary packet through the registry: a closed
// Device wins over a malformed packet, as it does for the Device's Write.
func (r *udpRegistry) inject(datagram []byte) (bool, error) {
	if r.accounting.device.closed.Load() {
		return false, os.ErrClosed
	}
	ipHeaderLen, err := parseLocalUDP(datagram, r.accounting.local)
	if err != nil {
		return false, err
	}
	return r.injectLocal(datagram, ipHeaderLen)
}

// The two checks below are the local UDP checks as they stood before
// parseLocalUDP replaced them: isLocalUDP chose the registry in writeIPv4 and
// the head of inject parsed the datagram again. They are kept only as the
// oracle for TestParseLocalUDPMatchesTheFormerChecks.

func formerIsLocalUDP(packet []byte, local netip.Addr) bool {
	if len(packet) < header.IPv4MinimumSize {
		return false
	}
	ip := header.IPv4(packet)
	if !ip.IsValid(len(packet)) || int(ip.TotalLength()) != len(packet) ||
		ip.More() || ip.FragmentOffset() != 0 || ip.Protocol() != uint8(udp.ProtocolNumber) ||
		int(ip.TotalLength()) < int(ip.HeaderLength())+header.UDPMinimumSize {
		return false
	}
	dst := ip.DestinationAddress()
	return string(dst.AsSlice()) == string(local.AsSlice())
}

// formerInjectHead returns what the head of inject decided before its
// delivery loop: an error, a silent drop (deliver false, err nil), or the
// port, payload and charged bytes the loop reserves with.
func formerInjectHead(datagram []byte, local netip.Addr) (deliver bool, port uint16, payload, charged int, err error) {
	if len(datagram) < header.IPv4MinimumSize {
		return false, 0, 0, 0, errors.New("incomplete IPv4 datagram")
	}
	ip := header.IPv4(datagram)
	if !ip.IsValid(len(datagram)) || int(ip.TotalLength()) != len(datagram) || ip.More() || ip.FragmentOffset() != 0 ||
		ip.Protocol() != uint8(udp.ProtocolNumber) || int(ip.TotalLength()) < int(ip.HeaderLength())+header.UDPMinimumSize {
		return false, 0, 0, 0, errors.New("registry accepts only complete IPv4 UDP datagrams")
	}
	rawDest := ip.DestinationAddress()
	dest, ok := netip.AddrFromSlice(rawDest.AsSlice())
	if !ok || !dest.Is4() || dest.IsMulticast() || dest.IsUnspecified() || dest != local {
		return false, 0, 0, 0, errors.New("registry accepts only local IPv4 unicast")
	}
	udpHeader := header.UDP(datagram[int(ip.HeaderLength()):])
	available := len(datagram) - int(ip.HeaderLength())
	udpLength := int(udpHeader.Length())
	if udpLength < header.UDPMinimumSize || udpLength > available {
		return false, 0, 0, 0, nil
	}
	return true, udpHeader.DestinationPort(), udpLength - header.UDPMinimumSize, available - header.UDPMinimumSize, nil
}

// newInjectHead is the same decision as writeIPv4 and injectLocal now make
// it, without the closed check and the delivery loop.
func newInjectHead(datagram []byte, local netip.Addr) (registry, deliver bool, port uint16, payload, charged int, err error) {
	ipHeaderLen, err := parseLocalUDP(datagram, local)
	if err != nil {
		return false, false, 0, 0, 0, err
	}
	port, payload, charged, ok, err := localUDPPayload(datagram, ipHeaderLen, local)
	return true, ok, port, payload, charged, err
}

// randomLocalUDPCandidate builds an IPv4 packet near the boundary of every
// check: a valid local UDP datagram with a few fields disturbed at random.
func randomLocalUDPCandidate(rng *rand.Rand, local netip.Addr) []byte {
	if rng.Intn(10) == 0 {
		p := make([]byte, rng.Intn(80))
		rng.Read(p)
		return p
	}
	ihl := 5
	if rng.Intn(4) == 0 {
		ihl = 5 + rng.Intn(11)
	}
	hlen := ihl * 4
	payload := rng.Intn(48)
	p := make([]byte, hlen+header.UDPMinimumSize+payload)
	rng.Read(p[hlen:])
	dst := local
	switch rng.Intn(6) {
	case 0:
		dst = netip.AddrFrom4([4]byte{byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))})
	case 1:
		dst = netip.AddrFrom4([4]byte{224, 0, 0, 1})
	case 2:
		dst = netip.AddrFrom4([4]byte{})
	}
	proto := uint8(udp.ProtocolNumber)
	if rng.Intn(6) == 0 {
		proto = uint8(rng.Intn(256))
	}
	total := len(p)
	ip := header.IPv4(p)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(total),
		TTL:         64,
		Protocol:    proto,
		SrcAddr:     tcpip.AddrFromSlice(accountingRemote.AsSlice()),
		DstAddr:     tcpip.AddrFromSlice(dst.AsSlice()),
	})
	p[0] = 0x40 | byte(ihl)
	// Flags and fragment offset: DF alone, MF alone, an offset alone, both,
	// or anything.
	switch rng.Intn(10) {
	case 0:
		binary.BigEndian.PutUint16(p[6:8], 0x4000)
	case 1:
		binary.BigEndian.PutUint16(p[6:8], 0x2000)
	case 2:
		binary.BigEndian.PutUint16(p[6:8], uint16(1+rng.Intn(0x1fff)))
	case 3:
		binary.BigEndian.PutUint16(p[6:8], 0x2000|uint16(1+rng.Intn(0x1fff)))
	case 4:
		binary.BigEndian.PutUint16(p[6:8], uint16(rng.Intn(1<<16)))
	}
	if rng.Intn(8) == 0 {
		binary.BigEndian.PutUint16(p[2:4], uint16(rng.Intn(total+16)))
	}
	ip.SetChecksum(0)
	ip.SetChecksum(^checksum.Checksum(p[:hlen], 0))
	if rng.Intn(8) == 0 {
		p[0] = byte(rng.Intn(256))
	}
	udpLen := header.UDPMinimumSize + payload
	switch rng.Intn(5) {
	case 0:
		udpLen = rng.Intn(total + 8)
	case 1:
		udpLen = rng.Intn(header.UDPMinimumSize)
	}
	binary.BigEndian.PutUint16(p[hlen+4:hlen+6], uint16(udpLen))
	switch rng.Intn(10) {
	case 0:
		p = p[:rng.Intn(len(p)+1)]
	case 1:
		p = append(p, make([]byte, 1+rng.Intn(8))...)
	}
	return p
}

// TestParseLocalUDPMatchesTheFormerChecks compares the single local UDP
// check with the two it replaced, on random packets near every boundary and
// for a unicast, a multicast and the unspecified Device address.
func TestParseLocalUDPMatchesTheFormerChecks(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	locals := []netip.Addr{
		accountingLocal,
		netip.AddrFrom4([4]byte{224, 0, 0, 1}),
		netip.AddrFrom4([4]byte{}),
	}
	reached := map[string]int{}
	for i := 0; i < 200000; i++ {
		local := locals[rng.Intn(len(locals))]
		p := randomLocalUDPCandidate(rng, local)
		wantRegistry := formerIsLocalUDP(p, local)
		gotRegistry, gotDeliver, gotPort, gotPayload, gotCharged, gotErr := newInjectHead(p, local)
		if gotRegistry != wantRegistry {
			t.Fatalf("packet %x local %v: registry = %v, want %v", p, local, gotRegistry, wantRegistry)
		}
		wantDeliver, wantPort, wantPayload, wantCharged, wantErr := formerInjectHead(p, local)
		if errText(gotErr) != errText(wantErr) || gotDeliver != wantDeliver ||
			gotPort != wantPort || gotPayload != wantPayload || gotCharged != wantCharged {
			t.Fatalf("packet %x local %v: head = (%v %d %d %d %v), want (%v %d %d %d %v)", p, local,
				gotDeliver, gotPort, gotPayload, gotCharged, gotErr,
				wantDeliver, wantPort, wantPayload, wantCharged, wantErr)
		}
		switch {
		case gotDeliver:
			reached["delivered"]++
		case gotRegistry && gotErr != nil:
			reached["registry refuses the address"]++
		case gotRegistry:
			reached["registry drops the UDP length"]++
		default:
			reached[errText(gotErr)]++
		}
	}
	// The generator must reach every outcome for the comparison to mean
	// anything.
	for _, outcome := range []string{"delivered", "registry refuses the address", "registry drops the UDP length",
		errIncompleteIPv4.Error(), errNotWholeUDP.Error(), errNotLocalUDP.Error()} {
		if reached[outcome] < 1000 {
			t.Fatalf("generator reached %q %d times: %v", outcome, reached[outcome], reached)
		}
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
