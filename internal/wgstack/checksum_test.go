package wgstack

import (
	"encoding/binary"
	"math/rand/v2"
	"net"
	"net/netip"
	"testing"
)

// refChecksum は 2 byte ずつ足す定義どおりの和(RFC 1071)。
func refChecksum(sum uint32, b []byte) uint16 {
	s := uint64(sum)
	for len(b) >= 2 {
		s += uint64(b[0])<<8 | uint64(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		s += uint64(b[0]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return uint16(s)
}

// TestChecksumMatchesDefinition は 8 byte ずつの和が 2 byte ずつの和と一致することを、長さ、初めの値、0 と
// 0xff の詰まった中身で確かめる。
func TestChecksumMatchesDefinition(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	buf := make([]byte, 2048)
	sums := []uint32{0, 1, 0xffff, 0x10000, 0x5fffa, 0xffffffff}
	for n := 0; n <= 300; n++ {
		for fill := range 3 {
			for i := range buf[:n] {
				switch fill {
				case 0:
					buf[i] = byte(r.Uint32())
				case 1:
					buf[i] = 0xff
				default:
					buf[i] = 0
				}
			}
			for _, s := range sums {
				if got, want := checksum(s, buf[:n]), refChecksum(s, buf[:n]); got != want {
					t.Fatalf("len %d fill %d sum %#x: got %#04x, want %#04x", n, fill, s, got, want)
				}
			}
		}
	}
	for range 20000 {
		n := r.IntN(len(buf) + 1)
		for i := range buf[:n] {
			buf[i] = byte(r.Uint32())
		}
		s := r.Uint32()
		if got, want := checksum(s, buf[:n]), refChecksum(s, buf[:n]); got != want {
			t.Fatalf("len %d sum %#x: got %#04x, want %#04x", n, s, got, want)
		}
	}
}

func BenchmarkChecksum1400(b *testing.B) {
	buf := make([]byte, 1400)
	b.SetBytes(int64(len(buf)))
	for b.Loop() {
		checksum(0x1234, buf)
	}
}

func BenchmarkRefChecksum1400(b *testing.B) {
	buf := make([]byte, 1400)
	b.SetBytes(int64(len(buf)))
	for b.Loop() {
		refChecksum(0x1234, buf)
	}
}

// refUDPChecksum は、送る UDP の checksum を以前の udpChecksum と同じく 1 byte ずつ足して求める。
func refUDPChecksum(from, to netip.AddrPort, payload []byte) uint16 {
	ulen := udpHeaderLen + len(payload)
	sum := pseudoSum(addrBits(from.Addr()), addrBits(to.Addr()), protoUDP, ulen)
	var h [udpHeaderLen]byte
	binary.BigEndian.PutUint16(h[0:2], from.Port())
	binary.BigEndian.PutUint16(h[2:4], to.Port())
	binary.BigEndian.PutUint16(h[4:6], uint16(ulen))
	sum += uint32(refChecksum(0, h[:]))
	for i, x := range payload {
		if i&1 == 0 {
			sum += uint32(x) << 8
		} else {
			sum += uint32(x)
		}
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	cs := ^uint16(sum)
	if cs == 0 {
		cs = 0xffff
	}
	return cs
}

// TestUDPChecksumMatchesByteSum は、送る UDP の datagram の checksum を共有の checksum で求めても、1 byte ずつ
// 足していた以前の値と一致することを確かめる。区分の枠と chunk の列(16 KiB を超える datagram)の両方、奇数の
// 長さ、chunk の境目、0 と 0xff の詰まった中身、乱数の中身と長さを流す。
func TestUDPChecksumMatchesByteSum(t *testing.T) {
	n := newTestNet(t, smallLimits())
	pc := listenUDP(t, n, 53)
	r := rand.New(rand.NewPCG(3, 4))
	lens := []int{0, 1, 2, 3, 7, 8, 255, 256, 257, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 16383, 16384, 16385, 32767, 32769, 49153, udpMaxPayload}
	for range 400 {
		lens = append(lens, r.IntN(udpMaxPayload+1))
	}
	cases := 0
	for _, l := range lens {
		for fill := range 3 {
			b := make([]byte, l)
			switch fill {
			case 1:
				for i := range b {
					b[i] = 0xff
				}
			case 2:
				for i := range b {
					b[i] = byte(r.Uint32())
				}
			}
			to := netip.AddrPortFrom(peerAddr, uint16(1+r.IntN(65535)))
			if _, err := pc.WriteTo(b, net.UDPAddrFromAddrPort(to)); err != nil {
				t.Fatalf("WriteTo of %d bytes: %v", l, err)
			}
			u := &n.d.s.udp
			u.mu.Lock()
			got := u.dg[dirTx][u.txTail].csum
			u.mu.Unlock()
			if want := refUDPChecksum(pc.ep.local, to, b); got != want {
				t.Fatalf("checksum of a %d-byte datagram (fill %d): got %#04x, want %#04x", l, fill, got, want)
			}
			for n.d.Poll(n.buf) > 0 {
			}
			cases++
		}
	}
	t.Logf("%d datagrams", cases)
}
