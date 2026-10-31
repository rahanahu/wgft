package wgstack

import (
	"math/rand/v2"
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
