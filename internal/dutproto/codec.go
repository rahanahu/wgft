package dutproto

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"time"
	"unicode/utf8"
)

// Bytes is a byte string in a message. It marshals as lowercase hex, so the frame examples of
// testdata/frames read the same in every language.
type Bytes []byte

func (b Bytes) MarshalText() ([]byte, error) { return []byte(hex.EncodeToString(b)), nil }

func (b *Bytes) UnmarshalText(t []byte) error {
	v, err := hex.DecodeString(string(t))
	if err != nil {
		return err
	}
	*b = v
	return nil
}

// enc appends the body's fields: integers little endian, a byte string as a u32 length and the
// bytes, a string as a u16 length and UTF-8, an address as its 4 bytes in network order, an
// address and port as the address and a u16, a time or duration as u64 nanoseconds. A value the
// body cannot carry, such as a string over 0xffff bytes or an address that is not IPv4, is an
// error: the first one sticks and Encode returns it.
type enc struct {
	b   []byte
	err error
}

func (e *enc) fail(format string, args ...any) {
	if e.err == nil {
		e.err = protoErr(format, args...)
	}
}

func (e *enc) u8(v uint8)      { e.b = append(e.b, v) }
func (e *enc) u16(v uint16)    { e.b = binary.LittleEndian.AppendUint16(e.b, v) }
func (e *enc) u32(v uint32)    { e.b = binary.LittleEndian.AppendUint32(e.b, v) }
func (e *enc) u64(v uint64)    { e.b = binary.LittleEndian.AppendUint64(e.b, v) }
func (e *enc) bool(v bool)     { e.u8(b2u(v)) }
func (e *enc) handle(h Handle) { e.u32(uint32(h)) }
func (e *enc) dur(d time.Duration) {
	if d < 0 {
		e.fail("negative duration %v", d)
	}
	e.u64(uint64(d))
}

func (e *enc) bytes(b []byte) {
	e.u32(uint32(len(b)))
	e.b = append(e.b, b...)
}

func (e *enc) str(s string) {
	if len(s) > 0xffff {
		e.fail("string of %d bytes; at most 65535", len(s))
		s = ""
	}
	if !utf8.ValidString(s) {
		e.fail("string %q is not UTF-8", s)
	}
	e.u16(uint16(len(s)))
	e.b = append(e.b, s...)
}

func (e *enc) addr(a netip.Addr) {
	if !a.Is4() {
		e.fail("address %v is not IPv4", a)
		a = netip.IPv4Unspecified()
	}
	b := a.As4()
	e.b = append(e.b, b[:]...)
}

func (e *enc) addrPort(ap netip.AddrPort) {
	e.addr(ap.Addr())
	e.u16(ap.Port())
}

func (e *enc) list(n int) { e.u32(uint32(n)) }

// enum writes a u8 that must be below n, the number of values the appendix defines.
func (e *enc) enum(v uint8, n uint8, what string) {
	if v >= n {
		e.fail("%s %d is not one of the %d values", what, v, n)
	}
	e.u8(v)
}

func b2u(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}

// dec reads the body's fields. The first error sticks, and done reports it or trailing bytes.
type dec struct {
	b   []byte
	err error
}

func (d *dec) take(n int) []byte {
	if d.err != nil {
		return nil
	}
	if n < 0 || len(d.b) < n {
		d.err = protoErr("body ends %d bytes short", n-len(d.b))
		return nil
	}
	v := d.b[:n:n]
	d.b = d.b[n:]
	return v
}

func (d *dec) u8() uint8 {
	if v := d.take(1); v != nil {
		return v[0]
	}
	return 0
}

func (d *dec) u16() uint16 {
	if v := d.take(2); v != nil {
		return binary.LittleEndian.Uint16(v)
	}
	return 0
}

func (d *dec) u32() uint32 {
	if v := d.take(4); v != nil {
		return binary.LittleEndian.Uint32(v)
	}
	return 0
}

func (d *dec) u64() uint64 {
	if v := d.take(8); v != nil {
		return binary.LittleEndian.Uint64(v)
	}
	return 0
}

func (d *dec) bool() bool {
	switch v := d.u8(); v {
	case 0:
		return false
	case 1:
		return true
	default:
		if d.err == nil {
			d.err = protoErr("bool byte %d is neither 0 nor 1", v)
		}
		return false
	}
}

func (d *dec) handle() Handle { return Handle(d.u32()) }

func (d *dec) dur() time.Duration {
	v := d.u64()
	if v > 1<<63-1 && d.err == nil {
		d.err = protoErr("duration %d ns overflows", v)
	}
	return time.Duration(v)
}

func (d *dec) bytes() Bytes {
	n := d.u32()
	if d.err == nil && uint64(n) > uint64(len(d.b)) {
		d.err = protoErr("byte string of %d bytes in %d left", n, len(d.b))
		return nil
	}
	return append(Bytes{}, d.take(int(n))...)
}

func (d *dec) str() string {
	n := d.u16()
	s := string(d.take(int(n)))
	if d.err == nil && !utf8.ValidString(s) {
		d.err = protoErr("string %q is not UTF-8", s)
	}
	return s
}

// enum reads a u8 that must be below n.
func (d *dec) enum(n uint8, what string) uint8 {
	v := d.u8()
	if d.err == nil && v >= n {
		d.err = protoErr("%s %d is not one of the %d values", what, v, n)
	}
	return v
}

func (d *dec) addr() netip.Addr {
	v := d.take(4)
	if v == nil {
		return netip.Addr{}
	}
	return netip.AddrFrom4([4]byte(v))
}

func (d *dec) addrPort() netip.AddrPort {
	a := d.addr()
	return netip.AddrPortFrom(a, d.u16())
}

// list reads a list's length and checks that each element can take at least min bytes, so a
// corrupt length cannot make the reader allocate without bound.
func (d *dec) list(min int) int {
	n := d.u32()
	if d.err == nil && uint64(n)*uint64(min) > uint64(len(d.b)) {
		d.err = protoErr("list of %d elements in %d bytes", n, len(d.b))
		return 0
	}
	return int(n)
}

func (d *dec) done() error {
	if d.err == nil && len(d.b) > 0 {
		d.err = protoErr("%d trailing bytes", len(d.b))
	}
	return d.err
}
