package dutproto

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"time"
)

// Format renders m for a person: the kind and its fields, packets decoded as IPv4 with their
// TCP, UDP or ICMP header, and other byte strings as their length and first bytes.
func Format(m Msg) string {
	var b strings.Builder
	b.WriteString(m.Kind().String())
	v := reflect.ValueOf(m).Elem()
	formatFields(&b, v)
	return b.String()
}

func formatFields(b *strings.Builder, v reflect.Value) {
	t := v.Type()
	for i := range t.NumField() {
		f := t.Field(i)
		if f.Anonymous {
			formatFields(b, v.Field(i))
			continue
		}
		name := strings.ToLower(f.Name)
		if tag, _, _ := strings.Cut(f.Tag.Get("json"), ","); tag != "" {
			name = tag
		}
		fmt.Fprintf(b, " %s=%s", name, formatValue(f.Name, v.Field(i).Interface()))
	}
}

func formatValue(field string, x any) string {
	switch x := x.(type) {
	case Bytes:
		return bytesString(x)
	case []Bytes:
		parts := make([]string, len(x))
		for i, p := range x {
			parts[i] = PacketString(p)
		}
		return "[" + strings.Join(parts, "; ") + "]"
	case netip.Addr, netip.AddrPort:
		return fmt.Sprint(x)
	case time.Duration:
		return x.String()
	case string:
		return fmt.Sprintf("%q", x)
	case []Limit:
		if len(x) == 0 {
			return "default"
		}
		parts := make([]string, len(x))
		for i, l := range x {
			parts[i] = fmt.Sprintf("%s:%d", l.Name, l.Value)
		}
		return strings.Join(parts, ",")
	case Clock:
		return map[Clock]string{ClockFake: "fake", ClockReal: "real"}[x]
	case ErrKind:
		return x.String()
	}
	return fmt.Sprint(x)
}

func bytesString(b []byte) string {
	const show = 16
	if len(b) <= show {
		return fmt.Sprintf("%d:%s", len(b), hex.EncodeToString(b))
	}
	return fmt.Sprintf("%d:%s...", len(b), hex.EncodeToString(b[:show]))
}

// PacketString describes an IPv4 packet in one line: addresses, the TCP, UDP or ICMP header's
// main fields and the payload's length. Bytes that are not IPv4 show as a byte string.
func PacketString(p []byte) string {
	if len(p) < 20 || p[0]>>4 != 4 {
		return "raw " + bytesString(p)
	}
	ihl := int(p[0]&0xf) * 4
	total := int(binary.BigEndian.Uint16(p[2:4]))
	if ihl < 20 || len(p) < ihl || total < ihl || total > len(p) {
		return "bad-ipv4 " + bytesString(p)
	}
	src := netip.AddrFrom4([4]byte(p[12:16]))
	dst := netip.AddrFrom4([4]byte(p[16:20]))
	frag := binary.BigEndian.Uint16(p[6:8])
	id := binary.BigEndian.Uint16(p[4:6])
	l4 := p[ihl:total]
	var b strings.Builder
	fmt.Fprintf(&b, "ipv4 id=%d", id)
	if frag&0x4000 != 0 {
		b.WriteString(" DF")
	}
	if off := frag & 0x1fff; off != 0 || frag&0x2000 != 0 {
		fmt.Fprintf(&b, " frag=%d", int(off)*8)
		if frag&0x2000 != 0 {
			b.WriteString("+MF")
		}
		fmt.Fprintf(&b, " %s>%s proto=%d len=%d", src, dst, p[9], len(l4))
		return b.String()
	}
	switch p[9] {
	case 6:
		if len(l4) < 20 || int(l4[12]>>4)*4 < 20 || int(l4[12]>>4)*4 > len(l4) {
			fmt.Fprintf(&b, " %s>%s tcp-short len=%d", src, dst, len(l4))
			break
		}
		doff := int(l4[12]>>4) * 4
		fmt.Fprintf(&b, " tcp %s:%d>%s:%d %s seq=%d ack=%d win=%d len=%d", src, binary.BigEndian.Uint16(l4[0:2]),
			dst, binary.BigEndian.Uint16(l4[2:4]), tcpFlags(l4[13]), binary.BigEndian.Uint32(l4[4:8]),
			binary.BigEndian.Uint32(l4[8:12]), binary.BigEndian.Uint16(l4[14:16]), len(l4)-doff)
		if doff > 20 {
			fmt.Fprintf(&b, " opts=%s", hex.EncodeToString(l4[20:doff]))
		}
	case 17:
		if len(l4) < 8 {
			fmt.Fprintf(&b, " %s>%s udp-short len=%d", src, dst, len(l4))
			break
		}
		fmt.Fprintf(&b, " udp %s:%d>%s:%d len=%d", src, binary.BigEndian.Uint16(l4[0:2]), dst,
			binary.BigEndian.Uint16(l4[2:4]), len(l4)-8)
	case 1:
		if len(l4) < 4 {
			fmt.Fprintf(&b, " %s>%s icmp-short len=%d", src, dst, len(l4))
			break
		}
		fmt.Fprintf(&b, " icmp %s>%s type=%d code=%d len=%d", src, dst, l4[0], l4[1], len(l4))
	default:
		fmt.Fprintf(&b, " %s>%s proto=%d len=%d", src, dst, p[9], len(l4))
	}
	return b.String()
}

func tcpFlags(f byte) string {
	const names = "FSRPAUEC"
	var b strings.Builder
	for i := range 8 {
		if f&(1<<i) != 0 {
			b.WriteByte(names[i])
		}
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}
