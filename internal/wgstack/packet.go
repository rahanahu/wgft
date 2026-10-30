package wgstack

import (
	"encoding/binary"
	"net/netip"
)

// IPv4 と TCP の header の解釈と組み立て。解釈はどの byte の列でも範囲の外を読まず、panic しない
// (wgstack-verification.md の fuzzing)。

const (
	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17
)

// TCP の flag。
const (
	flagFIN = 0x01
	flagSYN = 0x02
	flagRST = 0x04
	flagPSH = 0x08
	flagACK = 0x10
	flagURG = 0x20
)

// tuple は接続の 4 つ組。laddr と lport は wgstack の側、raddr と rport は相手の側である。
type tuple struct {
	laddr, raddr uint32
	lport, rport uint16
}

func addrFrom(u uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(u >> 24), byte(u >> 16), byte(u >> 8), byte(u)})
}

func addrBits(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

func (t tuple) local() netip.AddrPort  { return netip.AddrPortFrom(addrFrom(t.laddr), t.lport) }
func (t tuple) remote() netip.AddrPort { return netip.AddrPortFrom(addrFrom(t.raddr), t.rport) }

// ipv4 は解釈した IPv4 の header。payload は Total Length で切った後の中身である。
type ipv4 struct {
	src, dst uint32
	proto    uint8
	hlen     int
	fragment bool // MF か、0 でない offset
	payload  []byte
	header   []byte
}

// ipv4Drop は IPv4 の packet を捨てた理由。
type ipv4Drop uint8

const (
	ipv4OK ipv4Drop = iota
	ipv4Malformed
	ipv4BadChecksum
)

// parseIPv4 は b を IPv4 の packet として解釈する。Total Length より後ろの byte は切り捨てる
// (packet-validation.md の IPv4 の Total Length)。
func parseIPv4(b []byte) (ipv4, ipv4Drop) {
	var ip ipv4
	if len(b) < ipHeaderLen || b[0]>>4 != 4 {
		return ip, ipv4Malformed
	}
	hlen := int(b[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if hlen < ipHeaderLen || total < hlen || total > len(b) {
		return ip, ipv4Malformed
	}
	b = b[:total]
	if checksum(0, b[:hlen]) != 0xffff {
		return ip, ipv4BadChecksum
	}
	ip.hlen = hlen
	ip.header = b[:hlen]
	ip.proto = b[9]
	ip.src = binary.BigEndian.Uint32(b[12:16])
	ip.dst = binary.BigEndian.Uint32(b[16:20])
	ip.fragment = binary.BigEndian.Uint16(b[6:8])&0x3fff != 0
	ip.payload = b[hlen:]
	return ip, ipv4OK
}

// checksum は b を 16 bit の 1 の補数で足した値を sum に足して畳む。結果の補数が checksum である。
func checksum(sum uint32, b []byte) uint16 {
	for len(b) >= 2 {
		sum += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return uint16(sum)
}

// pseudoSum は TCP と UDP の擬似 header の和。
func pseudoSum(src, dst uint32, proto uint8, length int) uint32 {
	return src>>16 + src&0xffff + dst>>16 + dst&0xffff + uint32(proto) + uint32(length)
}

// sackBlock は SACK の 1 つの block [left, right)。
type sackBlock struct{ left, right uint32 }

// tcpOptions は解釈した TCP の option。MSS、窓の scale、SACK の許可は SYN でだけ読む。
type tcpOptions struct {
	mss       uint16
	hasMSS    bool
	wscale    uint8
	hasWS     bool
	sackOK    bool
	hasTS     bool
	tsVal     uint32
	tsEcr     uint32
	nsack     int
	sack      [4]sackBlock
	malformed bool // 形の崩れた option で読み終えた
}

// parseOptions は TCP の option を読む。Linux の tcp_parse_options と同じく、長さの崩れた option で
// 読むのをやめ、それまでに読んだ値を使う。知らない option は長さで飛ばす。
func parseOptions(b []byte, syn bool) tcpOptions {
	var o tcpOptions
	for len(b) > 0 {
		kind := b[0]
		if kind == 0 { // EOL
			break
		}
		if kind == 1 { // NOP
			b = b[1:]
			continue
		}
		if len(b) < 2 {
			o.malformed = true
			break
		}
		size := int(b[1])
		if size < 2 || size > len(b) {
			o.malformed = true
			break
		}
		body := b[2:size]
		switch kind {
		case 2:
			if size == 4 && syn {
				o.mss = binary.BigEndian.Uint16(body)
				o.hasMSS = true
			}
		case 3:
			if size == 3 && syn {
				o.wscale = min(body[0], 14) // RFC 7323 2.3
				o.hasWS = true
			}
		case 4:
			if size == 2 && syn {
				o.sackOK = true
			}
		case 5:
			if (size-2)%8 == 0 && !syn {
				for i := 0; i+8 <= len(body) && o.nsack < len(o.sack); i += 8 {
					o.sack[o.nsack] = sackBlock{binary.BigEndian.Uint32(body[i:]), binary.BigEndian.Uint32(body[i+4:])}
					o.nsack++
				}
			}
		case 8:
			if size == 10 {
				o.hasTS = true
				o.tsVal = binary.BigEndian.Uint32(body)
				o.tsEcr = binary.BigEndian.Uint32(body[4:])
			}
		}
		b = b[size:]
	}
	return o
}

// segment は解釈した TCP の segment。tup は wgstack の側から見た 4 つ組である。
type segment struct {
	tup     tuple
	seq     uint32
	ack     uint32
	flags   uint8
	wnd     uint16
	opt     tcpOptions
	payload []byte
}

func (s *segment) has(f uint8) bool { return s.flags&f != 0 }

// seqLen は segment が使うシーケンス番号の長さ(中身と SYN と FIN)。
func (s *segment) seqLen() uint32 {
	n := uint32(len(s.payload))
	if s.has(flagSYN) {
		n++
	}
	if s.has(flagFIN) {
		n++
	}
	return n
}

// tcpDrop は TCP の segment を捨てた理由。
type tcpDrop uint8

const (
	tcpOK tcpDrop = iota
	tcpMalformed
	tcpBadChecksum
)

// parseTCP は ip の中身を TCP の segment として解釈し、checksum を確かめる。
func parseTCP(ip *ipv4) (segment, tcpDrop) {
	var s segment
	b := ip.payload
	if len(b) < tcpHeaderLen {
		return s, tcpMalformed
	}
	off := int(b[12]>>4) * 4
	if off < tcpHeaderLen || off > len(b) {
		return s, tcpMalformed
	}
	if ^checksum(pseudoSum(ip.src, ip.dst, protoTCP, len(b)), b) != 0 {
		return s, tcpBadChecksum
	}
	s.tup = tuple{laddr: ip.dst, raddr: ip.src, lport: binary.BigEndian.Uint16(b[2:4]), rport: binary.BigEndian.Uint16(b[0:2])}
	s.seq = binary.BigEndian.Uint32(b[4:8])
	s.ack = binary.BigEndian.Uint32(b[8:12])
	s.flags = b[13]
	s.wnd = binary.BigEndian.Uint16(b[14:16])
	s.opt = parseOptions(b[tcpHeaderLen:off], s.flags&flagSYN != 0)
	s.payload = b[off:]
	return s, tcpOK
}

// writeIPv4Header は b[:20] に option の無い IPv4 の header を書く。DF を立て、TTL は 64 である。
func writeIPv4Header(b []byte, total int, id uint16, proto uint8, src, dst uint32) {
	b[0] = 0x45
	b[1] = 0
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	binary.BigEndian.PutUint16(b[4:6], id)
	binary.BigEndian.PutUint16(b[6:8], 0x4000)
	b[8] = defaultTTL
	b[9] = proto
	b[10], b[11] = 0, 0
	binary.BigEndian.PutUint32(b[12:16], src)
	binary.BigEndian.PutUint32(b[16:20], dst)
	binary.BigEndian.PutUint16(b[10:12], ^checksum(0, b[:20]))
}

// clearDF は writeIPv4Header で書いた b[:20] の DF を下ろし、checksum を直す。
func clearDF(b []byte) {
	b[6] &^= 0x40
	b[10], b[11] = 0, 0
	binary.BigEndian.PutUint16(b[10:12], ^checksum(0, b[:20]))
}

// tcpHeader は組み立てる TCP の header の値。
type tcpHeader struct {
	tup   tuple
	seq   uint32
	ack   uint32
	flags uint8
	wnd   uint16
}

// optWriter は TCP の option を固定の枠に書く。
type optWriter struct {
	b [maxOptionLen]byte
	n int
}

func (w *optWriter) mss(v uint16) {
	w.b[w.n], w.b[w.n+1] = 2, 4
	binary.BigEndian.PutUint16(w.b[w.n+2:], v)
	w.n += 4
}

func (w *optWriter) sackPermWithTS(tsVal, tsEcr uint32) {
	// Linux と同じ並び:SACK-perm、TS
	w.b[w.n], w.b[w.n+1] = 4, 2
	w.b[w.n+2], w.b[w.n+3] = 8, 10
	binary.BigEndian.PutUint32(w.b[w.n+4:], tsVal)
	binary.BigEndian.PutUint32(w.b[w.n+8:], tsEcr)
	w.n += 12
}

func (w *optWriter) ts(tsVal, tsEcr uint32) {
	w.b[w.n], w.b[w.n+1], w.b[w.n+2], w.b[w.n+3] = 1, 1, 8, 10
	binary.BigEndian.PutUint32(w.b[w.n+4:], tsVal)
	binary.BigEndian.PutUint32(w.b[w.n+8:], tsEcr)
	w.n += 12
}

func (w *optWriter) sackPerm() {
	w.b[w.n], w.b[w.n+1], w.b[w.n+2], w.b[w.n+3] = 1, 1, 4, 2
	w.n += 4
}

func (w *optWriter) wscale(v uint8) {
	w.b[w.n], w.b[w.n+1], w.b[w.n+2], w.b[w.n+3] = 1, 3, 3, v
	w.n += 4
}

// sack は SACK の block を書く。入る数だけ書き、書いた数を返す。
func (w *optWriter) sack(blocks []sackBlock) int {
	room := (maxOptionLen - w.n - 4) / 8
	n := min(room, len(blocks))
	if n <= 0 {
		return 0
	}
	w.b[w.n], w.b[w.n+1], w.b[w.n+2], w.b[w.n+3] = 1, 1, 5, byte(2+8*n)
	w.n += 4
	for _, s := range blocks[:n] {
		binary.BigEndian.PutUint32(w.b[w.n:], s.left)
		binary.BigEndian.PutUint32(w.b[w.n+4:], s.right)
		w.n += 8
	}
	return n
}

// pad は option の長さを 4 の倍数にする。
func (w *optWriter) pad() {
	for w.n%4 != 0 {
		w.b[w.n] = 0
		w.n++
	}
}

// writeTCP は b に IPv4 と TCP の header と option を書き、中身を置く位置を返す。呼び出し側は
// 中身を b[off:off+payLen] に書いた後に finishTCP を呼ぶ。b は全体が入る長さを持つこと。
func writeTCP(b []byte, id uint16, h tcpHeader, opts *optWriter, payLen int) (off int) {
	optLen := 0
	if opts != nil {
		opts.pad()
		optLen = opts.n
	}
	thl := tcpHeaderLen + optLen
	total := ipHeaderLen + thl + payLen
	writeIPv4Header(b, total, id, protoTCP, h.tup.laddr, h.tup.raddr)
	t := b[ipHeaderLen:]
	binary.BigEndian.PutUint16(t[0:2], h.tup.lport)
	binary.BigEndian.PutUint16(t[2:4], h.tup.rport)
	binary.BigEndian.PutUint32(t[4:8], h.seq)
	binary.BigEndian.PutUint32(t[8:12], h.ack)
	t[12] = byte(thl/4) << 4
	t[13] = h.flags
	binary.BigEndian.PutUint16(t[14:16], h.wnd)
	t[16], t[17], t[18], t[19] = 0, 0, 0, 0
	if optLen > 0 {
		copy(t[tcpHeaderLen:], opts.b[:optLen])
	}
	return ipHeaderLen + thl
}

// finishTCP は b[:total] の TCP の checksum を書き、packet の長さを返す。
func finishTCP(b []byte) int {
	total := int(binary.BigEndian.Uint16(b[2:4]))
	t := b[ipHeaderLen:total]
	src := binary.BigEndian.Uint32(b[12:16])
	dst := binary.BigEndian.Uint32(b[16:20])
	binary.BigEndian.PutUint16(t[16:18], ^checksum(pseudoSum(src, dst, protoTCP, len(t)), t))
	return total
}
