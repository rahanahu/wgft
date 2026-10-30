package ipv4frag

import "bytes"

// 断片への ICMP の誤りを送るかの判定(packet-validation.md の断片に対する ICMP)。誤りを作って送るのは呼び出し側の
// Device で、ここは送る条件と引用する datagram だけを決める。internal/nettun と internal/wgstack が同じ規則を使う。

// TimeoutQuote は、期限を過ぎた項目への Time Exceeded が引用する、最初の断片の header と 8 byte を返す。最初の
// 断片を持ち、header が正しく、宛先が local のときだけ真を返す。
func (n *Notice) TimeoutQuote(local [4]byte) ([]byte, bool) {
	if !n.HasFirst || n.QuoteLen < 28 {
		return nil, false
	}
	quote := n.Quote[:n.QuoteLen]
	hlen := int(quote[0]&15) * 4
	if hlen < 20 || hlen > 60 || len(quote) < hlen+8 || !ChecksumOK(quote[:hlen]) ||
		quote[6]&0x1f != 0 || quote[7] != 0 ||
		!bytes.Equal(quote[16:20], local[:]) {
		return nil, false
	}
	return quote, true
}

// ParamProblemOK は、option の不正な断片 offending に Parameter Problem を返すかと、引用する datagram の
// header の長さを返す。引用するのは offending である。最初の断片の引用(Notice.Quote)を持つときは、offending が
// その最初の断片と同じであることを求める。宛先が local でない誤り、送信元が 0 の誤り、broadcast と multicast の
// 宛先、ICMP の誤りへの誤りには返さない。
func (n *Notice) ParamProblemOK(offending []byte, local [4]byte) (hlen int, ok bool) {
	if n.Pointer < 20 || len(offending) < 20 {
		return 0, false
	}
	var saved []byte
	if n.HasFirst {
		if n.QuoteLen < 20 {
			return 0, false
		}
		saved = n.Quote[:n.QuoteLen]
	} else {
		// 後続の断片の option の誤りには最初の断片の引用が無い。その断片そのものを使う
		saved = offending
	}
	hlen = int(saved[0]&15) * 4
	if hlen < 20 || hlen > 60 || len(saved) < hlen || len(offending) < hlen || int(n.Pointer) >= hlen {
		return 0, false
	}
	// 中身の無い断片は option を確かめる前に捨てる
	if len(saved) == hlen || len(offending) == hlen {
		return 0, false
	}
	quotePrefixLen := min(hlen+8, len(saved))
	if len(offending) < quotePrefixLen {
		return 0, false
	}
	// option の形の矛盾は後続の入力にも保存した最初の引用を付けうる。元の最初の断片だけを対象にする
	if (n.HasFirst && (!bytes.Equal(offending[:quotePrefixLen], saved[:quotePrefixLen]) ||
		offending[6]&0x1f != 0 || offending[7] != 0)) ||
		!ChecksumOK(saved[:hlen]) ||
		int(offending[2])<<8|int(offending[3]) != len(offending) {
		return 0, false
	}
	if bytes.Equal(saved[12:16], []byte{0, 0, 0, 0}) ||
		saved[16]&0xf0 == 0xe0 || bytes.Equal(saved[16:20], []byte{255, 255, 255, 255}) ||
		!bytes.Equal(saved[16:20], local[:]) {
		return 0, false
	}
	if saved[9] == 1 { // ICMP
		switch saved[hlen] {
		case 0, 8, 13, 14, 15, 16: // echo、timestamp、information の要求と応答
		default:
			return 0, false
		}
	}
	return hlen, true
}
