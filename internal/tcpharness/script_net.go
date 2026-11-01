package tcpharness

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// The IP-level part of the script language: UDP sockets, whole IPv4 packets with fragments and
// ICMP, and the composite steps of the Go scenarios (flight, burst, echo and the rest), which call
// the same helpers.

type (
	// ipv is an IPv4 packet and, for a capture, whether it was seen and when.
	ipv struct {
		p  IPv4
		ok bool
		at time.Time
	}
	udpv struct {
		u   UDP
		err error
	}
	icmpv struct {
		m  ICMP
		ok bool
	}
	quotev struct {
		q  Quote
		ok bool
	}
	udpconnv struct {
		c      net.PacketConn
		closed bool
	}
)

// netStmt runs the statements of this file and reports whether it knew the verb.
func (in *interp) netStmt(st *Stmt, arg func(int) any, bind func(any)) bool {
	h := in.h
	h.T.Helper()
	first := func() string { return st.Args[0].Name }
	switch st.Verb {
	case "collect_flow":
		p := in.peer(arg(0)).p
		d := in.dur(arg(1))
		var until func(any) bool
		if e, ok := st.Named["until"]; ok {
			until = in.predicate(e)
		}
		var out []any
		deadline := h.Now().Add(d)
		for {
			s, ok := p.Next(max(deadline.Sub(h.Now()), 0))
			if !ok {
				break
			}
			sv := &segv{seg: s, ok: true, at: h.Now()}
			out = append(out, sv)
			if until != nil && until(sv) {
				break
			}
		}
		bind(out)
	case "flight":
		segs, data := flight(h, in.peer(arg(0)).p, in.conn(arg(1)), int(in.int(arg(2))), byte(in.int(arg(3))))
		bind(&recordv{name: "flight", fields: map[string]any{"segs": segList(segs), "data": data}})
	case "burst":
		segs, n := burst(in.peer(arg(0)).p)
		bind(&recordv{name: "burst", fields: map[string]any{"segs": segList(segs), "bytes": int64(n)}})
	case "at_once":
		var segs []Segment
		for _, x := range in.list(arg(0)) {
			segs = append(segs, in.seg(x).seg)
		}
		bind(segList(atOnce(h, segs)))
	case "listen_udp":
		c := &udpconnv{}
		var err error
		port := in.port(arg(1))
		c.c, err = h.DUT.ListenUDP(port)
		if err != nil {
			h.T.Fatalf("listen on UDP %d: %v", port, err)
		}
		h.T.Cleanup(func() {
			if !c.closed {
				c.c.Close()
			}
		})
		in.vars[first()] = c
	case "udp_read":
		got, from, err := readDatagram(in.udpConn(arg(0)).c, in.dur(arg(1)))
		bind(&recordv{name: "udp_read", fields: map[string]any{"data": got, "from": from, "err": wrapErr(err)}})
	case "udp_write":
		e, ok := st.Named["to"]
		if !ok {
			in.failf("udp_write needs to=")
		}
		to, ok := in.eval(e, nil).(netip.AddrPort)
		if !ok {
			in.failf("to= takes an address and port")
		}
		_, err := in.udpConn(arg(0)).c.WriteTo(in.bytes(arg(1)), net.UDPAddrFromAddrPort(to))
		if st.Bind == "" && err != nil {
			h.T.Fatalf("WriteTo: %v", err)
		}
		bind(&recordv{name: "udp_write", fields: map[string]any{"err": wrapErr(err)}})
	case "inject_ip":
		switch v := arg(0).(type) {
		case *ipv:
			h.InjectIP(v.p)
		case []any:
			for _, x := range v {
				h.InjectIP(in.ip(x).p)
			}
		default:
			in.failf("inject_ip takes a packet or a list of them, not %s", typeName(v))
		}
	case "inject_icmp_error":
		b := in.bytes(arg(0))
		h.T.Logf("-> ICMP error % x", b[:min(len(b), 28)])
		if err := h.DUT.Inject(b); err != nil {
			h.T.Fatalf("inject: %v", err)
		}
	case "await_ip":
		pred := in.namedPredicate(st, "match")
		p, ok := h.Packet(in.dur(arg(0)), func(p IPv4) bool { return pred(&ipv{p: p, ok: true}) })
		bind(&ipv{p: p, ok: ok, at: h.Now()})
	case "await_datagram":
		// the loop of udp-large: collect packets until one datagram is whole
		pred := in.namedPredicate(st, "match")
		r := newReassembler()
		frags, df, zeroID := 0, false, false
		var back IPv4
		done := false
		deadline := h.Now().Add(in.dur(arg(0)))
		for !done {
			p, ok := h.Packet(max(deadline.Sub(h.Now()), 0), func(p IPv4) bool { return pred(&ipv{p: p, ok: true}) })
			if !ok {
				break
			}
			frags++
			df = df || p.DF
			zeroID = zeroID || p.ID == 0
			back, done = r.add(p)
		}
		bind(&recordv{name: "await_datagram", fields: map[string]any{"done": done, "packet": &ipv{p: back, ok: done, at: h.Now()},
			"frags": int64(frags), "df": df, "zero_id": zeroID}})
	case "echo":
		ipid, ident, seq := uint16(in.int(arg(0))), uint16(in.int(arg(1))), uint16(in.int(arg(2)))
		payload := in.bytes(arg(3))
		var cuts []int
		if e, ok := st.Named["cuts"]; ok {
			for _, x := range in.list(in.eval(e, nil)) {
				cuts = append(cuts, int(in.int(x)))
			}
		}
		m, frags, df, ok := echo(h, ipid, ident, seq, payload, cuts...)
		good, desc := echoDesc(m, ok, ident, seq, payload)
		bind(&recordv{name: "echo", fields: map[string]any{"ok": ok, "frags": int64(frags), "df": df, "good": good, "desc": []byte(desc)}})
	default:
		return false
	}
	return true
}

func (in *interp) namedPredicate(st *Stmt, name string) func(any) bool {
	e, ok := st.Named[name]
	if !ok {
		in.failf("%s needs %s=", st.Verb, name)
	}
	return in.predicate(e)
}

func segList(segs []Segment) []any {
	out := []any{}
	for _, s := range segs {
		out = append(out, &segv{seg: s, ok: true})
	}
	return out
}

// netCall evaluates the functions of this file and reports whether it knew the name.
func (in *interp) netCall(e *Expr, arg func(int) any) (any, bool) {
	n := len(e.Args)
	switch e.Name {
	case "list":
		out := []any{}
		for i := range n {
			out = append(out, arg(i))
		}
		return out, true
	case "max":
		return max(in.int(arg(0)), in.int(arg(1))), true
	case "zeros":
		return make([]byte, in.count(arg(0))), true
	case "addr":
		a, err := netip.ParseAddr(string(in.bytes(arg(0))))
		if err != nil {
			in.failf("addr: %v", err)
		}
		return a, true
	case "addrport":
		a, ok := arg(0).(netip.Addr)
		if !ok {
			in.failf("addrport takes an address and a port")
		}
		return netip.AddrPortFrom(a, in.port(arg(1))), true
	case "with_port":
		ap, ok := arg(0).(netip.AddrPort)
		if !ok {
			in.failf("with_port takes an address and port")
		}
		return netip.AddrPortFrom(ap.Addr(), in.port(arg(1))), true
	case "seg_size":
		return int64(segSize(in.peer(arg(0)).p)), true
	case "wire":
		switch v := arg(0).(type) {
		case *segv:
			return v.seg.Marshal(), true
		case *ipv:
			return v.p.Marshal(), true
		}
		in.failf("wire takes a segment or a packet")
	case "wire_len":
		switch v := arg(0).(type) {
		case *segv:
			return int64(len(v.seg.Marshal())), true
		case *ipv:
			return int64(len(v.p.Marshal())), true
		}
		in.failf("wire_len takes a segment or a packet")
	case "udp":
		return &ipv{p: UDPPacket(in.addrPort(arg(0)), in.addrPort(arg(1)), uint16(in.int(arg(2))), in.bytes(arg(3))), ok: true}, true
	case "icmp":
		m := ICMP{Type: uint8(in.int(arg(3))), Code: uint8(in.int(arg(4))), Rest: uint32(in.int(arg(5))), Body: in.bytes(arg(6))}
		return &ipv{p: ICMPPacket(in.addr(arg(0)), in.addr(arg(1)), uint16(in.int(arg(2))), m), ok: true}, true
	case "fragments":
		if n < 1 {
			in.failf("fragments takes a packet and cuts")
		}
		p := in.ip(arg(0)).p
		var cuts []int
		prev := 0
		for i := 1; i < n; i++ {
			c := int(in.int(arg(i)))
			// a fragment offset counts in 8-byte units, and the cuts split the payload in order
			if c%8 != 0 || c <= prev || c >= len(p.Payload) {
				in.failf("fragments: cut %d is not a multiple of 8 between %d and %d", c, prev, len(p.Payload))
			}
			cuts = append(cuts, c)
			prev = c
		}
		return ipList(Fragments(p, cuts...)), true
	case "fragments_every":
		p := in.ip(arg(0)).p
		step := int(in.int(arg(1)))
		if step <= 0 || step%8 != 0 {
			in.failf("fragments_every takes a positive multiple of 8")
		}
		var cuts []int
		for off := step; off < len(p.Payload); off += step {
			cuts = append(cuts, off)
		}
		return ipList(Fragments(p, cuts...)), true
	case "frag":
		p := in.ip(arg(0)).p
		from, to := int(in.int(arg(1))), int(in.int(arg(2)))
		if from < 0 || to < from || to > len(p.Payload) || from%8 != 0 {
			in.failf("frag [%d:%d] out of range of %d, or not at a multiple of 8", from, to, len(p.Payload))
		}
		return &ipv{p: Frag(p, from, to), ok: true}, true
	case "frag_needed":
		return FragNeeded(in.addr(arg(0)), in.bytes(arg(1)), uint16(in.int(arg(2)))), true
	case "corrupt", "set_bytes":
		p := in.ip(arg(0)).p
		p.Payload = append([]byte(nil), p.Payload...)
		off := int(in.int(arg(1)))
		if e.Name == "corrupt" {
			if off < 0 || off >= len(p.Payload) {
				in.failf("corrupt at %d out of range of %d", off, len(p.Payload))
			}
			p.Payload[off] ^= byte(in.int(arg(2)))
		} else {
			b := in.bytes(arg(2))
			if off < 0 || off+len(b) > len(p.Payload) {
				in.failf("set_bytes at %d out of range of %d", off, len(p.Payload))
			}
			copy(p.Payload[off:], b)
		}
		return &ipv{p: p, ok: true}, true
	case "to_peer":
		return toPeer(in.ip(arg(0)).p), true
	case "icmp_type":
		m, err := ParseICMP(in.ip(arg(0)).p)
		if err != nil {
			return int64(-1), true
		}
		return int64(m.Type), true
	case "parse_udp":
		u, err := ParseUDP(in.ip(arg(0)).p)
		return &udpv{u: u, err: err}, true
	case "parse_icmp":
		m, err := ParseICMP(in.ip(arg(0)).p)
		return &icmpv{m: m, ok: err == nil}, true
	case "parse_quote":
		q, ok := ParseQuote(in.bytes(arg(0)))
		return &quotev{q: q, ok: ok}, true
	case "reply_desc":
		u, ok := arg(1).(*udpv)
		if !ok {
			in.failf("reply_desc takes the result of parse_udp")
		}
		return []byte(replyDesc(in.truth(arg(0)), u.err, u.u, in.bytes(arg(2)))), true
	case "pmtu_desc":
		return []byte(pmtuDesc(int(in.int(arg(0))))), true
	case "seg_descs":
		var descs []string
		for _, x := range in.list(arg(0)) {
			s := in.seg(x)
			descs = append(descs, segDesc(s.seg, s.ok))
		}
		return []byte(fmt.Sprint(descs)), true
	case "seconds_text":
		return []byte(strconv.FormatFloat(in.dur(arg(0)).Seconds(), 'f', int(in.int(arg(1))), 64)), true
	}
	return nil, false
}

// netField reads the fields of this file's values.
func (in *interp) netField(x any, name string) (any, bool) {
	switch v := x.(type) {
	case *ipv:
		p := v.p
		switch name {
		case "ok":
			return v.ok, true
		case "at":
			return v.at, true
		case "src":
			return p.Src, true
		case "dst":
			return p.Dst, true
		case "proto":
			return int64(p.Proto), true
		case "id":
			return int64(p.ID), true
		case "df":
			return p.DF, true
		case "mf":
			return p.MF, true
		case "offset":
			return int64(p.Offset), true
		case "ttl":
			return int64(p.TTL), true
		case "payload":
			return append([]byte(nil), p.Payload...), true
		}
	case *udpv:
		switch name {
		case "err":
			return wrapErr(v.err), true
		case "src":
			return v.u.Src, true
		case "dst":
			return v.u.Dst, true
		case "payload":
			return append([]byte(nil), v.u.Payload...), true
		case "checksum":
			return int64(v.u.Checksum), true
		}
	case *icmpv:
		switch name {
		case "ok":
			return v.ok, true
		case "type":
			return int64(v.m.Type), true
		case "code":
			return int64(v.m.Code), true
		case "rest":
			return int64(v.m.Rest), true
		case "body":
			return append([]byte(nil), v.m.Body...), true
		}
	case *quotev:
		q := v.q
		switch name {
		case "ok":
			return v.ok, true
		case "id":
			return int64(q.ID), true
		case "src":
			return q.Src, true
		case "dst":
			return q.Dst, true
		case "proto":
			return int64(q.Proto), true
		case "offset":
			return int64(q.Offset), true
		case "payload":
			return append([]byte(nil), q.Payload...), true
		case "bytes":
			return int64(q.Bytes), true
		}
	case netip.AddrPort:
		switch name {
		case "addr":
			return v.Addr(), true
		case "port":
			return int64(v.Port()), true
		}
	}
	return nil, false
}

func ipList(ps []IPv4) []any {
	out := []any{}
	for _, p := range ps {
		out = append(out, &ipv{p: p, ok: true})
	}
	return out
}

func (in *interp) ip(v any) *ipv {
	p, ok := v.(*ipv)
	if !ok {
		in.failf("an IPv4 packet is expected, not %s", typeName(v))
	}
	return p
}

func (in *interp) addr(v any) netip.Addr {
	a, ok := v.(netip.Addr)
	if !ok {
		in.failf("an address is expected, not %s", typeName(v))
	}
	return a
}

func (in *interp) addrPort(v any) netip.AddrPort {
	a, ok := v.(netip.AddrPort)
	if !ok {
		in.failf("an address and port are expected, not %s", typeName(v))
	}
	return a
}

func (in *interp) udpConn(v any) *udpconnv {
	c, ok := v.(*udpconnv)
	if !ok {
		in.failf("a UDP socket is expected, not %s", typeName(v))
	}
	return c
}
