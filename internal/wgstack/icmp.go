package wgstack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

// ICMP(設計文書の「UDP、ICMP、再組み立て」)。自分のアドレス宛ての echo request には制御の輪から応答する。
// DialPing の endpoint は固定の数の表に置き、endpoint 1 つが持つ応答は 1 つだけで、読まれる前に届いた次の
// 応答は捨てる。ICMP の誤りは、外側の送信元が引用された datagram の宛先と一致するときだけ受け入れる
// (packet-validation.md の ICMP の誤りの入口)。wgstack が送る ICMP の誤りは、Device 全体の速さの制限の
// 内側で送る。

const (
	icmpEchoReply     = 0
	icmpDstUnreach    = 3
	icmpSrcQuench     = 4
	icmpRedirect      = 5
	icmpEcho          = 8
	icmpTimeExceeded  = 11
	icmpParamProblem  = 12
	icmpRateLimit     = 1000 // 1 秒あたりに送る ICMP の誤り(gVisor の既定の ICMP の速さの制限と同じ値)
	pingEndpoints     = 16   // N_ping
	icmpMinReassembly = 576  // IPv4 の最小の再組み立ての大きさ。誤りの引用はこれに収める
)

// icmpAllowed は Device 全体の ICMP の誤りの速さの制限から 1 つ取れたかを返す。
func (s *stack) icmpAllowed(now int64) bool {
	sec := now / int64(time.Second)
	s.icmpMu.Lock()
	defer s.icmpMu.Unlock()
	if sec != s.icmpSec {
		s.icmpSec, s.icmpCount = sec, icmpRateLimit
	}
	if s.icmpCount <= 0 {
		return false
	}
	s.icmpCount--
	return true
}

// sendICMPError は、届いた packet orig への ICMP の誤り(Destination Unreachable、Time Exceeded、Parameter
// Problem)を制御の輪に積む。rest は ICMP の header の後半の 4 byte(pointer など)である。誤りの packet、
// 先頭でない断片、自分のアドレスでない宛先、broadcast と multicast の送信元には送らない(RFC 1122 3.2.2)。
// laterFragment が真なら、先頭でない断片にも送る(後続の断片の option の誤りへの Parameter Problem)。
func (s *stack) sendICMPErrorRaw(orig []byte, typ, code uint8, rest uint32, now int64, laterFragment bool) {
	if len(orig) < ipHeaderLen {
		return
	}
	hlen := int(orig[0]&0x0f) * 4
	if hlen < ipHeaderLen || len(orig) < hlen {
		return
	}
	src := binary.BigEndian.Uint32(orig[12:16])
	dst := binary.BigEndian.Uint32(orig[16:20])
	if !s.isLocal(dst) || src == 0 || src == 0xffffffff || src>>28 == 0xe {
		return
	}
	if !laterFragment && binary.BigEndian.Uint16(orig[6:8])&0x1fff != 0 {
		return
	}
	if orig[9] == protoICMP && len(orig) > hlen {
		switch orig[hlen] {
		case icmpEchoReply, icmpEcho, 13, 14, 15, 16:
		default:
			return // ICMP の誤りに誤りを返さない
		}
	}
	if !s.icmpAllowed(now) {
		s.icmpLimited.Add(1)
		return
	}
	quote := orig[:min(len(orig), min(icmpMinReassembly, s.mtu)-ipHeaderLen-8)]
	id := s.nextID()
	ok := s.out.pushCtl(func(b []byte) int {
		total := ipHeaderLen + 8 + len(quote)
		if total > len(b) {
			return 0
		}
		writeIPv4Header(b, total, id, protoICMP, dst, src)
		m := b[ipHeaderLen:total]
		m[0], m[1], m[2], m[3] = typ, code, 0, 0
		binary.BigEndian.PutUint32(m[4:8], rest)
		copy(m[8:], quote)
		binary.BigEndian.PutUint16(m[2:4], ^checksum(0, m))
		return total
	})
	if !ok {
		s.refused(&s.ctlDropped, &s.ctlGate, now, "dropped control packets because the control output ring was full")
	}
}

func (s *stack) sendICMPError(ip *ipv4, typ, code uint8, rest uint32, now int64) {
	s.sendICMPErrorRaw(ip.header[:ip.hlen+len(ip.payload)], typ, code, rest, now, false)
}

// inputICMP は ICMP の入口。
func (s *stack) inputICMP(ip *ipv4, now int64) {
	b := ip.payload
	if len(b) < 8 || ^checksum(0, b) != 0 {
		s.icmpDropped.Add(1)
		return
	}
	switch b[0] {
	case icmpEcho:
		s.echoReply(ip, now)
	case icmpEchoReply:
		s.pingReply(ip)
	case icmpDstUnreach, icmpSrcQuench, icmpRedirect, icmpTimeExceeded, icmpParamProblem:
		s.icmpError(ip, now)
	default:
		s.icmpDropped.Add(1)
	}
}

// echoReply は自分のアドレス宛ての echo request に、制御の輪から echo reply を返す。
func (s *stack) echoReply(ip *ipv4, now int64) {
	total := ipHeaderLen + len(ip.payload)
	if total > s.mtu {
		s.icmpDropped.Add(1)
		return
	}
	id := s.nextID()
	ok := s.out.pushCtl(func(b []byte) int {
		writeIPv4Header(b, total, id, protoICMP, ip.dst, ip.src)
		m := b[ipHeaderLen:total]
		copy(m, ip.payload)
		m[0], m[2], m[3] = icmpEchoReply, 0, 0
		binary.BigEndian.PutUint16(m[2:4], ^checksum(0, m))
		return total
	})
	if !ok {
		s.refused(&s.ctlDropped, &s.ctlGate, now, "dropped control packets because the control output ring was full")
	}
}

// icmpError は ICMP の誤りを受ける。外側の送信元が引用の宛先と一致し、引用の送信元が自分であるときだけ
// 受け入れる。TCP の Fragmentation Needed は PMTU を下げる。ほかの誤りは数えて捨てる。UDP の待ち受けは
// 未接続なので、Port Unreachable を知らせる相手がいない。
func (s *stack) icmpError(ip *ipv4, now int64) {
	b := ip.payload
	q := b[8:]
	if len(q) < ipHeaderLen || q[0]>>4 != 4 {
		s.icmpDropped.Add(1)
		return
	}
	qsrc, qdst := binary.BigEndian.Uint32(q[12:16]), binary.BigEndian.Uint32(q[16:20])
	if qdst != ip.src || qsrc != ip.dst {
		s.icmpDropped.Add(1)
		return
	}
	if b[0] != icmpDstUnreach || b[1] != 4 {
		s.icmpDropped.Add(1)
		return
	}
	qhl := int(q[0]&0x0f) * 4
	if qhl < ipHeaderLen || len(q) < qhl+8 || q[9] != protoTCP {
		s.icmpDropped.Add(1)
		return
	}
	mtu := int(binary.BigEndian.Uint16(b[6:8]))
	if mtu < minPMTU {
		s.icmpDropped.Add(1)
		return
	}
	t := q[qhl:]
	tup := tuple{laddr: qsrc, raddr: qdst, lport: binary.BigEndian.Uint16(t[0:2]), rport: binary.BigEndian.Uint16(t[2:4])}
	seq := binary.BigEndian.Uint32(t[4:8])
	s.tmu.Lock()
	id, gen := s.connIdx.find(tup)
	s.tmu.Unlock()
	if id < 0 {
		s.icmpDropped.Add(1)
		return
	}
	c := &s.conns[id]
	c.mu.Lock()
	if c.gen == gen && c.inIndex {
		c.pmtuDrop(seq, mtu, now)
	}
	c.mu.Unlock()
}

// pingTable は DialPing の endpoint の固定の表。
type pingTable struct {
	mu   sync.Mutex
	eps  [pingEndpoints]pingEP
	next uint16 // 次に試す識別子
}

type pingEP struct {
	used  bool
	gen   uint32
	ident uint16
	laddr uint32
	raddr uint32
	reply []byte // MTU の大きさ。作成の時に確保する
	n     int    // 持っている応答の長さ。0 なら無し
	rch   chan struct{}
	rdl   deadline
}

// pingReply は echo reply を、識別子と送信元の合う endpoint に渡す。応答を 1 つ持っていれば捨てる。
func (s *stack) pingReply(ip *ipv4) {
	ident := binary.BigEndian.Uint16(ip.payload[4:6])
	p := &s.ping
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.eps {
		e := &p.eps[i]
		if !e.used || e.ident != ident || e.raddr != ip.src || e.laddr != ip.dst {
			continue
		}
		if e.n == 0 && len(ip.payload) <= len(e.reply) {
			e.n = copy(e.reply, ip.payload)
			select {
			case e.rch <- struct{}{}:
			default:
			}
		} else {
			s.icmpDropped.Add(1)
		}
		return
	}
	s.icmpDropped.Add(1)
}

// PingConn は DialPing が返す接続。Write は ICMP の echo request を 1 つ送り、識別子をこの endpoint の値に
// 書き換える。Read は応答を 1 つ読む。
type PingConn struct {
	s   *stack
	i   int
	gen uint32
	l   net.IPAddr
	r   net.IPAddr
}

// DialPing は laddr から raddr への ICMP の echo の endpoint を作る。laddr はこの Device のアドレスである
// こと。表が満杯なら誤りを返す。
func (d *Device) DialPing(laddr, raddr netip.Addr) (net.Conn, error) {
	s := d.s
	if !laddr.Is4() || !raddr.Is4() {
		return nil, &net.OpError{Op: "dial", Net: "ping4", Err: errors.New("ping needs IPv4 addresses")}
	}
	if !s.isLocal(addrBits(laddr)) {
		return nil, fmt.Errorf("ping source address %v is not a local address of this tunnel", laddr)
	}
	p := &s.ping
	p.mu.Lock()
	defer p.mu.Unlock()
	if s.isClosed() {
		return nil, &net.OpError{Op: "dial", Net: "ping4", Err: net.ErrClosed}
	}
	free := -1
	for i := range p.eps {
		if !p.eps[i].used {
			free = i
			break
		}
	}
	if free < 0 {
		return nil, &net.OpError{Op: "dial", Net: "ping4", Err: errors.New("all ping endpoints are in use")}
	}
	ident := p.next
	for inUse := true; inUse; {
		ident++
		inUse = false
		for i := range p.eps {
			if p.eps[i].used && p.eps[i].ident == ident {
				inUse = true
			}
		}
	}
	p.next = ident
	e := &p.eps[free]
	e.used, e.ident, e.laddr, e.raddr, e.n = true, ident, addrBits(laddr), addrBits(raddr), 0
	e.gen++
	if e.reply == nil {
		e.reply = make([]byte, s.mtu)
	}
	e.rch = make(chan struct{}, 1)
	e.rdl.reset()
	return &PingConn{s: s, i: free, gen: e.gen, l: net.IPAddr{IP: laddr.AsSlice()}, r: net.IPAddr{IP: raddr.AsSlice()}}, nil
}

func (s *stack) isClosed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// ep は endpoint を返す。閉じていれば nil。ping.mu を持って呼ぶ。
func (c *PingConn) ep() *pingEP {
	e := &c.s.ping.eps[c.i]
	if !e.used || e.gen != c.gen {
		return nil
	}
	return e
}

func (c *PingConn) opErr(op string, err error) error {
	return &net.OpError{Op: op, Net: "ping4", Source: &c.l, Addr: &c.r, Err: err}
}

// Write は ICMP の echo request の message b を送る。
func (c *PingConn) Write(b []byte) (int, error) {
	s := c.s
	if len(b) < 8 || b[0] != icmpEcho || ipHeaderLen+len(b) > s.mtu {
		return 0, c.opErr("write", errors.New("not an ICMP echo request that fits the MTU"))
	}
	p := &s.ping
	p.mu.Lock()
	e := c.ep()
	if e == nil {
		p.mu.Unlock()
		return 0, c.opErr("write", net.ErrClosed)
	}
	ident, src, dst := e.ident, e.laddr, e.raddr
	p.mu.Unlock()
	total := ipHeaderLen + len(b)
	id := s.nextID()
	ok := s.out.pushCtl(func(buf []byte) int {
		writeIPv4Header(buf, total, id, protoICMP, src, dst)
		m := buf[ipHeaderLen:total]
		copy(m, b)
		m[2], m[3] = 0, 0
		binary.BigEndian.PutUint16(m[4:6], ident)
		binary.BigEndian.PutUint16(m[2:4], ^checksum(0, m))
		return total
	})
	if !ok {
		return 0, c.opErr("write", errors.New("the control output ring is full"))
	}
	return len(b), nil
}

// Read は応答の message を 1 つ読む。期限を過ぎた読み取りは Timeout() が真の誤りを返す。
func (c *PingConn) Read(b []byte) (int, error) {
	s := c.s
	p := &s.ping
	for {
		p.mu.Lock()
		e := c.ep()
		if e == nil {
			p.mu.Unlock()
			return 0, c.opErr("read", net.ErrClosed)
		}
		if e.rdl.expired() {
			p.mu.Unlock()
			return 0, c.opErr("read", os.ErrDeadlineExceeded)
		}
		if e.n > 0 {
			n := copy(b, e.reply[:e.n])
			e.n = 0
			p.mu.Unlock()
			return n, nil
		}
		ch, dl := e.rch, e.rdl.wait()
		p.mu.Unlock()
		select {
		case <-ch:
		case <-dl:
		case <-s.done:
			return 0, c.opErr("read", net.ErrClosed)
		}
	}
}

// Close は endpoint を返し、識別子を空ける。
func (c *PingConn) Close() error {
	p := &c.s.ping
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := c.ep(); e != nil {
		e.used, e.n = false, 0
		close(e.rch)
	}
	return nil
}

func (c *PingConn) LocalAddr() net.Addr  { return &c.l }
func (c *PingConn) RemoteAddr() net.Addr { return &c.r }

func (c *PingConn) SetDeadline(t time.Time) error {
	c.SetWriteDeadline(t)
	return c.SetReadDeadline(t)
}

func (c *PingConn) SetReadDeadline(t time.Time) error {
	p := &c.s.ping
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := c.ep(); e != nil {
		e.rdl.set(t)
		select {
		case e.rch <- struct{}{}:
		default:
		}
	}
	return nil
}

// SetWriteDeadline は何もしない。Write は制御の輪に積むだけで待たない。
func (c *PingConn) SetWriteDeadline(time.Time) error { return nil }

var _ net.Conn = (*PingConn)(nil)
