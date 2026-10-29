package wgstack

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
)

// listener は TCP の待ち受け。accept の待ち行列は Device 全体で Q 本、待ち受け 1 つで Q の半分までで、
// 待ち行列の節は接続の枠に持つ(設計文書の「握手の途中の表と accept の待ち行列」)。closed、qhead、qtail、
// qLen、synCount は表の錠で守る。
type listener struct {
	s            *stack
	ap           netip.AddrPort
	closed       bool
	qhead, qtail int32
	qLen         int // 待ち行列の接続と、接続の枠へ移している途中の行
	synCount     int
	ch           chan struct{} // 待ち行列に入ったときに知らせる(容量 1)
	closeCh      chan struct{}
}

// enqueue は確立した接続を待ち行列の末尾に入れる。qLen と stack.queued は synInput が予約済みである。
// tmu を持って呼ぶ。
func (l *listener) enqueue(c *tcb) {
	c.lst, c.queued = l, true
	c.qprev, c.qnext = l.qtail, -1
	if l.qtail >= 0 {
		l.s.conns[l.qtail].qnext = c.id
	} else {
		l.qhead = c.id
	}
	l.qtail = c.id
}

// dequeue は接続を待ち行列から外し、予約を返す。tmu を持って呼ぶ。
func (l *listener) dequeue(c *tcb) {
	if !c.queued {
		return
	}
	if c.qprev >= 0 {
		l.s.conns[c.qprev].qnext = c.qnext
	} else {
		l.qhead = c.qnext
	}
	if c.qnext >= 0 {
		l.s.conns[c.qnext].qprev = c.qprev
	} else {
		l.qtail = c.qprev
	}
	c.qprev, c.qnext = -1, -1
	c.queued = false
	l.qLen--
	l.s.queued--
}

func (l *listener) signal() {
	select {
	case l.ch <- struct{}{}:
	default:
	}
}

// TCPListener は ListenTCP が返す net.Listener。Accept は *Conn を返す。
type TCPListener struct {
	l *listener
}

// ListenTCP は ap で TCP を待ち受ける。ap のアドレスは受け付ける宛先の集合に入ること。
func (d *Device) ListenTCP(ap netip.AddrPort) (*TCPListener, error) {
	return d.s.listenTCP(ap)
}

func (s *stack) listenTCP(ap netip.AddrPort) (*TCPListener, error) {
	addr := net.TCPAddrFromAddrPort(ap)
	if !ap.Addr().Is4() || !s.isLocal(addrBits(ap.Addr())) {
		return nil, &net.OpError{Op: "listen", Net: "tcp", Addr: addr, Err: errors.New("address is not a local address of this tunnel")}
	}
	if ap.Port() == 0 {
		return nil, &net.OpError{Op: "listen", Net: "tcp", Addr: addr, Err: errors.New("port 0 is not supported")}
	}
	s.tmu.Lock()
	defer s.tmu.Unlock()
	if s.closed {
		return nil, &net.OpError{Op: "listen", Net: "tcp", Addr: addr, Err: net.ErrClosed}
	}
	if _, ok := s.listeners[ap]; ok {
		return nil, &net.OpError{Op: "listen", Net: "tcp", Addr: addr, Err: syscall.EADDRINUSE}
	}
	l := &listener{s: s, ap: ap, qhead: -1, qtail: -1, ch: make(chan struct{}, 1), closeCh: make(chan struct{})}
	s.listeners[ap] = l
	return &TCPListener{l: l}, nil
}

// Accept は net.Listener の実装。待ち行列の先頭の接続を返す。
func (t *TCPListener) Accept() (net.Conn, error) {
	l := t.l
	s := l.s
	for {
		s.tmu.Lock()
		if l.closed || s.closed {
			s.tmu.Unlock()
			return nil, &net.OpError{Op: "accept", Net: "tcp", Addr: t.Addr(), Err: net.ErrClosed}
		}
		if id := l.qhead; id >= 0 {
			c := &s.conns[id]
			gen := c.gen
			l.dequeue(c)
			more := l.qhead >= 0
			s.tmu.Unlock()
			if more {
				l.signal()
			}
			c.mu.Lock()
			if c.gen != gen || c.state == stFree {
				c.mu.Unlock()
				continue
			}
			c.accepted = true
			h := newConn(c, gen)
			c.mu.Unlock()
			return h, nil
		}
		s.tmu.Unlock()
		select {
		case <-l.ch:
		case <-l.closeCh:
		case <-s.done:
		}
	}
}

// Close は net.Listener の実装。待ち行列の接続と握手の途中の行に RST を送って返し、ポートをその場で空ける。
func (t *TCPListener) Close() error {
	l := t.l
	s := l.s
	type ref struct {
		id  int32
		gen uint32
	}
	var queued []ref
	s.tmu.Lock()
	if l.closed {
		s.tmu.Unlock()
		return nil
	}
	l.closed = true
	if s.listeners[l.ap] == l {
		delete(s.listeners, l.ap)
	}
	close(l.closeCh)
	for id := range s.syn.rows {
		r := &s.syn.rows[id]
		if r.used && r.lst == l && !r.promoting {
			s.sendCtl(tcpHeader{tup: r.tup, seq: r.iss + 1, ack: r.irs + 1, flags: flagRST | flagACK})
			s.removeSynRow(int32(id))
		}
	}
	for id := l.qhead; id >= 0; {
		c := &s.conns[id]
		next := c.qnext
		queued = append(queued, ref{id, c.gen})
		l.dequeue(c)
		id = next
	}
	s.tmu.Unlock()
	for _, q := range queued {
		c := &s.conns[q.id]
		c.mu.Lock()
		if c.gen == q.gen && c.state != stFree {
			if c.state != stClosed {
				c.sendRST()
			}
			c.release()
		}
		c.mu.Unlock()
	}
	return nil
}

// Addr は net.Listener の実装。
func (t *TCPListener) Addr() net.Addr { return net.TCPAddrFromAddrPort(t.l.ap) }

var _ net.Listener = (*TCPListener)(nil)
