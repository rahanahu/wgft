package wgstack

import (
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

// deadline は接続の 1 つの向きの読み書きの期限。runtime のタイマーは枠ごとに向きあたり 1 つで、最初に
// 期限を置いたときに作り、その後は置き直す(設計文書の「並行性と時計」)。期限は壁時計で測る。ch は期限が
// 過ぎたときに閉じる。mu は末端の錠である。
type deadline struct {
	mu    sync.Mutex
	t     time.Time
	ch    chan struct{}
	timer *time.Timer
}

func (d *deadline) reset() { d.set(time.Time{}) }

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
	}
	if d.ch == nil {
		d.ch = make(chan struct{})
	} else {
		select {
		case <-d.ch:
			d.ch = make(chan struct{})
		default:
		}
	}
	d.t = t
	if t.IsZero() {
		return
	}
	dur := time.Until(t)
	if dur <= 0 {
		close(d.ch)
		return
	}
	if d.timer == nil {
		d.timer = time.AfterFunc(dur, d.fire)
	} else {
		d.timer.Reset(dur)
	}
}

func (d *deadline) fire() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.t.IsZero() || time.Now().Before(d.t) {
		return
	}
	select {
	case <-d.ch:
	default:
		close(d.ch)
	}
}

func (d *deadline) wait() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ch == nil {
		d.ch = make(chan struct{})
	}
	return d.ch
}

func (d *deadline) expired() bool {
	select {
	case <-d.wait():
		return true
	default:
		return false
	}
}

// Conn は ListenTCP の Accept が返す接続。net.Conn に加えて、中継と internal/netpipe が型アサーションで
// 探す Abort、CloseWrite、Delivered、CloseForDelivery、OnBoost を持つ(設計文書の「今の境目」)。
//
// Conn は接続の枠と、その枠を使い始めた時の世代を持つ。枠が TIME_WAIT の表の行に移った後か、別の接続に
// 使われた後(古い接続の値)は、Delivered が真を返し、Close は何もせずに nil を返し、Read と Write は
// net.ErrClosed を返す。Abort は、元の接続の行が表に残っていれば行を外して RST を送り、残っていなければ
// 何もしない。
type Conn struct {
	s     *stack
	c     *tcb
	gen   uint32
	tup   tuple
	laddr *net.TCPAddr
	raddr *net.TCPAddr
}

func newConn(c *tcb, gen uint32) *Conn {
	return &Conn{
		s:     c.s,
		c:     c,
		gen:   gen,
		tup:   c.tup,
		laddr: net.TCPAddrFromAddrPort(c.tup.local()),
		raddr: net.TCPAddrFromAddrPort(c.tup.remote()),
	}
}

func (h *Conn) opErr(op string, err error) error {
	return &net.OpError{Op: op, Net: "tcp", Source: h.laddr, Addr: h.raddr, Err: err}
}

// lock は接続の錠を取り、枠がまだこの接続のものかを返す。偽なら錠を持たない。
func (h *Conn) lock() bool {
	h.c.mu.Lock()
	if h.c.gen != h.gen || h.c.state == stFree {
		h.c.mu.Unlock()
		return false
	}
	return true
}

func (h *Conn) deviceClosed() bool {
	select {
	case <-h.s.done:
		return true
	default:
		return false
	}
}

// Read は net.Conn の実装。期限を過ぎた読み取りは Timeout() が真の net.Error を返し、相手の FIN の後は
// 受けたデータを読み終えてから io.EOF を返す。
func (h *Conn) Read(b []byte) (int, error) {
	s := h.s
	for {
		if !h.lock() {
			return 0, h.opErr("read", net.ErrClosed)
		}
		c := h.c
		if c.appClosed || h.deviceClosed() {
			c.mu.Unlock()
			return 0, h.opErr("read", net.ErrClosed)
		}
		if c.rdl.expired() {
			c.mu.Unlock()
			return 0, h.opErr("read", os.ErrDeadlineExceeded)
		}
		if len(b) == 0 {
			c.mu.Unlock()
			return 0, nil
		}
		if c.rcv.unread() > 0 {
			n := c.rcv.read(b)
			now := s.clock()
			c.rcvSpaceAdjust(now)
			c.ackOnDrain()
			c.windowUpdate()
			boost := c.rdem.add(now, n) && c.noteDemand(boostRecv, now)
			c.afterInput(now)
			c.mu.Unlock()
			if boost {
				s.tryBoost(c, h.gen, boostRecv)
			}
			return n, nil
		}
		if c.finRcvd || (c.state == stClosed && c.err == nil) {
			c.mu.Unlock()
			return 0, io.EOF
		}
		if c.err != nil {
			err := c.err
			c.mu.Unlock()
			return 0, h.opErr("read", err)
		}
		ch, dl := c.rch, c.rdl.wait()
		c.mu.Unlock()
		select {
		case <-ch:
		case <-dl:
		case <-s.done:
		}
	}
}

// Write は net.Conn の実装。送信のバッファに空きができるまで待つ。
func (h *Conn) Write(b []byte) (int, error) {
	s := h.s
	total := 0
	for {
		if !h.lock() {
			return total, h.opErr("write", net.ErrClosed)
		}
		c := h.c
		if c.appClosed || h.deviceClosed() {
			c.mu.Unlock()
			return total, h.opErr("write", net.ErrClosed)
		}
		if c.err != nil {
			err := c.err
			c.mu.Unlock()
			return total, h.opErr("write", err)
		}
		if c.sndShut || (c.state != stEstablished && c.state != stCloseWait) {
			c.mu.Unlock()
			return total, h.opErr("write", syscall.EPIPE)
		}
		if c.wdl.expired() {
			c.mu.Unlock()
			return total, h.opErr("write", os.ErrDeadlineExceeded)
		}
		if total == len(b) {
			c.mu.Unlock()
			return total, nil
		}
		if space := c.sndCap - (c.tailOff - c.unaOff); space > 0 {
			n := int(min(space, uint64(len(b)-total)))
			c.snd.write(c.tailOff, b[total:total+n])
			c.tailOff += uint64(n)
			total += n
			now := s.clock()
			boost := c.wdem.add(now, n) && c.noteDemand(boostSend, now)
			c.afterInput(now)
			c.mu.Unlock()
			if boost {
				s.tryBoost(c, h.gen, boostSend)
			}
			continue
		}
		ch, dl := c.wch, c.wdl.wait()
		c.mu.Unlock()
		select {
		case <-ch:
		case <-dl:
		case <-s.done:
		}
	}
}

// CloseWrite は送信の向きを閉じ、送信のバッファの後ろに FIN を置く。読み取りは続けられる。
func (h *Conn) CloseWrite() error {
	if !h.lock() {
		return h.opErr("close", net.ErrClosed)
	}
	c := h.c
	defer c.mu.Unlock()
	if c.appClosed {
		return h.opErr("close", net.ErrClosed)
	}
	c.shutdownWrite()
	c.afterInput(h.s.clock())
	return nil
}

// shutdownWrite は FIN を送る印を付け、状態を移す。
func (c *tcb) shutdownWrite() {
	if c.sndShut {
		return
	}
	switch c.state {
	case stEstablished:
		c.state = stFinWait1
	case stCloseWait:
		c.state = stLastAck
	default:
		return
	}
	c.sndShut = true
	c.signalWrite()
}

// Close は net.Conn の実装。未読の順序どおりのデータを持てば RST で終えて枠を返し(Linux と同じ)、持たなければ
// 送信のバッファの後ろに FIN を置く。送り残しを持つ接続は、届け終えるか再送の回数を使い切るまで枠に残り、
// 行に移る条件を満たした後に TIME_WAIT の表に移る。古い接続の値では何もせずに nil を返す。
func (h *Conn) Close() error {
	if !h.lock() {
		return nil
	}
	c := h.c
	defer c.mu.Unlock()
	if c.appClosed {
		return nil
	}
	c.appClosed = true
	c.signalRead()
	c.signalWrite()
	switch {
	case c.state == stClosed:
		c.release()
	case c.rcv.unread() > 0:
		c.sendRST()
		c.release()
	default:
		c.shutdownWrite()
		c.afterInput(h.s.clock())
	}
	return nil
}

// CloseForDelivery は wgstack では Close と同じである。送り残しを持つ接続は接続の枠に残り、TIME_WAIT の
// 表に入るのは行に移る条件を満たした後だけなので、表の追い出しで末尾を失わない(設計文書の「中継から見える
// 違い」)。
func (h *Conn) CloseForDelivery() error { return h.Close() }

// Abort は RST を送り、接続の枠をその場で返す。古い接続の値では、元の接続の行が TIME_WAIT の表に残って
// いれば行を外して RST を送る。
func (h *Conn) Abort() {
	c := h.c
	c.mu.Lock()
	if c.gen != h.gen || c.state == stFree {
		c.mu.Unlock()
		s := h.s
		s.tmu.Lock()
		if !s.closed {
			s.abortTWRow(h.tup, c.id, h.gen)
		}
		s.tmu.Unlock()
		return
	}
	defer c.mu.Unlock()
	c.appClosed = true
	if c.state != stClosed {
		c.sendRST()
	}
	c.release()
}

// Delivered は、最後の Close か Abort の後、この接続が送ったデータと FIN を届け終えたかを返す。CLOSED、
// TIME_WAIT、受信のバッファが空の FIN_WAIT_2 を届け終えたとする。古い接続の値では真を返す。
func (h *Conn) Delivered() bool {
	if !h.lock() {
		return true
	}
	c := h.c
	defer c.mu.Unlock()
	if !c.appClosed {
		return false
	}
	switch c.state {
	case stClosed, stTimeWait:
		return true
	case stFinWait2:
		return c.rcv.empty()
	}
	return false
}

// OnBoost は f を登録し、その場で今の状態を 1 回渡す。boost を得たときに f(true) を、需要の無い保有者として
// floor に戻るときに f(false) を呼ぶ。f(false) が偽を返したら戻りを取り消し、枠を持ち続ける。閉じた接続の
// 枠を返すときには呼ばない。f は接続の錠の中で呼ぶので、待たずに戻り、この接続を呼ばないこと。
func (h *Conn) OnBoost(f func(boosted bool) bool) {
	if !h.lock() {
		f(false)
		return
	}
	defer h.c.mu.Unlock()
	h.c.onBoost = f
	f(h.c.boosted)
}

func (h *Conn) LocalAddr() net.Addr  { return h.laddr }
func (h *Conn) RemoteAddr() net.Addr { return h.raddr }

func (h *Conn) SetDeadline(t time.Time) error {
	if err := h.SetReadDeadline(t); err != nil {
		return err
	}
	return h.SetWriteDeadline(t)
}

func (h *Conn) SetReadDeadline(t time.Time) error {
	if !h.lock() {
		return h.opErr("set", net.ErrClosed)
	}
	defer h.c.mu.Unlock()
	h.c.rdl.set(t)
	h.c.signalRead()
	return nil
}

func (h *Conn) SetWriteDeadline(t time.Time) error {
	if !h.lock() {
		return h.opErr("set", net.ErrClosed)
	}
	defer h.c.mu.Unlock()
	h.c.wdl.set(t)
	h.c.signalWrite()
	return nil
}

var _ net.Conn = (*Conn)(nil)
