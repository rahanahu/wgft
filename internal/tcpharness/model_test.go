package tcpharness

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// modelSender is a ClockedDUT with a small SACK sender behind it, for the loss-response family's
// teeth: a correct sender must pass the checks, and each fault the checks are meant to catch must
// fail them. It answers one passive open on any port, sends whatever the application writes, and
// knows RFC 6675's pipe, an RFC 8985 style loss detection whose reorder window is a quarter of
// lossRTT once it has seen reordering and zero before, a recovery that sends while the pipe is
// below cwnd, slow start, Reno's congestion avoidance and an RTO of 300 ms that doubles. Its
// reductions are what modelRule says. It is not a TCP: it ignores the peer's window and data.
type modelSender struct {
	rule modelRule

	mu   sync.Mutex
	cond *sync.Cond
	now  time.Time
	out  [][]byte

	accepted chan *modelConn
	conn     *modelConn
	local    netip.AddrPort
	peer     netip.AddrPort
	state    int // 0 none, 1 SYN-RECEIVED, 2 established, 3 closed
	iss      uint32
	rcvNxt   uint32
	tsRecent uint32

	sndUna, sndNxt uint32
	data           []byte // the application's bytes from sndUna on
	segs           []*modelSeg
	cwnd, ssthresh float64

	inRecovery, inLoss bool
	recoveryPoint      uint32
	reordered          bool
	rto                time.Duration
	rtoAt              time.Time
}

// modelRule names how the model reduces its window.
type modelRule int

const (
	// ruleWindow is the reference Linux's choice: half of cwnd at a loss, and an RTO during a
	// recovery keeps the recovery's ssthresh.
	ruleWindow modelRule = iota
	// ruleSpan takes 0.7 of the sequence span outstanding at a loss, SACKed data included.
	ruleSpan
	// ruleNone does not reduce at a loss.
	ruleNone
	// ruleCollapse sets ssthresh at an RTO to half the pipe, which is empty: two segments.
	ruleCollapse
	// ruleRTOSpan sets ssthresh at an RTO to the whole span outstanding, not reduced.
	ruleRTOSpan
)

type modelSeg struct {
	seq      uint32
	n        int
	sacked   bool
	sackedAt time.Time
	lost     bool
	rexmit   bool
}

const (
	modelSegSize = MTU - 40 - 12
	modelLimit   = 1 << 20
	modelReorder = lossRTT / 4
)

func newModel(rule modelRule) *modelSender {
	m := &modelSender{rule: rule, now: time.Unix(1_000_000, 0), accepted: make(chan *modelConn, 1),
		iss: 0x10000000, cwnd: 10, ssthresh: 1 << 30, rto: 300 * time.Millisecond}
	m.cond = sync.NewCond(&m.mu)
	return m
}

func modelEngine(rule modelRule) Engine {
	return Engine{Name: "model", New: func(tb testing.TB, _ uint64) DUT {
		m := newModel(rule)
		tb.Cleanup(func() { m.Close() })
		return m
	}}
}

func (m *modelSender) Name() string                             { return "model" }
func (m *modelSender) Addr() netip.Addr                         { return DUTAddr }
func (m *modelSender) MTU() int                                 { return MTU }
func (m *modelSender) Emitted() <-chan []byte                   { return nil }
func (m *modelSender) ListenUDP(uint16) (net.PacketConn, error) { return nil, errors.New("no UDP") }
func (m *modelSender) Listen(uint16) (Listener, error)          { return modelListener{m}, nil }

func (m *modelSender) Close() error {
	m.mu.Lock()
	m.state = 3
	m.cond.Broadcast()
	m.mu.Unlock()
	return nil
}

func (m *modelSender) Now() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.now
}

func (m *modelSender) Poll() ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.out) == 0 {
		return nil, false
	}
	p := m.out[0]
	m.out = m.out[1:]
	return p, true
}

func (m *modelSender) Advance(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = m.now.Add(d)
	if m.state != 2 {
		return
	}
	if !m.rtoAt.IsZero() && !m.now.Before(m.rtoAt) {
		m.timeout()
	}
	m.detect()
	m.send()
}

func (m *modelSender) ms() uint32 { return uint32(m.now.UnixMilli()) }

func (m *modelSender) emit(flags uint8, seq uint32, payload []byte, o Options) {
	o.TS = &Timestamps{Val: m.ms(), Ecr: m.tsRecent}
	s := Segment{Src: m.local, Dst: m.peer, Seq: seq, Ack: m.rcvNxt, Flags: flags, Window: 65535, Opts: o, Payload: payload}
	m.out = append(m.out, s.Marshal())
}

func (m *modelSender) Inject(pkt []byte) error {
	s, err := Parse(pkt)
	if err != nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.Opts.TS != nil {
		m.tsRecent = s.Opts.TS.Val
	}
	switch {
	case s.Has(FlagSYN) && m.state == 0:
		m.local, m.peer, m.rcvNxt, m.state = s.Dst, s.Src, s.Seq+1, 1
		mss := uint16(MTU - 40)
		o := Options{MSS: &mss, WS: 7, SACKPermitted: true}
		m.emit(FlagSYN|FlagACK, m.iss, nil, o)
	case m.state == 1 && s.Has(FlagACK) && s.Ack == m.iss+1:
		m.state, m.sndUna, m.sndNxt = 2, m.iss+1, m.iss+1
		m.rto = 300 * time.Millisecond
		m.conn = &modelConn{m: m}
		m.accepted <- m.conn
	case m.state == 2 && s.Has(FlagACK):
		m.ack(s)
		m.detect()
		m.send()
	}
	return nil
}

// ack takes an ACK's cumulative point and SACK blocks.
func (m *modelSender) ack(s Segment) {
	delivered := 0
	advanced := after(s.Ack, m.sndUna) && !after(s.Ack, m.sndNxt)
	if advanced {
		var rest []*modelSeg
		for _, g := range m.segs {
			if after(g.seq+uint32(g.n), s.Ack) {
				rest = append(rest, g)
				continue
			}
			if !g.sacked {
				delivered++
				if !g.rexmit && m.sackedAbove(g) {
					m.reordered = true // an original filled a hole below SACKed data, RFC 8985 6.2
				}
			}
		}
		m.data = m.data[s.Ack-m.sndUna:]
		m.sndUna = s.Ack
		m.segs = rest
		m.cond.Broadcast()
		m.rtoAt = time.Time{}
		m.rto = 300 * time.Millisecond
		if len(m.segs) > 0 {
			m.rtoAt = m.now.Add(m.rto)
		}
	}
	for _, b := range s.Opts.SACK {
		for _, g := range m.segs {
			if !g.sacked && !after(b.Left, g.seq) && !after(g.seq+uint32(g.n), b.Right) {
				g.sacked, g.sackedAt = true, m.now
				delivered++
			}
		}
	}
	if (m.inRecovery || m.inLoss) && !after(m.recoveryPoint, m.sndUna) {
		if m.inRecovery {
			m.cwnd = m.ssthresh
		}
		m.inRecovery, m.inLoss = false, false
	}
	if advanced && !m.inRecovery {
		for range delivered {
			if m.cwnd < m.ssthresh {
				m.cwnd = min(m.cwnd+1, m.ssthresh)
			} else {
				m.cwnd += 1 / m.cwnd
			}
		}
	}
}

func (m *modelSender) sackedAbove(g *modelSeg) bool {
	for _, x := range m.segs {
		if x.sacked && after(x.seq, g.seq) {
			return true
		}
	}
	return false
}

// detect marks lost every original segment below a SACKed one once the reorder window after
// that SACK has passed, and starts a recovery at the first loss outside one.
func (m *modelSender) detect() {
	sacked := 0
	for _, g := range m.segs {
		if g.sacked {
			sacked++
		}
	}
	reo := modelReorder
	if !m.reordered && (sacked >= 3 || m.inRecovery) {
		reo = 0
	}
	var lostAny bool
	for i, g := range m.segs {
		if g.sacked || g.lost || g.rexmit {
			continue
		}
		for _, x := range m.segs[i+1:] {
			if x.sacked && !m.now.Before(x.sackedAt.Add(reo)) {
				g.lost, lostAny = true, true
				break
			}
		}
	}
	for _, g := range m.segs {
		lostAny = lostAny || g.lost && !g.sacked
	}
	if !lostAny || m.inRecovery || m.inLoss {
		return
	}
	m.inRecovery, m.recoveryPoint = true, m.sndNxt
	switch m.rule {
	case ruleSpan:
		m.ssthresh = max(0.7*float64(m.sndNxt-m.sndUna)/modelSegSize, 2)
	case ruleNone:
		m.ssthresh = m.cwnd
	default:
		m.ssthresh = max(m.cwnd/2, 2)
	}
	m.cwnd = m.ssthresh
	// RFC 6675 5 step 4.3: the first loss goes at once, whatever the pipe
	for _, g := range m.segs {
		if g.lost && !g.sacked && !g.rexmit {
			m.resend(g)
			break
		}
	}
}

func (m *modelSender) timeout() {
	m.rto *= 2
	m.rtoAt = m.now.Add(m.rto)
	for _, g := range m.segs {
		if !g.sacked {
			g.lost, g.rexmit = true, false
		}
	}
	switch m.rule {
	case ruleCollapse:
		m.ssthresh = max(float64(m.pipe())/2, 2)
	case ruleRTOSpan:
		m.ssthresh = float64(m.sndNxt-m.sndUna) / modelSegSize
	default:
		if !m.inRecovery && !m.inLoss {
			m.ssthresh = max(m.cwnd/2, 2)
		}
	}
	m.cwnd = 1
	m.inRecovery, m.inLoss, m.recoveryPoint = false, true, m.sndNxt
}

// pipe is RFC 6675's: segments neither SACKed nor lost, and lost ones resent.
func (m *modelSender) pipe() int {
	n := 0
	for _, g := range m.segs {
		if !g.sacked && (!g.lost || g.rexmit) {
			n++
		}
	}
	return n
}

func (m *modelSender) resend(g *modelSeg) {
	g.rexmit = true
	off := g.seq - m.sndUna
	m.emit(FlagACK, g.seq, append([]byte(nil), m.data[off:off+uint32(g.n)]...), NoOptions())
	if m.rtoAt.IsZero() {
		m.rtoAt = m.now.Add(m.rto)
	}
}

// send resends lost segments, then sends new data, while the pipe is below cwnd.
func (m *modelSender) send() {
	if m.state != 2 {
		return
	}
	for pipe := m.pipe(); float64(pipe) < m.cwnd; pipe++ {
		var g *modelSeg
		for _, x := range m.segs {
			if x.lost && !x.sacked && !x.rexmit {
				g = x
				break
			}
		}
		if g != nil {
			m.resend(g)
			continue
		}
		off := int(m.sndNxt - m.sndUna)
		n := min(modelSegSize, len(m.data)-off)
		if n <= 0 {
			return
		}
		m.segs = append(m.segs, &modelSeg{seq: m.sndNxt, n: n})
		m.emit(FlagACK, m.sndNxt, append([]byte(nil), m.data[off:off+n]...), NoOptions())
		m.sndNxt += uint32(n)
		if m.rtoAt.IsZero() {
			m.rtoAt = m.now.Add(m.rto)
		}
	}
}

type modelListener struct{ m *modelSender }

func (l modelListener) Close() error { return nil }
func (l modelListener) Accept(ctx context.Context) (Conn, error) {
	select {
	case c := <-l.m.accepted:
		return c, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// modelConn is the application's end: writes wait while the model holds modelLimit bytes.
type modelConn struct{ m *modelSender }

func (c *modelConn) Write(b []byte) (int, error) {
	m := c.m
	m.mu.Lock()
	defer m.mu.Unlock()
	for m.state == 2 && len(m.data) >= modelLimit {
		m.cond.Wait()
	}
	if m.state != 2 {
		return 0, net.ErrClosed
	}
	m.data = append(m.data, b...)
	m.send()
	return len(b), nil
}

func (c *modelConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *modelConn) Close() error                     { return c.m.Close() }
func (c *modelConn) Abort() error                     { return c.m.Close() }
func (c *modelConn) CloseWrite() error                { return nil }
func (c *modelConn) LocalAddr() net.Addr              { return net.TCPAddrFromAddrPort(c.m.local) }
func (c *modelConn) RemoteAddr() net.Addr             { return net.TCPAddrFromAddrPort(c.m.peer) }
func (c *modelConn) SetDeadline(time.Time) error      { return nil }
func (c *modelConn) SetReadDeadline(time.Time) error  { return nil }
func (c *modelConn) SetWriteDeadline(time.Time) error { return nil }

var _ ClockedDUT = (*modelSender)(nil)
