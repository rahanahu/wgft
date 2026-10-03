package relay

// serveUDP が受け付けの印を読み取りのループより先に立てること。

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/rahanahu/wgft/proto"
)

// firstReadConn は最初の ReadFrom の呼び出しの時点の受け付けの印を記録し、その後は Close まで
// ブロックする PacketConn である。読み取りのループが最初に印を読む時点を観測する。
type firstReadConn struct {
	l      *listener
	once   sync.Once
	closed chan struct{}
	seen   chan bool
}

func (c *firstReadConn) ReadFrom([]byte) (int, net.Addr, error) {
	c.once.Do(func() { c.seen <- c.l.accepting.Load() })
	<-c.closed
	return 0, nil, net.ErrClosed
}
func (c *firstReadConn) WriteTo([]byte, net.Addr) (int, error) { return 0, net.ErrClosed }
func (c *firstReadConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}
func (c *firstReadConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *firstReadConn) SetDeadline(time.Time) error      { return nil }
func (c *firstReadConn) SetReadDeadline(time.Time) error  { return nil }
func (c *firstReadConn) SetWriteDeadline(time.Time) error { return nil }

// readLoop の最初の読み取りが始まる時点で accepting が立っていなければ、その読み取りが返す
// 新しい送信元のデータグラムは受け付けの印の判定で捨てられ、セッションができない。そのため、
// serveUDP は goroutine を始める前に印を立てる。順を入れ替えたときの窓は
// 極めて短く、-race なしでは見えない。-race のビルドでは runtime が scheduler の順を乱す
// (randomizeScheduler)ので、新しい goroutine が先に走る回が出る。落ちるのは data race の報告では
// なく、観測した印の値による。P が 2 つ以上のときだけ捕まり、GOMAXPROCS=1 では捕まらない。
func TestServeUDPSetsAcceptingBeforeReadLoopStarts(t *testing.T) {
	m := New(&loopback{}, Options{UDPIdleTimeout: time.Hour, Logf: testLogf(t)})
	t.Cleanup(m.Close)
	const rounds = 2000
	for i := 0; i < rounds; i++ {
		l := m.newListener(Key{proto.UDP, 1}, Desired{"127.0.0.1:1", "r1"})
		c := &firstReadConn{l: l, closed: make(chan struct{}), seen: make(chan bool, 1)}
		m.serveUDP(l, c)
		select {
		case ok := <-c.seen:
			if !ok {
				t.Fatalf("round %d: the read loop's first read saw accepting false", i)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("round %d: the read loop did not read within 5s", i)
		}
		l.shutdownLocked()
	}
}
