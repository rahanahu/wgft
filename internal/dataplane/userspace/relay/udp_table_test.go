package relay

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// heldConn は、試験が離すまでセッションの goroutine を応答の待ちに留める宛先への接続である。
// WaitReadable は接続を閉じても戻らず、release の後に誤りを返す。これでセッションの goroutine が
// 終わる時点(表から自分を外し、枠を返す時点)を試験が決められる。
type heldConn struct {
	*net.UDPConn
	gate chan struct{}
	once sync.Once
}

func (c *heldConn) WaitReadable() error {
	<-c.gate
	return net.ErrClosed
}

func (c *heldConn) release() { c.once.Do(func() { close(c.gate) }) }

type heldUDPRig struct {
	m        *Manager
	key      Key
	releases atomic.Int32
	mu       sync.Mutex
	dialed   []*heldConn
}

func newHeldUDPRig(t *testing.T) *heldUDPRig {
	t.Helper()
	r := &heldUDPRig{}
	target, _ := udpEcho(t)
	lb := &loopback{}
	r.key = Key{proto.UDP, reserveUDP(t, lb)}
	// 後に登録した Cleanup が先に走るので、Manager を閉じた後に goroutine を離す
	t.Cleanup(func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, c := range r.dialed {
			c.release()
			c.Close()
		}
	})
	r.m = New(lb, Options{
		UDPIdleTimeout: time.Hour,
		UDPPool:        resource.NewPool(8),
		Logf:           testLogf(t),
		Admit: func(string, netip.Addr, int) (func(), bool) {
			return func() { r.releases.Add(1) }, true
		},
		Dial: func(network, addr string) (net.Conn, error) {
			ua, err := net.ResolveUDPAddr(network, addr)
			if err != nil {
				return nil, err
			}
			uc, err := net.DialUDP(network, nil, ua)
			if err != nil {
				return nil, err
			}
			c := &heldConn{UDPConn: uc, gate: make(chan struct{})}
			r.mu.Lock()
			r.dialed = append(r.dialed, c)
			r.mu.Unlock()
			return c, nil
		},
	})
	t.Cleanup(r.m.Close)
	r.m.Prepare(map[Key]Desired{r.key: {target, "r1"}}).Commit(nil)
	return r
}

func (r *heldUDPRig) sessions() int {
	r.m.mu.Lock()
	l := r.m.listeners[r.key]
	r.m.mu.Unlock()
	return l.sessions()
}

func (r *heldUDPRig) dials() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.dialed)
}

func (r *heldUDPRig) conn(i int) *heldConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dialed[i]
}

// sweep は閉じたセッションを、その goroutine の終わりを待たずに表から外す。sweep の直後に
// セッションの数を読む操作(Retiring の判定と Status)は、閉じたセッションを数えない。
func TestUDPSweepRemovesSessionsAtOnce(t *testing.T) {
	r := newHeldUDPRig(t)
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(r.key.Port)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the session to be registered", 5*time.Second, func() bool { return r.sessions() == 1 })

	if n := r.m.CloseSessions(func(string, netip.Addr) bool { return false }); n != 1 {
		t.Fatalf("CloseSessions = %d, want 1", n)
	}
	// セッションの goroutine はまだ heldConn の待ちにいて、表から自分を外していない
	if got := r.sessions(); got != 0 {
		t.Errorf("sessions = %d right after the sweep, want 0", got)
	}
	if got := r.releases.Load(); got != 0 {
		t.Fatalf("the session's charge was released %d times before its goroutine ended", got)
	}
}

// 終わったセッションの goroutine は、同じ送信元の後継のセッションを表から外さない。sweep が閉じた
// セッションの goroutine が終わる前に、同じ送信元から次のデータグラムが届き、同じ鍵で新しい
// セッションが登録される場合である。後継を外すと、表に無いセッションは closeF でも閉じられず、
// 宛先へのソケットと枠が残る。
func TestUDPEndedSessionKeepsItsSuccessor(t *testing.T) {
	r := newHeldUDPRig(t)
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(r.key.Port)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the first session to be registered", 5*time.Second, func() bool { return r.sessions() == 1 })
	if n := r.m.CloseSessions(func(string, netip.Addr) bool { return false }); n != 1 {
		t.Fatalf("CloseSessions = %d, want 1", n)
	}

	if _, err := c.Write([]byte("b")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the successor to be registered", 5*time.Second, func() bool { return r.dials() == 2 && r.sessions() == 1 })

	// 最初のセッションの goroutine を終わらせる。表から外す処理の後に枠を返すので、返したことを
	// 見てから表を確かめる
	r.conn(0).release()
	waitFor(t, "the first session's charge to be released", 5*time.Second, func() bool { return r.releases.Load() == 1 })
	if got := r.sessions(); got != 1 {
		t.Errorf("sessions = %d after the first session ended, want 1: the successor was removed from the table", got)
	}

	// 後継は表にあるので、待ち受けを閉じれば閉じられる
	r.m.Close()
	waitFor(t, "the successor to be closed by the listener's close", 5*time.Second, func() bool {
		_, err := r.conn(1).Write([]byte("x"))
		return err != nil
	})
}
