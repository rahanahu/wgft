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

// gatedPacketConn は公開側のソケットを包み、WriteTo を試験が開けるまで止める。*net.UDPConn では
// ないので、relay は WriteTo で送る(waitingSender)。止めた WriteTo は Close では戻らず、gate を
// 開けたときだけ進む。止まっている数を entered で数える。
type gatedPacketConn struct {
	net.PacketConn
	gate    chan struct{}
	entered atomic.Int64
	inside  atomic.Int64
}

func (g *gatedPacketConn) WriteTo(b []byte, to net.Addr) (int, error) {
	g.entered.Add(1)
	g.inside.Add(1)
	defer g.inside.Add(-1)
	<-g.gate
	return g.PacketConn.WriteTo(b, to)
}

// replyGatedNet は loopback の UDP の待ち受けを gatedPacketConn で包む。
type replyGatedNet struct {
	*loopback
	gate chan struct{}
	mu   sync.Mutex
	pcs  []*gatedPacketConn
}

func (n *replyGatedNet) ListenUDP(port uint16) (net.PacketConn, error) {
	pc, err := n.loopback.ListenUDP(port)
	if err != nil {
		return nil, err
	}
	g := &gatedPacketConn{PacketConn: pc, gate: n.gate}
	n.mu.Lock()
	n.pcs = append(n.pcs, g)
	n.mu.Unlock()
	return g, nil
}

func (n *replyGatedNet) inside() int64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	var c int64
	for _, g := range n.pcs {
		c += g.inside.Load()
	}
	return c
}

func waitFor(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// replySlotFixture は、公開側の送信を止められる UDP の中継を 1 つ立て、指定した数の枠の pool を
// 付ける。戻り値の dial は新しい送信元(セッション)を作る。
func replySlotFixture(t *testing.T, slots int) (m *Manager, gn *replyGatedNet, dial func() *net.UDPConn, waited chan struct{}) {
	t.Helper()
	echoAddr, _ := udpEcho(t)
	gn = &replyGatedNet{loopback: &loopback{}, gate: make(chan struct{})}
	port := reserveUDP(t, gn.loopback)
	m = New(gn, Options{UDPIdleTimeout: time.Hour, UDPPool: resource.NewPool(8), Logf: testLogf(t)})
	t.Cleanup(m.Close)
	m.replies = newReplyPool(slots)
	waited = make(chan struct{}, 16)
	m.replies.waitHook = func() {
		select {
		case waited <- struct{}{}:
		default:
		}
	}
	m.Apply(map[Key]Desired{{proto.UDP, port}: {echoAddr, "r1"}})
	dial = func() *net.UDPConn {
		c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	return m, gn, dial, waited
}

// 応答のバッファは同時に枠の数までしか借りられない。枠が無いセッションは待ち、枠が空けば届く。
// 待っても応答は失われない。
func TestUDPReplySlotsCapConcurrentBorrows(t *testing.T) {
	m, gn, dial, waited := replySlotFixture(t, 2)
	clients := []*net.UDPConn{dial(), dial(), dial()}
	for i, c := range clients {
		if _, err := c.Write([]byte{byte('a' + i)}); err != nil {
			t.Fatal(err)
		}
	}
	// 2 つが公開側の送信で止まり、3 つ目は枠を待つ
	waitFor(t, "two replies inside the public send", 3*time.Second, func() bool { return gn.inside() == 2 })
	select {
	case <-waited:
	case <-time.After(3 * time.Second):
		t.Fatal("the third reply did not wait for a slot")
	}
	if got := m.replies.free(); got != 0 {
		t.Fatalf("free slots while two are held = %d, want 0", got)
	}
	if got := gn.inside(); got != 2 {
		t.Fatalf("replies inside the public send = %d, want exactly the slot count 2", got)
	}
	// 開けると 3 つとも届く
	close(gn.gate)
	for i, c := range clients {
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		b := make([]byte, 16)
		n, err := c.Read(b)
		if err != nil || string(b[:n]) != string(rune('a'+i)) {
			t.Fatalf("client %d reply: %q %v", i, b[:n], err)
		}
	}
	waitFor(t, "all slots returned", 3*time.Second, func() bool { return m.replies.free() == 2 })
	st := m.replies.stats()
	if st.Waits != 1 || st.Cancelled != 0 || st.Longest <= 0 || st.Total < st.Longest {
		t.Errorf("wait stats = %+v, want exactly one wait with a positive duration", st)
	}
}

// 枠の待ちは待ち受けを閉じると取り消され、待っていたセッションはフローの予算を返す。
// 枠を持ったまま公開側で止まっているセッションはそのまま残る。
func TestUDPReplySlotWaitCancelledByListenerClose(t *testing.T) {
	m, gn, dial, waited := replySlotFixture(t, 1)
	c1, c2 := dial(), dial()
	c1.Write([]byte("1"))
	waitFor(t, "the first reply inside the public send", 3*time.Second, func() bool { return gn.inside() == 1 })
	c2.Write([]byte("2"))
	select {
	case <-waited:
	case <-time.After(3 * time.Second):
		t.Fatal("the second reply did not wait for a slot")
	}
	if got := m.UDPPool().InUse(); got != 2 {
		t.Fatalf("flows in use = %d, want 2", got)
	}
	m.Apply(nil) // 待ち受けを閉じる。止まっている WriteTo は gate を開けるまで戻らない
	waitFor(t, "the waiting session to release its flow", 3*time.Second, func() bool { return m.UDPPool().InUse() == 1 })
	if got := gn.inside(); got != 1 {
		t.Fatalf("replies inside the public send after the close = %d, want the stuck one only", got)
	}
	close(gn.gate)
	waitFor(t, "the stuck session to end", 3*time.Second, func() bool { return m.UDPPool().InUse() == 0 })
	if got := m.replies.free(); got != 1 {
		t.Errorf("free slots after both sessions ended = %d, want 1", got)
	}
}

// 枠の待ちはセッションを閉じても取り消される(接続元制限の変更による sweep)。
func TestUDPReplySlotWaitCancelledBySessionClose(t *testing.T) {
	m, gn, dial, waited := replySlotFixture(t, 1)
	c1, c2 := dial(), dial()
	c1.Write([]byte("1"))
	waitFor(t, "the first reply inside the public send", 3*time.Second, func() bool { return gn.inside() == 1 })
	c2.Write([]byte("2"))
	select {
	case <-waited:
	case <-time.After(3 * time.Second):
		t.Fatal("the second reply did not wait for a slot")
	}
	// 両方のセッションを閉じる。待っていた方だけが戻り、止まっている方は gate を開けるまで残る
	if n := m.CloseSessions(func(string, netip.Addr) bool { return false }); n != 2 {
		t.Fatalf("closed sessions = %d, want 2", n)
	}
	waitFor(t, "the waiting session to release its flow", 3*time.Second, func() bool { return m.UDPPool().InUse() == 1 })
	if got := gn.inside(); got != 1 {
		t.Fatalf("replies inside the public send after the sweep = %d, want the stuck one only", got)
	}
	close(gn.gate)
	waitFor(t, "the stuck session to end", 3*time.Second, func() bool { return m.UDPPool().InUse() == 0 })
	// 取り消された待ちは回数だけを数え、合計と最長には入れない(無通信で閉じたセッションの長い待ちが
	// 最長の観測値にならないため)
	if st := m.replies.stats(); st.Waits != 1 || st.Cancelled != 1 || st.Total != 0 || st.Longest != 0 {
		t.Errorf("wait stats after a cancelled wait = %+v, want one wait counted as cancelled with no duration", st)
	}
}

// 通常の往復は枠を待たない。Manager はプロセス全体の pool を使い、枠の数は設計文書 7 節の値である。
func TestUDPReplySlotsDefaultPoolAndNoWaitOnTheFastPath(t *testing.T) {
	echoAddr, _ := udpEcho(t)
	lb := &loopback{}
	port := reserveUDP(t, lb)
	m := New(lb, Options{Logf: testLogf(t)})
	defer m.Close()
	if m.replies != defaultReplyPool {
		t.Fatal("a Manager must borrow from the process-wide pool")
	}
	if cap(defaultReplyPool.slots) != replySlots || replySlots != 64 {
		t.Fatalf("slots = %d, want 64", cap(defaultReplyPool.slots))
	}
	m.replies = newReplyPool(2)
	m.Apply(map[Key]Desired{{proto.UDP, port}: {echoAddr, "r1"}})
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 20; i++ {
		c.Write([]byte("x"))
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		b := make([]byte, 8)
		if n, err := c.Read(b); err != nil || string(b[:n]) != "x" {
			t.Fatalf("round %d: %q %v", i, b[:n], err)
		}
	}
	if st := m.replies.stats(); st.Waits != 0 {
		t.Errorf("waits on the fast path = %d, want 0", st.Waits)
	}
}

// free は今空いている枠の数。
func (p *replyPool) free() int { return len(p.slots) }

// replyWaitStats は枠の待ちの観測値である。Total と Longest は枠を得た待ちだけの値で、
// 取り消された待ちは Cancelled に数える。
type replyWaitStats struct {
	Waits     uint64
	Cancelled uint64
	Total     time.Duration
	Longest   time.Duration
}

func (p *replyPool) stats() replyWaitStats {
	return replyWaitStats{Waits: p.waits.Load(), Cancelled: p.cancelled.Load(), Total: time.Duration(p.waitNanos.Load()), Longest: time.Duration(p.maxWait.Load())}
}

// release は 1 回だけ効く。2 回目の呼び出しは枠を増やさず、バッファも 2 度は戻さない。
func TestReplyLeaseReleaseIsOnceOnly(t *testing.T) {
	p := newReplyPool(2)
	l, ok := p.acquire(nil)
	if !ok {
		t.Fatal("acquire failed")
	}
	if p.free() != 1 {
		t.Fatalf("free after acquire = %d, want 1", p.free())
	}
	// 二重に効くと、満杯の枠の channel への送信で止まる。止まったら失敗にする
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.release()
		l.release()
		l.release()
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a repeated release blocked on the slot channel")
	}
	if got := p.free(); got != 2 {
		t.Fatalf("free after a repeated release = %d, want 2 (the slot count)", got)
	}
}
