package relay

// relay の UDP の停止、再開、閉鎖と取得の競合 (設計文書 7a.10 節)。

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

type udpRig struct {
	m        *Manager
	pool     *resource.Pool
	key      Key
	target   string
	echoed   *atomic.Int64
	releases atomic.Int32
	dials    atomic.Int32
	armAdmit atomic.Bool
	entered  chan struct{}
	proceed  chan struct{}
	blocker  *net.UDPConn
	hook     atomic.Pointer[func()]
}

func newUDPRig(t *testing.T, total int) *udpRig {
	t.Helper()
	r := &udpRig{pool: resource.NewPool(total), entered: make(chan struct{}), proceed: make(chan struct{})}
	r.target, r.echoed = udpEcho(t)
	lb := &loopback{}
	r.key = Key{proto.UDP, reserveUDP(t, lb)}
	b, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r.blocker = b
	t.Cleanup(func() { b.Close() })
	t.Cleanup(r.resume)
	r.m = New(lb, Options{
		UDPIdleTimeout: time.Hour,
		UDPPool:        r.pool,
		Logf:           testLogf(t),
		Admit: func(string, netip.Addr, int) (func(), bool) {
			if r.armAdmit.CompareAndSwap(true, false) {
				close(r.entered)
				<-r.proceed
			}
			return func() { r.releases.Add(1) }, true
		},
		Dial: func(network, addr string) (net.Conn, error) {
			r.dials.Add(1)
			return net.Dial(network, addr)
		},
	})
	r.m.testHookAfterTake = func(*listener) {
		if h := r.hook.Load(); h != nil {
			(*h)()
		}
	}
	t.Cleanup(r.m.Close)
	r.m.Prepare(map[Key]Desired{r.key: {r.target, "r1"}}).Commit(nil)
	return r
}

// keeper は成立済みのセッションを 1 つ作る。セッションの無い Retiring の待ち受けは同じ Commit で閉じるため。
func (r *udpRig) keeper(t *testing.T) *net.UDPConn {
	t.Helper()
	c := r.client(t)
	if !udpRoundTrip(c, 2*time.Second) {
		t.Fatal("keeper session not relayed")
	}
	return c
}

func (r *udpRig) resume() {
	select {
	case <-r.proceed:
	default:
		close(r.proceed)
	}
}

// retire は fail-closed で待ち受けを Retiring にする (成立済みのセッションは残す)。
func (r *udpRig) retire(t *testing.T) {
	t.Helper()
	blocked := Key{proto.UDP, uint16(r.blocker.LocalAddr().(*net.UDPAddr).Port)}
	s := r.m.Prepare(map[Key]Desired{blocked: {r.target, "r1"}})
	if s.Failed()["r1"] == nil {
		t.Fatal("want r1 to fail")
	}
	s.Commit(map[string]func(netip.Addr) bool{"r1": func(netip.Addr) bool { return true }})
	if got := r.m.Retiring(); len(got) != 1 {
		t.Fatalf("Retiring = %v", got)
	}
}

func (r *udpRig) revive(t *testing.T, rule string) {
	t.Helper()
	r.m.Prepare(map[Key]Desired{r.key: {r.target, rule}}).Commit(nil)
	if got := r.m.Retiring(); len(got) != 0 {
		t.Fatalf("Retiring = %v after revive", got)
	}
}

func (r *udpRig) listener() *listener {
	r.m.mu.Lock()
	defer r.m.mu.Unlock()
	if l := r.m.listeners[r.key]; l != nil {
		return l
	}
	return r.m.retiring[r.key]
}

func (r *udpRig) client(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(r.key.Port)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// roundTrip は 1 つ送り、応答が来たかを返す。
func udpRoundTrip(c *net.UDPConn, d time.Duration) bool {
	c.Write([]byte("ping"))
	c.SetReadDeadline(time.Now().Add(d))
	_, err := c.Read(make([]byte, 16))
	return err == nil
}

// Retiring の直後の新しい送信元: Admit で止めた読み取りのループが、Retiring の後に取得する。
func TestUDPRetiringNewSourceMakesNoSession(t *testing.T) {
	r := newUDPRig(t, 8)
	r.keeper(t)
	r.armAdmit.Store(true)
	c := r.client(t)
	c.Write([]byte("first"))
	select {
	case <-r.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("read loop did not pause")
	}
	r.retire(t)
	r.resume()
	time.Sleep(100 * time.Millisecond)
	l := r.listener()
	lg := checkPool(t, r.pool)
	// keeper の 1 セッションだけが残る
	if l.sessions() != 1 || lg.InUse != 1 || r.dials.Load() != 1 || len(r.pool.Refusals()) != 0 || lg.NotAccepting != 1 || r.releases.Load() != 1 {
		t.Errorf("sessions %d, in use %d, dials %d, refusals %v, not accepting %d, releases %d",
			l.sessions(), lg.InUse, r.dials.Load(), r.pool.Refusals(), lg.NotAccepting, r.releases.Load())
	}
	// 止めていない新しい送信元は受け付けの印で捨てる (取得まで行かない)
	c2 := r.client(t)
	if udpRoundTrip(c2, 200*time.Millisecond) {
		t.Error("a new source got a reply through a retiring listener")
	}
	lg = checkPool(t, r.pool)
	t.Logf("sessions=%d inUse=%d dials=%d refusals=%v notAccepting=%d releases=%d", l.sessions(), lg.InUse, r.dials.Load(), r.pool.Refusals(), lg.NotAccepting, r.releases.Load())
}

// 再開の順: Commit は受け付けの印を先に立て、Pool の Accept を後に呼ぶ。2 文の間の取得は「受け付けて
// いない」で拒まれ、Commit の直後のデータグラムは中継される。
func TestUDPResumeOrder(t *testing.T) {
	r := newUDPRig(t, 8)
	r.keeper(t)
	r.retire(t)
	var mid resource.Outcome = -1
	var midLease *resource.Lease
	r.m.testHookRevive = func(l *listener) {
		// m.mu の外で ruleOf を済ませた読み取りのループの取得を模す
		midLease, _, mid = l.budget.Take()
	}
	r.revive(t, "r1")
	if midLease != nil {
		midLease.Release()
	}
	if mid != resource.NotAccepting {
		t.Errorf("a take between the two steps of the resume = %v, want not accepting", mid)
	}
	c := r.client(t)
	if !udpRoundTrip(c, 2*time.Second) {
		t.Error("the first datagram right after the resume was dropped")
	}
	checkPool(t, r.pool)
	if len(r.pool.Refusals()) != 0 {
		t.Errorf("refusals %v, want none", r.pool.Refusals())
	}
}

// 再開の Commit の途中 (2 文の間) に届いたデータグラムは、読み取りのループが ruleOf で Manager の mu を
// 待つので、Commit の後に取得して中継される。
func TestUDPResumeDatagramDuringCommit(t *testing.T) {
	r := newUDPRig(t, 8)
	r.keeper(t)
	r.retire(t)
	c := r.client(t)
	r.m.testHookRevive = func(*listener) {
		c.Write([]byte("mid"))
		time.Sleep(100 * time.Millisecond)
	}
	r.revive(t, "r1")
	c.SetReadDeadline(time.Now().Add(time.Second))
	_, err := c.Read(make([]byte, 16))
	lg := checkPool(t, r.pool)
	if err != nil || lg.NotAccepting != 0 {
		t.Errorf("the datagram sent during the resume: %v, not accepting %d", err, lg.NotAccepting)
	}
}

// 閉鎖の後にセッションが表へ入らず lease が残らない: 取得の後 (dial の前) で止めて閉じる。
func TestUDPCloseAfterTake(t *testing.T) {
	r := newUDPRig(t, 8)
	entered, proceed := make(chan struct{}), make(chan struct{})
	var once sync.Once
	h := func() { once.Do(func() { close(entered); <-proceed }) }
	r.hook.Store(&h)
	c := r.client(t)
	c.Write([]byte("first"))
	<-entered
	l := r.listener()
	r.m.Prepare(map[Key]Desired{}).Commit(nil)
	close(proceed)
	deadline := time.Now().Add(5 * time.Second)
	for (r.pool.InUse() != 0 || r.releases.Load() != 1) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	lg := checkPool(t, r.pool)
	if lg.InUse != 0 || l.sessions() != 0 || r.releases.Load() != 1 || len(r.pool.Refusals()) != 0 {
		t.Errorf("in use %d sessions %d releases %d refusals %v", lg.InUse, l.sessions(), r.releases.Load(), r.pool.Refusals())
	}
	t.Logf("inUse=%d sessions=%d dials=%d releases=%d double=%d", lg.InUse, l.sessions(), r.dials.Load(), r.releases.Load(), lg.DoubleReleases)
}

// 再開した待ち受けの旧いセッションは加入の発火で今の登録へ移り、新しいセッションも今の登録に数える。
// 再開と同時に所属ルールが変わる場合は、旧い ID の登録が一瞬でき、付け替えで退役して新しい ID へ移る。
func TestUDPResumeJoinMovesSessions(t *testing.T) {
	for _, rule := range []string{"r1", "r2"} {
		t.Run("resume as "+rule, func(t *testing.T) {
			r := newUDPRig(t, 8)
			c1 := r.client(t)
			if !udpRoundTrip(c1, 2*time.Second) {
				t.Fatal("no relay")
			}
			serialBefore := r.pool.Ledger().RegSerial["r1"]
			r.retire(t)
			lg := checkPool(t, r.pool)
			if lg.RetiredFlows != 1 || len(lg.RegFlows) != 0 || lg.InUse != 1 {
				t.Fatalf("retiring ledger %+v", lg)
			}
			r.revive(t, rule)
			lg = checkPool(t, r.pool)
			if lg.RegFlows[rule] != 1 || lg.RetiredFlows != 0 {
				t.Errorf("after resume %+v", lg)
			}
			if !udpRoundTrip(c1, 2*time.Second) {
				t.Error("old session stopped")
			}
			c2 := r.client(t)
			if !udpRoundTrip(c2, 2*time.Second) {
				t.Fatal("new session after resume not relayed")
			}
			lg = checkPool(t, r.pool)
			l := r.listener()
			if lg.RegFlows[rule] != 2 || lg.InUse != 2 || l.sessions() != 2 || lg.RetiredFlows != 0 {
				t.Errorf("after new session %+v sessions %d", lg, l.sessions())
			}
			t.Logf("rule=%s regSerialBefore=%d regSerialAfter=%d regFlows=%v retired=%d inUse=%d sessions=%d", rule, serialBefore, lg.RegSerial[rule], lg.RegFlows, lg.RetiredFlows, lg.InUse, l.sessions())
			r.m.Close()
			deadline := time.Now().Add(5 * time.Second)
			for r.pool.InUse() != 0 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if lg := checkPool(t, r.pool); lg.InUse != 0 {
				t.Errorf("in use after close %d", lg.InUse)
			}
		})
	}
}

// 並行の組: 多数の送信元が送り続ける間に Retiring、再開、閉鎖、開き直し、付け替えを繰り返す。
func TestUDPLedgerUnderConfigChurn(t *testing.T) {
	r := newUDPRig(t, 64)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var replies, sent atomic.Int64
	var budgetConns atomic.Int64
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// 一時ポートを使い切らないよう、1 回の実行の接続を 1500 までにし、間を空ける
				if budgetConns.Add(1) > 1500 {
					return
				}
				time.Sleep(time.Millisecond)
				c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(r.key.Port)})
				if err != nil {
					continue
				}
				for j := 0; j < 3; j++ {
					sent.Add(1)
					if udpRoundTrip(c, 20*time.Millisecond) {
						replies.Add(1)
					}
				}
				c.Close()
			}
		}()
	}
	blocked := Key{proto.UDP, uint16(r.blocker.LocalAddr().(*net.UDPAddr).Port)}
	deadline := time.Now().Add(3 * time.Second)
	iter := 0
	for time.Now().Before(deadline) {
		var d map[Key]Desired
		switch iter % 5 {
		case 0:
			d = map[Key]Desired{blocked: {r.target, "r1"}} // r1 fail-closed
		case 1:
			d = map[Key]Desired{r.key: {r.target, "r1"}} // 再開
		case 2:
			d = map[Key]Desired{r.key: {r.target, "r2"}} // 付け替え
		case 3:
			d = map[Key]Desired{} // 閉鎖
		case 4:
			d = map[Key]Desired{r.key: {r.target, "r1"}} // 開き直し
		}
		s := r.m.Prepare(d)
		keep := map[string]func(netip.Addr) bool{}
		for id := range s.Failed() {
			keep[id] = func(netip.Addr) bool { return true }
		}
		s.Commit(keep)
		if err := r.pool.CheckLedger(); err != nil {
			t.Fatalf("iter %d: %v", iter, err)
		}
		if lg := r.pool.Ledger(); lg.Orphans != 0 {
			t.Fatalf("iter %d: orphans %d", iter, lg.Orphans)
		}
		iter++
		time.Sleep(3 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	r.m.Close()
	deadline = time.Now().Add(5 * time.Second)
	for r.pool.InUse() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	lg := checkPool(t, r.pool)
	if lg.InUse != 0 {
		t.Errorf("in use after close %d", lg.InUse)
	}
	t.Logf("commits=%d sent=%d replies=%d notAccepting=%d refusals=%v dials=%d releases=%d", iter, sent.Load(), replies.Load(), lg.NotAccepting, r.pool.Refusals(), r.dials.Load(), r.releases.Load())
}
