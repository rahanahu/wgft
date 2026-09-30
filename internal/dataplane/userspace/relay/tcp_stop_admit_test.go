package relay

// relay の TCP の停止と取得の競合 (設計文書 7a.10 節)。worker を取得の前 (Admission Policy の判定の
// 中) と取得の後 (停止の印の確認の前) で止め、その間に停止の操作を行ってから進める。

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

type stopRig struct {
	m        *Manager
	pool     *resource.Pool
	lb       *loopback
	key      Key // 止める接続の待ち受け
	key2     Key // 統合先のルール r1 の別の待ち受け
	target   string
	target2  string
	releases atomic.Int32
	armAdmit atomic.Bool
	armTake  atomic.Bool
	entered  chan struct{}
	proceed  chan struct{}
	connMu   sync.Mutex
	dialed   []*closeTrackedTCP
}

func newStopRig(t *testing.T, staged bool, rule string, second bool) *stopRig {
	return newStopRigT(t, staged, rule, second, 8, false)
}

// newStopRigT: total は予算、closing が真なら宛先は EOF で閉じる echo (tcpEcho)、偽なら閉じない (halfOpenEcho)。
func newStopRigT(t *testing.T, staged bool, rule string, second bool, total int, closing bool) *stopRig {
	t.Helper()
	r := &stopRig{pool: resource.NewPool(total), lb: &loopback{}, entered: make(chan struct{}), proceed: make(chan struct{})}
	if closing {
		r.target, r.target2 = tcpEcho(t), tcpEcho(t)
	} else {
		r.target, _ = halfOpenEcho(t)
		r.target2, _ = halfOpenEcho(t)
	}
	t.Cleanup(func() {
		r.resume()
		r.connMu.Lock()
		defer r.connMu.Unlock()
		for _, c := range r.dialed {
			c.Close()
		}
	})
	pause := func() {
		close(r.entered)
		<-r.proceed
	}
	r.m = New(r.lb, Options{
		TCPPool: r.pool,
		Logf:    testLogf(t),
		Admit: func(ruleID string, src netip.Addr, size int) (func(), bool) {
			if r.armAdmit.CompareAndSwap(true, false) {
				pause()
			}
			return func() { r.releases.Add(1) }, true
		},
		Dial: func(network, addr string) (net.Conn, error) {
			c, err := net.Dial(network, addr)
			if err != nil {
				return nil, err
			}
			tracked := &closeTrackedTCP{TCPConn: c.(*net.TCPConn)}
			r.connMu.Lock()
			r.dialed = append(r.dialed, tracked)
			r.connMu.Unlock()
			return tracked, nil
		},
	})
	r.m.testHookAfterTake = func(*listener) {
		if r.armTake.CompareAndSwap(true, false) {
			pause()
		}
	}
	t.Cleanup(r.m.Close)
	r.key = Key{proto.TCP, reserveTCP(t, r.lb)}
	desired := map[Key]Desired{r.key: {r.target, rule}}
	if second {
		r.key2 = Key{proto.TCP, reserveTCP(t, r.lb)}
		desired[r.key2] = Desired{r.target, "r1"}
	}
	if staged {
		r.m.Prepare(desired).Commit(nil)
	} else {
		r.m.Apply(desired)
	}
	return r
}

func (r *stopRig) resume() {
	select {
	case <-r.proceed:
	default:
		close(r.proceed)
	}
}

func (r *stopRig) relayedDials() int {
	r.connMu.Lock()
	defer r.connMu.Unlock()
	// 開き直しの到達確認は target2 へ dial する。止めた接続の中継の dial は旧い宛先 target へ行く
	n := 0
	for _, c := range r.dialed {
		if c.RemoteAddr().String() == r.target {
			n++
		}
	}
	return n
}

// ending は接続の終わり方: "rst"、"eof"、"open" (期限まで何も来ない)。
func ending(c net.Conn, d time.Duration) (string, error) {
	c.SetReadDeadline(time.Now().Add(d))
	_, err := c.Read(make([]byte, 1))
	var ne net.Error
	switch {
	case err == nil:
		return "data", nil
	case isReset(err):
		return "rst", err
	case errors.Is(err, io.EOF):
		return "eof", err
	case errors.As(err, &ne) && ne.Timeout():
		return "open", err
	}
	return "other", err
}

func (r *stopRig) waitIdle(t *testing.T, wantReleases int32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if r.pool.InUse() == 0 && r.releases.Load() == wantReleases {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not idle: pool in use %d, per-source releases %d (want %d)", r.pool.InUse(), r.releases.Load(), wantReleases)
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(30 * time.Millisecond)
	if got := r.releases.Load(); got != wantReleases {
		t.Errorf("per-source releases = %d, want %d", got, wantReleases)
	}
}

func checkPool(t *testing.T, p *resource.Pool) resource.Ledger {
	t.Helper()
	if err := p.CheckLedger(); err != nil {
		t.Error(err)
	}
	lg := p.Ledger()
	if lg.Orphans != 0 || lg.DoubleReleases != 0 {
		t.Errorf("orphans %d, double releases %d", lg.Orphans, lg.DoubleReleases)
	}
	return lg
}

func TestTCPStopWhileAdmitting(t *testing.T) {
	type op struct {
		name   string
		staged bool
		rule   string // 止める待ち受けのルール
		second bool   // 統合先の待ち受けを開く
		kind   string // close | retire | merge
		do     func(t *testing.T, r *stopRig)
	}
	retire := func(t *testing.T, r *stopRig) {
		blocker, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Close()
		blocked := uint16(blocker.Addr().(*net.TCPAddr).Port)
		s := r.m.Prepare(map[Key]Desired{{proto.TCP, blocked}: {r.target, "r1"}})
		if s.Failed()["r1"] == nil {
			t.Fatal("want r1 to fail")
		}
		s.Commit(map[string]func(netip.Addr) bool{"r1": func(netip.Addr) bool { return true }})
	}
	ops := []op{
		{name: "Apply close", rule: "r1", kind: "close", do: func(t *testing.T, r *stopRig) { r.m.Apply(map[Key]Desired{}) }},
		{name: "Apply reopen", rule: "r1", kind: "close", do: func(t *testing.T, r *stopRig) {
			r.m.Apply(map[Key]Desired{r.key: {r.target2, "r1"}})
		}},
		{name: "Commit close", staged: true, rule: "r1", kind: "close", do: func(t *testing.T, r *stopRig) {
			r.m.Prepare(map[Key]Desired{}).Commit(nil)
		}},
		{name: "Commit retiring", staged: true, rule: "r1", kind: "retire", do: retire},
		{name: "Commit merge", staged: true, rule: "r2", second: true, kind: "merge", do: func(t *testing.T, r *stopRig) {
			r.m.Prepare(map[Key]Desired{r.key: {r.target, "r1"}, r.key2: {r.target, "r1"}}).Commit(nil)
		}},
		{name: "Apply merge", rule: "r2", second: true, kind: "merge", do: func(t *testing.T, r *stopRig) {
			r.m.Apply(map[Key]Desired{r.key: {r.target, "r1"}, r.key2: {r.target, "r1"}})
		}},
	}
	for _, o := range ops {
		for _, at := range []string{"before Take", "after Take"} {
			t.Run(o.name+"/"+at, func(t *testing.T) {
				r := newStopRig(t, o.staged, o.rule, o.second)
				probes := r.relayedDials()
				if at == "before Take" {
					r.armAdmit.Store(true)
				} else {
					r.armTake.Store(true)
				}
				client, err := dialLoopback(r.key.Port)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				select {
				case <-r.entered:
				case <-time.After(5 * time.Second):
					t.Fatal("worker did not reach the pause point")
				}
				opDone := make(chan struct{})
				go func() { defer close(opDone); o.do(t, r) }()
				select {
				case <-opDone:
				case <-time.After(5 * time.Second):
					t.Fatal("the stop operation blocked while the worker was paused")
				}
				r.resume()
				switch o.kind {
				case "close", "retire":
					end, err := ending(client, 3*time.Second)
					r.waitIdle(t, 1)
					lg := checkPool(t, r.pool)
					if len(r.pool.Refusals()) != 0 {
						t.Errorf("refusals = %v, want none", r.pool.Refusals())
					}
					wantNA := uint64(0)
					if at == "before Take" {
						wantNA = 1
						if end != "rst" {
							t.Errorf("a connection refused as not accepting ended with %s (%v), want RST", end, err)
						}
					} else if end != "rst" {
						t.Errorf("a connection cut after its listener stopped ended with %s (%v), want RST", end, err)
					}
					if lg.NotAccepting != wantNA {
						t.Errorf("not accepting = %d, want %d", lg.NotAccepting, wantNA)
					}
					if d := r.relayedDials() - probes; d != 0 {
						t.Errorf("relay dialled the target %d times for a stopped listener", d)
					}
					t.Logf("op=%q at=%q ending=%s notAccepting=%d inUse=%d retiredFlows=%d", o.name, at, end, lg.NotAccepting, lg.InUse, lg.RetiredFlows)
				case "merge":
					if got, err := echoLine(client, "hi"); err != nil || got != "hi\n" {
						t.Fatalf("connection accepted during the merge was not relayed: %q, %v", got, err)
					}
					lg := checkPool(t, r.pool)
					if lg.RegFlows["r1"] != 1 || lg.RetiredFlows != 0 || lg.NotAccepting != 0 || lg.InUse != 1 {
						t.Errorf("merge ledger %+v, want the lease in r1's registration", lg)
					}
					t.Logf("op=%q at=%q regR1=%d retired=%d", o.name, at, lg.RegFlows["r1"], lg.RetiredFlows)
					// 宛先は FIN で閉じないので、中継を閉じて片付ける
					r.m.Close()
					r.waitIdle(t, 1)
					checkPool(t, r.pool)
				}
			})
		}
	}
}

// Retiring の前に登録を終えた接続は Retiring のフローとして残り、その lease は退役した登録に残る。
func TestTCPRetiringKeepsRegisteredConns(t *testing.T) {
	r := newStopRig(t, true, "r1", false)
	client, err := dialLoopback(r.key.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if got, err := echoLine(client, "hi"); err != nil || got != "hi\n" {
		t.Fatalf("no relay: %q %v", got, err)
	}
	blocker, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	s := r.m.Prepare(map[Key]Desired{{proto.TCP, uint16(blocker.Addr().(*net.TCPAddr).Port)}: {r.target, "r1"}})
	s.Commit(map[string]func(netip.Addr) bool{"r1": func(netip.Addr) bool { return true }})
	if got, err := echoLine(client, "again"); err != nil || got != "again\n" {
		t.Fatalf("retained connection stopped: %q %v", got, err)
	}
	lg := checkPool(t, r.pool)
	if lg.InUse != 1 || lg.RetiredFlows != 1 || len(lg.RegFlows) != 0 {
		t.Errorf("ledger %+v", lg)
	}
	r.m.Close()
	r.waitIdle(t, 1)
	checkPool(t, r.pool)
}

// 並行の組: 多数のクライアントが接続し続ける間に、閉鎖、開き直し、Retiring、統合、分割を繰り返す。
// 毎回の Commit の後に帳簿の整合を確かめ、最後に全部を閉じて u が 0、二重返却 0 であることを確かめる。
func TestTCPLedgerUnderConfigChurn(t *testing.T) {
	r := newStopRigT(t, true, "r1", true, 64, true)
	var (
		stop    = make(chan struct{})
		wg      sync.WaitGroup
		results sync.Map
	)
	count := func(k string) {
		v, _ := results.LoadOrStore(k, new(atomic.Int64))
		v.(*atomic.Int64).Add(1)
	}
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
				// 一時ポートを使い切らないよう、1 回の実行の接続を 1500 程度までにし、間を空ける
				if budgetConns.Add(1) > 750 {
					return
				}
				time.Sleep(time.Millisecond)
				for _, k := range []Key{r.key, r.key2} {
					c, err := dialLoopback(k.Port)
					if err != nil {
						count("dial-error")
						continue
					}
					c.SetDeadline(time.Now().Add(200 * time.Millisecond))
					c.Write([]byte("x\n"))
					b := make([]byte, 2)
					_, err = io.ReadFull(c, b)
					switch {
					case err == nil:
						count("relayed")
					case isReset(err):
						count("rst")
					case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
						count("eof")
					default:
						count("other")
					}
					c.Close()
				}
			}
		}()
	}
	blocker, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	blocked := Key{proto.TCP, uint16(blocker.Addr().(*net.TCPAddr).Port)}
	states := []map[Key]Desired{
		{r.key: {r.target, "r2"}, r.key2: {r.target, "r1"}},   // 2 ルール
		{r.key: {r.target, "r1"}, r.key2: {r.target, "r1"}},   // 統合
		{r.key: {r.target2, "r1"}, r.key2: {r.target, "r1"}},  // 宛先の変更
		{r.key2: {r.target, "r1"}},                            // 閉鎖
		{r.key: {r.target, "r3"}, r.key2: {r.target, "r1"}},   // 開き直し
		{r.key2: {r.target, "r1"}, blocked: {r.target, "r3"}}, // r3 は fail-closed (Retiring)
		{r.key: {r.target, "r2"}, r.key2: {r.target, "r2"}},   // 付け替え
	}
	deadline := time.Now().Add(3 * time.Second)
	iter := 0
	for time.Now().Before(deadline) {
		d := states[iter%len(states)]
		s := r.m.Prepare(d)
		keep := map[string]func(netip.Addr) bool{}
		for id := range s.Failed() {
			keep[id] = func(netip.Addr) bool { return iter%2 == 0 }
		}
		s.Commit(keep)
		if err := r.pool.CheckLedger(); err != nil {
			t.Fatalf("iter %d: %v", iter, err)
		}
		if lg := r.pool.Ledger(); lg.Orphans != 0 {
			t.Fatalf("iter %d: orphans %d", iter, lg.Orphans)
		}
		iter++
		time.Sleep(2 * time.Millisecond)
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
		t.Errorf("in use after close = %d", lg.InUse)
	}
	var sb []string
	results.Range(func(k, v any) bool {
		sb = append(sb, fmt.Sprintf("%s=%d", k, v.(*atomic.Int64).Load()))
		return true
	})
	t.Logf("commits=%d notAccepting=%d refusals=%v conns=%v", iter, lg.NotAccepting, r.pool.Refusals(), sb)
}
