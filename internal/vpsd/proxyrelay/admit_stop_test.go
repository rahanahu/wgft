package proxyrelay

// proxyrelay の停止と取得の競合と、予算の拒否 (設計文書 7a.10 節)。

import (
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/resource"
)

// closingAgent は読んだものを返し、EOF で閉じるエージェント。
func closingAgent(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

type admitRig struct {
	m        *Manager
	pool     *resource.Pool
	mu       sync.Mutex
	addrs    map[uint16]string
	agents   map[string]string
	releases atomic.Int32
	admitFn  atomic.Pointer[func(id string)]
}

func newAdmitRig(t *testing.T, total int, halfOpen bool) *admitRig {
	t.Helper()
	r := &admitRig{pool: resource.NewPool(total), addrs: map[uint16]string{}}
	a1, a2 := closingAgent(t), closingAgent(t)
	if halfOpen {
		a1, a2 = halfOpenAgent(t, nil), halfOpenAgent(t, nil)
	}
	r.agents = map[string]string{"10.200.0.2:8443": a1, "10.200.0.3:8443": a2, "10.200.0.2:8444": a1, "10.200.0.3:8444": a2}
	r.m = New(Options{
		Listen: func(port uint16) (net.Listener, error) {
			if port >= 9000 {
				return nil, errors.New("address already in use")
			}
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err == nil {
				r.mu.Lock()
				r.addrs[port] = ln.Addr().String()
				r.mu.Unlock()
			}
			return ln, err
		},
		Dial: func(addr string) (net.Conn, error) {
			r.mu.Lock()
			dst, ok := r.agents[addr]
			r.mu.Unlock()
			if !ok {
				return nil, errors.New("no agent at " + addr)
			}
			return net.Dial("tcp4", dst)
		},
		Logf: testLogf(t),
		Pool: r.pool,
		Admit: func(id string, _ netip.Addr) (func(), bool) {
			if f := r.admitFn.Load(); f != nil {
				(*f)(id)
			}
			return func() { r.releases.Add(1) }, true
		},
	})
	t.Cleanup(r.m.Close)
	return r
}

func (r *admitRig) addr(port uint16) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.addrs[port]
}

func a3Check(t *testing.T, p *resource.Pool) resource.Ledger {
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

func a3Ending(c net.Conn) string {
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := c.Read(make([]byte, 1))
	var ne net.Error
	switch {
	case err == nil:
		return "data"
	case isReset(err):
		return "rst"
	case errors.Is(err, io.EOF):
		return "eof"
	case errors.As(err, &ne) && ne.Timeout():
		return "open"
	}
	return "other:" + err.Error()
}

// 予算の拒否は SetLinger(0) の RST で終わり、理由つきで数える。
func TestBudgetRefusalIsRST(t *testing.T) {
	r := newAdmitRig(t, 1, false)
	r.m.Apply([]Rule{agentRule("r", 8443, "home", "10.200.0.2", nil)})
	c1, err := net.Dial("tcp4", r.addr(8443))
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	c1.Write([]byte("hi"))
	b := make([]byte, 2)
	c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c1, b); err != nil {
		t.Fatal(err)
	}
	c2, err := net.Dial("tcp4", r.addr(8443))
	end := "rst-at-connect"
	if err == nil {
		defer c2.Close()
		end = a3Ending(c2)
	} else if !isReset(err) {
		t.Fatal(err)
	}
	lg := a3Check(t, r.pool)
	t.Logf("ending=%s refusals=%v notAccepting=%d", end, r.pool.Refusals(), lg.NotAccepting)
	if end != "rst" && end != "rst-at-connect" {
		t.Errorf("budget refusal ended with %s", end)
	}
	if r.pool.Refusals()["r"][resource.ReasonBudget] != 1 || lg.NotAccepting != 0 {
		t.Errorf("refusals %v not accepting %d", r.pool.Refusals(), lg.NotAccepting)
	}
}

// Admission Policy の判定の中で止めた接続の間に、停止、閉鎖、宛先の変更、付け替えを行う。
func TestStopDuringAdmit(t *testing.T) {
	base := func() []Rule { return []Rule{agentRule("r", 8443, "home", "10.200.0.2", nil)} }
	ops := []struct {
		name string
		do   func(r *admitRig)
		kind string // cancel | relabel
	}{
		{"remove", func(r *admitRig) { r.m.Apply(nil) }, "cancel"},
		{"retire", func(r *admitRig) {
			p := r.m.Prepare([]Rule{agentRule("r", 9443, "home", "10.200.0.2", nil)})
			p.Commit(map[string]func(netip.Addr) bool{"r": func(netip.Addr) bool { return true }})
		}, "cancel"},
		{"retarget", func(r *admitRig) { r.m.Apply([]Rule{agentRule("r", 8443, "home2", "10.200.0.3", nil)}) }, "cancel"},
		{"relabel", func(r *admitRig) { r.m.Apply([]Rule{agentRule("r2", 8443, "home", "10.200.0.2", nil)}) }, "relabel"},
	}
	for _, o := range ops {
		t.Run(o.name, func(t *testing.T) {
			r := newAdmitRig(t, 8, true)
			r.m.Apply(base())
			entered, proceed := make(chan struct{}), make(chan struct{})
			var once sync.Once
			f := func(string) { once.Do(func() { close(entered); <-proceed }) }
			r.admitFn.Store(&f)
			c, err := net.Dial("tcp4", r.addr(8443))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("no admit")
			}
			opDone := make(chan struct{})
			go func() { defer close(opDone); o.do(r) }()
			// 停止は、判定の中の接続を持つ serve の戻りを待つ (join) ので、ここで進める
			time.Sleep(50 * time.Millisecond)
			close(proceed)
			select {
			case <-opDone:
			case <-time.After(5 * time.Second):
				t.Fatal("the operation did not finish after the paused admission resumed")
			}
			switch o.kind {
			case "cancel":
				end := a3Ending(c)
				deadline := time.Now().Add(3 * time.Second)
				for (r.pool.InUse() != 0 || r.releases.Load() != 1) && time.Now().Before(deadline) {
					time.Sleep(5 * time.Millisecond)
				}
				lg := a3Check(t, r.pool)
				t.Logf("op=%s ending=%s inUse=%d releases=%d refusals=%v notAccepting=%d", o.name, end, lg.InUse, r.releases.Load(), r.pool.Refusals(), lg.NotAccepting)
				if end != "rst" || lg.InUse != 0 || r.releases.Load() != 1 || len(r.pool.Refusals()) != 0 || lg.NotAccepting != 0 {
					t.Errorf("op %s: ending %s in use %d releases %d refusals %v not accepting %d", o.name, end, lg.InUse, r.releases.Load(), r.pool.Refusals(), lg.NotAccepting)
				}
			case "relabel":
				c.SetDeadline(time.Now().Add(2 * time.Second))
				c.Write([]byte("ok"))
				b := make([]byte, 2)
				_, err := io.ReadFull(c, b)
				lg := a3Check(t, r.pool)
				t.Logf("op=%s relayed=%v regFlows=%v retired=%d notAccepting=%d", o.name, err == nil, lg.RegFlows, lg.RetiredFlows, lg.NotAccepting)
				if err != nil || lg.RegFlows["r2"] != 1 || lg.RetiredFlows != 0 || lg.NotAccepting != 0 {
					t.Errorf("relabel: err %v ledger %+v", err, lg)
				}
			}
		})
	}
}

// 並行の組: 多数のクライアントが接続し続ける間に Commit で停止、閉鎖、宛先の変更、付け替えを繰り返す。
// Admission Policy の判定に短い待ちを入れて窓を広げる。受け付けていない handle からの取得が 0 回で
// あること、帳簿の整合、最後に u が 0 を確かめる。
func TestLedgerUnderConfigChurn(t *testing.T) {
	r := newAdmitRig(t, 16, false)
	f := func(string) {
		if n := rand.IntN(4); n > 0 {
			time.Sleep(time.Duration(n) * 200 * time.Microsecond)
		}
	}
	r.admitFn.Store(&f)
	states := [][]Rule{
		{agentRule("r", 8443, "home", "10.200.0.2", nil), agentRule("s", 8444, "home", "10.200.0.2", nil)},
		{agentRule("r", 9443, "home", "10.200.0.2", nil), agentRule("s", 8444, "home", "10.200.0.2", nil)},                      // r fail-closed
		{agentRule("r", 8443, "home", "10.200.0.2", nil), agentRule("s2", 8444, "home", "10.200.0.2", nil)},                     // s の付け替え
		{agentRule("r", 8443, "home2", "10.200.0.3", nil), agentRule("s2", 8444, "home2", "10.200.0.3", nil)},                   // 宛先の変更
		{agentRule("s2", 8444, "home2", "10.200.0.3", nil)},                                                                     // r の閉鎖
		{agentRule("r", 8443, "home", "10.200.0.2", []string{"127.0.0.1/32"}), agentRule("s", 8444, "home", "10.200.0.2", nil)}, // 接続元の拒否
	}
	r.m.Apply(states[0])
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var res sync.Map
	count := func(k string) {
		v, _ := res.LoadOrStore(k, new(atomic.Int64))
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
				for _, p := range []uint16{8443, 8444} {
					a := r.addr(p)
					c, err := net.DialTimeout("tcp4", a, 200*time.Millisecond)
					if err != nil {
						count("dial-error")
						continue
					}
					c.SetDeadline(time.Now().Add(200 * time.Millisecond))
					c.Write([]byte("x"))
					_, err = io.ReadFull(c, make([]byte, 1))
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
	var maxCommit time.Duration
	deadline := time.Now().Add(3 * time.Second)
	iter := 0
	for time.Now().Before(deadline) {
		st := states[iter%len(states)]
		start := time.Now()
		p := r.m.Prepare(st)
		keep := map[string]func(netip.Addr) bool{}
		for id := range p.Failed() {
			k := iter%2 == 0
			keep[id] = func(netip.Addr) bool { return k }
		}
		done := make(chan struct{})
		go func() { p.Commit(keep); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("iter %d: Commit did not finish", iter)
		}
		if d := time.Since(start); d > maxCommit {
			maxCommit = d
		}
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
	dl := time.Now().Add(5 * time.Second)
	for r.pool.InUse() != 0 && time.Now().Before(dl) {
		time.Sleep(5 * time.Millisecond)
	}
	lg := a3Check(t, r.pool)
	var out []string
	res.Range(func(k, v any) bool { out = append(out, fmt.Sprintf("%s=%d", k, v.(*atomic.Int64).Load())); return true })
	t.Logf("commits=%d maxCommit=%v notAccepting=%d inUse=%d refusals=%v conns=%v", iter, maxCommit, lg.NotAccepting, lg.InUse, r.pool.Refusals(), out)
	if lg.NotAccepting != 0 || lg.InUse != 0 {
		t.Errorf("not accepting %d, in use %d", lg.NotAccepting, lg.InUse)
	}
}
