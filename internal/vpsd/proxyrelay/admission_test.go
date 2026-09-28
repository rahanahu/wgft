package proxyrelay

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/resource"
)

type admissionListener struct {
	queue    chan net.Conn
	accepted chan struct{}
	closed   chan struct{}
	once     sync.Once
}

func newAdmissionListener() *admissionListener {
	return &admissionListener{queue: make(chan net.Conn, 4), accepted: make(chan struct{}, 4), closed: make(chan struct{})}
}
func (l *admissionListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	case c := <-l.queue:
		l.accepted <- struct{}{}
		return c, nil
	}
}
func (l *admissionListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *admissionListener) Addr() net.Addr { return &net.TCPAddr{} }

type admissionConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *admissionConn) Close() error { c.once.Do(func() { close(c.closed) }); return c.Conn.Close() }
func admissionPipe(t *testing.T) (*admissionConn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	c := &admissionConn{Conn: a, closed: make(chan struct{})}
	t.Cleanup(func() { c.Close(); b.Close() })
	return c, b
}
func admissionWait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for owned operation")
	}
}
func admissionAbsent(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
		t.Fatal("unexpected operation before release")
	case <-time.After(20 * time.Millisecond):
	}
}
func admissionRule(id string, port uint16) Rule {
	return Rule{ID: id, Agent: "agent", ListenPort: port, AgentPort: port, AgentAddr: netip.IPv4Unspecified()}
}
func admissionDrain(t *testing.T, p *resource.Pool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for p.InUse() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if p.InUse() != 0 {
		t.Fatal("budget still held after worker completion")
	}
}

// A blocked policy call may own one accepted socket, while another port progresses.
func TestAdmissionOnePerPortAndIndependentProgress(t *testing.T) {
	a, b := newAdmissionListener(), newAdmissionListener()
	entered, release, dialed := make(chan struct{}), make(chan struct{}), make(chan struct{}, 4)
	var once sync.Once
	m := New(Options{Listen: func(p uint16) (net.Listener, error) {
		if p == 1 {
			return a, nil
		}
		return b, nil
	}, Admit: func(id string, _ netip.Addr) (func(), bool) {
		if id == "a" {
			once.Do(func() { close(entered) })
			<-release
		}
		return func() {}, true
	}, Dial: func(string) (net.Conn, error) { dialed <- struct{}{}; return nil, errors.New("fixture dial failure") }, Logf: func(string, ...any) {}})
	t.Cleanup(m.Close)
	t.Cleanup(func() { close(release) })
	m.Apply([]Rule{admissionRule("a", 1), admissionRule("b", 2)})
	c, _ := admissionPipe(t)
	a.queue <- c
	admissionWait(t, entered)
	admissionWait(t, a.accepted)
	c2, _ := admissionPipe(t)
	a.queue <- c2
	admissionAbsent(t, a.accepted)
	admissionAbsent(t, dialed)
	other, _ := admissionPipe(t)
	b.queue <- other
	admissionWait(t, dialed)
	if got := len(a.accepted); got != 0 {
		t.Fatalf("blocked port accepted another socket: %d", got)
	}
}

// Every affected socket must be stopped before joining any blocked policy call.
func TestAdmissionStopAllBeforeJoin(t *testing.T) {
	for _, op := range []string{"close", "agent", "remove", "retire"} {
		t.Run(op, func(t *testing.T) {
			a, b := newAdmissionListener(), newAdmissionListener()
			entered := make(chan struct{}, 2)
			release := make(chan struct{})
			var released atomic.Int32
			m := New(Options{Listen: func(p uint16) (net.Listener, error) {
				if p == 1 {
					return a, nil
				}
				return b, nil
			}, Admit: func(string, netip.Addr) (func(), bool) {
				entered <- struct{}{}
				<-release
				return func() { released.Add(1) }, true
			}, Dial: func(string) (net.Conn, error) {
				t.Error("stopped admission dialled")
				return nil, errors.New("unexpected dial")
			}, Logf: func(string, ...any) {}})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			t.Cleanup(m.Close)
			t.Cleanup(unblock)
			m.Apply([]Rule{admissionRule("a", 1), admissionRule("b", 2)})
			ca, _ := admissionPipe(t)
			cb, _ := admissionPipe(t)
			a.queue <- ca
			b.queue <- cb
			admissionWait(t, entered)
			admissionWait(t, entered)
			done := make(chan struct{})
			go func() {
				defer close(done)
				switch op {
				case "close":
					m.Close()
				case "agent":
					m.CloseAgent("agent")
				case "remove":
					m.Apply(nil)
				case "retire":
					m.Prepare(nil).Commit(map[string]func(netip.Addr) bool{"a": func(netip.Addr) bool { return true }, "b": func(netip.Addr) bool { return true }})
				}
			}()
			admissionWait(t, a.closed)
			admissionWait(t, b.closed)
			admissionWait(t, ca.closed)
			admissionWait(t, cb.closed)
			admissionAbsent(t, done)
			unblock()
			admissionWait(t, done)
			admissionDrain(t, m.Pool())
			if released.Load() != 2 {
				t.Fatalf("policy releases=%d", released.Load())
			}
		})
	}
}

func TestAdmissionStopBlocksSamePortReplacement(t *testing.T) {
	for iteration := 0; iteration < 3; iteration++ {
		old, next := newAdmissionListener(), newAdmissionListener()
		entered, release, reopened := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var opens atomic.Int32
		m := New(Options{Listen: func(uint16) (net.Listener, error) {
			if opens.Add(1) == 1 {
				return old, nil
			}
			close(reopened)
			return next, nil
		}, Admit: func(string, netip.Addr) (func(), bool) { close(entered); <-release; return func() {}, true }, Logf: func(string, ...any) {}})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		t.Cleanup(m.Close)
		t.Cleanup(unblock)
		r := admissionRule("a", 1)
		m.Apply([]Rule{r})
		c, _ := admissionPipe(t)
		old.queue <- c
		admissionWait(t, entered)
		stopped := make(chan struct{})
		go func() { m.Apply(nil); close(stopped) }()
		admissionWait(t, old.closed)
		replaced := make(chan struct{})
		go func() { m.Apply([]Rule{r}); close(replaced) }()
		admissionAbsent(t, reopened)
		unblock()
		admissionWait(t, stopped)
		admissionWait(t, replaced)
		admissionWait(t, reopened)
		m.Close()
	}
}

func admissionState(pool *resource.Pool) *listener {
	return &listener{rule: admissionRule("a", 1), ln: newAdmissionListener(), conns: map[net.Conn]string{}, budget: pool.Listener("a"), stopAccept: make(chan struct{}), serveDone: make(chan struct{})}
}

// Exercise the two linearization orders directly, without a scheduler-dependent pause hook.
func TestAdmissionHandoffAndStopOwnership(t *testing.T) {
	for _, stopFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "stop-first", false: "handoff-first"}[stopFirst], func(t *testing.T) {
			pool := resource.NewPool(2)
			l := admissionState(pool)
			var policyReleases, dials atomic.Int32
			m := New(Options{Pool: pool, Admit: func(string, netip.Addr) (func(), bool) { return func() { policyReleases.Add(1) }, true }, Dial: func(string) (net.Conn, error) { dials.Add(1); return nil, errors.New("dial failure") }, Logf: func(string, ...any) {}})
			c, _ := admissionPipe(t)
			if stopFirst {
				l.beginClose()
			}
			a := m.admitAccepted(l, c)
			if stopFirst {
				if a != nil || dials.Load() != 0 || pool.InUse() != 0 || policyReleases.Load() != 0 {
					t.Fatal("stopped accept obtained ownership")
				}
				return
			}
			if a == nil || pool.InUse() != 1 || l.pending != 1 {
				t.Fatal("handoff lacks budget/pending ownership")
			}
			l.beginClose()
			if pool.InUse() != 1 || policyReleases.Load() != 0 {
				t.Fatal("stop released a committed worker's charges")
			}
			m.relayAdmitted(l, a)
			if pool.InUse() != 0 || l.pending != 0 || policyReleases.Load() != 1 || dials.Load() != 1 {
				t.Fatal("worker failed to release exact ownership")
			}
		})
	}
}

func TestAdmissionDenialReleasesPolicyAndBudget(t *testing.T) {
	for _, kind := range []string{"policy", "pool", "retarget", "header"} {
		t.Run(kind, func(t *testing.T) {
			pool := resource.NewPool(1)
			l := admissionState(pool)
			var releases atomic.Int32
			if kind == "pool" {
				if _, ok := l.budget.Acquire(); !ok {
					t.Fatal("fixture acquire")
				}
				defer l.budget.Release()
			}
			m := New(Options{Pool: pool, Admit: func(string, netip.Addr) (func(), bool) {
				if kind == "policy" {
					return nil, false
				}
				if kind == "retarget" {
					r := l.rule
					r.AgentPort++
					l.updateRestriction(r)
				}
				return func() { releases.Add(1) }, true
			}, Dial: func(string) (net.Conn, error) { up, peer := net.Pipe(); peer.Close(); return up, nil }, Logf: func(string, ...any) {}})
			l.rule.ProxyProtocol = kind == "header"
			c, _ := admissionPipe(t)
			a := m.admitAccepted(l, c)
			if kind == "header" {
				if a == nil {
					t.Fatal("header fixture not admitted")
				}
				m.relayAdmitted(l, a)
			} else if a != nil {
				t.Fatal("denial admitted a worker")
			}
			admissionWait(t, c.closed)
			want := int32(1)
			if kind == "policy" {
				want = 0
			}
			if releases.Load() != want {
				t.Fatalf("policy released %d, want %d", releases.Load(), want)
			}
			inUse := 0
			if kind == "pool" {
				inUse = 1
			}
			if pool.InUse() != inUse {
				t.Fatal("budget leak")
			}
		})
	}
}

func TestAdmissionStopDuringPolicyDoesNotCountBudgetRefusal(t *testing.T) {
	pool := resource.NewPool(1)
	l := admissionState(pool)
	if _, ok := l.budget.Acquire(); !ok {
		t.Fatal("fixture acquire")
	}
	defer l.budget.Release()
	var releases atomic.Int32
	m := New(Options{Pool: pool, Admit: func(string, netip.Addr) (func(), bool) { l.beginClose(); return func() { releases.Add(1) }, true }})
	c, _ := admissionPipe(t)
	if m.admitAccepted(l, c) != nil || releases.Load() != 1 || len(pool.Refusals()) != 0 {
		t.Fatal("administrative stop became a resource refusal")
	}
}

func TestAdmissionSharedBudgetPreservesOtherRuleProgress(t *testing.T) {
	pool := resource.NewPool(2)
	a, b := admissionState(pool), admissionState(pool)
	b.rule.ID = "b"
	b.budget.SetRule("b")
	m := New(Options{Pool: pool, Dial: func(string) (net.Conn, error) { return nil, errors.New("fixture dial") }, Logf: func(string, ...any) {}})
	ca, _ := admissionPipe(t)
	first := m.admitAccepted(a, ca)
	if first == nil {
		t.Fatal("first rule refused")
	}
	excess, _ := admissionPipe(t)
	if m.admitAccepted(a, excess) != nil {
		t.Fatal("rule exceeded shared budget cap")
	}
	cb, _ := admissionPipe(t)
	second := m.admitAccepted(b, cb)
	if second == nil {
		t.Fatal("other rule could not use its share")
	}
	if pool.InUse() != 2 {
		t.Fatal("wrong shared ownership")
	}
	m.relayAdmitted(a, first)
	m.relayAdmitted(b, second)
	admissionDrain(t, pool)
}

// Retirement still inspects tracked connections only. A previously committed
// Dial can finish afterward; fixing that inherited policy gap is separate.
func TestAdmissionRetirementPreservesPendingBehavior(t *testing.T) {
	pool := resource.NewPool(2)
	l := admissionState(pool)
	up, peer := net.Pipe()
	defer peer.Close()
	m := New(Options{Pool: pool, Dial: func(string) (net.Conn, error) { return up, nil }})
	c, client := admissionPipe(t)
	a := m.admitAccepted(l, c)
	if a == nil {
		t.Fatal("not admitted")
	}
	l.beginStopAccepting()
	l.retire(func(netip.Addr) bool { return false })
	done := make(chan struct{})
	go func() { m.relayAdmitted(l, a); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	tracked := false
	for time.Now().Before(deadline) {
		l.mu.Lock()
		tracked = len(l.conns) == 1
		l.mu.Unlock()
		if tracked {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !tracked {
		client.Close()
		peer.Close()
		t.Fatal("retirement unexpectedly changed pending-flow semantics")
	}
	client.Close()
	peer.Close()
	admissionWait(t, done)
	admissionDrain(t, pool)
}

// Pause at the exact validity-check/budget-attempt boundary. Stop must not
// cross this boundary; a full-budget result ordered before stop is a real refusal.
func TestAdmissionBudgetAttemptSerializesStop(t *testing.T) {
	pool := resource.NewPool(1)
	l := admissionState(pool)
	if _, ok := l.budget.Acquire(); !ok {
		t.Fatal("fixture acquire")
	}
	defer l.budget.Release()
	c, _ := admissionPipe(t)
	l.admitting = c
	entered, proceed, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(proceed) }) }
	defer unblock()
	go func() {
		defer close(done)
		ref, ok, cancelled := l.acquireAdmission(0, func() (resource.Refusal, bool) { close(entered); <-proceed; return l.budget.Acquire() })
		if ok || cancelled || ref.Reason != resource.ReasonBudget {
			t.Errorf("budget decision = %+v, %v, %v", ref, ok, cancelled)
		}
	}()
	admissionWait(t, entered)
	// Unlike a timed negative assertion, this directly verifies the mutex remains
	// held after validity was checked and before the actual Pool call.
	if l.mu.TryLock() {
		l.mu.Unlock()
		t.Fatal("validity and budget attempt are separated by an unlock")
	}
	stopping, stopped := make(chan struct{}), make(chan struct{})
	go func() { close(stopping); l.beginClose(); close(stopped) }()
	admissionWait(t, stopping)
	admissionAbsent(t, stopped)
	unblock()
	admissionWait(t, done)
	admissionWait(t, stopped)
	if got := pool.Refusals()["a"][resource.ReasonBudget]; got != 1 {
		t.Fatalf("ordinary refusal count=%d, want 1", got)
	}
	// Stop won the next attempt: the Pool function must never be invoked.
	_, ok, cancelled := l.acquireAdmission(0, func() (resource.Refusal, bool) {
		t.Error("cancelled admission attempted budget")
		return l.budget.Acquire()
	})
	if ok || !cancelled || pool.Refusals()["a"][resource.ReasonBudget] != 1 {
		t.Fatal("cancelled attempt added a refusal")
	}
}
