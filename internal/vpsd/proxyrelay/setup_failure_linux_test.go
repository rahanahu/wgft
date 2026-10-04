//go:build linux

package proxyrelay

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/resource"
)

func setupTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan *net.TCPConn, 1)
	go func() { c, _ := ln.AcceptTCP(); got <- c }()
	peer, err := net.DialTCP("tcp4", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	c := <-got
	if c == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { c.Close(); peer.Close() })
	return c, peer
}

// setupUp keeps the actual upstream identity and substitutes only delivery state. It does not
// claim that a fresh production header leaves a queue behind after Close.
type setupUp struct {
	*net.TCPConn
	safe                 atomic.Bool
	aborted              atomic.Bool
	closed               chan struct{}
	checked              chan struct{}
	closeOnce, checkOnce sync.Once
}

func (u *setupUp) Close() error {
	err := u.TCPConn.Close()
	u.closeOnce.Do(func() { close(u.closed) })
	return err
}
func (u *setupUp) Abort() { u.aborted.Store(true); u.TCPConn.SetLinger(0); u.Close() }
func (u *setupUp) Delivered() bool {
	u.checkOnce.Do(func() { close(u.checked) })
	return u.safe.Load() || u.aborted.Load()
}

type setupHeaderError struct{ io.Writer }

func (w setupHeaderError) Write(b []byte) (int, error) {
	n, err := w.Writer.Write(b[:min(len(b), 8)])
	if err != nil {
		return n, err
	}
	return n, errors.New("header failure")
}

type setupWorker struct {
	m               *Manager
	l               *listener
	a               *admitted
	pool            *resource.Pool
	releases, dials atomic.Int32
	c, client, peer *net.TCPConn
	up              *setupUp
	done            chan struct{}
}

func newSetupWorker(t *testing.T, header bool) *setupWorker {
	t.Helper()
	r := &setupWorker{pool: resource.NewPool(8), done: make(chan struct{})}
	r.c, r.client = setupTCPPair(t)
	tc, peer := setupTCPPair(t)
	r.peer = peer
	r.up = &setupUp{TCPConn: tc, closed: make(chan struct{}), checked: make(chan struct{})}
	r.l = admissionState(r.pool)
	r.l.delivering = map[net.Conn]delivering{}
	close(r.l.serveDone)
	r.l.rule.ProxyProtocol = header
	r.m = New(Options{Pool: r.pool, HoldUntilDelivered: true, Logf: func(string, ...any) {},
		Admit: func(string, netip.Addr) (func(), bool) { return func() { r.releases.Add(1) }, true },
		Dial: func(string) (net.Conn, error) {
			r.dials.Add(1)
			if header {
				return r.up, nil
			}
			return nil, errors.New("dial failure")
		}})
	r.m.testHeaderWriter = func(up net.Conn) io.Writer {
		if up != r.up {
			t.Error("header writer lost real upstream")
		}
		return setupHeaderError{up}
	}
	r.m.ls[r.l.rule.ListenPort] = r.l
	r.a = r.m.admitAccepted(r.l, r.c)
	if r.a == nil {
		t.Fatal("not admitted")
	}
	t.Cleanup(func() { r.up.safe.Store(true); r.l.beginClose() })
	return r
}
func (r *setupWorker) start() { go func() { r.m.relayAdmitted(r.l, r.a); close(r.done) }() }
func setupWait(t *testing.T, d time.Duration, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(d):
		t.Fatal("setup worker did not reach the required state")
	}
}
func setupEOF(t *testing.T, c *net.TCPConn) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 1)
	if n, e := c.Read(b); n != 0 || !errors.Is(e, io.EOF) {
		t.Fatalf("empty peer ended with %d bytes and %v; want EOF", n, e)
	}
}
func (r *setupWorker) released(t *testing.T, d time.Duration) {
	t.Helper()
	setupWait(t, d, r.done)
	if r.pool.InUse() != 0 || r.releases.Load() != 1 || r.pool.Ledger().DoubleReleases != 0 {
		t.Fatalf("in use %d, policy releases %d, double releases %d", r.pool.InUse(), r.releases.Load(), r.pool.Ledger().DoubleReleases)
	}
	r.l.mu.Lock()
	defer r.l.mu.Unlock()
	if r.l.pending != 0 || len(r.l.conns) != 0 || len(r.l.delivering) != 0 {
		t.Fatal("finished setup worker retained a record")
	}
}

func TestSetupDialFailurePreservesEmptyPeerEOF(t *testing.T) {
	r := newSetupWorker(t, false)
	r.start()
	setupEOF(t, r.client)
	r.released(t, 5*time.Second)
}

func TestSetupHeaderFailureHoldsTheRealUpstream(t *testing.T) {
	r := newSetupWorker(t, true)
	r.start()
	setupWait(t, 5*time.Second, r.up.closed)
	setupEOF(t, r.client)
	r.peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := io.Copy(io.Discard, r.peer)
	if n != 8 || err != nil || r.up.aborted.Load() {
		t.Fatalf("partial header ended with %d bytes, %v, aborted %v; want prefix then EOF", n, err, r.up.aborted.Load())
	}
	setupWait(t, 5*time.Second, r.up.checked)
	r.l.mu.Lock()
	d, ok := r.l.delivering[r.c]
	p := r.l.pending
	r.l.mu.Unlock()
	if !ok || d.up != r.up || p != 0 || r.l.idle() {
		t.Fatal("failed setup lost the actual pair or idle ownership")
	}
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		if r.pool.InUse() != 1 || r.releases.Load() != 0 {
			t.Fatal("undelivered upstream returned the charges")
		}
		time.Sleep(20 * time.Millisecond)
	}
	r.up.safe.Store(true)
	r.released(t, 3*time.Second)
}

func TestSetupHeaderFailureReturnsWhenTheUpstreamIsSafe(t *testing.T) {
	r := newSetupWorker(t, true)
	r.up.safe.Store(true)
	r.start()
	setupEOF(t, r.client)
	r.released(t, 5*time.Second)
	if r.up.aborted.Load() {
		t.Fatal("ordinary header failure reset upstream")
	}
}

func TestSetupFailureCutOrders(t *testing.T) {
	for _, kind := range []string{"closed before header returns", "retarget before header returns", "agent after delivery"} {
		t.Run(kind, func(t *testing.T) {
			r := newSetupWorker(t, true)
			entered, proceed := make(chan struct{}), make(chan struct{})
			var once sync.Once
			resume := func() { once.Do(func() { close(proceed) }) }
			t.Cleanup(resume)
			r.m.testHeaderWriter = func(up net.Conn) io.Writer { return setupBlockedHeader{setupHeaderError{up}, entered, proceed} }
			r.start()
			setupWait(t, 5*time.Second, entered)
			if kind == "closed before header returns" {
				r.m.CloseAgent("agent")
			} else if kind == "retarget before header returns" {
				rule := r.l.rule
				rule.AgentPort++
				r.l.updateRestriction(rule)
			}
			if r.pool.InUse() != 1 || r.releases.Load() != 0 || r.l.idle() {
				t.Fatal("blocked committed header lost pending ownership")
			}
			resume()
			if kind == "agent after delivery" {
				setupWait(t, 5*time.Second, r.up.checked)
				time.Sleep(4 * time.Second)
				r.m.CloseAgent("agent")
				r.released(t, 500*time.Millisecond)
			} else {
				r.released(t, 5*time.Second)
			}
			if !r.up.aborted.Load() {
				t.Fatal("intentional cut did not reach real upstream")
			}
			if r.dials.Load() != 1 {
				t.Fatal("committed setup did not dial exactly once")
			}
		})
	}
}

type setupBlockedHeader struct {
	setupHeaderError
	entered chan struct{}
	proceed <-chan struct{}
}

func (w setupBlockedHeader) Write(b []byte) (int, error) {
	close(w.entered)
	<-w.proceed
	return w.setupHeaderError.Write(b)
}

func TestSetupFailedPendingPolicyException(t *testing.T) {
	for _, op := range []string{"retire", "source restriction"} {
		t.Run(op, func(t *testing.T) {
			r := newSetupWorker(t, true)
			if op == "retire" {
				r.l.beginStopAccepting()
				r.l.retire(func(netip.Addr) bool { return false })
			} else {
				rule := r.l.rule
				rule.Policy.SourceDeny = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
				r.l.updateRestriction(rule)
			}
			r.start()
			setupWait(t, 5*time.Second, r.up.checked)
			if r.l.idle() || r.pool.InUse() != 1 || r.up.aborted.Load() {
				t.Fatal("prior pending exception was changed")
			}
			// Once failed delivery is registered, the next source recheck reaches it.
			time.Sleep(4 * time.Second)
			r.l.retire(func(netip.Addr) bool { return false })
			r.released(t, 500*time.Millisecond)
			if !r.up.aborted.Load() {
				t.Fatal("later recheck missed failed delivery")
			}
		})
	}
}

func TestSetupPendingRegistrationIsAtomicForIdle(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "active", true: "failed delivery"}[failed], func(t *testing.T) {
			r := newSetupWorker(t, true)
			entered, proceed, registered := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			resume := func() { once.Do(func() { close(proceed) }) }
			t.Cleanup(resume)
			r.l.testHookPendingRegistration = func() { close(entered); <-proceed }
			go func() {
				wake, ok := r.l.finishPending(r.a, r.up, failed)
				if !ok || failed != (wake != nil) {
					t.Error("invalid committed transition")
				}
				close(registered)
			}()
			setupWait(t, 5*time.Second, entered)
			idle := make(chan bool, 1)
			go func() { idle <- r.l.idle() }()
			select {
			case got := <-idle:
				t.Fatalf("idle crossed locked transition: %v", got)
			case <-time.After(20 * time.Millisecond):
			}
			resume()
			setupWait(t, 5*time.Second, registered)
			select {
			case got := <-idle:
				if got {
					t.Fatal("retained setup pair appeared idle")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("idle query stalled after transition")
			}
			r.l.beginClose()
			r.a.charge.Release()
			if r.pool.InUse() != 0 || r.releases.Load() != 1 {
				t.Fatal("single flow ownership was lost")
			}
		})
	}
}

func TestSetupNilUpDeliveryCanBeCut(t *testing.T) {
	r := newSetupWorker(t, false)
	wake, ok := r.l.finishPending(r.a, nil, true)
	if !ok || wake == nil || r.l.idle() {
		t.Fatal("nil-up failed setup was not registered")
	}
	r.l.beginClose()
	setupWait(t, 500*time.Millisecond, wake)
	r.a.charge.Release()
	if r.pool.InUse() != 0 || r.releases.Load() != 1 || r.pool.Ledger().DoubleReleases != 0 {
		t.Fatal("nil-up cut lost single-charge ownership")
	}
}

func TestSetupDialStillRunsAfterCommittedClose(t *testing.T) {
	r := newSetupWorker(t, false)
	r.m.CloseAgent("agent")
	if r.pool.InUse() != 1 || r.releases.Load() != 0 {
		t.Fatal("close released a committed worker's charge")
	}
	r.start()
	r.released(t, 5*time.Second)
	if r.dials.Load() != 1 {
		t.Fatal("close skipped the committed Dial")
	}
}
