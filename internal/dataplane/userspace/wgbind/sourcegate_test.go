package wgbind

import (
	"encoding/binary"
	"errors"
	"math"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ratelimiter"

	"github.com/rahanahu/wgft/internal/nettun"
)

func limiterFixture(t *testing.T) (*ratelimiter.Ratelimiter, *limiterObserver) {
	t.Helper()
	r := new(ratelimiter.Ratelimiter)
	r.Init()
	t.Cleanup(r.Close)
	o, err := observerFields(nil, reflect.ValueOf(r).Elem())
	if err != nil {
		t.Fatal(err)
	}
	return r, o
}

func fixtureIP(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)})
}

func fillLimiter(r *ratelimiter.Ratelimiter) {
	for i := 0; i < sourceThreshold; i++ {
		r.Allow(fixtureIP(i))
	}
}

func TestLimiterObservationUsesActualLockAndCombinedExactKeys(t *testing.T) {
	r, o := limiterFixture(t)
	v4 := fixtureIP(0)
	v6 := netip.MustParseAddr("2001:db8::1")
	mapped := netip.MustParseAddr("::ffff:192.0.0.0")
	r.Allow(v4)
	r.Allow(v6)
	r.Allow(mapped)
	o.mu.RLock()
	if o.table.Len() != 3 {
		t.Fatalf("combined map count = %d", o.table.Len())
	}
	o.mu.RUnlock()
	fillLimiter(r)
	for _, ip := range []netip.Addr{v4, v6, mapped} {
		if !o.admit(ip) {
			t.Fatalf("existing exact key %v rejected", ip)
		}
	}
	if o.admit(fixtureIP(sourceThreshold + 1)) {
		t.Fatal("unseen source admitted above threshold")
	}
	o.mu.Lock()
	if o.admit(v4) {
		t.Fatal("observation did not use the actual locked mutex")
	}
	o.mu.Unlock()
	// Public Allow still works after observation; the guard changes no entries.
	r.Allow(v4)
}

func TestLimiterObservationThresholdAndRecovery(t *testing.T) {
	r, o := limiterFixture(t)
	newIP := fixtureIP(sourceThreshold)
	for i := 0; i < sourceThreshold-1; i++ {
		r.Allow(fixtureIP(i))
	}
	if !o.admit(newIP) {
		t.Fatal("unseen source rejected below threshold")
	}
	r.Allow(fixtureIP(sourceThreshold - 1))
	if o.admit(newIP) {
		t.Fatal("unseen source admitted at threshold")
	}
	// Wait for actual empty state, not an assumed two-second recovery.
	deadline := time.Now().Add(10 * time.Second)
	for {
		o.mu.RLock()
		empty := o.table.Len() == 0
		o.mu.RUnlock()
		if empty {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("limiter did not become empty")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !o.admit(newIP) {
		t.Fatal("unseen admission did not recover after GC")
	}
}

type gatePacket struct {
	data []byte
	ep   conn.Endpoint
}
type gateBind struct {
	*fakeBind
	packets        []gatePacket
	functions      int
	nilFunction    bool
	reads          int
	openSignal     chan struct{}
	emptyFunctions bool
}

func (b *gateBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.opened++
	if b.openSignal != nil {
		close(b.openSignal)
	}
	n := b.functions
	if n == 0 {
		n = 1
	}
	if b.emptyFunctions {
		n = 0
	}
	fns := make([]conn.ReceiveFunc, n)
	for i := range fns {
		if !b.nilFunction {
			fns[i] = b.receive
		}
	}
	return fns, port, nil
}
func (b *gateBind) receive(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	b.reads++
	if len(b.packets) == 0 {
		return 0, net.ErrClosed
	}
	p := b.packets[0]
	b.packets = b.packets[1:]
	sizes[0] = copy(bufs[0], p.data)
	eps[0] = p.ep
	return 1, nil
}
func handshake(typ uint32, size int) []byte {
	p := make([]byte, size)
	if size >= 4 {
		binary.LittleEndian.PutUint32(p, typ)
	}
	return p
}
func stdEndpoint(ip netip.Addr) conn.Endpoint {
	return &conn.StdNetEndpoint{AddrPort: netip.AddrPortFrom(ip, 12345)}
}
func preparedGate(t *testing.T, b conn.Bind, o *limiterObserver) *sourceGate {
	t.Helper()
	g := newSourceGate(b)
	g.attachOnce.Do(func() { g.observer.Store(o); close(g.ready) })
	return g
}

func TestSourceGatePacketClassificationAndConsumedDrop(t *testing.T) {
	r, o := limiterFixture(t)
	fillLimiter(r)
	for _, batch := range []int{1, 4} {
		t.Run(string(rune('0'+batch)), func(t *testing.T) {
			known, newEP := stdEndpoint(fixtureIP(0)), stdEndpoint(fixtureIP(sourceThreshold))
			cases := []struct {
				typ  uint32
				size int
				ep   conn.Endpoint
				drop bool
			}{
				{1, 148, newEP, true}, {2, 92, newEP, true}, {1, 148, known, false}, {2, 92, known, false},
				{1, 147, newEP, false}, {2, 93, newEP, false}, {3, 64, newEP, false}, {4, 148, newEP, false},
				{99, 92, newEP, false}, {1, 3, newEP, false}, {1, 148, fakeEndpoint{}, true},
			}
			b := &gateBind{fakeBind: &fakeBind{batch: batch}}
			for _, c := range cases {
				b.packets = append(b.packets, gatePacket{handshake(c.typ, c.size), c.ep})
			}
			g := preparedGate(t, b, o)
			if g.BatchSize() != 1 {
				t.Fatal("gate is not single-item")
			}
			fns, _, err := g.Open(0)
			if err != nil {
				t.Fatal(err)
			}
			for i, c := range cases {
				data, ep, err := one(t, fns[0])
				if err != nil {
					t.Fatal(err)
				}
				if c.drop {
					if data != "" || ep != nil {
						t.Fatalf("case %d not consumed", i)
					}
				} else if data != string(handshake(c.typ, c.size)) || ep != c.ep {
					t.Fatalf("case %d baseline changed", i)
				}
				if b.reads != i+1 {
					t.Fatal("gate read again after consuming a drop")
				}
			}
			if g.drops.Load() != 3 {
				t.Fatalf("drops=%d, want 3", g.drops.Load())
			}
		})
	}
	if candidate([]byte{1}, 148) || candidate(handshake(1, 148), -1) {
		t.Fatal("unsafe slice boundary classified")
	}
}

func TestSourceGateReadinessFailureAndNormalClose(t *testing.T) {
	b := &gateBind{fakeBind: &fakeBind{batch: 1}, openSignal: make(chan struct{})}
	g := newSourceGate(b)
	started, done := make(chan struct{}), make(chan error, 1)
	go func() { close(started); _, _, err := g.Open(0); done <- err }()
	<-started
	select {
	case <-b.openSignal:
		t.Fatal("inner Open happened before attachment")
	case <-time.After(50 * time.Millisecond):
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-g.ready:
		t.Fatal("ordinary Close canceled attachment")
	default:
	}
	if err := g.attach(nil); err != errLimiterLayout {
		t.Fatalf("attach failure=%v", err)
	}
	select {
	case err := <-done:
		if err != errLimiterLayout {
			t.Fatalf("Open failure=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("attachment failure did not wake Open")
	}
	if b.opened != 0 {
		t.Fatal("failed attachment opened inner bind")
	}
}

func TestSourceGateReceiveLayoutReopenAndDetach(t *testing.T) {
	_, o := limiterFixture(t)
	for _, batch := range []int{1, 4} {
		for _, n := range []int{1, 2, 3} {
			b := &gateBind{fakeBind: &fakeBind{batch: batch}, functions: n}
			g := preparedGate(t, b, o)
			fns, _, err := g.Open(0)
			if n > 2 {
				if err != errReceiveLayout || b.closed != 1 {
					t.Fatalf("R=%d: error=%v closes=%d", n, err, b.closed)
				}
				continue
			}
			if err != nil || len(fns) != n {
				t.Fatalf("R=%d: %v", n, err)
			}
			g.Close()
			if _, _, err := one(t, fns[0]); !errors.Is(err, net.ErrClosed) {
				t.Fatal("old generation survived Close")
			}
			if _, _, err := g.Open(0); err != nil {
				t.Fatal("normal reopen failed", err)
			}
			g.Close()
			g.detach()
			if g.observer.Load() != nil {
				t.Fatal("detach retained observer")
			}
			if _, _, err := g.Open(0); !errors.Is(err, net.ErrClosed) {
				t.Fatal("detached Open passed through")
			}
		}
		b := &gateBind{fakeBind: &fakeBind{batch: batch}, nilFunction: true}
		g := preparedGate(t, b, o)
		if _, _, err := g.Open(0); err != errReceiveLayout || b.closed != 1 {
			t.Fatalf("nil function error=%v closes=%d", err, b.closed)
		}
	}
	g := preparedGate(t, &fakeBind{batch: 0}, o)
	if _, _, err := g.Open(0); err != errReceiveLayout {
		t.Fatal("invalid batch was admitted")
	}
	b := &gateBind{fakeBind: &fakeBind{batch: 1}, emptyFunctions: true}
	g = preparedGate(t, b, o)
	if _, _, err := g.Open(0); err != errReceiveLayout || b.closed != 1 {
		t.Fatalf("empty functions error=%v closes=%d", err, b.closed)
	}
}

func TestSourceGateInnerErrorIdentity(t *testing.T) {
	_, o := limiterFixture(t)
	sentinel := permanentError{}
	g := preparedGate(t, &fakeBind{batch: 1, script: []fakeResult{{err: sentinel}}}, o)
	fns, _, err := g.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = one(t, fns[0])
	if err != error(sentinel) {
		t.Fatal("inner error wrapped or changed")
	}
}

func TestManagedDeviceAttachesEarlyEventAndDetaches(t *testing.T) {
	tnet, err := nettun.Create(netip.MustParseAddr("192.0.2.1"), 1420)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDevice(tnet, New(), device.NewLogger(device.LogLevelSilent, ""))
	if err != nil {
		t.Fatal(err)
	}
	if d.gate.observer.Load() == nil {
		t.Fatal("managed Device returned unattached")
	}
	if err := d.Up(); err != nil {
		d.Close()
		t.Fatal(err)
	}
	d.Close()
	if d.gate.observer.Load() != nil {
		t.Fatal("managed Close did not detach")
	}
	if _, _, err := d.gate.Open(0); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed managed bind reopened")
	}
	// Do not call Allow after Close here: dependency handshake workers are
	// asynchronous and its closed stopReset insertion race is a separate issue.
}

func TestLimiterLayoutMismatchAndCounterSaturation(t *testing.T) {
	if _, err := observeLimiter(nil); err != errLimiterLayout {
		t.Fatal("nil Device accepted")
	}
	wrong := struct {
		mu    int
		table map[netip.Addr]*ratelimiter.RatelimiterEntry
	}{}
	if _, err := observerFields(nil, reflect.ValueOf(&wrong).Elem()); err != errLimiterLayout {
		t.Fatal("wrong mutex type accepted")
	}
	wrongTable := struct {
		mu    sync.RWMutex
		table map[netip.Addr]int
	}{}
	if _, err := observerFields(nil, reflect.ValueOf(&wrongTable).Elem()); err != errLimiterLayout {
		t.Fatal("wrong map type accepted")
	}
	var count atomic.Uint64
	count.Store(math.MaxUint64 - 1)
	saturatingIncrement(&count)
	saturatingIncrement(&count)
	if count.Load() != math.MaxUint64 {
		t.Fatal("counter wrapped")
	}
}

// These pinned dependency facts support the documented count and planning
// coefficient. A change needs source review rather than silently updating H.
func TestPinnedSourceGateResourceFacts(t *testing.T) {
	if device.QueueHandshakeSize != 1024 || device.MessageInitiationType != 1 ||
		device.MessageResponseType != 2 || device.MessageInitiationSize != 148 || device.MessageResponseSize != 92 {
		t.Fatal("WireGuard queue or packet constants changed; review the source bound")
	}
	entry := reflect.TypeFor[ratelimiter.RatelimiterEntry]()
	if entry.NumField() != 3 || entry.Field(0).Type != reflect.TypeFor[sync.Mutex]() ||
		entry.Field(1).Type != reflect.TypeFor[time.Time]() || entry.Field(2).Type != reflect.TypeFor[int64]() {
		t.Fatal("limiter entry fields changed; review the planning coefficient")
	}
	w := runtime.NumCPU()
	t.Logf("CPU workers=%d, proposed planning bytes=%d, entry bytes=%d, address bytes=%d", w,
		64*1024+256*(2051+2*w), entry.Size(), reflect.TypeFor[netip.Addr]().Size())
}
