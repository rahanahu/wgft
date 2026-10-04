package wgbind

import (
	"encoding/binary"
	"errors"
	"math"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ratelimiter"
	"golang.zx2c4.com/wireguard/tun"
)

// Proposed default; see docs/design/userspace/wireguard-sources.md. The limiter
// can overshoot by its fixed handshake queue, workers and receive locals.
const sourceThreshold = 1024

var (
	errLimiterLayout = errors.New("unsupported WireGuard limiter layout")
	errReceiveLayout = errors.New("unsupported WireGuard receive layout")
)

// Device owns the observer's lifecycle as well as the underlying Device. Close
// joins receive routines before releasing the observer; it does not join the
// dependency's handshake workers.
type Device struct {
	*device.Device
	gate *sourceGate
}

// NewDevice attaches before returning or configuring the Device. An early TUN
// EventUp can reach Open during device.NewDevice, so Open waits for attachment.
func NewDevice(tunDevice tun.Device, bind conn.Bind, logger *device.Logger) (*Device, error) {
	g := newSourceGate(bind)
	d := device.NewDevice(tunDevice, g, logger)
	if err := g.attach(d); err != nil {
		// attach has already woken Open, including an early EventUp holding
		// device state/net locks. Closing before that would deadlock.
		d.Close()
		g.detach()
		return nil, err
	}
	return &Device{Device: d, gate: g}, nil
}

func (d *Device) Close() {
	d.Device.Close()
	d.gate.detach()
}

// SourceDrops is one saturating aggregate, with no source-keyed history.
func (d *Device) SourceDrops() uint64 { return d.gate.drops.Load() }

type sourceGate struct {
	conn.Bind
	ready      chan struct{}
	attachOnce sync.Once
	attachErr  error // published by ready close; never subsequently changed
	observer   atomic.Pointer[limiterObserver]
	detached   atomic.Bool
	drops      atomic.Uint64
	mu         sync.Mutex // only protects cur; never spans limiter observation
	cur        *generation
}

func newSourceGate(inner conn.Bind) *sourceGate {
	return &sourceGate{Bind: BatchOne(inner), ready: make(chan struct{})}
}

func (g *sourceGate) attach(d *device.Device) error {
	g.attachOnce.Do(func() {
		o, err := observeLimiter(d)
		g.attachErr = err
		if err == nil {
			g.observer.Store(o)
			if g.detached.Load() {
				g.observer.Store(nil)
			}
		}
		close(g.ready)
	})
	return g.attachErr
}

func (g *sourceGate) detach() {
	g.detached.Store(true)
	g.observer.Store(nil)
}

func (*sourceGate) BatchSize() int { return 1 }

func (g *sourceGate) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	<-g.ready
	if g.attachErr != nil {
		return nil, 0, g.attachErr
	}
	if g.detached.Load() {
		return nil, 0, net.ErrClosed
	}
	if g.Bind.BatchSize() != 1 {
		return nil, 0, errReceiveLayout
	}
	fns, actualPort, err := g.Bind.Open(port)
	if err != nil {
		return nil, actualPort, err
	}
	valid := len(fns) >= 1 && len(fns) <= 2
	for _, fn := range fns {
		valid = valid && fn != nil
	}
	if !valid {
		_ = g.Bind.Close()
		return nil, 0, errReceiveLayout
	}
	gen := &generation{}
	g.mu.Lock()
	g.cur = gen
	g.mu.Unlock()
	for i, inner := range fns {
		fns[i] = func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			if gen.closed.Load() || g.detached.Load() {
				return 0, net.ErrClosed
			}
			n, err := inner(bufs, sizes, eps)
			if err != nil {
				return n, err
			}
			if n < 0 || n > 1 {
				return 0, errReceiveLayout
			}
			if gen.closed.Load() || g.detached.Load() {
				if len(eps) > 0 {
					eps[0] = nil
				}
				return 0, net.ErrClosed
			}
			if n == 1 && len(bufs) > 0 && len(sizes) > 0 && len(eps) > 0 && candidate(bufs[0], sizes[0]) {
				if !g.admit(eps[0]) {
					saturatingIncrement(&g.drops)
					sizes[0], eps[0] = 0, nil
				}
			}
			return n, nil
		}
	}
	return fns, actualPort, nil
}

// BindUpdate calls Close even before its first Open. It must not cancel ready.
func (g *sourceGate) Close() error {
	g.mu.Lock()
	if g.cur != nil {
		g.cur.closed.Store(true)
	}
	g.mu.Unlock()
	return g.Bind.Close()
}

func candidate(buf []byte, size int) bool {
	if size < 4 || size > len(buf) {
		return false
	}
	typ := binary.LittleEndian.Uint32(buf[:4])
	return typ == device.MessageInitiationType && size == device.MessageInitiationSize ||
		typ == device.MessageResponseType && size == device.MessageResponseSize
}

func (g *sourceGate) admit(ep conn.Endpoint) bool {
	// StdNetBind gives every datagram its own endpoint. AddrPort is immutable
	// throughout the dependency's receive/handshake path; ClearSrc changes src.
	e, ok := ep.(*conn.StdNetEndpoint)
	if !ok || e == nil || !e.DstIP().IsValid() {
		return false
	}
	o := g.observer.Load()
	return o != nil && o.admit(e.DstIP())
}

func saturatingIncrement(v *atomic.Uint64) {
	for old := v.Load(); old != math.MaxUint64; old = v.Load() {
		if v.CompareAndSwap(old, old+1) {
			return
		}
	}
}

// limiterObserver is a read-only shim for pinned wireguard-go ecfc5a8d5446.
// table is the actual map field, so replacements under mu are also observed.
// owner keeps the field addresses alive until detach; no private fields are set.
type limiterObserver struct {
	owner *device.Device
	mu    *sync.RWMutex
	table reflect.Value
}

func observeLimiter(d *device.Device) (*limiterObserver, error) {
	if d == nil {
		return nil, errLimiterLayout
	}
	v := reflect.ValueOf(d).Elem()
	rate := v.FieldByName("rate")
	if !rate.IsValid() || rate.Kind() != reflect.Struct {
		return nil, errLimiterLayout
	}
	limiter := rate.FieldByName("limiter")
	if !limiter.IsValid() || limiter.Type() != reflect.TypeFor[ratelimiter.Ratelimiter]() || !limiter.CanAddr() {
		return nil, errLimiterLayout
	}
	return observerFields(d, limiter)
}

func observerFields(d *device.Device, limiter reflect.Value) (*limiterObserver, error) {
	mu, table := limiter.FieldByName("mu"), limiter.FieldByName("table")
	if !mu.IsValid() || mu.Type() != reflect.TypeFor[sync.RWMutex]() || !mu.CanAddr() ||
		!table.IsValid() || table.Type() != reflect.TypeFor[map[netip.Addr]*ratelimiter.RatelimiterEntry]() || !table.CanAddr() {
		return nil, errLimiterLayout
	}
	// NewAt preserves each validated field's exact type and points to the
	// original storage, particularly the real sync.RWMutex, never a copy/cast.
	actualMu := reflect.NewAt(mu.Type(), unsafe.Pointer(mu.UnsafeAddr())).Interface().(*sync.RWMutex)
	actualTable := reflect.NewAt(table.Type(), unsafe.Pointer(table.UnsafeAddr())).Elem()
	return &limiterObserver{owner: d, mu: actualMu, table: actualTable}, nil
}

func (o *limiterObserver) admit(ip netip.Addr) bool {
	if !o.mu.TryRLock() {
		return false
	}
	defer o.mu.RUnlock()
	return o.table.MapIndex(reflect.ValueOf(ip)).IsValid() || o.table.Len() < sourceThreshold
}
