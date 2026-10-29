// Package wgstackdut is the tcpharness DUT for internal/wgstack, wgft's own netstack for the
// agent, built as docs/design/userspace/wgstack-verification.md asks: a ManualClock and a fixed
// random source from the scenario's seed, so the Device starts no goroutine and the harness drives
// it with Write, Poll and Tick. It is a ClockedDUT: the scenarios never wait on the wall clock,
// except for the application's read and write deadlines, which wgstack measures in real time.
package wgstackdut

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/tcpharness"
	"github.com/rahanahu/wgft/internal/wgstack"
)

// epoch is where the harness's view of the engine's clock starts; the ManualClock starts at 0.
var epoch = time.Unix(1_000_000_000, 0)

// DUT wraps one wgstack Device on a ManualClock.
type DUT struct {
	dev  *wgstack.Device
	clk  *wgstack.ManualClock
	addr netip.Addr
	mtu  int
	buf  []byte
}

// randSource is the engine's random source: an endless byte stream from the seed.
type randSource struct{ r *rand.ChaCha8 }

func (s randSource) Read(p []byte) (int, error) { return s.r.Read(p) }

// New builds a Device at addr with the given MTU, a ManualClock and randomness from seed.
func New(addr netip.Addr, mtu int, seed uint64) (*DUT, error) {
	var key [32]byte
	for i := range 4 {
		v := seed ^ uint64(i)*0x9e3779b97f4a7c15
		for j := range 8 {
			key[i*8+j] = byte(v >> (8 * j))
		}
	}
	clk := wgstack.NewManualClock()
	dev, err := wgstack.New(wgstack.Config{Addr: addr, MTU: mtu, Clock: clk, Rand: randSource{rand.NewChaCha8(key)}})
	if err != nil {
		return nil, err
	}
	return &DUT{dev: dev, clk: clk, addr: addr, mtu: mtu, buf: make([]byte, 65536)}, nil
}

// Engine is the harness's description of this engine. The seed becomes the engine's random
// source, so a run replays with the same ISNs and hash seeds.
func Engine(known map[string]tcpharness.Known) tcpharness.Engine {
	return tcpharness.Engine{
		Name: "wgstack",
		New: func(tb testing.TB, seed uint64) tcpharness.DUT {
			d, err := New(tcpharness.DUTAddr, tcpharness.MTU, seed)
			if err != nil {
				tb.Fatalf("wgstack.New: %v", err)
			}
			tb.Cleanup(func() { d.Close() })
			return d
		},
		Known: known,
	}
}

func (d *DUT) Name() string           { return "wgstack" }
func (d *DUT) Addr() netip.Addr       { return d.addr }
func (d *DUT) MTU() int               { return d.mtu }
func (d *DUT) Emitted() <-chan []byte { return nil }
func (d *DUT) Close() error           { return d.dev.Close() }

func (d *DUT) Inject(pkt []byte) error {
	_, err := d.dev.Write([][]byte{pkt}, 0)
	return err
}

// Now is the engine's clock as a time for the harness.
func (d *DUT) Now() time.Time { return epoch.Add(d.clk.Now()) }

// Advance moves the ManualClock and runs the timers that fall due.
func (d *DUT) Advance(dt time.Duration) {
	d.clk.Advance(dt)
	d.dev.Tick()
}

// Poll takes the next packet the engine sends now.
func (d *DUT) Poll() ([]byte, bool) {
	n := d.dev.Poll(d.buf)
	if n == 0 {
		return nil, false
	}
	return append([]byte(nil), d.buf[:n]...), true
}

func (d *DUT) Listen(port uint16) (tcpharness.Listener, error) {
	l, err := d.dev.ListenTCP(netip.AddrPortFrom(d.addr, port))
	if err != nil {
		return nil, err
	}
	return &listener{l: l}, nil
}

type listener struct{ l *wgstack.TCPListener }

func (l *listener) Close() error { return l.l.Close() }

// Accept waits in a goroutine, because TCPListener.Accept takes no context. The engine is
// synchronous, so a connection whose handshake the harness finished is ready at once.
func (l *listener) Accept(ctx context.Context) (tcpharness.Conn, error) {
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := l.l.Accept()
		ch <- result{c, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		wc, ok := r.c.(*wgstack.Conn)
		if !ok {
			r.c.Close()
			return nil, errors.New("accepted connection is not a *wgstack.Conn")
		}
		return conn{wc}, nil
	case <-ctx.Done():
		l.l.Close()
		return nil, ctx.Err()
	}
}

// conn is the accepted *wgstack.Conn. Its Abort returns nothing, so conn adapts it; Delivered,
// CloseForDelivery and OnBoost are promoted.
type conn struct{ *wgstack.Conn }

func (c conn) Abort() error { c.Conn.Abort(); return nil }

// The adapter meets the harness's interfaces, including the optional methods the relay looks up
// by type assertion; a change of signature on either side fails the build here.
var (
	_ tcpharness.ClockedDUT     = (*DUT)(nil)
	_ tcpharness.Listener       = (*listener)(nil)
	_ tcpharness.Conn           = conn{}
	_ tcpharness.Deliverer      = conn{}
	_ tcpharness.DeliveryCloser = conn{}
	_ tcpharness.Booster        = conn{}
)
