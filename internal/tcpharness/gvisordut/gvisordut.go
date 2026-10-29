// Package gvisordut is the tcpharness DUT for the gVisor netstack exactly as wgft's agent builds
// it: a Device from internal/nettun, with its SACK setting, buffer ranges, TUN-ingress checks and
// ACK budget, and listeners from Device.ListenTCP. Only nettun's exported API is used, the same
// surface internal/dataplane/userspace/tunnel uses.
package gvisordut

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/rahanahu/wgft/internal/nettun"
	"github.com/rahanahu/wgft/internal/tcpharness"
)

// DUT wraps one nettun.Device.
type DUT struct {
	dev     *nettun.Device
	addr    netip.Addr
	mtu     int
	emitted chan []byte
	stop    chan struct{}
	done    chan struct{}
}

// New builds a Device at addr with the given MTU and starts reading what it emits.
func New(addr netip.Addr, mtu int) (*DUT, error) {
	dev, err := nettun.Create(addr, mtu)
	if err != nil {
		return nil, err
	}
	d := &DUT{dev: dev, addr: addr, mtu: mtu, emitted: make(chan []byte, 1024), stop: make(chan struct{}), done: make(chan struct{})}
	go d.read()
	return d, nil
}

// Engine is the harness's description of this engine. Known is filled in by the caller. The
// seed is not used: gVisor takes its randomness from the stack's own source.
func Engine(known map[string]tcpharness.Known) tcpharness.Engine {
	return tcpharness.Engine{
		Name: "gvisor",
		New: func(tb testing.TB, _ uint64) tcpharness.DUT {
			d, err := New(tcpharness.DUTAddr, tcpharness.MTU)
			if err != nil {
				tb.Fatalf("nettun.Create: %v", err)
			}
			tb.Cleanup(func() { d.Close() })
			return d
		},
		Known: known,
	}
}

func (d *DUT) read() {
	defer close(d.done)
	defer close(d.emitted)
	buf := make([]byte, 65536)
	sizes := make([]int, 1)
	for {
		if _, err := d.dev.Read([][]byte{buf}, sizes, 0); err != nil {
			return
		}
		select {
		case d.emitted <- append([]byte(nil), buf[:sizes[0]]...):
		case <-d.stop:
			return
		}
	}
}

func (d *DUT) Name() string           { return "gvisor" }
func (d *DUT) Addr() netip.Addr       { return d.addr }
func (d *DUT) MTU() int               { return d.mtu }
func (d *DUT) Emitted() <-chan []byte { return d.emitted }
func (d *DUT) Inject(pkt []byte) error {
	_, err := d.dev.Write([][]byte{pkt}, 0)
	return err
}

// Close closes the Device and waits for its goroutines.
func (d *DUT) Close() error {
	select {
	case <-d.stop:
		return nil
	default:
	}
	close(d.stop)
	d.dev.Close()
	d.dev.Wait()
	<-d.done
	return nil
}

func (d *DUT) Listen(port uint16) (tcpharness.Listener, error) {
	l, err := d.dev.ListenTCP(netip.AddrPortFrom(d.addr, port))
	if err != nil {
		return nil, err
	}
	return &listener{l: l}, nil
}

type listener struct{ l *nettun.TCPListener }

func (l *listener) Close() error { return l.l.Close() }

// Accept waits in a goroutine, because TCPListener.Accept takes no context. On ctx's end the
// listener is closed to release that goroutine, so a scenario accepts at most once after a
// timeout.
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
		tc, ok := r.c.(*nettun.TCPConn)
		if !ok {
			r.c.Close()
			return nil, errors.New("accepted connection is not a *nettun.TCPConn")
		}
		return conn{tc}, nil
	case <-ctx.Done():
		l.l.Close()
		return nil, ctx.Err()
	}
}

// conn is the accepted *nettun.TCPConn. Its Delivered, CloseForDelivery and OnBoost are promoted,
// so the scenarios find them by type assertion as the relay does.
type conn struct{ *nettun.TCPConn }

func (c conn) Abort() error { c.TCPConn.Abort(); return nil }
