//go:build qbench

package qbench

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/rahanahu/wgft/internal/nettun"
	"github.com/rahanahu/wgft/internal/wgstack"
)

const mtu = 1420

var (
	clientAddr = netip.MustParseAddr("10.200.0.1")
	dutAddr    = netip.MustParseAddr("10.200.0.2")
)

const port = 5001

// Listener is what the DUT side accepts on.
type Listener interface {
	Accept() (net.Conn, error)
	Close() error
}

// DUT is the engine under test, the passive-open side.
type DUT struct {
	Name   string
	Dev    tun.Device
	Listen func(port uint16) (Listener, error)
	Close  func()
	// Stats, when set, describes the engine's own counters for the run's log line, with the RTO
	// in use at outageEnd; it is called after the transfer and before Close.
	Stats func(outageEnd time.Time) string
	// OnAccept, when set, sees the accepted connection; RTOAt then returns the sender's RTO in
	// use at a moment, backoff included, or a negative value when the engine cannot tell.
	OnAccept func(net.Conn) error
	RTOAt    func(at time.Time) time.Duration
	RTOErr   func() error // the last error reading the RTO, if any
}

func newWgstack() (*DUT, error) {
	tr := &traceRTO{}
	cfg := wgstack.Config{Addr: dutAddr, MTU: mtu, Trace: tr.record}
	setBoost(&cfg)
	d, err := wgstack.New(cfg)
	if err != nil {
		return nil, err
	}
	return &DUT{Name: "wgstack", Dev: d,
		Listen: func(p uint16) (Listener, error) { return d.ListenTCP(netip.AddrPortFrom(dutAddr, p)) },
		Close:  func() { d.Close(); d.Wait() },
		Stats:  func(end time.Time) string { return wgstackStats(d.Stats()) + " rto_at_outage_end=" + tr.rtoBefore(end) },
		RTOAt:  tr.rtoAt,
	}, nil
}

func newGvisor() (*DUT, error) {
	d, err := nettun.Create(dutAddr, mtu)
	if err != nil {
		return nil, err
	}
	return &DUT{Name: "gvisor", Dev: d,
		Listen: func(p uint16) (Listener, error) { return d.ListenTCP(netip.AddrPortFrom(dutAddr, p)) },
		Close:  func() { d.Close(); d.Wait() }}, nil
}

// Client is the side that dials: gVisor's netstack from wireguard-go by default, or the Linux
// kernel in a network namespace of its own (newLinuxClient).
type Client struct {
	Name  string
	Dev   tun.Device
	dial  func(ctx context.Context) (net.Conn, error)
	close func()
	// RTOAt, when set, returns the client's RTO in use at a moment, as DUT.RTOAt does: the
	// sender's RTO in the cells where the DUT receives.
	RTOAt  func(at time.Time) time.Duration
	RTOErr func() error
}

func newClient() (*Client, error) {
	dev, n, err := netstack.CreateNetTUN([]netip.Addr{clientAddr}, nil, mtu)
	if err != nil {
		return nil, err
	}
	return &Client{Name: "gvisor", Dev: dev,
		dial: func(ctx context.Context) (net.Conn, error) {
			return n.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(dutAddr, port))
		},
		close: func() { dev.Close() },
	}, nil
}

func (c *Client) Dial(ctx context.Context) (net.Conn, error) { return c.dial(ctx) }

// clientFor builds the client a rig asks for.
func clientFor(name string) (*Client, error) {
	switch name {
	case "", "gvisor":
		return newClient()
	case "linux":
		return newLinuxClient()
	}
	return nil, fmt.Errorf("unknown client %q", name)
}

// pump reads packets a device emits and hands them to send until the device closes.
func pump(dev tun.Device, send func([]byte), wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		sizes := make([]int, 1)
		for {
			if _, err := dev.Read([][]byte{buf}, sizes, 0); err != nil {
				return
			}
			send(append([]byte(nil), buf[:sizes[0]]...))
		}
	}()
}

func writeTo(dev tun.Device) func([]byte) {
	return func(p []byte) { dev.Write([][]byte{p}, 0) }
}

// Rig is one client, one DUT and the link between them.
type Rig struct {
	C     *Client
	D     *DUT
	L     *Link
	wg    sync.WaitGroup
	trace *os.File
}

// newRig joins a client of the given kind (direction 0 leaves the client) and DUT.
// trace, when set, is where the rig writes its link's packet log.
func newRig(engine, client string, imp Impair, seed int64, trace string) (*Rig, error) {
	c, err := clientFor(client)
	if err != nil {
		return nil, err
	}
	var d *DUT
	switch engine {
	case "wgstack":
		d, err = newWgstack()
	case "gvisor":
		d, err = newGvisor()
	case "linux":
		d, err = newLinux()
	default:
		err = fmt.Errorf("unknown engine %q", engine)
	}
	if err != nil {
		c.close()
		return nil, err
	}
	r := &Rig{C: c, D: d}
	r.L = NewLink(imp, seed, writeTo(d.Dev), writeTo(c.Dev))
	if trace != "" {
		f, err := os.Create(trace)
		if err != nil {
			r.Close()
			return nil, err
		}
		r.trace = f
		r.L.SetTrace(f)
	}
	pump(c.Dev, func(p []byte) { r.L.Send(0, p) }, &r.wg)
	pump(d.Dev, func(p []byte) { r.L.Send(1, p) }, &r.wg)
	return r, nil
}

func (r *Rig) Close() {
	r.C.close()
	r.D.Close()
	r.wg.Wait()
	r.L.Close()
	if r.trace != nil {
		r.trace.Close()
	}
}

var _ = time.Second
