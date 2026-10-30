//go:build qbench

package qbench

import (
	"context"
	"net"
	"net/netip"
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

// Client is gVisor's netstack from wireguard-go, which dials.
type Client struct {
	Dev tun.Device
	Net *netstack.Net
}

func newClient() (*Client, error) {
	dev, n, err := netstack.CreateNetTUN([]netip.Addr{clientAddr}, nil, mtu)
	if err != nil {
		return nil, err
	}
	return &Client{Dev: dev, Net: n}, nil
}

func (c *Client) Dial(ctx context.Context) (net.Conn, error) {
	return c.Net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(dutAddr, port))
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
	C  *Client
	D  *DUT
	L  *Link
	wg sync.WaitGroup
}

// newRig joins client (direction 0 leaves the client) and DUT.
func newRig(engine string, imp Impair, seed int64) (*Rig, error) {
	c, err := newClient()
	if err != nil {
		return nil, err
	}
	var d *DUT
	if engine == "wgstack" {
		d, err = newWgstack()
	} else {
		d, err = newGvisor()
	}
	if err != nil {
		c.Dev.Close()
		return nil, err
	}
	r := &Rig{C: c, D: d}
	r.L = NewLink(imp, seed, writeTo(d.Dev), writeTo(c.Dev))
	pump(c.Dev, func(p []byte) { r.L.Send(0, p) }, &r.wg)
	pump(d.Dev, func(p []byte) { r.L.Send(1, p) }, &r.wg)
	return r, nil
}

func (r *Rig) Close() {
	r.C.Dev.Close()
	r.D.Close()
	r.wg.Wait()
	r.L.Close()
}

var _ = time.Second
