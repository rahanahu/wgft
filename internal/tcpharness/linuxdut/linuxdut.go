//go:build linux

// Package linuxdut is the tcpharness DUT for the Linux kernel's TCP, the reference engine: a TUN
// device in the caller's network namespace carries the testbench's packets, and ordinary sockets
// listen on it. It needs CAP_NET_ADMIN in that namespace, so its tests run only in the lab VM
// (build tag lab), in a network namespace of their own, with the kernel's default TCP settings
// for a new namespace. Those are the settings of the LAN host a kernel-mode agent forwards to.
package linuxdut

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rahanahu/wgft/internal/tcpharness"
)

// IfName is the TUN device's name. One DUT exists at a time in a namespace.
const IfName = "wgfth0"

// DUT is one TUN device and the sockets on its address.
type DUT struct {
	tun     *os.File
	addr    netip.Addr
	mtu     int
	emitted chan []byte
	stop    chan struct{}
	done    chan struct{}
}

// New creates the TUN device, gives it addr/24 and the MTU, and brings it up.
func New(addr netip.Addr, mtu int) (*DUT, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	ifr, err := unix.NewIfreq(IfName)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF: %w", err)
	}
	tun := os.NewFile(uintptr(fd), "/dev/net/tun")
	if err := configure(addr, mtu); err != nil {
		tun.Close()
		return nil, err
	}
	d := &DUT{tun: tun, addr: addr, mtu: mtu, emitted: make(chan []byte, 1024), stop: make(chan struct{}), done: make(chan struct{})}
	go d.read()
	return d, nil
}

func configure(addr netip.Addr, mtu int) error {
	// The kernel would otherwise send IPv6 router and multicast listener traffic on the device.
	// A kernel without IPv6 has no such file; that is fine.
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/"+IfName+"/disable_ipv6", []byte("1"), 0); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("disabling IPv6 on %s: %w", IfName, err)
	}
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(s)
	step := func(what string, req uint, set func(*unix.Ifreq) error) error {
		ifr, err := unix.NewIfreq(IfName)
		if err != nil {
			return err
		}
		if err := set(ifr); err != nil {
			return err
		}
		if err := unix.IoctlIfreq(s, req, ifr); err != nil {
			return fmt.Errorf("%s on %s: %w", what, IfName, err)
		}
		return nil
	}
	if err := step("setting the MTU", unix.SIOCSIFMTU, func(r *unix.Ifreq) error { r.SetUint32(uint32(mtu)); return nil }); err != nil {
		return err
	}
	if err := step("setting the address", unix.SIOCSIFADDR, func(r *unix.Ifreq) error { return r.SetInet4Addr(addr.AsSlice()) }); err != nil {
		return err
	}
	if err := step("setting the netmask", unix.SIOCSIFNETMASK, func(r *unix.Ifreq) error { return r.SetInet4Addr([]byte{255, 255, 255, 0}) }); err != nil {
		return err
	}
	return step("bringing the device up", unix.SIOCSIFFLAGS, func(r *unix.Ifreq) error { r.SetUint16(unix.IFF_UP | unix.IFF_RUNNING); return nil })
}

// Engine is the harness's description of this engine. The seed is not used: the kernel takes
// its randomness from its own source.
func Engine(known map[string]tcpharness.Known) tcpharness.Engine {
	return tcpharness.Engine{
		Name: "linux",
		New: func(tb testing.TB, _ uint64) tcpharness.DUT {
			d, err := New(tcpharness.DUTAddr, tcpharness.MTU)
			if err != nil {
				tb.Fatalf("linux DUT: %v", err)
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
	for {
		n, err := d.tun.Read(buf)
		if err != nil {
			return
		}
		if n == 0 || buf[0]>>4 != 4 {
			continue
		}
		select {
		case d.emitted <- append([]byte(nil), buf[:n]...):
		case <-d.stop:
			return
		}
	}
}

func (d *DUT) Name() string           { return "linux" }
func (d *DUT) Addr() netip.Addr       { return d.addr }
func (d *DUT) MTU() int               { return d.mtu }
func (d *DUT) Emitted() <-chan []byte { return d.emitted }
func (d *DUT) Inject(pkt []byte) error {
	_, err := d.tun.Write(pkt)
	return err
}

// Close removes the TUN device; the kernel deletes a non-persistent device with its last fd.
func (d *DUT) Close() error {
	select {
	case <-d.stop:
		return nil
	default:
	}
	close(d.stop)
	err := d.tun.Close()
	<-d.done
	return err
}

func (d *DUT) Listen(port uint16) (tcpharness.Listener, error) {
	l, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(netip.AddrPortFrom(d.addr, port)))
	if err != nil {
		return nil, err
	}
	return listener{l}, nil
}

type listener struct{ l *net.TCPListener }

func (l listener) Close() error { return l.l.Close() }

func (l listener) Accept(ctx context.Context) (tcpharness.Conn, error) {
	if dl, ok := ctx.Deadline(); ok {
		l.l.SetDeadline(dl)
	} else {
		l.l.SetDeadline(time.Time{})
	}
	c, err := l.l.AcceptTCP()
	if err != nil {
		return nil, err
	}
	return conn{c}, nil
}

type conn struct{ *net.TCPConn }

func (c conn) Abort() error {
	c.SetLinger(0)
	return c.Close()
}
