//go:build linux

// Package linuxdut is the tcpharness DUT for the Linux kernel's TCP, the reference engine: a TUN
// device in the caller's network namespace carries the testbench's packets, and ordinary sockets
// listen on it. It needs CAP_NET_ADMIN in that namespace, so its tests run only in the lab VM,
// under the build tag lab, in a network namespace of their own.
//
// A new network namespace takes most net.ipv4.tcp_* values from the kernel's compiled-in
// defaults, but copies some from the initial namespace: on the lab VM's 6.1 kernel
// tcp_congestion_control, tcp_rmem and tcp_wmem follow it, while tcp_frto, tcp_sack, tcp_recovery
// and tcp_autocorking do not. Which values follow may change between kernels, so PinReference
// sets every value of the reference configuration in docs/design/userspace/wgstack-verification.md
// explicitly and reads each one back.
package linuxdut

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/rahanahu/wgft/internal/tcpharness"
)

// IfName is the TUN device's name. One DUT exists at a time in a namespace.
const IfName = "wgfth0"

// ReferenceSysctls is the reference Linux configuration of wgstack-verification.md: the recovery
// mechanisms outside wgstack's completion feature set are off, so a loss-recovery scenario means
// the same on Linux and on wgstack. The order is the order PinReference writes them in.
var ReferenceSysctls = [][2]string{
	{"net/ipv4/tcp_congestion_control", "reno"},
	{"net/ipv4/tcp_recovery", "0"},
	{"net/ipv4/tcp_early_retrans", "0"},
	{"net/ipv4/tcp_frto", "0"},
	{"net/ipv4/tcp_ecn", "0"},
	{"net/ipv4/tcp_fastopen", "0"},
	{"net/ipv4/tcp_syncookies", "0"},
	{"net/ipv4/tcp_dsack", "0"},
	{"net/ipv4/tcp_no_metrics_save", "1"},
	{"net/ipv4/tcp_moderate_rcvbuf", "0"},
	{"net/ipv4/tcp_autocorking", "0"},
	// The UDP, reassembly and ICMP scenarios depend on these IP-level values, pinned at the 6.1
	// defaults: the fragment lifetime of 30 s, the path MTU floor of 552, path MTU discovery on,
	// and ICMP errors limited to 1 per second per destination for the types in the default mask.
	{"net/ipv4/ipfrag_time", "30"},
	{"net/ipv4/route/min_pmtu", "552"},
	{"net/ipv4/ip_no_pmtu_disc", "0"},
	{"net/ipv4/icmp_ratelimit", "1000"},
	{"net/ipv4/icmp_ratemask", "6168"},
}

// SocketFloor is the send and receive buffer each listening socket gets, the size of the floor
// every connection of wgft's agent is guaranteed: tcpSendFloor and tcpRecvFloor in
// internal/nettun. Linux doubles the value it is given to cover its bookkeeping, so the data it
// holds is about the floor.
const SocketFloor = 256 << 10

// PinReference writes ReferenceSysctls in the calling network namespace and reads each back.
func PinReference() error {
	for _, kv := range ReferenceSysctls {
		if err := writeSysctl(kv[0], kv[1]); err != nil {
			return err
		}
	}
	return nil
}

// writeSysctl writes one value under /proc/sys and reads it back.
func writeSysctl(name, value string) error {
	path := "/proc/sys/" + name
	if err := os.WriteFile(path, []byte(value), 0); err != nil {
		return fmt.Errorf("setting %s to %s: %w", name, value, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if v := strings.TrimSpace(string(got)); v != value {
		return fmt.Errorf("%s reads %q after writing %q", name, v, value)
	}
	return nil
}

// DUT is one TUN device and the sockets on its address.
type DUT struct {
	plain   bool // listening sockets keep the kernel's buffer autotuning
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
	// No offload: without IFF_VNET_HDR the device takes none, and the zero makes it explicit, so
	// segments are as TCP cut them and the harness can hold every packet to the MTU.
	if err := unix.IoctlSetInt(fd, unix.TUNSETOFFLOAD, 0); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("TUNSETOFFLOAD: %w", err)
	}
	if err := gsoOff(); err != nil {
		unix.Close(fd)
		return nil, err
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

// NewPerformance is New for the performance measurements of wgstack-performance.md: listening
// sockets get no SO_RCVBUF or SO_SNDBUF, which would stop the kernel's buffer autotuning.
func NewPerformance(addr netip.Addr, mtu int) (*DUT, error) {
	d, err := New(addr, mtu)
	if err != nil {
		return nil, err
	}
	d.plain = true
	return d, nil
}

// PerformanceSysctls is the reference Linux of wgstack-performance.md's measurement plan: the
// kernel's defaults for recovery and congestion control, written out so a namespace does not
// inherit other values, with tcp_no_metrics_save and tcp_ecn fixed and the buffer limits at the
// 4 MiB of wgstack's boost.
var PerformanceSysctls = [][2]string{
	{"net/ipv4/tcp_congestion_control", "cubic"},
	{"net/ipv4/tcp_sack", "1"},
	{"net/ipv4/tcp_dsack", "1"},
	{"net/ipv4/tcp_recovery", "1"},
	{"net/ipv4/tcp_early_retrans", "3"},
	{"net/ipv4/tcp_frto", "2"},
	{"net/ipv4/tcp_moderate_rcvbuf", "1"},
	{"net/ipv4/tcp_autocorking", "1"},
	{"net/ipv4/tcp_no_metrics_save", "1"},
	{"net/ipv4/tcp_ecn", "0"},
	{"net/ipv4/tcp_rmem", "4096\t131072\t4194304"},
	{"net/ipv4/tcp_wmem", "4096\t16384\t4194304"},
}

// PinPerformance writes PerformanceSysctls in the calling network namespace and reads each back.
func PinPerformance() error {
	for _, kv := range PerformanceSysctls {
		if err := writeSysctl(kv[0], kv[1]); err != nil {
			return err
		}
	}
	return nil
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
		NewPerformance: func(tb testing.TB, _ uint64) tcpharness.DUT {
			d, err := NewPerformance(tcpharness.DUTAddr, tcpharness.MTU)
			if err != nil {
				tb.Fatalf("linux DUT: %v", err)
			}
			tb.Cleanup(func() { d.Close() })
			return d
		},
		Known: known,
		// Each scenario starts from the pinned reference and adds its family's settings. A
		// Performance scenario adds PerformanceSysctls first; the values ReferenceSysctls does not
		// pin, such as tcp_rmem, go back to what they were when the scenario ends.
		Prepare: func(tb testing.TB, s tcpharness.Scenario) {
			if err := PinReference(); err != nil {
				tb.Fatalf("pinning the reference sysctls: %v", err)
			}
			if s.Performance {
				pinned := map[string]bool{}
				for _, kv := range ReferenceSysctls {
					pinned[kv[0]] = true
				}
				for _, kv := range PerformanceSysctls {
					if pinned[kv[0]] {
						continue
					}
					old, err := os.ReadFile("/proc/sys/" + kv[0])
					if err != nil {
						tb.Fatalf("reading %s: %v", kv[0], err)
					}
					name, value := kv[0], strings.TrimSpace(string(old))
					tb.Cleanup(func() {
						if err := writeSysctl(name, value); err != nil {
							tb.Errorf("restoring %s: %v", name, err)
						}
					})
				}
				if err := PinPerformance(); err != nil {
					tb.Fatalf("pinning the performance sysctls: %v", err)
				}
				tb.Logf("scenario runs on the performance sysctls, listeners without SO_RCVBUF or SO_SNDBUF")
			}
			for _, kv := range s.Linux {
				if err := writeSysctl(kv[0], kv[1]); err != nil {
					tb.Fatalf("setting the scenario's sysctl: %v", err)
				}
				tb.Logf("scenario sysctl %s = %s", kv[0], kv[1])
			}
		},
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

// Listen opens a listener whose send and receive buffers are SocketFloor; accepted sockets
// inherit them. Go's accepted connections have TCP_NODELAY set, as wgstack has no Nagle.
func (d *DUT) Listen(port uint16) (tcpharness.Listener, error) {
	lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
		if d.plain {
			return nil
		}
		var serr error
		err := rc.Control(func(fd uintptr) {
			if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, SocketFloor); serr == nil {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, SocketFloor)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}}
	l, err := lc.Listen(context.Background(), "tcp4", netip.AddrPortFrom(d.addr, port).String())
	if err != nil {
		return nil, err
	}
	return listener{l.(*net.TCPListener)}, nil
}

// ListenUDP opens an ordinary UDP socket on the DUT's address.
func (d *DUT) ListenUDP(port uint16) (net.PacketConn, error) {
	return net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(d.addr, port)))
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

// The adapter meets the harness's interfaces; a change of signature fails the build here.
var (
	_ tcpharness.DUT      = (*DUT)(nil)
	_ tcpharness.Listener = listener{}
	_ tcpharness.Conn     = conn{}
)

func (c conn) Abort() error {
	c.SetLinger(0)
	return c.Close()
}

// gsoOff turns off generic segmentation offload on the TUN device. With it on, the kernel's TCP
// builds multi-segment buffers and its TSO deferral can hold a segment the congestion window
// allows, a timing the scenarios would read as TCP's own.
func gsoOff() error {
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(s)
	v := struct{ cmd, data uint32 }{unix.ETHTOOL_SGSO, 0}
	var ifr struct {
		name [unix.IFNAMSIZ]byte
		data unsafe.Pointer
		_    [16]byte
	}
	copy(ifr.name[:], IfName)
	ifr.data = unsafe.Pointer(&v)
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(s), unix.SIOCETHTOOL, uintptr(unsafe.Pointer(&ifr))); e != 0 {
		return fmt.Errorf("turning GSO off on %s: %w", IfName, e)
	}
	return nil
}
