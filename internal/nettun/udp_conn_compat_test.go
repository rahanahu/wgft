package nettun

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

// DialUDP and ListenUDP returned gonet.UDPConn before the accounting. These
// tests run the same steps on gonet.UDPConn and on the Device's connections
// and require the same observable result for deadlines, short reads, error
// translation and Close, except where a difference is pinned on purpose.

type udpConnImpl struct {
	name   string
	listen func(t *testing.T, d *Device, ap netip.AddrPort) net.PacketConn
	dial   func(t *testing.T, d *Device, ap netip.AddrPort) net.Conn
}

var udpConnImpls = []udpConnImpl{
	{
		name: "gonet",
		listen: func(t *testing.T, d *Device, ap netip.AddrPort) net.PacketConn {
			a := fullAddr(ap)
			c, err := gonet.DialUDP(d.stack, &a, nil, ipv4.ProtocolNumber)
			if err != nil {
				t.Fatal(err)
			}
			return c
		},
		dial: func(t *testing.T, d *Device, ap netip.AddrPort) net.Conn {
			a := fullAddr(ap)
			c, err := gonet.DialUDP(d.stack, nil, &a, ipv4.ProtocolNumber)
			if err != nil {
				t.Fatal(err)
			}
			return c
		},
	},
	{
		name: "device",
		listen: func(t *testing.T, d *Device, ap netip.AddrPort) net.PacketConn {
			c, err := d.ListenUDP(ap)
			if err != nil {
				t.Fatal(err)
			}
			return c
		},
		dial: func(t *testing.T, d *Device, ap netip.AddrPort) net.Conn {
			c, err := d.DialUDP(ap)
			if err != nil {
				t.Fatal(err)
			}
			return c
		},
	},
}

func forEachUDPConn(t *testing.T, fn func(t *testing.T, impl udpConnImpl, d *Device, listener net.PacketConn, client net.Conn)) {
	for _, impl := range udpConnImpls {
		t.Run(impl.name, func(t *testing.T) {
			d := ingressDevice(t)
			ap := netip.AddrPortFrom(accountingLocal, accountingPort)
			listener := impl.listen(t, d, ap)
			t.Cleanup(func() { listener.Close() })
			client := impl.dial(t, d, ap)
			t.Cleanup(func() { client.Close() })
			fn(t, impl, d, listener, client)
		})
	}
}

func requireTimeoutOpError(t *testing.T, err error, op string) {
	t.Helper()
	var oe *net.OpError
	if !errors.As(err, &oe) || oe.Op != op || oe.Net != "udp" || !oe.Timeout() || oe.Err.Error() != "i/o timeout" {
		t.Fatalf("%s error = %#v, want a udp *net.OpError timing out with i/o timeout", op, err)
	}
}

func TestUDPConnCompatDeadlines(t *testing.T) {
	forEachUDPConn(t, func(t *testing.T, _ udpConnImpl, _ *Device, listener net.PacketConn, client net.Conn) {
		if err := listener.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		_, _, err := listener.ReadFrom(make([]byte, 8))
		requireTimeoutOpError(t, err, "read")
		var oe *net.OpError
		errors.As(err, &oe)
		if oe.Source == nil || oe.Source.String() != listener.LocalAddr().String() {
			t.Fatalf("read timeout Source = %v, want %v", oe.Source, listener.LocalAddr())
		}
		if err := listener.SetReadDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		if err := client.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		_, err = client.Write([]byte("late"))
		requireTimeoutOpError(t, err, "write")
		if err := client.SetDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		if n, err := client.Write([]byte("ok")); err != nil || n != 2 {
			t.Fatalf("Write after clearing = %d/%v", n, err)
		}
		if n, _, err := listener.ReadFrom(make([]byte, 8)); err != nil || n != 2 {
			t.Fatalf("ReadFrom after clearing = %d/%v", n, err)
		}
	})
}

func TestUDPConnCompatShortReadAndAddresses(t *testing.T) {
	forEachUDPConn(t, func(t *testing.T, _ udpConnImpl, _ *Device, listener net.PacketConn, client net.Conn) {
		for _, p := range []string{"abcdef", "", "next"} {
			if _, err := client.Write([]byte(p)); err != nil {
				t.Fatal(err)
			}
		}
		b := make([]byte, 3)
		n, from, err := listener.ReadFrom(b)
		if err != nil || n != 3 || string(b) != "abc" {
			t.Fatalf("short ReadFrom = %d/%q/%v", n, b[:n], err)
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok || len(ua.IP) != 4 || ua.String() != client.LocalAddr().String() {
			t.Fatalf("ReadFrom address = %#v, want the 4-byte %v", from, client.LocalAddr())
		}
		if n, _, err := listener.ReadFrom(b); err != nil || n != 0 {
			t.Fatalf("empty datagram = %d/%v", n, err)
		}
		if n, _, err := listener.ReadFrom(b); err != nil || string(b[:n]) != "nex" {
			t.Fatalf("next datagram after a short read = %q/%v", b[:n], err)
		}
		if _, ok := listener.LocalAddr().(*net.UDPAddr); !ok {
			t.Fatalf("LocalAddr = %T", listener.LocalAddr())
		}
		if got := client.RemoteAddr().String(); got != listener.LocalAddr().String() {
			t.Fatalf("RemoteAddr = %s, want %s", got, listener.LocalAddr())
		}
		if n, err := listener.WriteTo([]byte("back"), from); err != nil || n != 4 {
			t.Fatalf("WriteTo the source = %d/%v", n, err)
		}
		if n, err := client.Read(b); err != nil || string(b[:n]) != "bac" {
			t.Fatalf("reply = %q/%v", b[:n], err)
		}
	})
}

// A connected socket whose peer answered Port Unreachable reads the same
// error text from both.
func TestUDPConnCompatRefusedPeer(t *testing.T) {
	for _, impl := range udpConnImpls {
		t.Run(impl.name, func(t *testing.T) {
			d := ingressDevice(t)
			c := impl.dial(t, d, netip.AddrPortFrom(accountingLocal, accountingPort+5))
			defer c.Close()
			if _, err := c.Write([]byte("nobody")); err != nil {
				t.Fatal(err)
			}
			if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			_, err := c.Read(make([]byte, 8))
			var oe *net.OpError
			if !errors.As(err, &oe) || oe.Op != "read" || oe.Net != "udp" || oe.Err.Error() != "connection was refused" {
				t.Fatalf("Read after Port Unreachable = %#v", err)
			}
		})
	}
}

// Close releases a blocked Read in both. The error differs on purpose:
// gonet reports io.EOF from the closed endpoint, the Device's connection
// reports net.ErrClosed, as a closed net.UDPConn does. The relay treats any
// error from a Read as the end of that reader.
func TestUDPConnCompatClose(t *testing.T) {
	forEachUDPConn(t, func(t *testing.T, impl udpConnImpl, _ *Device, listener net.PacketConn, client net.Conn) {
		done := make(chan error, 1)
		go func() { _, _, err := listener.ReadFrom(make([]byte, 8)); done <- err }()
		time.Sleep(10 * time.Millisecond)
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		var err error
		select {
		case err = <-done:
		case <-time.After(time.Second):
			t.Fatal("Close did not release a blocked ReadFrom")
		}
		want := net.ErrClosed
		if impl.name == "gonet" {
			want = io.EOF
		}
		if !errors.Is(err, want) {
			t.Fatalf("blocked ReadFrom after Close = %v, want %v", err, want)
		}
		if _, _, err := listener.ReadFrom(make([]byte, 8)); err == nil {
			t.Fatal("ReadFrom after Close returned no error")
		}
		if _, err := listener.WriteTo([]byte("x"), client.LocalAddr()); err == nil {
			t.Fatal("WriteTo after Close returned no error")
		}
		if err := listener.Close(); err != nil {
			t.Fatalf("second Close = %v", err)
		}
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write([]byte("x")); err == nil {
			t.Fatal("Write after Close returned no error")
		}
	})
}
