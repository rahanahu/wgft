//go:build linux

package vpsd

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// tailnetSource:Tailscale の IPv4 と IPv6 の帯の内側だけを通す。境界の両側、IPv4 を写した IPv6 の形、
// TCP 以外の型のアドレスを確かめる。
func TestTailnetSource(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"100.64.0.0", true},
		{"100.64.0.1", true},
		{"100.100.1.1", true},
		{"100.127.255.255", true},
		{"100.63.255.255", false},
		{"100.128.0.0", false},
		{"198.51.100.2", false},
		{"10.200.0.2", false},
		{"127.0.0.1", false},
		{"::ffff:100.64.0.1", true},
		{"::ffff:100.127.255.255", true},
		{"::ffff:100.128.0.0", false},
		{"::ffff:198.51.100.2", false},
		{"::ffff:127.0.0.1", false},
		{"fd7a:115c:a1e0::", true},
		{"fd7a:115c:a1e0::1", true},
		{"fd7a:115c:a1e0:ffff:ffff:ffff:ffff:ffff", true},
		{"fd7a:115c:a1df:ffff:ffff:ffff:ffff:ffff", false},
		{"fd7a:115c:a1e1::", false},
		{"2001:db8::1", false},
		{"::1", false},
		// IPv4 の帯の値を IPv6 の下位に置いただけの形は、写した形ではないので通さない
		{"::100.64.0.1", false},
		{"64:ff9b::100.64.0.1", false},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("bad test address %q", c.ip)
		}
		if got := tailnetSource(&net.TCPAddr{IP: ip, Port: 40000}); got != c.want {
			t.Errorf("tailnetSource(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
	// 4 バイトの形の IPv4 も同じに扱う
	if !tailnetSource(&net.TCPAddr{IP: net.IPv4(100, 64, 0, 1).To4()}) {
		t.Errorf("4-byte 100.64.0.1 should be a tailnet source")
	}
	for _, a := range []net.Addr{
		&net.UnixAddr{Name: "/run/wgft/admin.sock", Net: "unix"},
		&net.TCPAddr{},
		nil,
	} {
		if tailnetSource(a) {
			t.Errorf("tailnetSource(%#v) = true, want false", a)
		}
	}
}

// fakeConn は RemoteAddr だけを差し替えた net.Conn。
type fakeConn struct {
	net.Conn
	remote net.Addr
}

func (c fakeConn) RemoteAddr() net.Addr { return c.remote }

// fakeListener は用意した接続を順に返し、尽きたら net.ErrClosed を返す。
type fakeListener struct{ conns []net.Conn }

func (l *fakeListener) Accept() (net.Conn, error) {
	if len(l.conns) == 0 {
		return nil, net.ErrClosed
	}
	c := l.conns[0]
	l.conns = l.conns[1:]
	return c, nil
}
func (l *fakeListener) Close() error   { return nil }
func (l *fakeListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(100, 100, 1, 1), Port: 8686} }

// tailnetListener:tailnet の帯に無い接続元の接続は Accept から返さずに閉じ、帯の内側の接続だけを返す。
func TestTailnetListenerClosesNonTailnet(t *testing.T) {
	mk := func(ip string) (fakeConn, net.Conn) {
		a, b := net.Pipe()
		return fakeConn{Conn: a, remote: &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000}}, b
	}
	out1, peer1 := mk("198.51.100.2")
	out2, peer2 := mk("::ffff:203.0.113.9")
	in1, peer3 := mk("100.100.2.2")
	in2, peer4 := mk("fd7a:115c:a1e0::2")
	defer peer3.Close()
	defer peer4.Close()
	ln := &tailnetListener{Listener: &fakeListener{conns: []net.Conn{out1, out2, in1, in2}}}

	for i, want := range []net.Conn{in1, in2} {
		c, err := ln.Accept()
		if err != nil {
			t.Fatalf("Accept #%d: %v", i, err)
		}
		if c != want {
			t.Fatalf("Accept #%d returned %v, want the connection from %v", i, c.RemoteAddr(), want.RemoteAddr())
		}
	}
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after the last connection: err = %v, want net.ErrClosed", err)
	}
	// 閉じられた接続の相手側は EOF を読む
	for i, p := range []net.Conn{peer1, peer2} {
		p.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := p.Read(make([]byte, 1)); err != io.EOF {
			t.Errorf("rejected connection #%d: peer read err = %v, want io.EOF", i, err)
		}
	}
	if !ln.logged.Load() {
		t.Errorf("the first rejection should have been logged")
	}
}

// listenTailnet:アドレスを持つインタフェースに SO_BINDTODEVICE で縛り、帯の外の接続元は HTTP を読まずに
// 閉じる。ホストでは lo の 127.0.0.1 で確かめる。127.0.0.1 は tailnet の帯に無いので、実際の接続が閉じられる。
func TestListenTailnetBindsToDevice(t *testing.T) {
	ln, iface, err := listenTailnet(context.Background(), "127.0.0.1", "0")
	if err != nil {
		t.Fatalf("listenTailnet: %v", err)
	}
	defer ln.Close()
	if iface != "lo" {
		t.Fatalf("iface = %q, want lo", iface)
	}
	tl, ok := ln.(*tailnetListener)
	if !ok {
		t.Fatalf("listener is %T, want *tailnetListener", ln)
	}
	rc, err := tl.Listener.(*net.TCPListener).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var dev string
	var gerr error
	if err := rc.Control(func(fd uintptr) {
		dev, gerr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	}); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatalf("getsockopt SO_BINDTODEVICE: %v", gerr)
	}
	if dev != "lo" {
		t.Fatalf("SO_BINDTODEVICE = %q, want lo", dev)
	}

	accepted := make(chan struct{})
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
			close(accepted)
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	c.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := c.Read(make([]byte, 64)); n != 0 || err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("connection from 127.0.0.1: read n=%d err=%v, want the connection closed", n, err)
	}
	select {
	case <-accepted:
		t.Fatalf("Accept returned a connection from 127.0.0.1")
	default:
	}
}

// listenTailnet:どのインタフェースにも無いアドレスでは待ち受けを開かない。bind の失敗に任せず自分で
// 拒むのは、net.ipv4.ip_nonlocal_bind が 1 のホストでは bind が通り、縛る先の無い待ち受けになるためである。
func TestListenTailnetNoInterface(t *testing.T) {
	if ifaceHolding(netip.MustParseAddr("192.0.2.123")) != "" {
		t.Skip("192.0.2.123 is assigned on this host")
	}
	ln, _, err := listenTailnet(context.Background(), "192.0.2.123", "0")
	if err == nil {
		ln.Close()
		t.Fatalf("listenTailnet on an address no interface holds: want an error")
	}
	if !strings.Contains(err.Error(), "no interface holds") {
		t.Fatalf("err = %v, want the missing-interface refusal", err)
	}
}

// bindToDevice:縛れないインタフェースでは待ち受けを開かない。
func TestBindToDeviceFailureRefusesListen(t *testing.T) {
	lc := net.ListenConfig{Control: bindToDevice("wgftnoexist0")}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err == nil {
		ln.Close()
		t.Fatalf("listen with SO_BINDTODEVICE to a missing interface: want an error")
	}
	if !errors.Is(err, unix.ENODEV) {
		t.Fatalf("err = %v, want ENODEV", err)
	}
}
