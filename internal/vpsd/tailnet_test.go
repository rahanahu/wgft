//go:build linux

package vpsd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
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

// listenTailnet:アドレスを持つインタフェースの番号に SO_BINDTOIFINDEX で縛り、帯の外の接続元は HTTP を読まずに
// 閉じる。ホストでは lo の 127.0.0.1 で確かめる。127.0.0.1 は tailnet の帯に無いので、実際の接続が閉じられる。
func TestListenTailnetBindsToDevice(t *testing.T) {
	ln, iface, err := listenTailnet(context.Background(), "127.0.0.1", "0")
	if err != nil {
		t.Fatalf("listenTailnet: %v", err)
	}
	defer ln.Close()
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if iface.name != "lo" || iface.index != lo.Index {
		t.Fatalf("iface = %+v, want lo index %d", iface, lo.Index)
	}
	tl, ok := ln.(*tailnetListener)
	if !ok {
		t.Fatalf("listener is %T, want *tailnetListener", ln)
	}
	rc, err := tl.Listener.(*net.TCPListener).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var idx int
	var gerr error
	if err := rc.Control(func(fd uintptr) {
		idx, gerr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX)
	}); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatalf("getsockopt SO_BINDTOIFINDEX: %v", gerr)
	}
	if idx != lo.Index {
		t.Fatalf("SO_BINDTOIFINDEX = %d, want %d", idx, lo.Index)
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
	if _, ok := ifaceHolding(netip.MustParseAddr("192.0.2.123")); ok {
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

// bindToIfindex:番号 0 は縛りを外す意味になるので、setsockopt に渡さずに拒む。無い番号はカーネルが
// 拒まない(SO_BINDTODEVICE と違い、SO_BINDTOIFINDEX は番号の存在を確かめない)ので、縛った後に
// インタフェースが作り直された場合と同じく、tailnetAdmin の見張りが番号の食い違いとして拾う。
func TestBindToIfindexRefusesZero(t *testing.T) {
	lc := net.ListenConfig{Control: bindToIfindex(tailnetIface{name: "lo", index: 0})}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err == nil {
		ln.Close()
		t.Fatalf("listen with index 0: want an error")
	}
	if !strings.Contains(err.Error(), "invalid index 0") {
		t.Fatalf("err = %v, want the invalid-index refusal", err)
	}
	// setsockopt の誤りも待ち受けを開かない
	lc = net.ListenConfig{Control: bindToIfindex(tailnetIface{name: "bogus", index: -1})}
	ln, err = lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err == nil {
		ln.Close()
		t.Fatalf("listen with index -1: want an error")
	}
	if !errors.Is(err, unix.EINVAL) {
		t.Fatalf("err = %v, want EINVAL", err)
	}
}

// fakeLinks は tailnetLinks の差し替え。名前ごとの番号とアドレスを持つ。
type fakeLinks struct {
	index map[string]int
	addrs map[string][]netip.Addr
}

func (f *fakeLinks) state(name string, ip netip.Addr) (int, bool, bool) {
	idx, ok := f.index[name]
	if !ok {
		return 0, false, false
	}
	for _, a := range f.addrs[name] {
		if a == ip {
			return idx, true, true
		}
	}
	return idx, false, true
}

func (f *fakeLinks) candidate(string) bool {
	for name := range f.index {
		for _, a := range f.addrs[name] {
			if tailnetPrefixes[0].Contains(a) {
				return true
			}
		}
	}
	return false
}

// holderOf は ip を持つインタフェースを返す。
func (f *fakeLinks) holderOf(ip string) (tailnetIface, bool) {
	a := netip.MustParseAddr(ip)
	for name, idx := range f.index {
		for _, x := range f.addrs[name] {
			if x == a {
				return tailnetIface{name: name, index: idx}, true
			}
		}
	}
	return tailnetIface{}, false
}

// watchHarness は実際のソケットを使わずに tailnetAdmin を組み立てる。開いた待ち受けは fakeListener で、
// Serve は待ち受けが閉じるまで待つ。
type watchHarness struct {
	links   *fakeLinks
	tsIP    string // detect が返す tailnet の IP。空なら見つからない
	tsDNS   string
	opened  []string // listen の呼び出しの記録: "ip@name#index"
	hosts   []string
	errc    chan error
	detects int
	t       *tailnetAdmin
}

type blockingListener struct {
	closed chan struct{}
	once   atomic.Bool
}

func (l *blockingListener) Accept() (net.Conn, error) { <-l.closed; return nil, net.ErrClosed }
func (l *blockingListener) Close() error {
	if l.once.CompareAndSwap(false, true) {
		close(l.closed)
	}
	return nil
}
func (l *blockingListener) Addr() net.Addr { return &net.TCPAddr{} }

func newWatchHarness(t *testing.T) *watchHarness {
	h := &watchHarness{
		links: &fakeLinks{
			index: map[string]int{"tailscale0": 4, "eth0": 2},
			addrs: map[string][]netip.Addr{"tailscale0": {netip.MustParseAddr("100.100.1.1")}, "eth0": {netip.MustParseAddr("198.51.100.1")}},
		},
		tsIP:  "100.100.1.1",
		tsDNS: "vps.example.ts.net",
		errc:  make(chan error, 4),
	}
	h.t = &tailnetAdmin{
		port:  "8686",
		links: h.links,
		detect: func(context.Context) (string, string, string) {
			h.detects++
			return h.tsIP, h.tsDNS, "test"
		},
		listen: func(_ context.Context, ip, _ string) (net.Listener, tailnetIface, error) {
			iface, ok := h.links.holderOf(ip)
			if !ok {
				return nil, tailnetIface{}, errors.New("no interface holds the tailnet address " + ip)
			}
			h.opened = append(h.opened, fmt.Sprintf("%s@%s#%d", ip, iface.name, iface.index))
			return &blockingListener{closed: make(chan struct{})}, iface, nil
		},
		serve: func(ln net.Listener) error {
			_, err := ln.Accept()
			return err
		},
		setHosts: func(hs []string) { h.hosts = hs },
		errc:     h.errc,
	}
	ln, iface, err := h.t.listen(context.Background(), "100.100.1.1", "8686")
	if err != nil {
		t.Fatal(err)
	}
	h.opened = nil
	h.t.start(ln, netip.MustParseAddr("100.100.1.1"), iface)
	return h
}

func (h *watchHarness) noServeError(t *testing.T) {
	t.Helper()
	select {
	case err := <-h.errc:
		t.Fatalf("a deliberate close reached errc: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
}

// tailnetAdmin:インタフェースが同じ名前とアドレスで作り直されたら(番号が変わったら)、古い待ち受けを
// 閉じて新しい番号に縛り直す。自分で閉じた待ち受けの終わりは server を止めない。
func TestTailnetAdminReopensOnRecreate(t *testing.T) {
	h := newWatchHarness(t)
	old := h.t.ln
	h.t.check(context.Background())
	if h.t.ln != old || len(h.opened) != 0 || h.detects != 0 {
		t.Fatalf("unchanged interface: opened=%v detects=%d, want nothing", h.opened, h.detects)
	}
	h.links.index["tailscale0"] = 5
	h.t.check(context.Background())
	if h.t.ln == nil || h.t.ln == old {
		t.Fatalf("recreated interface: listener not reopened")
	}
	if !old.closing.Load() {
		t.Fatalf("the old listener was not closed")
	}
	if want := []string{"100.100.1.1@tailscale0#5"}; fmt.Sprint(h.opened) != fmt.Sprint(want) {
		t.Fatalf("opened = %v, want %v", h.opened, want)
	}
	if h.t.iface.index != 5 {
		t.Fatalf("remembered index = %d, want 5", h.t.iface.index)
	}
	h.noServeError(t)
}

// tailnetAdmin:インタフェースが消えている間は閉じたままで、戻ったら開き直す。
func TestTailnetAdminClosedWhileGone(t *testing.T) {
	h := newWatchHarness(t)
	old := h.t.ln
	delete(h.links.index, "tailscale0")
	delete(h.links.addrs, "tailscale0")
	h.t.check(context.Background())
	h.t.check(context.Background())
	if h.t.ln != nil || !old.closing.Load() {
		t.Fatalf("gone interface: listener still open")
	}
	if len(h.opened) != 0 || h.detects != 0 {
		t.Fatalf("gone interface: opened=%v detects=%d, want no attempt while nothing is a candidate", h.opened, h.detects)
	}
	h.links.index["tailscale0"] = 7
	h.links.addrs["tailscale0"] = []netip.Addr{netip.MustParseAddr("100.100.1.1")}
	h.t.check(context.Background())
	if h.t.ln == nil || fmt.Sprint(h.opened) != "[100.100.1.1@tailscale0#7]" {
		t.Fatalf("interface back: ln=%v opened=%v", h.t.ln, h.opened)
	}
	h.noServeError(t)
}

// tailnetAdmin:tailnet のアドレスが変わったら、新しいアドレスで開き直し、Host の許可を差し替える。
// 検出がまだ古いアドレスを返す間は、開けずに閉じたままでいる。
func TestTailnetAdminFollowsNewAddress(t *testing.T) {
	h := newWatchHarness(t)
	h.links.addrs["tailscale0"] = []netip.Addr{netip.MustParseAddr("100.101.0.9")}
	h.t.check(context.Background())
	if h.t.ln != nil {
		t.Fatalf("detect still reports the old address, which no interface holds: want closed")
	}
	h.tsIP, h.tsDNS = "100.101.0.9", "vps2.example.ts.net"
	h.t.check(context.Background())
	if h.t.ln == nil || fmt.Sprint(h.opened) != "[100.101.0.9@tailscale0#4]" {
		t.Fatalf("new address: ln=%v opened=%v", h.t.ln, h.opened)
	}
	if fmt.Sprint(h.hosts) != "[100.101.0.9 vps2.example.ts.net]" {
		t.Fatalf("hosts = %v, want the new address and name only", h.hosts)
	}
	if h.t.ip != netip.MustParseAddr("100.101.0.9") {
		t.Fatalf("remembered ip = %v", h.t.ip)
	}
}

// tailnetAdmin:見張りが閉じたのではない Serve の終わりは、従来どおり errc に届く。
func TestTailnetAdminUnexpectedServeEnd(t *testing.T) {
	h := newWatchHarness(t)
	h.t.ln.Listener.Close() // 見張りを通さずに閉じる
	select {
	case err := <-h.errc:
		if !strings.Contains(err.Error(), "admin API tailscale") {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("an unexpected Serve end did not reach errc")
	}
}

// tailnetAdmin:run は ctx の終わりで待ち受けを閉じ、その終わりを誤りにしない。
func TestTailnetAdminRunStops(t *testing.T) {
	h := newWatchHarness(t)
	h.t.interval = 10 * time.Millisecond
	ln := h.t.ln
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.t.run(ctx); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	if !ln.closing.Load() {
		t.Fatalf("run did not close the listener on ctx end")
	}
	h.noServeError(t)
}
