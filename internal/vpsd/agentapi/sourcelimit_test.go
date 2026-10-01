package agentapi

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// fakeAddr は任意の送信元を名乗る net.Addr である。
type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

// fakeConn は RemoteAddr だけを持つ接続で、閉じられたかを記録する。
type fakeConn struct {
	net.Conn
	remote fakeAddr
	mu     sync.Mutex
	closed bool
}

func (c *fakeConn) RemoteAddr() net.Addr { return c.remote }
func (c *fakeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}
func (c *fakeConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// fakeListener は用意した接続を順に返し、尽きたら誤りを返す。
type fakeListener struct {
	net.Listener
	conns []*fakeConn
}

var errNoMore = errors.New("no more connections")

func (l *fakeListener) Accept() (net.Conn, error) {
	if len(l.conns) == 0 {
		return nil, errNoMore
	}
	c := l.conns[0]
	l.conns = l.conns[1:]
	return c, nil
}

// perSourceOnly は、送信元の最初の段(IPv4 のアドレスか IPv6 の /64)の上限だけを持つ上限の組である。
// 全体の上限は届かない大きさにする。
func perSourceOnly(n int) preAuthLimits {
	return preAuthLimits{total: 1 << 20, tiers: []sourceTier{{v4Bits: 32, v6Bits: 64, max: n}}}
}

// acceptAll は l が返す接続をすべて受け取る(fakeListener が尽きるまで)。
func acceptAll(l net.Listener) []net.Conn {
	var got []net.Conn
	for {
		c, err := l.Accept()
		if err != nil {
			return got
		}
		got = append(got, c)
	}
}

// TestSourceLimitListenerCapsEachSource は、1 つの送信元の未認証の接続が上限に達すると、その送信元の
// 次の接続は閉じられて返されず、他の送信元の接続は返されることを確かめる(設計文書 11 節)。IPv6 は
// /64 ごとに数える。
// 変異の確認:Accept の上限の判定を外すと a3 が返されて落ちる。IPv6 の鍵を /64 でなく
// アドレスにすると v6c が返されて落ちる。
func TestSourceLimitListenerCapsEachSource(t *testing.T) {
	a1 := &fakeConn{remote: "192.0.2.1:1001"}
	a2 := &fakeConn{remote: "192.0.2.1:1002"}
	a3 := &fakeConn{remote: "192.0.2.1:1003"}
	b1 := &fakeConn{remote: "192.0.2.2:1001"}
	v6a := &fakeConn{remote: "[2001:db8:1:2::1]:1001"}
	v6b := &fakeConn{remote: "[2001:db8:1:2::ffff]:1002"}
	v6c := &fakeConn{remote: "[2001:db8:1:2:abcd::1]:1003"} // v6a、v6b と同じ /64
	v6d := &fakeConn{remote: "[2001:db8:1:3::1]:1001"}      // 別の /64
	l := newSourceLimitListener(&fakeListener{conns: []*fakeConn{a1, a2, a3, b1, v6a, v6b, v6c, v6d}}, perSourceOnly(2))

	var got []net.Conn
	for {
		c, err := l.Accept()
		if err != nil {
			break
		}
		got = append(got, c)
	}
	var remotes []string
	for _, c := range got {
		remotes = append(remotes, c.RemoteAddr().String())
	}
	want := []string{"192.0.2.1:1001", "192.0.2.1:1002", "192.0.2.2:1001", "[2001:db8:1:2::1]:1001", "[2001:db8:1:2::ffff]:1002", "[2001:db8:1:3::1]:1001"}
	if fmt.Sprint(remotes) != fmt.Sprint(want) {
		t.Fatalf("accepted %v, want %v", remotes, want)
	}
	if !a3.isClosed() || !v6c.isClosed() {
		t.Error("a connection over the source's cap was not closed")
	}
	if a1.isClosed() || a2.isClosed() || b1.isClosed() {
		t.Error("a connection within the cap was closed")
	}

	// 閉じれば枠が空き、同じ送信元の次の接続が返される。release と Close を重ねても二重に数えない
	sc := got[0].(*sourceConn)
	sc.release()
	sc.Close()
	sc.Close()
	if n := l.count("192.0.2.1"); n != 1 {
		t.Fatalf("after one conn released and closed, the source counts %d, want 1", n)
	}
	a4 := &fakeConn{remote: "192.0.2.1:1004"}
	a5 := &fakeConn{remote: "192.0.2.1:1005"}
	l.Listener = &fakeListener{conns: []*fakeConn{a4, a5}}
	if c, err := l.Accept(); err != nil || c.RemoteAddr().String() != "192.0.2.1:1004" {
		t.Fatalf("after a slot freed up, Accept = %v, %v; want the source's next conn", c, err)
	}
	if _, err := l.Accept(); !errors.Is(err, errNoMore) || !a5.isClosed() {
		t.Fatalf("the source is at its cap again, so its next conn must be closed; err = %v, closed = %v", err, a5.isClosed())
	}
	got[1].Close()
	got[2].Close()
	if n := l.count("192.0.2.1"); n != 1 {
		t.Errorf("source count = %d after closing, want 1 (the conn accepted after the slot freed)", n)
	}
	if n := l.count("192.0.2.2"); n != 0 {
		t.Errorf("a source with no conn left still counts %d", n)
	}
}

// TestAuthenticatedConnLeavesSourceCap は TLS の待ち受けの全体で、認証を通った接続(stream)は送信元の
// 未認証の接続の数から外れ、同じ送信元から上限までの未認証の接続を新たに受け付けられること、その上で
// 上限を超える接続は TLS のハンドシェイクの前に閉じられることを確かめる(設計文書 11 節)。同じ NAT の
// 後ろにいる多数のエージェントの stream が、この上限に縛られないことの確認である。
// 変異の確認:Authenticated の中の release を外すと、未認証の 2 本目のハンドシェイクが拒まれて落ちる。
// withSourceConn の TLS の接続を剥がす部分を外しても同じく落ちる。
func TestAuthenticatedConnLeavesSourceCap(t *testing.T) {
	const perSource = 2
	s, err := New(newTestStore(t), &fakeBackend{})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var hijacked []net.Conn
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range hijacked {
			c.Close()
		}
	})
	// stream に見立てたハンドラ:認証を通ったことを記し、接続を乗っ取って持ち続ける
	s.Handle("GET /hold", func(w http.ResponseWriter, r *http.Request) {
		s.Authenticated(r)
		w.WriteHeader(http.StatusSwitchingProtocols)
		c, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		mu.Lock()
		hijacked = append(hijacked, c)
		mu.Unlock()
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go s.serveListener(ln, 64, perSourceOnly(perSource))
	addr := ln.Addr().String()

	var clients []net.Conn
	t.Cleanup(func() {
		for _, c := range clients {
			c.Close()
		}
	})
	handshake := func() (*tls.Conn, error) {
		raw, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		clients = append(clients, raw)
		c := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
		c.SetDeadline(time.Now().Add(3 * time.Second))
		return c, c.Handshake()
	}

	// 上限の 2 倍の stream を張る。どれも認証を通るので、送信元の数には残らない
	for i := 0; i < 2*perSource; i++ {
		c, err := handshake()
		if err != nil {
			t.Fatalf("stream %d: handshake: %v", i, err)
		}
		fmt.Fprint(c, "GET /hold HTTP/1.1\r\nHost: x\r\n\r\n")
		br := make([]byte, 12)
		if _, err := c.Read(br); err != nil || string(br) != "HTTP/1.1 101" {
			t.Fatalf("stream %d: response %q, %v", i, br, err)
		}
	}
	// 未認証の接続は、stream とは別に上限まで受け付ける(ハンドシェイクだけして止まる)
	for i := 0; i < perSource; i++ {
		if _, err := handshake(); err != nil {
			t.Fatalf("unauthenticated conn %d within the cap: handshake: %v", i, err)
		}
	}
	// 上限を超えた接続は、ハンドシェイクの前に閉じられる
	if _, err := handshake(); err == nil {
		t.Fatal("a handshake over the source's cap of unauthenticated conns succeeded")
	}
}

// TestSourceLimitListenerCountsIPv6Prefixes は、IPv6 の送信元を /64 だけでなく /56 と /48 でも数え、
// どの段の上限に達しても、その段に入る次の接続を閉じることを確かめる(設計文書 11 節)。/56 を持つ
// 1 人が /64 を替えながら接続しても、/56 の上限より多くは持てない。IPv4 はアドレスだけで数え、
// IPv4 射影の IPv6 アドレスは IPv4 として数える。
// 変異の確認:keys の /56 と /48 の段を外すと v56c と v48c が返されて落ちる。remoteAddr の Unmap を
// 外すと mapped が別の送信元として返されて落ちる。release で段ごとの数を戻さないと最後の確認で落ちる。
func TestSourceLimitListenerCountsIPv6Prefixes(t *testing.T) {
	limits := preAuthLimits{total: 1 << 20, tiers: []sourceTier{
		{v4Bits: 32, v6Bits: 64, max: 2},
		{v6Bits: 56, max: 3},
		{v6Bits: 48, max: 4},
	}}
	conns := []*fakeConn{
		{remote: "[2001:db8:1:100::1]:1"}, // /64 A
		{remote: "[2001:db8:1:100::2]:2"}, // /64 A
		{remote: "[2001:db8:1:100::3]:3"}, // /64 A は上限 2 に達している
		{remote: "[2001:db8:1:101::1]:4"}, // 同じ /56 の別の /64:/56 は 3 本目
		{remote: "[2001:db8:1:102::1]:5"}, // 同じ /56 の 3 つ目の /64:/56 は上限 3 に達している
		{remote: "[2001:db8:1:200::1]:6"}, // 同じ /48 の別の /56:/48 は 4 本目
		{remote: "[2001:db8:1:300::1]:7"}, // 同じ /48 の 3 つ目の /56:/48 は上限 4 に達している
		{remote: "[2001:db8:2:100::1]:8"}, // 別の /48
		{remote: "192.0.2.1:9"},
		{remote: "192.0.2.2:10"}, // 同じ /24 でも IPv4 はアドレスごと
		{remote: "192.0.2.3:11"},
		{remote: "[::ffff:192.0.2.1]:12"}, // 192.0.2.1 と同じ送信元
		{remote: "[::ffff:192.0.2.1]:13"}, // 192.0.2.1 は上限 2 に達している
	}
	l := newSourceLimitListener(&fakeListener{conns: conns}, limits)
	got := acceptAll(l)
	var remotes []string
	for _, c := range got {
		remotes = append(remotes, c.RemoteAddr().String())
	}
	want := []string{
		"[2001:db8:1:100::1]:1", "[2001:db8:1:100::2]:2", "[2001:db8:1:101::1]:4", "[2001:db8:1:200::1]:6",
		"[2001:db8:2:100::1]:8", "192.0.2.1:9", "192.0.2.2:10", "192.0.2.3:11", "[::ffff:192.0.2.1]:12",
	}
	if fmt.Sprint(remotes) != fmt.Sprint(want) {
		t.Fatalf("accepted %v, want %v", remotes, want)
	}
	for _, i := range []int{2, 4, 6, 12} {
		if !conns[i].isClosed() {
			t.Errorf("%s is over a prefix's cap but was not closed", conns[i].remote)
		}
	}
	if n := l.count("2001:db8:1:100::/56"); n != 3 {
		t.Errorf("the /56 counts %d, want 3", n)
	}
	if n := l.count("2001:db8:1::/48"); n != 4 {
		t.Errorf("the /48 counts %d, want 4", n)
	}
	if n := l.count("192.0.2.1"); n != 2 {
		t.Errorf("192.0.2.1 counts %d, want 2 with its IPv4-mapped connection", n)
	}
	for _, c := range got {
		c.Close()
	}
	if n := l.totalCount(); n != 0 {
		t.Errorf("after closing every conn the total counts %d", n)
	}
	for _, key := range []string{"2001:db8:1:100::/64", "2001:db8:1:100::/56", "2001:db8:1::/48", "192.0.2.1"} {
		if n := l.count(key); n != 0 {
			t.Errorf("after closing every conn %s still counts %d", key, n)
		}
	}
}

// TestSourceLimitListenerCapsUnauthenticatedTotal は、未認証の接続が全体の上限に達すると、送信元に
// 関わらず次の接続を閉じ、1 本閉じれば次の接続を受け付けることを確かめる(設計文書 11 節)。
// 変異の確認:Accept の全体の上限の判定を外すと 4 本目が返されて落ちる。release で全体の数を
// 戻さないと、1 本閉じた後の接続が閉じられて落ちる。
func TestSourceLimitListenerCapsUnauthenticatedTotal(t *testing.T) {
	limits := preAuthLimits{total: 3, tiers: []sourceTier{{v4Bits: 32, v6Bits: 64, max: 16}}}
	c4 := &fakeConn{remote: "192.0.2.4:1"}
	l := newSourceLimitListener(&fakeListener{conns: []*fakeConn{
		{remote: "192.0.2.1:1"}, {remote: "192.0.2.2:1"}, {remote: "[2001:db8::1]:1"}, c4,
	}}, limits)
	got := acceptAll(l)
	if len(got) != 3 || !c4.isClosed() {
		t.Fatalf("accepted %d conns (want 3); the conn over the total cap closed = %v", len(got), c4.isClosed())
	}
	got[0].Close()
	c5 := &fakeConn{remote: "192.0.2.5:1"}
	l.Listener = &fakeListener{conns: []*fakeConn{c5}}
	if c, err := l.Accept(); err != nil || c.RemoteAddr().String() != "192.0.2.5:1" {
		t.Fatalf("after a slot freed up, Accept = %v, %v; want the next conn", c, err)
	}
}

// TestDefaultPreAuthLimitsBoundOneIPv6Block は、本番の上限で、1 つの IPv6 のブロックを持つ 1 人が
// アドレスを替えながら接続したときに持てる未認証の接続の数を確かめる(設計文書 11 節)。/56 からは
// 64 本、/48 からは 256 本までで、どちらも全体の上限を埋めず、別の送信元の接続は受け付けられる。
// 以前は /64 だけで数えたので、/56 から 256 × 16 本を持てた。
// 変異の確認:defaultPreAuthLimits から /56 か /48 の段を外すと本数が合わずに落ちる。
func TestDefaultPreAuthLimitsBoundOneIPv6Block(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prefix netip.Prefix
		want   int
	}{
		{"/56", netip.MustParsePrefix("2001:db8:0:100::/56"), maxPreAuthConnsPer56},
		{"/48", netip.MustParsePrefix("2001:db8:1::/48"), maxPreAuthConnsPer48},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// ブロックの中の /64 を替え、それぞれから /64 の上限まで接続する。/48 では、/56 の上限を
			// 埋められるだけの /64 を、ブロックの中のすべての /56 から使う
			var nets []int // ブロックの中の /64 の番号
			for i := 0; i < 256; i++ {
				if tc.name == "/56" {
					nets = append(nets, i)
					continue
				}
				for q := 0; q < maxPreAuthConnsPer56/maxPreAuthConnsPerSource; q++ {
					nets = append(nets, i<<8|q)
				}
			}
			var conns []*fakeConn
			base := tc.prefix.Addr().As16()
			for _, i := range nets {
				a := base
				n := (uint16(base[6])<<8 | uint16(base[7])) + uint16(i)
				a[6], a[7] = byte(n>>8), byte(n)
				if !tc.prefix.Contains(netip.AddrFrom16(a)) {
					t.Fatalf("test address %v is outside %v", netip.AddrFrom16(a), tc.prefix)
				}
				for j := 0; j < maxPreAuthConnsPerSource; j++ {
					a[15] = byte(j + 1)
					conns = append(conns, &fakeConn{remote: fakeAddr(netip.AddrPortFrom(netip.AddrFrom16(a), 1000).String())})
				}
			}
			other := &fakeConn{remote: "[2001:db8:ffff::1]:1"}
			l := newSourceLimitListener(&fakeListener{conns: append(conns, other)}, defaultPreAuthLimits)
			got := acceptAll(l)
			if len(got) != tc.want+1 {
				t.Fatalf("accepted %d conns from one %s and another source, want %d and 1", len(got)-1, tc.name, tc.want)
			}
			if got[len(got)-1].RemoteAddr().String() != "[2001:db8:ffff::1]:1" {
				t.Fatal("a source outside the block was refused")
			}
			if tc.want >= maxPreAuthConns {
				t.Fatalf("one %s can fill the total cap of unauthenticated conns", tc.name)
			}
		})
	}
}

// TestListenUnspecifiedHostIsDualStack は、既定の待ち受けのようにホストを 0.0.0.0 とした Listen が、
// IPv6 の接続も受け付けることを確かめる。Go は IPv6 が使えるホストでこのソケットを IPV6_V6ONLY を
// 外して開く。設計文書 11 節が、IPv6 の送信元をプレフィクスの段で数える前提である。IPv6 のループ
// バックが無いホストでは飛ばす。
func TestListenUnspecifiedHostIsDualStack(t *testing.T) {
	probe, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback on this host: %v", err)
	}
	probe.Close()
	s, err := New(newTestStore(t), &fakeBackend{})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := s.Listen("0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	c, err := net.DialTimeout("tcp6", net.JoinHostPort("::1", port), 2*time.Second)
	if err != nil {
		t.Fatalf("the listener for 0.0.0.0 did not accept an IPv6 connection: %v", err)
	}
	c.Close()
}

// TestPreAuthHandshakeDeadline は、本番の期限で、ClientHello を送らない接続が 5 秒の期限で閉じられる
// ことを確かめる(設計文書 11 節)。net/http はハンドシェイクの期限に ReadHeaderTimeout と
// ReadTimeout の小さい方を使う。
// 変異の確認:defaultTimeouts の ReadHeaderTimeout を 10 秒に戻すと、7 秒の予算で閉じられずに落ちる。
func TestPreAuthHandshakeDeadline(t *testing.T) {
	t.Parallel()
	s, err := New(newTestStore(t), &fakeBackend{})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go s.serveListener(ln, maxAgentConns, defaultPreAuthLimits)
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	took := expectClosedWithin(t, c, 7*time.Second)
	if took < 4*time.Second {
		t.Fatalf("closed after %s, before the 5 s handshake deadline", took)
	}
	// ハンドシェイクの後は ReadTimeout がリクエスト全体を抑える。未認証の接続が枠を持つ最長は、
	// 2 つの和の 15 秒である(設計文書 11 節。この和は実時間で確かめると長いので値で確かめる)
	if hold := defaultTimeouts.ReadHeaderTimeout + defaultTimeouts.ReadTimeout; hold != 15*time.Second {
		t.Errorf("an unauthenticated conn can hold its slot for %s, want 15s as the design states", hold)
	}
}

// TestDefaultPreAuthLimitsCountIPv4MappedAsIPv4 は、本番の上限で、IPv4 射影の IPv6 アドレスで届いた
// 多数の IPv4 の送信元を、IPv6 のプレフィクスの段でまとめずに、アドレスごとに数えることを確かめる。
// 既定の待ち受けは IPv6 のソケットなので、IPv4 の相手はこの形で届きうる。射影のまま /56 で数えると、
// すべての IPv4 の送信元が 1 つの /56 に入り、合わせて 64 本しか持てなくなる。
// 変異の確認:remoteAddr の文字列の経路の Unmap を外すと 65 個目の送信元から閉じられて落ちる。
// *net.TCPAddr の経路の Unmap を外すと、16 byte の形の IPv4 の鍵が合わずに落ちる。
func TestDefaultPreAuthLimitsCountIPv4MappedAsIPv4(t *testing.T) {
	// net.TCPAddr の IP は、IPv6 のソケットに届いた IPv4 の相手では 16 byte の形で入る
	l0 := newSourceLimitListener(nil, defaultPreAuthLimits)
	if got := l0.keys(&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1}); fmt.Sprint(got) != fmt.Sprint([]sourceKeyMax{{"192.0.2.1", maxPreAuthConnsPerSource}}) {
		t.Errorf("keys of a 16-byte IPv4 TCPAddr = %v, want the address alone", got)
	}

	var conns []*fakeConn
	for i := 0; i < 2*maxPreAuthConnsPer56; i++ {
		conns = append(conns, &fakeConn{remote: fakeAddr(fmt.Sprintf("[::ffff:198.51.%d.%d]:1000", i/200, i%200+1))})
	}
	l := newSourceLimitListener(&fakeListener{conns: conns}, defaultPreAuthLimits)
	if got := acceptAll(l); len(got) != len(conns) {
		t.Fatalf("accepted %d of %d IPv4 sources that arrived as IPv4-mapped addresses", len(got), len(conns))
	}
}

// count は key の段が今数えられている接続の数である。
func (l *sourceLimitListener) count(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.open[key]
}

// totalCount は全体で今数えられている接続の数である。
func (l *sourceLimitListener) totalCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total
}
