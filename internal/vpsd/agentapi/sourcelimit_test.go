package agentapi

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
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
	l := newSourceLimitListener(&fakeListener{conns: []*fakeConn{a1, a2, a3, b1, v6a, v6b, v6c, v6d}}, 2)

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
	go s.serveListener(ln, 64, perSource)
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
