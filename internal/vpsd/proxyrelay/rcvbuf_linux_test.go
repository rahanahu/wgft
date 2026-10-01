//go:build linux

package proxyrelay

import (
	"io"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rahanahu/wgft/internal/netpipe"
)

func rcvBufOf(t *testing.T, c net.Conn) int {
	t.Helper()
	rc, err := c.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var n int
	var gerr error
	if err := rc.Control(func(fd uintptr) { n, gerr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF) }); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatal(gerr)
	}
	return n
}

// boostPeer はユーザー空間モードのエージェントへの接続(nettun.TCPConn)を模す。nettun.TCPConn と
// 同じく、登録のときの 1 回を含めて、知らせの関数を錠の中で 1 つずつ呼ぶ。netpipe.FollowBoost の関数は
// この直列化を前提にする。登録は中継の goroutine で、試験の知らせは試験の goroutine で呼ぶので、錠の
// 外で呼ぶと 2 つが重なる。
type boostPeer struct {
	net.Conn
	mu sync.Mutex
	f  func(bool) bool
}

func (b *boostPeer) OnBoost(f func(bool) bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.f = f
	f(false)
}

// linked は、登録のときの呼び出しまで終えたかを返す。
func (b *boostPeer) linked() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.f != nil
}

// set は枠の知らせを錠の中で送る。
func (b *boostPeer) set(on bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.f(on)
}

type spyListener struct {
	net.Listener
	got chan net.Conn
}

func (s *spyListener) Accept() (net.Conn, error) {
	c, err := s.Listener.Accept()
	if err == nil {
		s.got <- c
	}
	return c, err
}

// ユーザー空間モードの形(エージェントへの接続が netstack の接続)では、公開側のカーネルのソケットの
// 受信のバッファが、その接続の枠に合わせて固定し直される(設計文書 7 節)。
func TestProxyPublicSocketFollowsPeerBoost(t *testing.T) {
	agent, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	go func() {
		for {
			c, err := agent.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(io.Discard, c); c.Close() }()
		}
	}()
	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	spy := &spyListener{Listener: raw, got: make(chan net.Conn, 1)}
	peers := make(chan *boostPeer, 1)
	m := New(Options{
		Listen: func(uint16) (net.Listener, error) { return spy, nil },
		Dial: func(string) (net.Conn, error) {
			c, err := net.Dial("tcp", agent.Addr().String())
			if err != nil {
				return nil, err
			}
			p := &boostPeer{Conn: c}
			peers <- p
			return p, nil
		},
		Logf: testLogf(t),
	})
	defer m.Close()
	m.Apply([]Rule{rule(false, nil, nil)})
	c, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("x"))
	var pub net.Conn
	var peer *boostPeer
	select {
	case pub = <-spy.got:
	case <-time.After(3 * time.Second):
		t.Fatal("the proxy relay did not accept")
	}
	select {
	case peer = <-peers:
	case <-time.After(3 * time.Second):
		t.Fatal("the proxy relay did not dial the agent")
	}
	deadline := time.Now().Add(3 * time.Second)
	for !peer.linked() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !peer.linked() {
		t.Fatal("the proxy relay never linked the public socket to the peer's boost")
	}
	if got := rcvBufOf(t, pub); got != 2*netpipe.KernelRecvFloor {
		t.Fatalf("public SO_RCVBUF at the floor = %d, want %d", got, 2*netpipe.KernelRecvFloor)
	}
	peer.set(true)
	if got := rcvBufOf(t, pub); got <= 2*netpipe.KernelRecvFloor {
		t.Fatalf("public SO_RCVBUF while the peer holds a slot = %d, want above %d", got, 2*netpipe.KernelRecvFloor)
	}
	peer.set(false)
	if got := rcvBufOf(t, pub); got != 2*netpipe.KernelRecvFloor {
		t.Fatalf("public SO_RCVBUF after the slot went back = %d, want %d", got, 2*netpipe.KernelRecvFloor)
	}
}
