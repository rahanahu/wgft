//go:build linux

package relay

import (
	"io"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rahanahu/wgft/internal/netpipe"
	"github.com/rahanahu/wgft/proto"
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

// sinkTarget は読んで捨てるだけの宛先。
func sinkTarget(t *testing.T) string {
	t.Helper()
	srv, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	go func() {
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(io.Discard, c); c.Close() }()
		}
	}()
	return srv.Addr().String()
}

// boostPeer は vpsd の netstack の接続(nettun.TCPConn)を模す。枠の知らせを試験が起こす。
type boostPeer struct {
	net.Conn
	mu sync.Mutex
	f  func(bool) bool
}

func (b *boostPeer) OnBoost(f func(bool) bool) {
	b.mu.Lock()
	b.f = f
	b.mu.Unlock()
	f(false)
}

func (b *boostPeer) hook() func(bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.f
}

// acceptSpy は accept した接続を試験に渡す待ち受け。wrap なら、接続を boostPeer に包んで
// エージェントの netstack の待ち受けを模す。
type acceptSpy struct {
	net.Listener
	got  chan net.Conn
	wrap bool
}

func (a *acceptSpy) Accept() (net.Conn, error) {
	c, err := a.Listener.Accept()
	if err != nil {
		return c, err
	}
	if a.wrap {
		c = &boostPeer{Conn: c}
	}
	a.got <- c
	return c, nil
}

type spyNet struct {
	*loopback
	got  chan net.Conn
	wrap bool
}

func (n spyNet) ListenTCP(port uint16) (net.Listener, error) {
	l, err := n.loopback.ListenTCP(port)
	if err != nil {
		return nil, err
	}
	return &acceptSpy{Listener: l, got: n.got, wrap: n.wrap}, nil
}

// vpsd の形(公開側がカーネルのソケット、宛先への接続が netstack の接続)では、公開側の受信のバッファが
// 宛先への接続の枠に合わせて固定し直される。
func TestPublicSocketFollowsPeerBoost(t *testing.T) {
	target := sinkTarget(t)
	lb := &loopback{}
	port := reserveTCP(t, lb)
	sn := spyNet{loopback: lb, got: make(chan net.Conn, 1)}
	// 待ち受けを開いたときの宛先の試し接続も Dial を通るので、中継が張った接続は後から来る
	peers := make(chan *boostPeer, 4)
	m := New(sn, Options{
		Logf: testLogf(t),
		Dial: func(network, addr string) (net.Conn, error) {
			c, err := net.Dial(network, addr)
			if err != nil {
				return nil, err
			}
			p := &boostPeer{Conn: c}
			peers <- p
			return p, nil
		},
	})
	defer m.Close()
	m.Apply(map[Key]Desired{{proto.TCP, port}: {target, "r1"}})
	c, err := net.DialTCP("tcp4", nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("x"))
	var pub net.Conn
	var peer *boostPeer
	select {
	case pub = <-sn.got:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not accept")
	}
	var f func(bool) bool
	deadline := time.After(3 * time.Second)
	for f == nil {
		select {
		case peer = <-peers:
		case <-deadline:
			t.Fatal("the relay never linked the public socket to the peer's boost")
		}
		for i := 0; i < 100 && peer.hook() == nil; i++ {
			time.Sleep(5 * time.Millisecond)
		}
		f = peer.hook()
	}
	if got := rcvBufOf(t, pub); got != 2*netpipe.KernelRecvFloor {
		t.Fatalf("public SO_RCVBUF at the floor = %d, want %d", got, 2*netpipe.KernelRecvFloor)
	}
	f(true)
	if got := rcvBufOf(t, pub); got <= 2*netpipe.KernelRecvFloor {
		t.Fatalf("public SO_RCVBUF while the peer holds a slot = %d, want above %d", got, 2*netpipe.KernelRecvFloor)
	}
	f(false)
	if got := rcvBufOf(t, pub); got != 2*netpipe.KernelRecvFloor {
		t.Fatalf("public SO_RCVBUF after the slot went back = %d, want %d", got, 2*netpipe.KernelRecvFloor)
	}
}

// エージェントの形(待ち受けが netstack の接続、宛先への接続がカーネルのソケット)では、宛先へ dial した
// ソケットの受信のバッファが、待ち受けの側の netstack の接続の枠に合わせて固定し直される。
func TestTargetSocketFollowsPeerBoost(t *testing.T) {
	target := sinkTarget(t)
	lb := &loopback{}
	port := reserveTCP(t, lb)
	sn := spyNet{loopback: lb, got: make(chan net.Conn, 1), wrap: true}
	// 待ち受けを開いたときの宛先の試し接続も Dial を通るので、最後に dial した接続が中継のもの
	var mu sync.Mutex
	var dialed []net.Conn
	m := New(sn, Options{
		Logf: testLogf(t),
		Dial: func(network, addr string) (net.Conn, error) {
			c, err := net.Dial(network, addr)
			if err == nil {
				mu.Lock()
				dialed = append(dialed, c)
				mu.Unlock()
			}
			return c, err
		},
	})
	defer m.Close()
	m.Apply(map[Key]Desired{{proto.TCP, port}: {target, "r1"}})
	c, err := net.DialTCP("tcp4", nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("x"))
	var peer *boostPeer
	select {
	case pc := <-sn.got:
		peer = pc.(*boostPeer)
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not accept")
	}
	for i := 0; i < 600 && peer.hook() == nil; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	f := peer.hook()
	if f == nil {
		t.Fatal("the relay never linked the target socket to the peer's boost")
	}
	mu.Lock()
	tgt := dialed[len(dialed)-1]
	mu.Unlock()
	if got := rcvBufOf(t, tgt); got != 2*netpipe.KernelRecvFloor {
		t.Fatalf("target SO_RCVBUF at the floor = %d, want %d", got, 2*netpipe.KernelRecvFloor)
	}
	f(true)
	if got := rcvBufOf(t, tgt); got <= 2*netpipe.KernelRecvFloor {
		t.Fatalf("target SO_RCVBUF while the peer holds a slot = %d, want above %d", got, 2*netpipe.KernelRecvFloor)
	}
	f(false)
	if got := rcvBufOf(t, tgt); got != 2*netpipe.KernelRecvFloor {
		t.Fatalf("target SO_RCVBUF after the slot went back = %d, want %d", got, 2*netpipe.KernelRecvFloor)
	}
}
