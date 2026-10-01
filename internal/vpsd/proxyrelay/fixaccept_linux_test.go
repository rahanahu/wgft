//go:build linux

package proxyrelay

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/rahanahu/wgft/internal/netpipe"
)

// 試験が使う floor の実効の値と窓の上限。Linux は SO_RCVBUF の要求の 2 倍を割り当てる。
const (
	acceptFloor  = 2 * netpipe.KernelRecvFloor
	acceptWindow = netpipe.KernelBoostWindow
)

// acceptOrder は、accept のループが通った段を順に記録する。admitRcvbuf と admitClamp は、Admission
// の時点の公開側のソケットの SO_RCVBUF と TCP_WINDOW_CLAMP である。
type acceptOrder struct {
	mu          sync.Mutex
	events      []string
	last        net.Conn
	admitRcvbuf int
	admitClamp  int
	logs        []string
}

func (o *acceptOrder) add(e string) {
	o.mu.Lock()
	o.events = append(o.events, e)
	o.mu.Unlock()
}

func (o *acceptOrder) snapshot() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.events...)
}

func (o *acceptOrder) logged(sub string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, l := range o.logs {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

// sockOpt は c のソケットの整数の option を読む。accept のループの goroutine からも呼ぶので、
// 失敗は -1 で返す。
func sockOpt(c net.Conn, level, opt int) int {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return -1
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return -1
	}
	n := -1
	rc.Control(func(fd uintptr) {
		if v, err := unix.GetsockoptInt(int(fd), level, opt); err == nil {
			n = v
		}
	})
	return n
}

// rmemAlloc は SO_MEMINFO の受信のメモリ(SK_MEMINFO_RMEM_ALLOC)を読む。読めなければ -1。
func rmemAlloc(c net.Conn) int {
	rc, err := c.(syscall.Conn).SyscallConn()
	if err != nil {
		return -1
	}
	n := -1
	rc.Control(func(fd uintptr) {
		var m [9]uint32
		l := uint32(unsafe.Sizeof(m))
		_, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.SOL_SOCKET, unix.SO_MEMINFO,
			uintptr(unsafe.Pointer(&m[0])), uintptr(unsafe.Pointer(&l)), 0)
		if e == 0 {
			n = int(m[0])
		}
	})
	return n
}

// raiseRecvBuf は c の受信のバッファを boost の大きさに広げ、窓の上限も広げる。
func raiseRecvBuf(t *testing.T, c net.Conn) {
	rc, err := c.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Error(err)
		return
	}
	rc.Control(func(fd uintptr) {
		if unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, netpipe.KernelRecvBoost) != nil {
			unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, netpipe.KernelRecvBoost)
		}
		unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP, netpipe.KernelBoostWindow)
	})
}

type orderListener struct {
	net.Listener
	o *acceptOrder
}

func (l *orderListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.o.mu.Lock()
		l.o.events = append(l.o.events, "accept")
		l.o.last = c
		l.o.mu.Unlock()
	}
	return c, err
}

// startOrderProxy は、ユーザー空間モードの vpsd と同じ形の中継(FloorAtAccept)を、Admission と
// エージェントへの dial を記録する形で立てる。fix は accept の直後の固定と確かめ(fixAtAccept)の
// 代わりに呼ばれる。戻り値のアドレスに繋げば、本物の accept のループ(serve)を通る。
func startOrderProxy(t *testing.T, floorAtAccept bool, fix func(net.Conn) bool) (*acceptOrder, string) {
	t.Helper()
	o := &acceptOrder{}
	saved := fixAtAccept
	fixAtAccept = func(c net.Conn) bool {
		o.add("fix")
		return fix(c)
	}
	t.Cleanup(func() { fixAtAccept = saved })
	agent, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { agent.Close() })
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
	logf := testLogf(t)
	m := New(Options{
		Listen: func(uint16) (net.Listener, error) { return &orderListener{Listener: raw, o: o}, nil },
		Dial: func(string) (net.Conn, error) {
			o.add("dial")
			return net.Dial("tcp", agent.Addr().String())
		},
		FloorAtAccept: floorAtAccept,
		Logf: func(format string, args ...any) {
			o.mu.Lock()
			o.logs = append(o.logs, fmt.Sprintf(format, args...))
			o.mu.Unlock()
			logf(format, args...)
		},
		Admit: func(string, netip.Addr) (func(), bool) {
			o.mu.Lock()
			o.events = append(o.events, "admit")
			if o.last != nil {
				o.admitRcvbuf = sockOpt(o.last, unix.SOL_SOCKET, unix.SO_RCVBUF)
				o.admitClamp = sockOpt(o.last, unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP)
			}
			o.mu.Unlock()
			return func() {}, true
		},
	})
	t.Cleanup(m.Close)
	m.Apply([]Rule{rule(false, nil, nil)})
	return o, raw.Addr().String()
}

func dialOrderProxy(t *testing.T, addr string) *net.TCPConn {
	t.Helper()
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c.(*net.TCPConn)
}

func equalEvents(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func waitEvents(t *testing.T, o *acceptOrder, want ...string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !equalEvents(o.snapshot(), want...) {
		if time.Now().After(deadline) {
			t.Fatalf("events = %v, want %v", o.snapshot(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// ユーザー空間モードの accept のループは、accept した公開側のソケットを floor に固定して確かめてから
// Admission を呼び、その後にエージェントへ dial する。Admission の時点で、ソケットはすでに floor に
// 固定されている。
func TestProxyAcceptLocksTheFloorBeforeAdmission(t *testing.T) {
	o, addr := startOrderProxy(t, true, netpipe.FixAtAccept)
	c := dialOrderProxy(t, addr)
	c.Write([]byte("x"))
	waitEvents(t, o, "accept", "fix", "admit", "dial")
	o.mu.Lock()
	rcvbuf, clamp := o.admitRcvbuf, o.admitClamp
	o.mu.Unlock()
	if rcvbuf != acceptFloor {
		t.Fatalf("public SO_RCVBUF at Admission = %d, want the floor %d", rcvbuf, acceptFloor)
	}
	if clamp != acceptWindow {
		t.Fatalf("public TCP_WINDOW_CLAMP at Admission = %d, want %d", clamp, acceptWindow)
	}
}

// カーネルモード(FloorAtAccept が偽)の accept のループは、固定も確かめもしない。組の両側が
// カーネルのソケットで、後から枠に合わせることも無いためである。
func TestProxyAcceptSkipsTheFloorInKernelMode(t *testing.T) {
	o, addr := startOrderProxy(t, false, func(net.Conn) bool { return false })
	c := dialOrderProxy(t, addr)
	c.Write([]byte("x"))
	waitEvents(t, o, "accept", "admit", "dial")
}

// accept の直後の固定と確かめが通さない接続は、RST で切り、Admission にもエージェントへの dial にも
// 進めない。場合の作り方は relay の TestAcceptResetsWhenTheFloorFails と同じである。
func TestProxyAcceptResetsWhenTheFloorFails(t *testing.T) {
	for _, tc := range []struct {
		name string
		fix  func(t *testing.T, client chan<- struct{}) func(net.Conn) bool
		data bool
	}{
		{
			name: "receive memory above the floor",
			data: true,
			fix: func(t *testing.T, client chan<- struct{}) func(net.Conn) bool {
				return func(c net.Conn) bool {
					raiseRecvBuf(t, c)
					close(client)
					deadline := time.Now().Add(5 * time.Second)
					for rmemAlloc(c) <= acceptFloor && time.Now().Before(deadline) {
						time.Sleep(10 * time.Millisecond)
					}
					if n := rmemAlloc(c); n <= acceptFloor {
						t.Errorf("receive memory before the check = %d, want above the floor %d", n, acceptFloor)
					}
					return netpipe.FixAtAccept(c)
				}
			},
		},
		{
			name: "receive buffer cannot be locked",
			fix: func(*testing.T, chan<- struct{}) func(net.Conn) bool {
				return func(net.Conn) bool { return false }
			},
		},
		{
			name: "receive memory cannot be read",
			fix: func(*testing.T, chan<- struct{}) func(net.Conn) bool {
				return func(c net.Conn) bool {
					// 固定は通り、読み取りだけが失敗した形
					rc, err := c.(syscall.Conn).SyscallConn()
					if err == nil {
						rc.Control(func(fd uintptr) {
							unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, netpipe.KernelRecvFloor)
						})
					}
					return false
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := make(chan struct{})
			o, addr := startOrderProxy(t, true, tc.fix(t, client))
			// 中継がすぐに切ると、クライアントの connect がすでに RST を受け取っていることがある
			c, err := net.Dial("tcp4", addr)
			if err == nil {
				t.Cleanup(func() { c.Close() })
				err = clientReset(c, tc.data, client)
			}
			if !errors.Is(err, syscall.ECONNRESET) {
				t.Fatalf("client after the refusal: %v, want a reset", err)
			}
			// RST の後に Admission か dial に進んでいないこと
			time.Sleep(100 * time.Millisecond)
			if got := o.snapshot(); !equalEvents(got, "accept", "fix") {
				t.Fatalf("events = %v, want [accept fix]: the refused connection reached Admission or dial", got)
			}
			if !o.logged("reset a new connection before it was counted") {
				t.Fatal("no log line for the reset")
			}
		})
	}
}

// clientReset は、中継が切った接続でクライアントが受け取った誤りを返す。RST の誤りは、書き込みと
// 読み取りのうち先に気づいた方が受け取る。data なら client が閉じた後に 1 MiB を送る。受信の
// バッファを広げる前に送ると、握手の時点の窓で止まるためである。
func clientReset(c net.Conn, data bool, client <-chan struct{}) error {
	wrote := make(chan error, 1)
	if data {
		go func() {
			<-client
			_, err := c.Write(make([]byte, 1<<20))
			wrote <- err
		}()
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := c.Read(make([]byte, 1))
	if data && errors.Is(err, io.EOF) {
		select {
		case err = <-wrote:
		case <-time.After(5 * time.Second):
		}
	}
	return err
}
