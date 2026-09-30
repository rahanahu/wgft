//go:build linux

package netpipe

import (
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// sockInt は c のソケットの整数の option を読む。
func sockInt(t *testing.T, c net.Conn, level, opt int) int {
	t.Helper()
	sc, ok := c.(syscall.Conn)
	if !ok {
		t.Fatalf("no socket behind %T", c)
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var n int
	var gerr error
	if err := rc.Control(func(fd uintptr) { n, gerr = unix.GetsockoptInt(int(fd), level, opt) }); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatal(gerr)
	}
	return n
}

func rcvBuf(t *testing.T, c net.Conn) int { return sockInt(t, c, unix.SOL_SOCKET, unix.SO_RCVBUF) }

func procInt(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("cannot read %s: %v", path, err)
	}
	n, err := strconv.Atoi(strings.Fields(string(b))[0])
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// tcpPairLoopback は loopback の上の TCP の組を返す。accepted は待ち受けの側。
func tcpPairLoopback(t *testing.T, d *net.Dialer) (dialed, accepted *net.TCPConn) {
	t.Helper()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan *net.TCPConn, 1)
	go func() {
		c, err := ln.AcceptTCP()
		if err != nil {
			c = nil
		}
		ch <- c
	}()
	c, err := d.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s := <-ch
	if s == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { c.Close(); s.Close() })
	return c.(*net.TCPConn), s
}

// 設計文書 7 節の値。Linux は要求の 2 倍をソケットに割り当て、getsockopt もその値を返す。
const (
	floorEffective = 256 << 10
	boostEffective = 8 << 20
)

// fakeBoost は nettun.TCPConn.OnBoost を模す。登録の時点の状態で 1 回呼ぶ。
type fakeBoost struct {
	net.Conn
	mu sync.Mutex
	f  func(bool)
	n  int
}

func (b *fakeBoost) OnBoost(f func(bool)) {
	b.mu.Lock()
	b.f, b.n = f, b.n+1
	b.mu.Unlock()
	f(false)
}

func (b *fakeBoost) set(on bool) {
	b.mu.Lock()
	f := b.f
	b.mu.Unlock()
	f(on)
}

// カーネルのソケットは、組にした netstack の接続の枠に合わせて受信のバッファを固定し直す。窓の上限は
// KernelBoostWindow に置く。vpsd の形(accept したソケットが先)とエージェントの形(dial したソケットが
// 後)の両方で同じに働く。
func TestFollowBoostTracksTheSlot(t *testing.T) {
	for _, agent := range []bool{false, true} {
		dialed, accepted := tcpPairLoopback(t, &net.Dialer{Timeout: 5 * time.Second})
		peer := &fakeBoost{}
		if agent {
			FollowBoost(peer, dialed)
			followBoostCase(t, dialed, peer)
		} else {
			FollowBoost(accepted, peer)
			followBoostCase(t, accepted, peer)
		}
	}
}

func followBoostCase(t *testing.T, s net.Conn, peer *fakeBoost) {
	t.Helper()
	if peer.n != 1 {
		t.Fatalf("OnBoost registered %d times, want 1", peer.n)
	}
	if got := rcvBuf(t, s); got != floorEffective {
		t.Fatalf("SO_RCVBUF at the floor = %d, want %d", got, floorEffective)
	}
	clamp := func(when string) {
		t.Helper()
		if got := sockInt(t, s, unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP); got != 4<<20 {
			t.Fatalf("TCP_WINDOW_CLAMP %s = %d, want %d", when, got, 4<<20)
		}
	}
	clamp("at the floor")
	peer.set(true)
	// SO_RCVBUFFORCE が通れば要求の 2 倍になる。権限が無ければ SO_RCVBUF が net.core.rmem_max で
	// 切り詰める
	rmemMax := procInt(t, "/proc/sys/net/core/rmem_max")
	got := rcvBuf(t, s)
	if got != boostEffective && got != 2*min(rmemMax, boostEffective/2) {
		t.Fatalf("SO_RCVBUF while boosted = %d, want %d, or %d when capped by rmem_max", got, boostEffective, 2*min(rmemMax, boostEffective/2))
	}
	if got <= floorEffective {
		t.Fatalf("SO_RCVBUF while boosted = %d, not above the floor %d", got, floorEffective)
	}
	clamp("while boosted")
	peer.set(false)
	if got := rcvBuf(t, s); got != floorEffective {
		t.Fatalf("SO_RCVBUF after the slot went back = %d, want %d", got, floorEffective)
	}
	clamp("after the slot went back")
	// 閉じた後の知らせは何もしない(誤りも出さない)
	s.Close()
	peer.set(true)
}

// カーネルの TCP の接続でないか、相手が枠を知らせないときは何もしない。
func TestFollowBoostIgnoresOtherPairs(t *testing.T) {
	_, s := tcpPairLoopback(t, &net.Dialer{Timeout: 5 * time.Second})
	before := rcvBuf(t, s)
	FollowBoost(s, &net.TCPConn{}) // 枠を知らせない相手
	if got := rcvBuf(t, s); got != before {
		t.Fatalf("SO_RCVBUF changed to %d with a peer that reports no slot, want %d", got, before)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	peer := &fakeBoost{}
	FollowBoost(a, peer) // どちらもカーネルの TCP の接続でない
	FollowBoost(peer, a)
	if peer.n != 0 {
		t.Fatal("registered a boost hook for a connection that is not a kernel TCP socket")
	}
}
