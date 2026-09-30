//go:build linux

package netpipe

import (
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

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
func sndBuf(t *testing.T, c net.Conn) int { return sockInt(t, c, unix.SOL_SOCKET, unix.SO_SNDBUF) }

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
	floorEffective     = 256 << 10
	boostEffective     = 8 << 20
	sendFloorEffective = 256 << 10
	sendBoostEffective = 4 << 20
)

// fakeBoost は nettun.TCPConn.OnBoost を模す。登録の時点の状態で 1 回呼ぶ。
type fakeBoost struct {
	net.Conn
	mu sync.Mutex
	f  func(bool) bool
	n  int
}

func (b *fakeBoost) OnBoost(f func(bool) bool) {
	b.mu.Lock()
	b.f, b.n = f, b.n+1
	b.mu.Unlock()
	f(false)
}

// set は枠の知らせを起こし、f の戻り値(floor に戻ってよいか)を返す。
func (b *fakeBoost) set(on bool) bool {
	b.mu.Lock()
	f := b.f
	b.mu.Unlock()
	return f(on)
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
	if got := sndBuf(t, s); got != sendFloorEffective {
		t.Fatalf("SO_SNDBUF at the floor = %d, want %d", got, sendFloorEffective)
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
	wmemMax := procInt(t, "/proc/sys/net/core/wmem_max")
	if got := sndBuf(t, s); got != sendBoostEffective && got != 2*min(wmemMax, sendBoostEffective/2) {
		t.Fatalf("SO_SNDBUF while boosted = %d, want %d, or %d when capped by wmem_max", got, sendBoostEffective, 2*min(wmemMax, sendBoostEffective/2))
	}
	clamp("while boosted")
	if !peer.set(false) {
		t.Fatal("an idle socket refused to go back to the floor")
	}
	if got := rcvBuf(t, s); got != floorEffective {
		t.Fatalf("SO_RCVBUF after the slot went back = %d, want %d", got, floorEffective)
	}
	if got := sndBuf(t, s); got != sendFloorEffective {
		t.Fatalf("SO_SNDBUF after the slot went back = %d, want %d", got, sendFloorEffective)
	}
	clamp("after the slot went back")
	// 閉じた後の知らせは何もせず(誤りも出さず)、floor に戻るのも止めない
	s.Close()
	peer.set(true)
	if !peer.set(false) {
		t.Fatal("a notice after close held the slot")
	}
}

// meminfo は c のソケットの SO_MEMINFO から、送信のキューのメモリと送信のバッファを読む。
func meminfo(t *testing.T, c net.Conn) (queued, sndbuf int) {
	t.Helper()
	rc, err := c.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var m [unix.SK_MEMINFO_VARS]uint32
	var e syscall.Errno
	rc.Control(func(fd uintptr) {
		l := uint32(unsafe.Sizeof(m))
		_, _, e = unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.SOL_SOCKET, unix.SO_MEMINFO,
			uintptr(unsafe.Pointer(&m)), uintptr(unsafe.Pointer(&l)), 0)
	})
	if e != 0 {
		t.Fatal(e)
	}
	return int(m[unix.SK_MEMINFO_WMEM_QUEUED]), int(m[unix.SK_MEMINFO_SNDBUF])
}

// fill は相手が読まない s に、書き込みが止まるまで書く。
func fill(t *testing.T, s net.Conn) {
	t.Helper()
	buf := make([]byte, 256<<10)
	for i := 0; i < 1000; i++ {
		s.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
		if _, err := s.Write(buf); err != nil {
			s.SetWriteDeadline(time.Time{})
			return
		}
	}
	t.Fatal("the socket never stopped accepting writes")
}

// smallReceiver は受信のバッファを小さく固定して接続する dialer。相手の送信のキューに溜まる量を、
// 相手の送信のバッファで決めるために使う。
var smallReceiver = &net.Dialer{Timeout: 5 * time.Second, Control: func(_, _ string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) { unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<10) })
}}

// 送信のキューが送信の floor を超えている間は floor に戻らず、送信と受信のバッファを boost に保つ。
// 相手が読んでキューが減れば戻る(設計文書 7 節「送信のキューと枠の返却」)。
func TestFollowBoostHoldsWhileSendQueueIsHigh(t *testing.T) {
	c, s := tcpPairLoopback(t, smallReceiver)
	peer := &fakeBoost{}
	FollowBoost(s, peer)
	peer.set(true)
	boostRcv, boostSnd := rcvBuf(t, s), sndBuf(t, s)
	if boostSnd <= sendFloorEffective {
		t.Fatalf("SO_SNDBUF while boosted = %d, not above the floor", boostSnd)
	}
	fill(t, s)
	if q, _ := meminfo(t, s); q <= sendFloorEffective {
		t.Fatalf("send queue after filling = %d, want above the floor %d", q, sendFloorEffective)
	}
	if peer.set(false) {
		t.Fatal("went back to the floor with the send queue above it")
	}
	if got := sndBuf(t, s); got != boostSnd {
		t.Fatalf("SO_SNDBUF after the refused return = %d, want the boost %d", got, boostSnd)
	}
	if got := rcvBuf(t, s); got != boostRcv {
		t.Fatalf("SO_RCVBUF after the refused return = %d, want the boost %d", got, boostRcv)
	}
	go io.Copy(io.Discard, c)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if q, _ := meminfo(t, s); q == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the send queue never drained")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !peer.set(false) {
		t.Fatal("refused to go back to the floor after the send queue drained")
	}
	if got := sndBuf(t, s); got != sendFloorEffective {
		t.Fatalf("SO_SNDBUF after the slot went back = %d, want %d", got, sendFloorEffective)
	}
	if got := rcvBuf(t, s); got != floorEffective {
		t.Fatalf("SO_RCVBUF after the slot went back = %d, want %d", got, floorEffective)
	}
}

// floor のソケットの送信のキューは、相手が読まなくても送信の floor の近くで止まる。
func TestFollowBoostFloorBoundsSendQueue(t *testing.T) {
	_, s := tcpPairLoopback(t, smallReceiver)
	FollowBoost(s, &fakeBoost{})
	fill(t, s)
	q, b := meminfo(t, s)
	if b != sendFloorEffective {
		t.Fatalf("SO_MEMINFO sndbuf = %d, want %d", b, sendFloorEffective)
	}
	// カーネルはキューが送信のバッファより小さいときに確保した segment に書き足すので、少し超えうる
	if q > sendFloorEffective+128<<10 {
		t.Fatalf("send queue at the floor = %d, want near %d", q, sendFloorEffective)
	}
	t.Logf("send queue at the floor: %d bytes against a %d-byte buffer", q, b)
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

// 送信のキューが送信の floor を少し超えるだけでも floor に戻らない。
func TestFollowBoostHoldsJustAboveFloor(t *testing.T) {
	_, s := tcpPairLoopback(t, smallReceiver)
	peer := &fakeBoost{}
	FollowBoost(s, peer)
	peer.set(true)
	// 16 KiB ずつ書き、キューが floor を少し超えたら止める。boost が wmem_max で切り詰められる
	// 環境(CAP_NET_ADMIN が無く wmem_max が既定の 212992 なら実効 416 KiB)でも届く量である
	buf := make([]byte, 16<<10)
	q := 0
	for i := 0; i < 64 && q <= sendFloorEffective+32<<10; i++ {
		s.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
		if _, err := s.Write(buf); err != nil {
			t.Fatalf("the queue stopped at %d, below the floor plus 32 KiB: %v", q, err)
		}
		q, _ = meminfo(t, s)
	}
	if q <= sendFloorEffective || q >= 2*sendFloorEffective {
		t.Fatalf("send queue = %d, want between %d and %d for this case", q, sendFloorEffective, 2*sendFloorEffective)
	}
	if peer.set(false) {
		t.Fatalf("went back to the floor with a send queue of %d", q)
	}
}
