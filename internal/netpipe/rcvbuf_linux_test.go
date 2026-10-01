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
	f  func(bool) bool
	n  int
}

func (b *fakeBoost) OnBoost(f func(bool) bool) {
	b.mu.Lock()
	b.f, b.n = f, b.n+1
	b.mu.Unlock()
	f(false)
}

// set は枠の知らせを送り、知らせの関数の値を返す。
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
	if !peer.set(false) {
		t.Fatal("refused to go back to the floor with nothing received")
	}
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

// rmemOf は SO_MEMINFO の受信のメモリを読む。
func rmemOf(t *testing.T, c *net.TCPConn) int {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var rmem int
	var ok bool
	if err := rc.Control(func(fd uintptr) { rmem, _, ok = sockMemInfo(int(fd)) }); err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("SO_MEMINFO failed")
	}
	return rmem
}

// カーネルのソケットが floor を超える受信のデータを持つ間は、floor への戻りを断って boost のままに
// する。SO_RCVBUF を下げてもデータは解放されないためである。データを読み終えると floor に戻れる。
// 順序外のキューは、穴を作れないこの試験では作れないので、ラボの試験(lab/rcvwin.sh)が確かめる。
func TestFollowBoostKeepsBoostWhileDataHeld(t *testing.T) {
	dialed, accepted := tcpPairLoopback(t, &net.Dialer{Timeout: 5 * time.Second})
	peer := &fakeBoost{}
	FollowBoost(accepted, peer)
	peer.set(true)
	boosted := rcvBuf(t, accepted)
	const n = 1 << 20
	go dialed.Write(make([]byte, n))
	deadline := time.Now().Add(5 * time.Second)
	for rmemOf(t, accepted) <= kernelFloorBytes {
		if time.Now().After(deadline) {
			t.Fatalf("receive memory stayed at %d, never above the floor %d", rmemOf(t, accepted), kernelFloorBytes)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// 断った後の次の要求でも改めて確かめ、同じく断る。断ったときに floor に戻ったと記録すると、
	// 次の要求で確かめずに戻してしまう
	for i := 1; i <= 2; i++ {
		if peer.set(false) {
			t.Fatalf("request %d: went back to the floor while holding %d bytes of receive memory", i, rmemOf(t, accepted))
		}
		if got := rcvBuf(t, accepted); got != boosted {
			t.Fatalf("request %d: SO_RCVBUF after the refused return = %d, want the boost %d", i, got, boosted)
		}
	}
	// 窓の上限は確かめない。新しいカーネルは、受信の segment の大きさの比が変わると、窓の上限を
	// 受信のバッファから置き直すためである
	if _, err := io.ReadFull(accepted, make([]byte, n)); err != nil {
		t.Fatal(err)
	}
	if !peer.set(false) {
		t.Fatalf("refused to go back to the floor after reading everything; receive memory %d", rmemOf(t, accepted))
	}
	if got := rcvBuf(t, accepted); got != floorEffective {
		t.Fatalf("SO_RCVBUF after the data drained = %d, want %d", got, floorEffective)
	}
}

// 受信のメモリを読めないときは、floor への戻りを断って boost のままにする。
func TestFollowBoostKeepsBoostWhenUnmeasured(t *testing.T) {
	_, accepted := tcpPairLoopback(t, &net.Dialer{Timeout: 5 * time.Second})
	peer := &fakeBoost{}
	FollowBoost(accepted, peer)
	peer.set(true)
	boosted := rcvBuf(t, accepted)
	saved := sockMemInfo
	sockMemInfo = func(int) (int, int, bool) { return 0, 0, false }
	refused := !peer.set(false)
	sockMemInfo = saved
	if !refused {
		t.Fatal("went back to the floor without measuring the receive memory")
	}
	if got := rcvBuf(t, accepted); got != boosted {
		t.Fatalf("SO_RCVBUF after the refused return = %d, want the boost %d", got, boosted)
	}
	if !peer.set(false) {
		t.Fatal("refused to go back to the floor once the receive memory could be read")
	}
}

// 下げる前の確かめが通っても、下げた後の確かめで floor を超えていれば boost に戻して断る。下げる前に
// 読んだ後で、古い大きさのバッファが segment を受け入れうるためである。
func TestFollowBoostRechecksAfterLowering(t *testing.T) {
	_, accepted := tcpPairLoopback(t, &net.Dialer{Timeout: 5 * time.Second})
	peer := &fakeBoost{}
	FollowBoost(accepted, peer)
	peer.set(true)
	boosted := rcvBuf(t, accepted)
	saved := sockMemInfo
	calls := 0
	sockMemInfo = func(fd int) (int, int, bool) {
		calls++
		_, rcvbuf, ok := saved(fd)
		if calls == 1 {
			return 0, rcvbuf, ok
		}
		return kernelFloorBytes + 1, rcvbuf, ok
	}
	refused := !peer.set(false)
	sockMemInfo = saved
	if calls != 2 {
		t.Fatalf("read the receive memory %d times, want once before and once after lowering", calls)
	}
	if !refused {
		t.Fatal("went back to the floor although the receive memory was above it after lowering")
	}
	if got := rcvBuf(t, accepted); got != boosted {
		t.Fatalf("SO_RCVBUF after the refused return = %d, want the boost %d", got, boosted)
	}
}

// 下げた後の確かめは、受信のバッファが実際に floor に下がったことも求める。
func TestFollowBoostRechecksTheBuffer(t *testing.T) {
	_, accepted := tcpPairLoopback(t, &net.Dialer{Timeout: 5 * time.Second})
	peer := &fakeBoost{}
	FollowBoost(accepted, peer)
	peer.set(true)
	boosted := rcvBuf(t, accepted)
	saved := sockMemInfo
	sockMemInfo = func(fd int) (int, int, bool) {
		_, _, ok := saved(fd)
		return 0, 2 * kernelFloorBytes, ok
	}
	refused := !peer.set(false)
	sockMemInfo = saved
	if !refused {
		t.Fatal("went back to the floor although the receive buffer read back above the floor")
	}
	if got := rcvBuf(t, accepted); got != boosted {
		t.Fatalf("SO_RCVBUF after the refused return = %d, want the boost %d", got, boosted)
	}
}
