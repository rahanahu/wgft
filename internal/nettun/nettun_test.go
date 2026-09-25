package nettun

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// inWriteNotify は、いずれかの goroutine が Device.WriteNotify の中にいるかを返す。
func inWriteNotify() bool {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return strings.Contains(string(buf[:n]), "nettun.(*Device).WriteNotify")
}

// Close は、stack の goroutine が WriteNotify で受け渡しを待っている間に呼ばれても、その
// goroutine を panic させずに返させる。読む者がいない間に stack が送ったパケットは、Read に
// 渡るまで WriteNotify を止めておく。この状態で Close が受け渡しの channel を閉じると、閉じた
// channel への送信で panic する。
func TestCloseWhileWriteNotifyWaits(t *testing.T) {
	dev, err := Create(netip.MustParseAddr("10.99.0.1"), 1420)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		var pkts stack.PacketBufferList
		pkts.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{0x45, 0, 0, 20})}))
		// channel.Endpoint は書いた goroutine のまま WriteNotify を呼ぶ。
		dev.ep.WritePackets(pkts)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for !inWriteNotify() {
		if time.Now().After(deadline) {
			t.Fatal("the write never reached WriteNotify")
		}
		time.Sleep(time.Millisecond)
	}

	dev.Close()
	select {
	case p := <-done:
		if p != nil {
			t.Fatalf("WriteNotify panicked after Close: %v", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WriteNotify still waits 5s after Close")
	}

	if err := readWithin(dev, 5*time.Second); err != os.ErrClosed {
		t.Fatalf("Read after Close = %v, want os.ErrClosed", err)
	}
	// 2 回目の Close は何もしない。
	dev.Close()
}

// Read は、パケットを待っている間に Close されると os.ErrClosed で返る。
func TestReadReturnsOnClose(t *testing.T) {
	dev, err := Create(netip.MustParseAddr("10.99.0.1"), 1420)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(10 * time.Millisecond)
		dev.Close()
	}()
	if err := readWithin(dev, 5*time.Second); err != os.ErrClosed {
		t.Fatalf("Read = %v, want os.ErrClosed", err)
	}
}

// gVisor の tcp.(*Endpoint).Connect は LockUser を持ったまま SYN を送る。その送信は
// channel.Endpoint 経由で Device.WriteNotify を呼び、無バッファの incomingPacket が
// Read で引き取られるまで、その goroutine は LockUser を持ったままブロックする。
// Device.Close の stack.Close は Abort 経由で同じ LockUser を待つので、closed を
// 閉じて WriteNotify のブロックを解く前に stack.Close を呼ぶ順序では、両者が
// 待ち合ったまま戻らない。この試験は、下流 (Read) が止まったまま接続中の TCP dial が
// あっても、Close が戻ることを確かめる。
func TestDeviceCloseWithStalledTCPConnect(t *testing.T) {
	dev, err := Create(netip.MustParseAddr("10.99.0.1"), 1420)
	if err != nil {
		t.Fatal(err)
	}
	dial := goDone(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if c, err := dev.DialTCP(ctx, netip.MustParseAddrPort("10.99.0.2:80")); err == nil {
			c.Close()
		}
	})
	waitGoroutine(t, "nettun.(*Device).WriteNotify", "tcp.(*Endpoint).Connect")
	dc := goDone(func() { dev.Close() })
	if !waitOrUnstick(dev, dc, 5*time.Second) {
		t.Fatal("Device.Close blocked behind a stalled TCP connect")
	}
	within(t, dial, 5*time.Second, "DialTCP after Device.Close")
}

// waitGoroutine は、want の全部を 1 つの goroutine のスタックに含むものが現れるまで待つ。
func waitGoroutine(t *testing.T, want ...string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		for _, gr := range strings.Split(string(buf[:n]), "\n\n") {
			ok := true
			for _, w := range want {
				if !strings.Contains(gr, w) {
					ok = false
					break
				}
			}
			if ok {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no goroutine with %q in its stack", want)
		}
		time.Sleep(time.Millisecond)
	}
}

// goDone は fn を別の goroutine で走らせ、終わると閉じる channel を返す。
func goDone(fn func()) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	return done
}

// within は done が d の間に閉じることを確かめる。
func within(t *testing.T, done <-chan struct{}, d time.Duration, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %v", what, d)
	}
}

// waitOrUnstick は done を d まで待つ。戻らなければ Device.Read で下流を動かして後始末し、false を返す。
func waitOrUnstick(dev *Device, done <-chan struct{}, d time.Duration) bool {
	select {
	case <-done:
		return true
	case <-time.After(d):
	}
	go func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			dev.Read([][]byte{make([]byte, 2048)}, []int{0}, 0)
		}
	}()
	<-done
	return false
}

// readWithin は dev.Read の誤りを返す。timeout の間に返らなければ errReadTimeout を返す。
func readWithin(dev *Device, timeout time.Duration) error {
	errc := make(chan error, 1)
	go func() {
		_, err := dev.Read([][]byte{make([]byte, 1500)}, []int{0}, 0)
		errc <- err
	}()
	select {
	case err := <-errc:
		return err
	case <-time.After(timeout):
		return errReadTimeout
	}
}

var errReadTimeout = errors.New("read did not return")
