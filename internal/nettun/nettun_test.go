package nettun

import (
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
