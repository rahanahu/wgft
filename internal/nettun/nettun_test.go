package nettun

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// 出力の通知を待たずに書き込みが戻り、Read がキューから順に受け取る。
func TestReadPullsQueuedPackets(t *testing.T) {
	dev, err := Create(netip.MustParseAddr("10.99.0.1"), 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()

	for _, last := range []byte{1, 2} {
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{0x45, 0, 0, last})})
		var pkts stack.PacketBufferList
		pkts.PushBack(pkt)
		written, err := dev.ep.WritePackets(pkts)
		pkt.DecRef()
		if err != nil || written != 1 {
			t.Fatalf("WritePackets = (%d, %v), want (1, nil)", written, err)
		}
	}
	for _, last := range []byte{1, 2} {
		buf := []byte{0xaa, 0, 0, 0, 0}
		sizes := []int{0}
		n, err := dev.Read([][]byte{buf}, sizes, 1)
		if err != nil || n != 1 || sizes[0] != 4 {
			t.Fatalf("Read = (%d, %v), sizes=%v", n, err, sizes)
		}
		if got := buf; got[0] != 0xaa || got[1] != 0x45 || got[4] != last {
			t.Fatalf("Read buffer = %v, want offset preserved and last byte %d", got, last)
		}
	}
}

func TestQueuedPacketsDroppedOnClose(t *testing.T) {
	dev, err := Create(netip.MustParseAddr("10.99.0.1"), 1420)
	if err != nil {
		t.Fatal(err)
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{0x45, 0, 0, 20})})
	var pkts stack.PacketBufferList
	pkts.PushBack(pkt)
	dev.ep.WritePackets(pkts)
	pkt.DecRef()
	dev.Close()

	if err := readWithin(dev, 5*time.Second); err != os.ErrClosed {
		t.Fatalf("Read after Close = %v, want os.ErrClosed", err)
	}
	// 2 回目の Close は何もしない。
	dev.Close()
}

// 読み手が止まっていても送信側は有限キューの容量まで進み、それを超える出力は入らない。
func TestOutboundQueueBoundedWithoutReader(t *testing.T) {
	dev, err := Create(netip.MustParseAddr("10.99.0.1"), 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	var pkts stack.PacketBufferList
	for i := 0; i < 1025; i++ {
		pkts.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{0x45, 0, 0, 20})}))
	}
	written, writeErr := dev.ep.WritePackets(pkts)
	pkts.DecRef()
	if writeErr != nil || written != 1024 {
		t.Fatalf("WritePackets = (%d, %v), want (1024, nil)", written, writeErr)
	}
	if got := dev.ep.NumQueued(); got != 1024 {
		t.Fatalf("NumQueued = %d, want 1024", got)
	}
}

// キューの読み取り、次の送信、Close が競合しても、操作は待ち合わずに終了する。
func TestReadWriteAndCloseConcurrent(t *testing.T) {
	for i := 0; i < 32; i++ {
		dev, err := Create(netip.MustParseAddr("10.99.0.1"), 1420)
		if err != nil {
			t.Fatal(err)
		}
		first := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{0x45, 0, 0, 1})})
		var queued stack.PacketBufferList
		queued.PushBack(first)
		n, writeErr := dev.ep.WritePackets(queued)
		first.DecRef()
		if writeErr != nil || n != 1 {
			dev.Close()
			t.Fatalf("queue packet: (%d, %v)", n, writeErr)
		}

		start := make(chan struct{})
		type readResult struct {
			n    int
			size int
			data [4]byte
			err  error
		}
		readDone := make(chan readResult, 1)
		go func() {
			<-start
			buf := make([]byte, 4)
			sizes := []int{0}
			n, err := dev.Read([][]byte{buf}, sizes, 0)
			readDone <- readResult{n: n, size: sizes[0], data: [4]byte(buf), err: err}
		}()
		type writeResult struct {
			n   int
			err tcpip.Error
		}
		writeDone := make(chan writeResult, 1)
		go func() {
			<-start
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{0x45, 0, 0, 2})})
			var pkts stack.PacketBufferList
			pkts.PushBack(pkt)
			n, err := dev.ep.WritePackets(pkts)
			pkt.DecRef()
			writeDone <- writeResult{n: n, err: err}
		}()
		closeDone := make(chan struct{})
		go func() {
			<-start
			dev.Close()
			close(closeDone)
		}()
		close(start)
		within(t, closeDone, 5*time.Second, "Close racing with queue operations")
		select {
		case got := <-readDone:
			if got.err == nil {
				if got.n != 1 || got.size != 4 || got.data != [4]byte{0x45, 0, 0, 1} {
					t.Fatalf("iteration %d: Read = %+v", i, got)
				}
			} else if got.err != os.ErrClosed || got.n != 0 {
				t.Fatalf("iteration %d: Read = %+v", i, got)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d: Read did not return", i)
		}
		select {
		case got := <-writeDone:
			if got.err == nil {
				if got.n != 1 {
					t.Fatalf("iteration %d: WritePackets = %+v", i, got)
				}
			} else if _, ok := got.err.(*tcpip.ErrClosedForSend); !ok || got.n != 0 {
				t.Fatalf("iteration %d: WritePackets = %+v", i, got)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d: WritePackets did not return", i)
		}
	}
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

// TUN の読み手が止まっていても、送信中の TCP dial と Close が戻る。
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
	deadline := time.Now().Add(5 * time.Second)
	for dev.ep.NumQueued() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("TCP dial did not queue a SYN")
		}
		time.Sleep(time.Millisecond)
	}
	dc := goDone(func() { dev.Close() })
	within(t, dc, 5*time.Second, "Device.Close with a stalled TUN reader")
	within(t, dial, 5*time.Second, "DialTCP after Device.Close")
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
