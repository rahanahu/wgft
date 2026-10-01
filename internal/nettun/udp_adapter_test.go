package nettun

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/waiter"
)

// A zero send buffer exercises real gVisor ErrWouldBlock. The pinned channel
// link clones outgoing packets without OnRelease, so retaining output alone
// does not keep send-buffer usage charged after endpoint.Write returns.
func blockedOutboundAdapter(t *testing.T) (*Device, *rawUDPAdapter) {
	t.Helper()
	dev, err := Create(accountingLocal, 1420)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dev.Close() })
	remote := netip.AddrPortFrom(accountingRemote, accountingPort)
	c, err := newRawUDPAdapter(dev, nil, &remote)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.wouldBlockObserved = make(chan struct{}, 1)
	c.ep.SocketOptions().SetSendBufferSize(0, false)
	if got := c.ep.SocketOptions().GetSendBufferSize(); got != 0 {
		t.Fatalf("send buffer = %d", got)
	}
	if got := c.ep.Readiness(waiter.WritableEvents); got != 0 {
		t.Fatalf("zero-capacity endpoint writable: %v", got)
	}
	return dev, c
}

func TestRawUDPAdapterRealWouldBlockResize(t *testing.T) {
	dev, c := blockedOutboundAdapter(t)
	defer dev.ep.Drain()
	done := make(chan error, 1)
	go func() {
		n, err := c.Write([]byte("retry"))
		if err == nil && n != 5 {
			err = errors.New("short retry write")
		}
		done <- err
	}()
	select {
	case <-c.wouldBlockObserved:
	case err := <-done:
		t.Fatalf("Write returned before raw ErrWouldBlock observation: %v", err)
	case <-time.After(time.Second):
		t.Fatal("raw ErrWouldBlock was not observed")
	}
	if !c.opMu.TryLock() {
		t.Fatal("Write held opMu while waiting for send space")
	}
	c.opMu.Unlock()
	c.ep.SocketOptions().SetSendBufferSize(1, true)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("retry Write: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("retry Write did not wake")
	}
	pkt := dev.ep.Read()
	if pkt == nil {
		t.Fatal("missing retry output")
	}
	v := pkt.ToView()
	got := append([]byte(nil), v.AsSlice()...)
	v.Release()
	pkt.DecRef()
	if !bytes.HasSuffix(got, []byte("retry")) {
		t.Fatalf("retry payload absent from %x", got)
	}
	if extra := dev.ep.Read(); extra != nil {
		extra.DecRef()
		t.Fatal("retry emitted more than once")
	}
}

func TestRawUDPAdapterRealWouldBlockDeadlineAndClose(t *testing.T) {
	for _, mode := range []string{"deadline", "close"} {
		t.Run(mode, func(t *testing.T) {
			dev, c := blockedOutboundAdapter(t)
			defer dev.ep.Drain()
			done := make(chan error, 1)
			go func() { _, err := c.Write([]byte("retry")); done <- err }()
			select {
			case <-c.wouldBlockObserved:
			case err := <-done:
				t.Fatalf("Write returned before raw ErrWouldBlock observation: %v", err)
			case <-time.After(time.Second):
				t.Fatal("raw ErrWouldBlock was not observed")
			}
			if mode == "deadline" {
				if err := c.SetWriteDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "close" {
				if err := c.Close(); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-done:
				if mode == "close" && !errors.Is(err, net.ErrClosed) {
					t.Fatalf("Close wakeup: %v", err)
				}
				if mode == "deadline" {
					if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
						t.Fatalf("deadline wakeup: %v", err)
					}
				}
			case <-time.After(time.Second):
				t.Fatal("blocked Write did not end")
			}
		})
	}
}

func adapterPair(t *testing.T) (*Device, *rawUDPAdapter, *rawUDPAdapter) {
	t.Helper()
	dev, err := Create(accountingLocal, 1420)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dev.Close() })
	listenAddr := netip.AddrPortFrom(accountingLocal, accountingPort)
	listener, err := newRawUDPAdapter(dev, &listenAddr, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	client, err := newRawUDPAdapter(dev, nil, &listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return dev, listener, client
}

func TestRawUDPAdapterReadWriteAndAddresses(t *testing.T) {
	_, listener, client := adapterPair(t)
	if _, ok := listener.LocalAddr().(*net.UDPAddr); !ok {
		t.Fatalf("listener LocalAddr = %T", listener.LocalAddr())
	}
	if got := client.RemoteAddr().(*net.UDPAddr).AddrPort(); got != netip.AddrPortFrom(accountingLocal, accountingPort) {
		t.Fatalf("client RemoteAddr = %v", got)
	}
	if n, err := client.Write([]byte("four")); err != nil || n != 4 {
		t.Fatalf("Write = (%d, %v)", n, err)
	}
	short := make([]byte, 2)
	n, from, err := listener.ReadFrom(short)
	if err != nil || n != 2 || !bytes.Equal(short, []byte("fo")) || from == nil {
		t.Fatalf("short ReadFrom = (%d, %v, %v)", n, from, err)
	}
	if n, err := client.Write(nil); err != nil || n != 0 {
		t.Fatalf("empty Write = (%d, %v)", n, err)
	}
	if n, _, err := listener.ReadFrom(make([]byte, 1)); err != nil || n != 0 {
		t.Fatalf("empty ReadFrom = (%d, %v)", n, err)
	}
	peer := client.LocalAddr().(*net.UDPAddr)
	if n, err := listener.WriteTo([]byte("reply"), peer); err != nil || n != 5 {
		t.Fatalf("WriteTo = (%d, %v)", n, err)
	}
	b := make([]byte, 5)
	if n, err := client.Read(b); err != nil || n != 5 || !bytes.Equal(b, []byte("reply")) {
		t.Fatalf("Read = (%d, %q, %v)", n, b, err)
	}
}

// extendWhileReading starts a ReadFrom on c under a read deadline window ahead,
// waits until that ReadFrom has registered for readable events, and then
// moves the deadline to extended. It reports whether the move landed before
// the first deadline. If it did not, the first deadline may have expired
// first and a timeout is then the correct result, so the attempt ends the
// ReadFrom and tells the caller to try again with a wider window.
func extendWhileReading(t *testing.T, c *rawUDPAdapter, window, extended time.Duration) (first time.Time, readDone <-chan error, inTime bool) {
	t.Helper()
	first = time.Now().Add(window)
	if err := c.SetReadDeadline(first); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := c.ReadFrom(make([]byte, 8))
		done <- err
	}()
	for c.wq.Events()&waiter.ReadableEvents == 0 && time.Now().Before(first) {
		time.Sleep(time.Millisecond)
	}
	if err := c.SetReadDeadline(time.Now().Add(extended)); err != nil {
		t.Fatal(err)
	}
	if time.Now().Before(first) {
		return first, done, true
	}
	if err := c.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("an expired deadline did not end ReadFrom")
	}
	return first, nil, false
}

func TestRawUDPAdapterDeadlineUpdateAndClear(t *testing.T) {
	_, listener, client := adapterPair(t)
	// Move the deadline while Read is waiting; the old timer must not win.
	// The move must land before the old deadline; a slow runner can let a
	// short fixed window pass first, so the window grows until it does.
	const extended = 10 * time.Second
	var (
		first    time.Time
		readDone <-chan error
		inTime   bool
	)
	for window := 20 * time.Millisecond; !inTime; window *= 2 {
		if window > 10*time.Second {
			t.Fatal("could not move the read deadline before it expired")
		}
		first, readDone, inTime = extendWhileReading(t, listener, window, extended)
	}
	// Let the old deadline pass while Read waits under the new one.
	time.Sleep(time.Until(first) + 50*time.Millisecond)
	select {
	case err := <-readDone:
		t.Fatalf("Read ended at the old deadline after the extension: %v", err)
	default:
	}
	if _, err := client.Write([]byte("ready")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("Read after deadline extension: %v", err)
		}
	case <-time.After(extended + 5*time.Second):
		t.Fatal("Read did not finish")
	}
	if err := listener.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := listener.ReadFrom(make([]byte, 1)); err == nil {
		t.Fatal("expired deadline allowed Read")
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("expired Read error = %v", err)
	}
	if err := listener.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("again")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 5)
	if n, _, err := listener.ReadFrom(b); err != nil || n != 5 || !bytes.Equal(b, []byte("again")) {
		t.Fatalf("Read after deadline clear = (%d, %q, %v)", n, b, err)
	}
	if err := client.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("blocked")); err == nil {
		t.Fatal("expired deadline allowed Write")
	}
	if err := client.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if n, err := client.Write([]byte("ok")); err != nil || n != 2 {
		t.Fatalf("Write after deadline clear = (%d, %v)", n, err)
	}
}

func TestRawUDPAdapterWaitAndClose(t *testing.T) {
	_, listener, client := adapterPair(t)
	ready := make(chan error, 1)
	go func() { ready <- listener.WaitReadable() }()
	if _, err := client.Write([]byte("one")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-ready:
		if err != nil {
			t.Fatalf("WaitReadable: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("WaitReadable did not observe data")
	}
	if n, _, err := listener.ReadFrom(make([]byte, 3)); err != nil || n != 3 {
		t.Fatalf("ReadFrom after WaitReadable = (%d, %v)", n, err)
	}
	readDone := make(chan error, 1)
	go func() {
		_, _, err := listener.ReadFrom(make([]byte, 3))
		readDone <- err
	}()
	waitDone := make(chan error, 1)
	go func() { waitDone <- listener.WaitReadable() }()
	listener.Close()
	select {
	case err := <-readDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("ReadFrom after Close = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not release ReadFrom")
	}
	select {
	case err := <-waitDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("WaitReadable released by Close = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not release WaitReadable")
	}
	if err := listener.WaitReadable(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("WaitReadable after Close = %v", err)
	}
}

func TestRawUDPAdapterDeadlineChangesWakeBlockedRead(t *testing.T) {
	_, listener, client := adapterPair(t)
	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	first := make(chan error, 1)
	go func() {
		_, _, err := listener.ReadFrom(make([]byte, 8))
		first <- err
	}()
	time.Sleep(5 * time.Millisecond)
	if err := listener.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-first:
		if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			t.Fatalf("shortened deadline error = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("shortened deadline did not wake ReadFrom")
	}
	if err := listener.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	second := make(chan error, 1)
	go func() {
		_, _, err := listener.ReadFrom(make([]byte, 8))
		second <- err
	}()
	time.Sleep(5 * time.Millisecond)
	if err := listener.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-second:
		t.Fatalf("cleared deadline returned early: %v", err)
	case <-time.After(70 * time.Millisecond):
	}
	if _, err := client.Write([]byte("wakeup")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-second:
		if err != nil {
			t.Fatalf("Read after deadline clear: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not finish after Write")
	}
}

func TestRawUDPAdapterDeadlineExpiresWhileOperationLockHeld(t *testing.T) {
	_, listener, client := adapterPair(t)
	if _, err := client.Write([]byte("queued")); err != nil {
		t.Fatal(err)
	}
	listener.opMu.Lock()
	if err := listener.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	readStarted := make(chan struct{})
	readDone := make(chan error, 1)
	go func() {
		close(readStarted)
		_, _, err := listener.ReadFrom(make([]byte, 8))
		readDone <- err
	}()
	<-readStarted
	time.Sleep(250 * time.Millisecond)
	listener.opMu.Unlock()
	select {
	case err := <-readDone:
		if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			t.Fatalf("Read after lock delay = %v, want timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read remained blocked after lock release")
	}
	// The timed-out Read must leave the already queued datagram untouched.
	b := make([]byte, 8)
	w := tcpip.SliceWriter(b)
	result, terr := listener.ep.Read(&w, tcpip.ReadOptions{})
	if terr != nil || result.Count != 6 || !bytes.Equal(b[:6], []byte("queued")) {
		t.Fatalf("raw Read after timeout = (%+v, %q, %v)", result, b, terr)
	}
	// A local write waits for the receiver's lock, not the sender's. Under
	// accounting, an expired write that waited must deliver nothing.
	_, r := registryFixture(t)
	managed := registryListen(t, r, accountingPort+1)
	sender := registryDial(t, r, netip.AddrPortFrom(accountingLocal, accountingPort+1))
	managed.opMu.Lock()
	release := releaseOnce(t, managed.opMu.Unlock)
	if err := sender.SetWriteDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	writeStarted := make(chan struct{})
	writeDone := make(chan error, 1)
	go func() {
		close(writeStarted)
		_, err := sender.Write([]byte("late"))
		writeDone <- err
	}()
	<-writeStarted
	time.Sleep(250 * time.Millisecond)
	select {
	case err := <-writeDone:
		t.Fatalf("Write returned while the receiver lock was held: %v", err)
	default:
	}
	release()
	select {
	case err := <-writeDone:
		if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			t.Fatalf("Write after lock delay = %v, want timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Write remained blocked after lock release")
	}
	w = tcpip.SliceWriter(make([]byte, 8))
	if _, terr := managed.ep.Read(&w, tcpip.ReadOptions{}); terr == nil {
		t.Fatal("expired Write delivered a datagram")
	} else if _, ok := terr.(*tcpip.ErrWouldBlock); !ok {
		t.Fatalf("empty receiver after expired Write: %v", terr)
	}
	assertRegistryUsage(t, r, 0, 0)
}

func TestRawUDPAdapterStaleTimerUsesCurrentDeadline(t *testing.T) {
	_, listener, _ := adapterPair(t)
	// Model a timer from an old deadline firing after the deadline has moved.
	stale := make(chan time.Time, 1)
	stale <- time.Now()
	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := listener.waitReady(true, nil, nil, stale); err != nil {
		t.Fatalf("extended deadline treated as expired: %v", err)
	}
	stale <- time.Now()
	if err := listener.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := listener.waitReady(true, nil, nil, stale); err != nil {
		t.Fatalf("cleared deadline treated as expired: %v", err)
	}
	stale <- time.Now()
	if err := listener.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if ne, ok := listener.waitReady(true, nil, nil, stale).(net.Error); !ok || !ne.Timeout() {
		t.Fatal("current expired deadline was not reported")
	}
	stale <- time.Now()
	listener.Close()
	if err := listener.waitReady(true, nil, nil, stale); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Close did not take precedence over timeout: %v", err)
	}
}

func TestRawUDPAdapterWaitReadableOnICMPError(t *testing.T) {
	dev, err := Create(accountingLocal, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	remote := netip.AddrPortFrom(accountingLocal, accountingPort)
	c, err := newRawUDPAdapter(dev, nil, &remote)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if n, err := c.Write([]byte("lost")); err != nil || n != 4 {
		t.Fatalf("local Write = (%d, %v)", n, err)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- c.WaitReadable() }()
	select {
	case err := <-waitDone:
		if err != nil {
			t.Fatalf("WaitReadable on ICMP error = %v", err)
		}
	case <-time.After(time.Second):
		c.Close()
		t.Fatal("WaitReadable stayed blocked after ICMP error")
	}
	if _, err := c.Read(make([]byte, 8)); err == nil {
		t.Fatal("Read after ICMP error did not return an error")
	}
}
