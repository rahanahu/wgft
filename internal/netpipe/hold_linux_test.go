//go:build linux

package netpipe

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// holdTCPPair returns the two ends of a loopback TCP connection.
func holdTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
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
			ch <- nil
			return
		}
		ch <- c
	}()
	d, err := net.DialTCP("tcp4", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	a := <-ch
	if a == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { d.Close(); a.Close() })
	return d, a
}

func holdSockInt(t *testing.T, c *net.TCPConn, f func(fd int) (int, error)) int {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		return -1
	}
	v := -1
	if rc.Control(func(fd uintptr) {
		if n, err := f(int(fd)); err == nil {
			v = n
		}
	}) != nil {
		return -1
	}
	return v
}

func outqOf(t *testing.T, c *net.TCPConn) int {
	return holdSockInt(t, c, func(fd int) (int, error) { return unix.IoctlGetInt(fd, unix.SIOCOUTQ) })
}

func stateOf(t *testing.T, c *net.TCPConn) int {
	return holdSockInt(t, c, func(fd int) (int, error) {
		info, err := unix.GetsockoptTCPInfo(fd, unix.IPPROTO_TCP, unix.TCP_INFO)
		if err != nil {
			return 0, err
		}
		return int(info.State), nil
	})
}

func holdEventually(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// heldWithTail returns the relay's end r of a connection whose peer p does not read, after r has
// queued data that p has not acknowledged and r has been stopped as PipeHold stops it.
func heldWithTail(t *testing.T) (r, p *net.TCPConn) {
	t.Helper()
	r, p = holdTCPPair(t)
	p.SetReadBuffer(16 << 10)
	data := make([]byte, 256<<10)
	r.SetWriteDeadline(time.Now().Add(2 * time.Second))
	n, _ := r.Write(data)
	r.SetWriteDeadline(time.Time{})
	if n == 0 {
		t.Fatal("setup: nothing written")
	}
	stopKernel(r)
	holdEventually(t, time.Second, "setup: no tail queued", func() bool { return outqOf(t, r) > 0 })
	return r, p
}

// A stopped socket is not closed: it keeps its tail and is not delivered until the peer reads it,
// and then it is.
func TestStoppedKernelSocketHoldsItsTail(t *testing.T) {
	r, p := heldWithTail(t)
	time.Sleep(200 * time.Millisecond)
	if Delivered(r) {
		t.Fatalf("delivered while %d bytes are queued", outqOf(t, r))
	}
	if _, err := io.Copy(io.Discard, p); err != nil {
		t.Fatal(err)
	}
	holdEventually(t, 2*time.Second, "not delivered after the peer read everything and EOF", func() bool { return Delivered(r) })
}

// A reset from the peer ends the hold although the send queue does not drain: the state is CLOSE.
func TestStoppedKernelSocketEndsOnReset(t *testing.T) {
	r, p := heldWithTail(t)
	p.SetLinger(0)
	p.Close()
	holdEventually(t, time.Second, "the socket did not reach CLOSE", func() bool { return stateOf(t, r) == tcpClose })
	if q := outqOf(t, r); q <= 0 {
		t.Fatalf("setup: the send queue drained (%d), so the CLOSE path was not needed", q)
	}
	if !Delivered(r) {
		t.Fatal("not delivered after the peer's reset")
	}
}

// Data that the peer sends after the stop makes Linux reset the socket at once.
func TestStoppedKernelSocketResetsOnNewData(t *testing.T) {
	r, p := heldWithTail(t)
	p.Write([]byte("late"))
	holdEventually(t, time.Second, "the socket did not reach CLOSE after data arrived", func() bool { return stateOf(t, r) == tcpClose })
	if !Delivered(r) {
		t.Fatal("not delivered after CLOSE")
	}
}

// A socket that still has unread received data is closed, not held, as before.
func TestStopClosesASocketWithUnreadData(t *testing.T) {
	r, p := holdTCPPair(t)
	p.Write([]byte("unread"))
	holdEventually(t, time.Second, "setup: no data arrived", func() bool {
		return holdSockInt(t, r, func(fd int) (int, error) { return unix.IoctlGetInt(fd, unix.SIOCINQ) }) > 0
	})
	stopKernel(r)
	if outqOf(t, r) != -1 {
		t.Fatal("the socket with unread data was not closed")
	}
	if !Delivered(r) {
		t.Fatal("a closed socket is not delivered")
	}
	p.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := p.Read(make([]byte, 16)); !errors.Is(err, unix.ECONNRESET) {
		t.Fatalf("the peer read %v, want a reset", err)
	}
}

// The stop unblocks a read waiting on the socket with EOF and a write waiting on it with an error,
// without a deadline.
func TestStopUnblocksReadAndWrite(t *testing.T) {
	r, _ := holdTCPPair(t)
	done := make(chan error, 1)
	go func() {
		_, err := r.Read(make([]byte, 16))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	stopKernel(r)
	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("read ended with %v, want EOF", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the stop did not unblock the read")
	}
	w, p := holdTCPPair(t)
	p.SetReadBuffer(16 << 10)
	go func() {
		_, err := w.Write(make([]byte, 64<<20))
		done <- err
	}()
	time.Sleep(200 * time.Millisecond)
	stopKernel(w)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the blocked write ended without an error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the stop did not unblock the write")
	}
}

// orderConn is a non-kernel conn whose Read fails at once and whose Close records the state of
// the kernel socket on the other side of the pipe at that moment.
type orderConn struct {
	net.Conn
	k       *net.TCPConn
	t       *testing.T
	atClose atomic.Int32
	closed  atomic.Bool
}

func (c *orderConn) Read([]byte) (int, error) { return 0, errors.New("broken") }
func (c *orderConn) Write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return len(b), nil
}
func (c *orderConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.atClose.Store(int32(stateOf(c.t, c.k)))
	}
	return nil
}
func (c *orderConn) SetReadDeadline(time.Time) error { return nil }

// On an error, PipeHold closes the side it does not hold before it stops the kernel side, so no
// FIN goes out on the kernel side before the other side is closed (or reset by resetB).
func TestPipeHoldClosesBeforeItStops(t *testing.T) {
	k, p := holdTCPPair(t)
	o := &orderConn{k: k, t: t}
	done := make(chan struct{})
	go func() {
		PipeHold(o, k, nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("PipeHold did not end")
	}
	const established = 1
	if got := o.atClose.Load(); got != established {
		t.Fatalf("the kernel socket was in state %d when the other side was closed, want ESTABLISHED", got)
	}
	// the kernel side is stopped, not closed: the peer sees EOF and the socket is still open
	p.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := p.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("the peer read %v, want EOF", err)
	}
	if outqOf(t, k) == -1 {
		t.Fatal("PipeHold closed the kernel socket")
	}
}

// PipeResetB, which the kernel-mode relay keeps using, still closes both kernel sockets.
func TestPipeResetBStillClosesKernelSockets(t *testing.T) {
	a, pa := holdTCPPair(t)
	b, pb := holdTCPPair(t)
	done := make(chan struct{})
	go func() {
		PipeResetB(a, b, nil)
		close(done)
	}()
	pa.CloseWrite()
	pb.CloseWrite()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("PipeResetB did not end")
	}
	if outqOf(t, a) != -1 || outqOf(t, b) != -1 {
		t.Fatal("PipeResetB left a kernel socket open")
	}
}

type fakeDeliverer struct {
	net.Conn
	done atomic.Bool
}

func (f *fakeDeliverer) Delivered() bool { return f.done.Load() }

// AwaitDelivered returns as soon as everything is delivered, and returns false at once when
// woken.
func TestAwaitDelivered(t *testing.T) {
	f := &fakeDeliverer{}
	wake := make(chan struct{})
	go func() {
		time.Sleep(120 * time.Millisecond)
		f.done.Store(true)
	}()
	start := time.Now()
	if !AwaitDelivered(wake, f) {
		t.Fatal("AwaitDelivered returned false without a wake")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("took %v", d)
	}
	g := &fakeDeliverer{}
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(wake)
	}()
	start = time.Now()
	if AwaitDelivered(wake, g) {
		t.Fatal("AwaitDelivered returned true for a pair that is not delivered")
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("the wake took %v", d)
	}
}
