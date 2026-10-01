package netpipe

import (
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// closeSeen records whether the relay has closed the conn.
type closeSeen struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeSeen) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func (c *closeSeen) CloseWrite() error { return c.Conn.(closeWriter).CloseWrite() }

// injected makes the conn's reads or writes fail with err while the other direction still works.
type injected struct {
	net.Conn
	readErr, writeErr error
}

func (c injected) Read(b []byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.Conn.Read(b)
}

func (c injected) Write(b []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.Conn.Write(b)
}

func (c injected) CloseWrite() error { return c.Conn.(closeWriter).CloseWrite() }

func sysErr(op string, errno syscall.Errno) error {
	return &net.OpError{Op: op, Net: "tcp", Err: os.NewSyscallError(op, errno)}
}

// resetRig relays between a client conn and a target conn through PipeResetB, with the client's
// side as a, and records each call of resetB and whether b was closed by then.
type resetRig struct {
	client, target net.Conn
	done           chan struct{}
	calls          atomic.Int32
	closedFirst    atomic.Bool
}

// newResetRig builds the rig. copyPath hides *net.TCPConn so that the relay copies through its own
// buffers; otherwise both sides are kernel TCP and io.Copy splices. wrapA and wrapB, if not nil,
// replace the relay's two conns.
func newResetRig(t *testing.T, copyPath bool, wrapA, wrapB func(net.Conn) net.Conn) *resetRig {
	t.Helper()
	client, cSide := tcpPair(t)
	tSide, target := tcpPair(t)
	var a, b net.Conn = cSide, tSide
	var seen *closeSeen
	if copyPath {
		seen = &closeSeen{Conn: wrapped{tSide.(*net.TCPConn)}}
		a, b = wrapped{cSide.(*net.TCPConn)}, seen
	}
	if wrapA != nil {
		a = wrapA(a)
	}
	if wrapB != nil {
		b = wrapB(b)
	}
	r := &resetRig{client: client, target: target, done: make(chan struct{})}
	go func() {
		PipeResetB(a, b, func() {
			r.calls.Add(1)
			if seen != nil && seen.closed.Load() {
				r.closedFirst.Store(true)
			}
		})
		close(r.done)
	}()
	return r
}

func (r *resetRig) wait(t *testing.T) {
	t.Helper()
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the pipe did not end")
	}
}

// PipeResetB calls resetB, before it closes b, exactly when the conn a ends with a reset: a
// failed read or write on a with ECONNRESET. A reset on b, any other error on a, and EOF leave
// resetB uncalled, so those endings stay as Pipe ends them. On the splice path the error does not
// say which conn failed, and a reset on either counts.
func TestPipeResetBCallsOnlyForAResetOnA(t *testing.T) {
	resetWrite := func(c net.Conn) net.Conn { return injected{Conn: c, writeErr: sysErr("write", syscall.ECONNRESET)} }
	for _, tc := range []struct {
		name         string
		copyPath     bool
		wrapA, wrapB func(net.Conn) net.Conn
		// end makes the pipe end; it may send data first
		end       func(t *testing.T, r *resetRig)
		wantCalls int32
	}{
		{name: "copy, a resets", copyPath: true, end: func(t *testing.T, r *resetRig) {
			resetConn(t, r.client)
		}, wantCalls: 1},
		{name: "copy bulk, a resets", copyPath: true, end: func(t *testing.T, r *resetRig) {
			msg := make([]byte, 4*idleBufSize)
			r.client.Write(msg)
			readSome(t, r.target, string(msg))
			resetConn(t, r.client)
		}, wantCalls: 1},
		{name: "copy, write to a fails with a reset", copyPath: true, wrapA: resetWrite, end: func(t *testing.T, r *resetRig) {
			r.target.Write([]byte("x"))
		}, wantCalls: 1},
		{name: "copy, b resets", copyPath: true, end: func(t *testing.T, r *resetRig) {
			resetConn(t, r.target)
		}, wantCalls: 0},
		{name: "copy, write to b fails with a reset", copyPath: true, wrapB: resetWrite, end: func(t *testing.T, r *resetRig) {
			r.client.Write([]byte("x"))
		}, wantCalls: 0},
		{name: "copy, read from a fails otherwise", copyPath: true, wrapA: func(c net.Conn) net.Conn {
			return injected{Conn: c, readErr: sysErr("read", syscall.ETIMEDOUT)}
		}, end: func(t *testing.T, r *resetRig) {}, wantCalls: 0},
		{name: "copy, EOF both ways", copyPath: true, end: func(t *testing.T, r *resetRig) {
			r.client.(*net.TCPConn).CloseWrite()
			r.target.(*net.TCPConn).CloseWrite()
		}, wantCalls: 0},
		{name: "splice, a resets", end: func(t *testing.T, r *resetRig) {
			resetConn(t, r.client)
		}, wantCalls: 1},
		{name: "splice, b resets", end: func(t *testing.T, r *resetRig) {
			resetConn(t, r.target)
		}, wantCalls: 1},
		{name: "splice, EOF both ways", end: func(t *testing.T, r *resetRig) {
			r.client.(*net.TCPConn).CloseWrite()
			r.target.(*net.TCPConn).CloseWrite()
		}, wantCalls: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newResetRig(t, tc.copyPath, tc.wrapA, tc.wrapB)
			// the relay carries data both ways before the end, unless a wrapper breaks a direction
			if tc.wrapA == nil && tc.wrapB == nil {
				r.client.Write([]byte("ping"))
				readSome(t, r.target, "ping")
				r.target.Write([]byte("pong"))
				readSome(t, r.client, "pong")
			}
			tc.end(t, r)
			r.wait(t)
			if got := r.calls.Load(); got != tc.wantCalls {
				t.Errorf("resetB called %d times, want %d", got, tc.wantCalls)
			}
			if r.closedFirst.Load() {
				t.Error("resetB ran after b was closed")
			}
		})
	}
}
