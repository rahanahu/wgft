package netpipe

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// wrapped は *net.TCPConn を隠して、splice ではなく自前の複写を通す(netstack の接続の代わり)。
type wrapped struct{ *net.TCPConn }

func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(ch)
			return
		}
		ch <- c
	}()
	client, err = net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server = <-ch
	if server == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

// 大きい転送の途中に無通信を挟んでも中身が変わらず、ハーフクローズが端から端まで伝わる。
func TestPipeBulkWithPausesAndHalfClose(t *testing.T) {
	a, aPipe := tcpPair(t) // a: 送り手
	bPipe, b := tcpPair(t) // b: 受け手
	go Pipe(wrapped{aPipe.(*net.TCPConn)}, wrapped{bPipe.(*net.TCPConn)})

	data := make([]byte, 3<<20)
	rand.Read(data)
	go func() {
		// 小さい書き込み、無通信(bulkWait より長い)、大きい書き込みを混ぜる
		a.Write(data[:100])
		time.Sleep(2 * bulkWait)
		a.Write(data[100 : 1<<20])
		time.Sleep(2 * bulkWait)
		a.Write(data[1<<20:])
		a.(*net.TCPConn).CloseWrite()
	}()
	b.SetDeadline(time.Now().Add(10 * time.Second))
	got, err := io.ReadAll(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("payload differs: got %d bytes, want %d", len(got), len(data))
	}
	// 反対向きはまだ開いている
	if _, err := b.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	b.(*net.TCPConn).CloseWrite()
	a.SetDeadline(time.Now().Add(5 * time.Second))
	back, err := io.ReadAll(a)
	if err != nil || string(back) != "reply" {
		t.Fatalf("reverse direction after half-close: %q %v", back, err)
	}
}

// resetConn closes c with a reset: the peer's next read fails with ECONNRESET instead of EOF.
func resetConn(t *testing.T, c net.Conn) {
	t.Helper()
	if err := c.(*net.TCPConn).SetLinger(0); err != nil {
		t.Fatal(err)
	}
	c.Close()
}

// pipeRig relays between a client conn and a target conn through Pipe and reports when Pipe
// returns. copyPath hides *net.TCPConn so that Pipe copies through its own buffers, the way it
// does for a netstack conn; otherwise both sides are kernel TCP and io.Copy splices.
type pipeRig struct {
	client, target net.Conn
	done           chan struct{}
}

func newPipeRig(t *testing.T, copyPath bool, wrapTarget func(net.Conn) net.Conn) *pipeRig {
	t.Helper()
	client, cSide := tcpPair(t)
	tSide, target := tcpPair(t)
	var a, b net.Conn = cSide, tSide
	if copyPath {
		a, b = wrapped{cSide.(*net.TCPConn)}, wrapped{tSide.(*net.TCPConn)}
	}
	if wrapTarget != nil {
		b = wrapTarget(b)
	}
	r := &pipeRig{client: client, target: target, done: make(chan struct{})}
	go func() {
		Pipe(a, b)
		close(r.done)
	}()
	return r
}

// readSome reads exactly len(want) bytes from c and compares them with want.
func readSome(t *testing.T, c net.Conn, want string) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != want {
		t.Fatalf("read %q, %v; want %q", got, err, want)
	}
	c.SetReadDeadline(time.Time{})
}

// waitEnded fails unless Pipe returns and the silent peer sees its side closed. The silent peer
// never writes and never closes, so a relay that treats the reset as a half-close keeps reading
// from it and never ends.
func (r *pipeRig) waitEnded(t *testing.T, silent net.Conn) {
	t.Helper()
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the pipe kept running after one side ended with an error: it still reads from the silent side")
	}
	silent.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := silent.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the silent side was not closed: %v", err)
	}
}

// A reset on one side ends the relay at once: both sides are closed, although the other peer
// stays silent and never closes. A clean EOF would only half-close the other side (see the
// half-close tests), but a reset leaves no direction to wait for.
func TestPipeResetClosesBothSides(t *testing.T) {
	for _, tc := range []struct {
		name        string
		copyPath    bool
		resetTarget bool
		// bulk sends more than the idle buffer first, so the reset reaches the copy while it
		// still holds the bulk buffer (within bulkWait of the last data)
		bulk bool
	}{
		{"copy, client resets", true, false, false},
		{"copy, target resets", true, true, false},
		{"copy bulk, client resets", true, false, true},
		{"splice, client resets", false, false, false},
		{"splice, target resets", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newPipeRig(t, tc.copyPath, nil)
			msg := "hello"
			if tc.bulk {
				msg = strings.Repeat("b", 4*idleBufSize)
			}
			r.client.Write([]byte(msg))
			readSome(t, r.target, msg)
			resetting, silent := r.client, r.target
			if tc.resetTarget {
				resetting, silent = r.target, r.client
			}
			resetConn(t, resetting)
			r.waitEnded(t, silent)
		})
	}
}

// failWrite makes every write to the conn fail while reads still work, so the only thing that can
// end the relay is the failed write.
type failWrite struct{ net.Conn }

func (failWrite) Write([]byte) (int, error) { return 0, errors.New("injected write failure") }

func (f failWrite) CloseWrite() error { return f.Conn.(closeWriter).CloseWrite() }

// A failed write ends the relay the same way as a failed read: the direction cannot carry data any
// more, and treating it as a half-close would leave the other direction reading from a silent peer.
func TestPipeWriteFailureClosesBothSides(t *testing.T) {
	r := newPipeRig(t, true, func(c net.Conn) net.Conn { return failWrite{c} })
	r.client.Write([]byte("hello"))
	r.waitEnded(t, r.target)
}

// A clean EOF stays a half-close on both copy paths: the other direction keeps carrying data until
// its own EOF, and the relay ends only then.
func TestPipeEOFKeepsTheOtherDirection(t *testing.T) {
	for _, tc := range []struct {
		name     string
		copyPath bool
	}{{"copy", true}, {"splice", false}} {
		t.Run(tc.name, func(t *testing.T) {
			r := newPipeRig(t, tc.copyPath, nil)
			r.client.Write([]byte("request"))
			r.client.(*net.TCPConn).CloseWrite()
			readSome(t, r.target, "request")
			r.target.SetReadDeadline(time.Now().Add(5 * time.Second))
			if n, err := r.target.Read(make([]byte, 1)); n != 0 || err != io.EOF {
				t.Fatalf("the target should see EOF after the client's FIN: %d, %v", n, err)
			}
			// The target answers well after the FIN; the relay still carries it.
			time.Sleep(2 * bulkWait)
			select {
			case <-r.done:
				t.Fatal("the pipe ended on the client's FIN while the target could still answer")
			default:
			}
			r.target.Write([]byte("late reply"))
			readSome(t, r.client, "late reply")
			r.target.(*net.TCPConn).CloseWrite()
			select {
			case <-r.done:
			case <-time.After(5 * time.Second):
				t.Fatal("the pipe did not end after both directions reached EOF")
			}
			r.client.SetReadDeadline(time.Now().Add(5 * time.Second))
			if n, err := r.client.Read(make([]byte, 1)); n != 0 || err != io.EOF {
				t.Fatalf("the client should see EOF after the target's FIN: %d, %v", n, err)
			}
		})
	}
}

// endRecorder stands in for a netstack conn that has a relay-end close. It records which close the
// relay used.
type endRecorder struct {
	net.Conn
	plain, relayEnd atomic.Int32
}

func (r *endRecorder) CloseWrite() error { return r.Conn.(closeWriter).CloseWrite() }

func (r *endRecorder) Close() error {
	r.plain.Add(1)
	return r.Conn.Close()
}

func (r *endRecorder) CloseAfterRelay() error {
	r.relayEnd.Add(1)
	return r.Conn.Close()
}

// The relay closes a conn that has a relay-end close only through it, at both places where the
// relay ends: after both directions reached EOF and after one direction failed. A half-close
// stays a CloseWrite and does not use it.
func TestPipeUsesRelayEndClose(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  func(t *testing.T, r *pipeRig)
	}{
		{"both directions EOF", func(t *testing.T, r *pipeRig) {
			r.target.(*net.TCPConn).CloseWrite()
			readEOF(t, r.client)
			r.client.(*net.TCPConn).CloseWrite()
		}},
		{"one direction fails", func(t *testing.T, r *pipeRig) {
			resetConn(t, r.client)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rec *endRecorder
			r := newPipeRig(t, true, func(c net.Conn) net.Conn {
				rec = &endRecorder{Conn: c}
				return rec
			})
			r.client.Write([]byte("hello"))
			readSome(t, r.target, "hello")
			if n := rec.relayEnd.Load() + rec.plain.Load(); n != 0 {
				t.Fatalf("closed %d times while relaying", n)
			}
			tc.end(t, r)
			select {
			case <-r.done:
			case <-time.After(5 * time.Second):
				t.Fatal("the pipe did not end")
			}
			if rec.relayEnd.Load() == 0 || rec.plain.Load() != 0 {
				t.Fatalf("relay-end close %d, plain Close %d; want only the relay-end close", rec.relayEnd.Load(), rec.plain.Load())
			}
		})
	}
}

// readEOF reads from c until EOF.
func readEOF(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.Copy(io.Discard, c); err != nil {
		t.Fatalf("read to EOF: %v", err)
	}
	c.SetReadDeadline(time.Time{})
}
