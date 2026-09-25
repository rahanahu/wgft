package agent

import (
	"bufio"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestListenControlExplainsLongPath は、sun_path に収まらないパスで制御ソケットを開けないとき、
// エラーがバイト数と対処を言うことを確かめる。Go の net は OS を呼ぶ前に拒否するので、
// ディレクトリが実在しなくても同じエラーになる。
func TestListenControlExplainsLongPath(t *testing.T) {
	path := ControlPath(filepath.Join(t.TempDir(), strings.Repeat("d", 120), "agent.json"))
	ln, err := listenControl(path)
	if err == nil {
		ln.Close()
		t.Fatalf("listenControl(%d-byte path) succeeded; want an error", len(path))
	}
	for _, want := range []string{"shorter data directory", "bytes"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// TestListenControlShortPath は、短いパスでは説明を足さずに開けることを確かめる。
func TestListenControlShortPath(t *testing.T) {
	dir := t.TempDir()
	path := ControlPath(filepath.Join(dir, "agent.json"))
	if len(path) > ControlPathLimit {
		t.Skipf("temp dir %q is already too long for a Unix socket", dir)
	}
	ln, err := listenControl(path)
	if err != nil {
		t.Fatalf("listenControl(%q): %v", path, err)
	}
	ln.Close()
}

// fakeControlServer opens a real Unix listener at ControlPath(path) and answers a single
// connection's "rotate-key\n" request with reply (verbatim, not necessarily well-formed), so the
// tests below exercise rotateKeyRunning's actual socket read rather than a simulated one.
//
// t.TempDir() can be long enough on its own (macOS's /var/folders/.../T/<test name><random>/001,
// Windows's C:\Users\RUNNER~1\AppData\Local\Temp\<test name><random>\001) to push ControlPath(path)
// past sun_path's limit before this test ever adds anything of its own; skip rather than fail in
// that case, the same way TestListenControlShortPath (this file) and serveTestControl
// (doctor_test.go) do. This is not the path-too-long behavior under test here, so skipping loses no
// coverage of it.
func fakeControlServer(t *testing.T, path string, reply func(net.Conn)) {
	t.Helper()
	sock := ControlPath(path)
	if len(sock) > ControlPathLimit {
		t.Skipf("temp dir makes the control socket path %d bytes, over the sun_path limit: %s", len(sock), sock)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("this host cannot open a unix socket at %s: %v", sock, err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		bufio.NewReader(c).ReadString('\n') //nolint:errcheck // the request line; its content is fixed
		reply(c)
	}()
}

// TestRotateKeyRunningSanitizesAHostileReply confirms that a compromised running agent's reply
// (design.md 11 節: the agent process answering this socket is outside the trust boundary) cannot
// put raw terminal control bytes into the message RotateKey hands back to the operator's CLI.
// Mutation check: removing the textsafe.SanitizeForTerminal call in rotateKeyRunning makes this
// fail, since the raw ESC would then survive into msg.
func TestRotateKeyRunningSanitizesAHostileReply(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	fakeControlServer(t, path, func(c net.Conn) {
		fmt.Fprintf(c, "ok fakepubkey\x1b[2Jinjected\x07\n")
	})
	msg, err := rotateKeyRunning(path)
	if err != nil {
		t.Fatalf("rotateKeyRunning: %v", err)
	}
	if strings.ContainsAny(msg, "\x1b\x07") {
		t.Errorf("rotateKeyRunning message still has a raw control byte: %q", msg)
	}
	if !strings.Contains(msg, "fakepubkey") {
		t.Errorf("rotateKeyRunning message = %q, want it to still carry the reported key text", msg)
	}
}

// TestRotateKeyRunningCapsAnUnboundedReply confirms that a running agent which never sends the
// newline bufio.Reader.ReadString waits for does not make rotateKeyRunning buffer without bound.
// Mutation check: removing the io.LimitReader wrap in rotateKeyRunning makes this fail, since the
// read then blocks until the connection's 30-second deadline instead of hitting EOF at
// rotateKeyReplyLimit.
func TestRotateKeyRunningCapsAnUnboundedReply(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	fakeControlServer(t, path, func(c net.Conn) {
		// Exactly at the cap, and never a newline: a well-behaved bufio.Reader over an
		// unbounded connection would keep waiting for more input past this point.
		c.Write(make([]byte, rotateKeyReplyLimit)) //nolint:errcheck // best effort; the read side decides the outcome
		<-block                                    // hold the connection open instead of closing it
	})

	done := make(chan error, 1)
	go func() {
		_, err := rotateKeyRunning(path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("rotateKeyRunning succeeded reading an unbounded, newline-free reply; want an error at the cap")
		}
		// The message should name the limit, not just say "EOF": a bare EOF reads like the
		// agent closed the connection early, not like this size cap was hit (レビューの指摘,
		// 2026-09-26; see ReadControlReply's own doc comment).
		if !strings.Contains(err.Error(), "exceeded") || !strings.Contains(err.Error(), "limit") {
			t.Errorf("rotateKeyRunning error = %q, want it to say the reply exceeded the limit, not a bare EOF", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("rotateKeyRunning did not return within 3s; it is buffering the reply without the size cap (want EOF at rotateKeyReplyLimit, not the 30s connection deadline)")
	}
}
