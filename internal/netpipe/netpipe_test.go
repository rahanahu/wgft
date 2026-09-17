package netpipe

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
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
