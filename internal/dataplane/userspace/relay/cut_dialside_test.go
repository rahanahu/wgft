package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestCutConnKeepsFINOnTheDialSide は、vpsd の側(netstack の dial した接続)を中継が切るとき、
// cutConn が RST ではなく今までどおり graceful な Close(FIN)で切ることを固定する。dial した
// 接続は Abort を持たない型なので、cutConn の aborter の分岐に入らない(設計文書 7 節)。
func TestCutConnKeepsFINOnTheDialSide(t *testing.T) {
	client, n := netstackPair(t)
	ln, err := n.dev.ListenTCP(netip.AddrPortFrom(cutAgentAddr, 7100))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := client.DialTCP(ctx, netip.AddrPortFrom(cutAgentAddr, 7100))
	if err != nil {
		t.Fatal(err)
	}
	var s net.Conn
	select {
	case s = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("accept timed out")
	}
	defer s.Close()
	if _, ok := c.(aborter); ok {
		t.Fatal("the dialed netstack connection satisfies aborter; cutConn would send RST")
	}
	cutConn(c)
	s.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	_, err = s.Read(buf)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("peer read after cutConn: %v; want io.EOF from a graceful close, not a reset", err)
	}
}
