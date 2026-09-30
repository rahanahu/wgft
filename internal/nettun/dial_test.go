package nettun

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"testing"
	"time"
)

// A relay that cuts a connection it dialed through the netstack (the server's relays toward an
// agent) must reach the agent as a reset, not as a FIN: the agent's relay treats a FIN as a
// half-close and keeps its target connection. DialTCP therefore returns a conn that can Abort,
// and the peer's read fails instead of returning EOF.
func TestDialTCPConnAbortSendsReset(t *testing.T) {
	p := newSaturationPair(t)
	p.startResponses()
	ln, err := p.responder.ListenTCP(netip.MustParseAddrPort("10.99.0.2:19030"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan *TCPConn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c.(*TCPConn)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := p.requester.DialTCP(ctx, netip.MustParseAddrPort("10.99.0.2:19030"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	peer := <-accepted
	if peer == nil {
		t.Fatal("accept failed")
	}
	defer peer.Close()
	a, ok := c.(interface{ Abort() })
	if !ok {
		t.Fatalf("DialTCP returned %T, which cannot Abort", c)
	}
	a.Abort()
	peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = peer.Read(make([]byte, 1))
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the peer should see a reset after Abort, got %v", err)
	}
}

// A dial that the context cancels before the handshake completes returns the context's error, the
// same as gonet.DialContextTCP, whose steps DialTCP copies.
func TestDialTCPContextCancelled(t *testing.T) {
	p := newSaturationPair(t) // no responses: the SYN-ACK never comes back
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := p.requester.DialTCP(ctx, netip.MustParseAddrPort("10.99.0.2:19031"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DialTCP with an expired context: %v", err)
	}
}
