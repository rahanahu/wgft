package nettun

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// These tests exercise the one shared outbound queue using two in-process netstacks.
// Packet forwarding is bounded and the responder's output can be paused independently.
type saturationPair struct {
	requester, responder            *Device
	requestPackets, responsePackets chan []byte
	forwardDone                     []<-chan struct{}
}

func newSaturationPair(t *testing.T) *saturationPair {
	t.Helper()
	a, err := Create(netip.MustParseAddr("10.99.0.1"), 1420)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Create(netip.MustParseAddr("10.99.0.2"), 1420)
	if err != nil {
		a.Close()
		t.Fatal(err)
	}
	p := &saturationPair{requester: a, responder: b, requestPackets: make(chan []byte, 32), responsePackets: make(chan []byte, 32)}
	p.forwardDone = append(p.forwardDone, p.forward(a, b, p.requestPackets))
	t.Cleanup(func() {
		closed := make(chan struct{})
		go func() {
			a.Close()
			b.Close()
			close(closed)
		}()
		select {
		case <-closed:
		case <-time.After(2 * time.Second):
			t.Error("devices did not close")
		}
		for _, done := range p.forwardDone {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Error("TUN forwarder did not stop")
			}
		}
	})
	return p
}

func (p *saturationPair) forward(from, to *Device, observed chan []byte) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		sizes := []int{0}
		for {
			n, err := from.Read([][]byte{buf}, sizes, 0)
			if err != nil {
				return
			}
			if n != 1 {
				return
			}
			packet := append([]byte(nil), buf[:sizes[0]]...)
			select {
			case observed <- packet:
			default:
			}
			if _, err := to.Write([][]byte{packet}, 0); err != nil {
				return
			}
		}
	}()
	return done
}

func (p *saturationPair) startResponses() {
	p.forwardDone = append(p.forwardDone, p.forward(p.responder, p.requester, p.responsePackets))
}

func (p *saturationPair) fillResponder(t *testing.T) {
	t.Helper()
	var packets stack.PacketBufferList
	for i := 0; i < 1025; i++ {
		packets.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{0x45, 0, 0, byte(i)})}))
	}
	n, err := p.responder.ep.WritePackets(packets)
	packets.DecRef() // The queue owns clones of the accepted packets.
	if err != nil || n != 1024 || p.responder.ep.NumQueued() != 1024 {
		t.Fatalf("fill queue: accepted=%d err=%v queued=%d", n, err, p.responder.ep.NumQueued())
	}
}

func (p *saturationPair) drainResponder(t *testing.T) {
	t.Helper()
	for i := 0; i < 1024; i++ {
		pkt := p.responder.ep.Read()
		if pkt == nil {
			t.Fatalf("queue empty after %d drains", i)
		}
		pkt.DecRef()
	}
	if got := p.responder.ep.NumQueued(); got != 0 {
		t.Fatalf("queue after drain=%d", got)
	}
	p.startResponses()
}

func waitPacket(t *testing.T, packets <-chan []byte, match func([]byte) bool) []byte {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case packet := <-packets:
			if match(packet) {
				return packet
			}
		case <-deadline:
			t.Fatal("expected output packet not observed")
		}
	}
}

func packetToPort(packet []byte, proto byte, port uint16) bool {
	if len(packet) < 28 || packet[0]>>4 != 4 || packet[9] != proto {
		return false
	}
	off := int(packet[0]&0xf) * 4
	return off+4 <= len(packet) && uint16(packet[off+2])<<8|uint16(packet[off+3]) == port
}

func reverseTuple(response, request []byte, proto byte) bool {
	if len(response) < 28 || len(request) < 28 || response[0]>>4 != 4 || request[0]>>4 != 4 || response[9] != proto || request[9] != proto {
		return false
	}
	rOff := int(response[0]&0xf) * 4
	qOff := int(request[0]&0xf) * 4
	return rOff+4 <= len(response) && qOff+4 <= len(request) &&
		bytes.Equal(response[12:16], request[16:20]) && bytes.Equal(response[16:20], request[12:16]) &&
		bytes.Equal(response[rOff:rOff+2], request[qOff+2:qOff+4]) &&
		bytes.Equal(response[rOff+2:rOff+4], request[qOff:qOff+2])
}

func isPortUnreachableFor(response, request []byte) bool {
	if !isICMP(response, 3, 3) || len(request) < 28 || request[9] != 17 {
		return false
	}
	off := int(response[0]&0xf)*4 + 8
	if off+28 > len(response) || response[off]>>4 != 4 || response[off+9] != 17 {
		return false
	}
	inner := response[off:]
	iOff := int(inner[0]&0xf) * 4
	rOff := int(request[0]&0xf) * 4
	return iOff+4 <= len(inner) && rOff+4 <= len(request) &&
		bytes.Equal(response[12:16], request[16:20]) && bytes.Equal(response[16:20], request[12:16]) &&
		bytes.Equal(inner[12:20], request[12:20]) && bytes.Equal(inner[iOff:iOff+4], request[rOff:rOff+4])
}

func isICMP(packet []byte, typ, code byte) bool {
	if len(packet) < 28 || packet[0]>>4 != 4 || packet[9] != 1 {
		return false
	}
	off := int(packet[0]&0xf) * 4
	return off+2 <= len(packet) && packet[off] == typ && packet[off+1] == code
}

func isTCPRST(packet []byte) bool {
	if len(packet) < 34 || packet[0]>>4 != 4 || packet[9] != 6 {
		return false
	}
	off := int(packet[0]&0xf) * 4
	return off+14 <= len(packet) && packet[off+13]&0x04 != 0
}

func pingOnce(p *saturationPair, deadline time.Duration) error {
	c, err := p.requester.DialPing(netip.MustParseAddr("10.99.0.1"), netip.MustParseAddr("10.99.0.2"))
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(deadline)); err != nil {
		return err
	}
	msg, err := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: 7, Seq: 1, Data: []byte("probe")}}).Marshal(nil)
	if err != nil {
		return err
	}
	if _, err = c.Write(msg); err != nil {
		return err
	}
	buf := make([]byte, 128)
	n, err := c.Read(buf)
	if err != nil {
		return err
	}
	parsed, err := icmp.ParseMessage(1, buf[:n])
	if err != nil {
		return err
	}
	if parsed.Type != ipv4.ICMPTypeEchoReply {
		return errors.New("wrong ICMP response")
	}
	echo, ok := parsed.Body.(*icmp.Echo)
	if !ok || echo.Seq != 1 || !bytes.Equal(echo.Data, []byte("probe")) {
		return errors.New("wrong ICMP echo payload")
	}
	return nil
}

func TestNormalOutputControl(t *testing.T) {
	p := newSaturationPair(t)
	p.startResponses()
	if err := pingOnce(p, 2*time.Second); err != nil {
		t.Fatalf("normal ICMP: %v", err)
	}

	udpListener, err := p.responder.ListenUDP(netip.MustParseAddrPort("10.99.0.2:19010"))
	if err != nil {
		t.Fatal(err)
	}
	udpDone := make(chan struct{})
	defer func() {
		udpListener.Close()
		select {
		case <-udpDone:
		case <-time.After(2 * time.Second):
			t.Error("normal UDP echo goroutine did not stop")
		}
	}()
	go func() {
		defer close(udpDone)
		buf := make([]byte, 32)
		_ = udpListener.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, peer, err := udpListener.ReadFrom(buf)
		if err == nil {
			_, _ = udpListener.WriteTo(buf[:n], peer)
		}
	}()
	udp, err := p.requester.DialUDP(netip.MustParseAddrPort("10.99.0.2:19010"))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := udp.Write([]byte("udp")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := udp.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], []byte("udp")) {
		t.Fatalf("normal UDP: %q, %v", buf[:n], err)
	}

	ln, err := p.responder.ListenTCP(netip.MustParseAddrPort("10.99.0.2:19011"))
	if err != nil {
		t.Fatal(err)
	}
	tcpDone := make(chan struct{})
	defer func() {
		ln.Close()
		select {
		case <-tcpDone:
		case <-time.After(2 * time.Second):
			t.Error("normal TCP echo goroutine did not stop")
		}
	}()
	go func() {
		defer close(tcpDone)
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	tcp, err := p.requester.DialTCP(ctx, netip.MustParseAddrPort("10.99.0.2:19011"))
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	_ = tcp.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := tcp.Write([]byte("tcp")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(tcp, buf[:3]); err != nil || !bytes.Equal(buf[:3], []byte("tcp")) {
		t.Fatalf("normal TCP: %q, %v", buf[:3], err)
	}

	closedUDP, err := p.requester.DialUDP(netip.MustParseAddrPort("10.99.0.2:19012"))
	if err != nil {
		t.Fatal(err)
	}
	defer closedUDP.Close()
	if _, err := closedUDP.Write([]byte("closed")); err != nil {
		t.Fatal(err)
	}
	udpRequest := waitPacket(t, p.requestPackets, func(pkt []byte) bool { return packetToPort(pkt, 17, 19012) })
	waitPacket(t, p.responsePackets, func(pkt []byte) bool { return isPortUnreachableFor(pkt, udpRequest) })
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	closedTCP, err := p.requester.DialTCP(ctx, netip.MustParseAddrPort("10.99.0.2:19013"))
	cancel()
	if err == nil {
		closedTCP.Close()
		t.Fatal("closed TCP port connected")
	}
	tcpRequest := waitPacket(t, p.requestPackets, func(pkt []byte) bool { return packetToPort(pkt, 6, 19013) })
	waitPacket(t, p.responsePackets, func(pkt []byte) bool { return isTCPRST(pkt) && reverseTuple(pkt, tcpRequest, 6) })
}

func TestSaturatedOutputDropsICMPAndRecovers(t *testing.T) {
	p := newSaturationPair(t)
	p.fillResponder(t)
	if err := pingOnce(p, 200*time.Millisecond); err == nil {
		t.Fatal("ICMP echo unexpectedly returned through full output queue")
	}
	if got := p.responder.ep.NumQueued(); got != 1024 {
		t.Fatalf("queued=%d after dropped echo", got)
	}
	p.drainResponder(t)
	if err := pingOnce(p, 2*time.Second); err != nil {
		t.Fatalf("ICMP after drain: %v", err)
	}
	waitPacket(t, p.responsePackets, func(pkt []byte) bool { return isICMP(pkt, 0, 0) })
}

func TestSaturatedOutputDropsUDPAndRecovers(t *testing.T) {
	p := newSaturationPair(t)
	listener, err := p.responder.ListenUDP(netip.MustParseAddrPort("10.99.0.2:19001"))
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan struct{})
	defer func() {
		listener.Close()
		select {
		case <-serverDone:
		case <-time.After(2 * time.Second):
			t.Error("saturated UDP echo goroutine did not stop")
		}
	}()
	served := make(chan []byte, 2)
	go func() {
		defer close(serverDone)
		buf := make([]byte, 128)
		for i := 0; i < 2; i++ {
			_ = listener.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, peer, err := listener.ReadFrom(buf)
			if err != nil {
				return
			}
			payload := append([]byte(nil), buf[:n]...)
			_, _ = listener.WriteTo(payload, peer)
			served <- payload
		}
	}()
	c, err := p.requester.DialUDP(netip.MustParseAddrPort("10.99.0.2:19001"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p.fillResponder(t)
	_ = c.SetDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := c.Write([]byte("lost")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("UDP echo unexpectedly returned through full output queue")
	}
	select {
	case got := <-served:
		if string(got) != "lost" {
			t.Fatalf("served %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("responder did not receive UDP request")
	}
	if got := p.responder.ep.NumQueued(); got != 1024 {
		t.Fatalf("queued=%d after dropped UDP echo", got)
	}
	p.drainResponder(t)
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("recovered")); err != nil {
		t.Fatal(err)
	}
	n, err := c.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], []byte("recovered")) {
		t.Fatalf("UDP after drain: %q, %v", buf[:n], err)
	}
}

func TestSaturatedOutputDropsTCPAndRecovers(t *testing.T) {
	p := newSaturationPair(t)
	ln, err := p.responder.ListenTCP(netip.MustParseAddrPort("10.99.0.2:19002"))
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan struct{})
	defer func() {
		ln.Close()
		select {
		case <-serverDone:
		case <-time.After(2 * time.Second):
			t.Error("saturated TCP echo goroutine did not stop")
		}
	}()
	go func() {
		defer close(serverDone)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = io.Copy(c, c)
			c.Close()
		}
	}()
	p.fillResponder(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	c, err := p.requester.DialTCP(ctx, netip.MustParseAddrPort("10.99.0.2:19002"))
	cancel()
	if err == nil {
		c.Close()
		t.Fatal("TCP handshake unexpectedly completed through full output queue")
	}
	if got := p.responder.ep.NumQueued(); got != 1024 {
		t.Fatalf("queued=%d after dropped SYN-ACK", got)
	}
	p.drainResponder(t)
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	c, err = p.requester.DialTCP(ctx, netip.MustParseAddrPort("10.99.0.2:19002"))
	cancel()
	if err != nil {
		t.Fatalf("TCP after drain: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil || !bytes.Equal(buf, []byte("ok")) {
		t.Fatalf("TCP echo after drain: %q, %v", buf, err)
	}
}

// The dial begins while the return path is full and remains the same pending
// attempt after drain. Its eventual completion depends on TCP retransmission.
func TestSaturatedOutputPendingTCPAfterDrain(t *testing.T) {
	p := newSaturationPair(t)
	ln, err := p.responder.ListenTCP(netip.MustParseAddrPort("10.99.0.2:19020"))
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan struct{})
	defer func() {
		ln.Close()
		select {
		case <-serverDone:
		case <-time.After(2 * time.Second):
			t.Error("pending TCP echo goroutine did not stop")
		}
	}()
	go func() {
		defer close(serverDone)
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = io.Copy(c, c)
		}
	}()
	p.fillResponder(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	var dialConn net.Conn
	var dialErr error
	dialDone := make(chan struct{})
	go func() {
		dialConn, dialErr = p.requester.DialTCP(ctx, netip.MustParseAddrPort("10.99.0.2:19020"))
		close(dialDone)
	}()
	defer func() {
		cancel()
		select {
		case <-dialDone:
			if dialConn != nil {
				dialConn.Close()
			}
		case <-time.After(2 * time.Second):
			t.Error("pending DialTCP goroutine did not stop")
		}
	}()
	waitPacket(t, p.requestPackets, func(pkt []byte) bool {
		if !packetToPort(pkt, 6, 19020) {
			return false
		}
		off := int(pkt[0]&0xf) * 4
		return off+14 <= len(pkt) && pkt[off+13]&0x02 != 0
	})
	select {
	case <-dialDone:
		t.Fatalf("pending dial completed before drain: %v", dialErr)
	case <-time.After(200 * time.Millisecond):
	}
	p.drainResponder(t)
	drainedAt := time.Now()
	select {
	case <-dialDone:
	case <-ctx.Done():
		t.Fatalf("same pending dial did not finish after drain: %v", ctx.Err())
	}
	if dialErr != nil {
		t.Fatalf("same pending dial after drain: %v", dialErr)
	}
	t.Logf("same pending dial completed %.3fs after drain in this fixture", time.Since(drainedAt).Seconds())
	_ = dialConn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := dialConn.Write([]byte("pending")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("pending"))
	if _, err := io.ReadFull(dialConn, buf); err != nil || !bytes.Equal(buf, []byte("pending")) {
		t.Fatalf("same pending TCP echo: %q, %v", buf, err)
	}
}

func TestRefusalPacketsAfterOutputDrain(t *testing.T) {
	p := newSaturationPair(t)
	p.fillResponder(t)
	udp, err := p.requester.DialUDP(netip.MustParseAddrPort("10.99.0.2:19003"))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	_, _ = udp.Write([]byte("closed"))
	waitPacket(t, p.requestPackets, func(pkt []byte) bool { return packetToPort(pkt, 17, 19003) })
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	c, err := p.requester.DialTCP(ctx, netip.MustParseAddrPort("10.99.0.2:19004"))
	cancel()
	if err == nil {
		c.Close()
		t.Fatal("closed TCP port unexpectedly connected")
	}
	waitPacket(t, p.requestPackets, func(pkt []byte) bool { return packetToPort(pkt, 6, 19004) })
	if got := p.responder.ep.NumQueued(); got != 1024 {
		t.Fatalf("queued=%d after dropped refusals", got)
	}
	p.drainResponder(t)
	_, _ = udp.Write([]byte("closed-again"))
	udpRequest := waitPacket(t, p.requestPackets, func(pkt []byte) bool { return packetToPort(pkt, 17, 19003) })
	waitPacket(t, p.responsePackets, func(pkt []byte) bool { return isPortUnreachableFor(pkt, udpRequest) })
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	c, err = p.requester.DialTCP(ctx, netip.MustParseAddrPort("10.99.0.2:19005"))
	cancel()
	if err == nil {
		c.Close()
		t.Fatal("closed TCP port connected after drain")
	}
	tcpRequest := waitPacket(t, p.requestPackets, func(pkt []byte) bool { return packetToPort(pkt, 6, 19005) })
	waitPacket(t, p.responsePackets, func(pkt []byte) bool { return isTCPRST(pkt) && reverseTuple(pkt, tcpRequest, 6) })
}

func TestSaturatedOutputCloseReturns(t *testing.T) {
	p := newSaturationPair(t)
	p.fillResponder(t)
	done := make(chan struct{})
	go func() {
		p.responder.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked on full output queue")
	}
}
