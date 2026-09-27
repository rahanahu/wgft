package nettun

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ping_test.go の試験が使う、2 つの Device を TUN の Read と Write でつないだ組と補助の関数。
// 名前と形は、後の版の nettun の試験の補助 (saturation_test.go と ingress_test.go) の一部に揃えてある。

var (
	ingressLocal  = netip.MustParseAddr("10.99.0.1")
	ingressRemote = netip.MustParseAddr("10.99.0.2")
)

func ingressDevice(t *testing.T) *Device {
	t.Helper()
	d, err := Create(ingressLocal, 1420)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

type saturationPair struct {
	requester, responder            *Device
	requestPackets, responsePackets chan []byte
	forwardDone                     []<-chan struct{}
}

func newSaturationPair(t *testing.T) *saturationPair {
	t.Helper()
	a, err := Create(ingressLocal, 1420)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Create(ingressRemote, 1420)
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

// forward は from が送り出したパケットを to へ渡し、observed に写しを置く (満杯なら置かない)。
func (p *saturationPair) forward(from, to *Device, observed chan []byte) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		sizes := []int{0}
		for {
			n, err := from.Read([][]byte{buf}, sizes, 0)
			if err != nil || n != 1 {
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

func isICMP(packet []byte, typ, code byte) bool {
	if len(packet) < 28 || packet[0]>>4 != 4 || packet[9] != 1 {
		return false
	}
	off := int(packet[0]&0xf) * 4
	return off+2 <= len(packet) && packet[off] == typ && packet[off+1] == code
}

// pingOnce は requester から responder へ echo を 1 つ送り、正しい echo reply が返ることを確かめる。
func pingOnce(p *saturationPair, deadline time.Duration) error {
	c, err := p.requester.DialPing(ingressLocal, ingressRemote)
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
