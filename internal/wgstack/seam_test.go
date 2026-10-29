package wgstack

import "testing"

// 中継と internal/netpipe が型アサーションで探すメソッド(設計文書の「今の境目」)。形は
// internal/dataplane/userspace/relay の aborter と、internal/netpipe の closeWriter、deliverer、
// deliveryCloser、boostReporter と同じである。
var (
	_ interface{ Abort() }                  = (*Conn)(nil)
	_ interface{ CloseWrite() error }       = (*Conn)(nil)
	_ interface{ Delivered() bool }         = (*Conn)(nil)
	_ interface{ CloseForDelivery() error } = (*Conn)(nil)
	_ interface{ OnBoost(func(bool) bool) } = (*Conn)(nil)
	_ interface{ UDPReceiveFault() error }  = (*Device)(nil)
)

func TestStubsReturnErrors(t *testing.T) {
	n := newTestNet(t, smallLimits())
	if _, err := n.d.ListenUDP(netipAP(53)); err == nil {
		t.Error("ListenUDP did not fail")
	}
	if _, err := n.d.DialPing(dutAddr, peerAddr); err == nil {
		t.Error("DialPing did not fail")
	}
	if n.d.UDPReceiveFault() != nil {
		t.Error("UDPReceiveFault")
	}
	if _, err := n.d.ListenTCP(netipAP(0)); err == nil {
		t.Error("ListenTCP on port 0")
	}
	listen(t, n, 80)
	if _, err := n.d.ListenTCP(netipAP(80)); err == nil {
		t.Error("second ListenTCP on the same port")
	}
}
