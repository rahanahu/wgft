package wgstack

import (
	"testing"
	"time"
)

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

func TestListenErrors(t *testing.T) {
	n := newTestNet(t, smallLimits())
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
	if _, err := n.d.ListenUDP(netipAP(0)); err == nil {
		t.Error("ListenUDP on port 0")
	}
	if _, err := n.d.ListenUDP(netipAP(53)); err != nil {
		t.Fatal(err)
	}
	if _, err := n.d.ListenUDP(netipAP(53)); err == nil {
		t.Error("second ListenUDP on the same port")
	}
}

// TestTimerGoroutine は本番の時計の Device で、タイマーの goroutine が SYN-ACK を再送することを確かめる。
func TestTimerGoroutine(t *testing.T) {
	d, err := newDevice(Config{Addr: dutAddr, MTU: testMTU}, smallLimits(), newBoostPool(1))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := d.ListenTCP(netipAP(80)); err != nil {
		t.Fatal(err)
	}
	d.Write([][]byte{buildPeer(tseg{sport: 5, dport: 80, seq: 1, flags: flagSYN, wnd: 1000, mss: 1380, ws: -1})}, 0)
	got := make(chan time.Time, 4)
	go func() {
		buf := make([]byte, 2000)
		for {
			if _, err := d.Read([][]byte{buf}, []int{0}, 0); err != nil {
				return
			}
			got <- time.Now()
		}
	}()
	first := <-got
	select {
	case second := <-got:
		if gap := second.Sub(first); gap < 900*time.Millisecond || gap > 3*time.Second {
			t.Fatalf("SYN-ACK retransmitted after %v", gap)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no SYN-ACK retransmission")
	}
}
