package nettun

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
)

func TestUDPAccountingEmptyDatagramsIgnorePayloadByteLimit(t *testing.T) {
	const count = 128
	dev, ep, stats := newAccountingEndpoint(t)
	ep.SocketOptions().SetReceiveBufferSize(1000, false)
	t.Logf("requested receive buffer=1000, effective=%d", ep.SocketOptions().GetReceiveBufferSize())
	before := snapshotUDPStats(stats)
	empty := accountingDatagram(nil, 0, 0)
	for i := 0; i < count; i++ {
		injectAccountingDatagram(t, dev, empty)
	}
	after := snapshotUDPStats(stats)
	if accepted := after.acceptedSince(before); accepted != count {
		t.Fatalf("accepted=%d, want %d; before=%+v after=%+v", accepted, count, before, after)
	}
	if overflow := after.overflow - before.overflow; overflow != 0 {
		t.Fatalf("receive buffer overflow=%d, want 0", overflow)
	}
	for i := 0; i < count; i++ {
		result, _, err := readAccountingDatagram(ep, 1)
		if err != nil || result.Count != 0 || result.Total != 0 {
			t.Fatalf("Read %d = (%+v, %v), want one empty datagram", i, result, err)
		}
	}
	if _, _, err := readAccountingDatagram(ep, 1); err == nil {
		t.Fatal("queue remained readable after 128 dequeues")
	} else if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
		t.Fatalf("after 128 dequeues error=%v, want ErrWouldBlock", err)
	}
}
