package nettun

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestUDPAccountingEmptyDatagramsUsePacketBufferBudget(t *testing.T) {
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
	accepted := after.acceptedSince(before)
	packetSize := len(empty) + stack.PacketBufferStructSize
	wantAccepted := uint64((1000 + packetSize - 1) / packetSize)
	if accepted != wantAccepted {
		t.Fatalf("accepted=%d, want %d from PacketBuffer.MemSize=%d; before=%+v after=%+v", accepted, wantAccepted, packetSize, before, after)
	}
	if overflow := after.overflow - before.overflow; overflow != count-accepted {
		t.Fatalf("receive buffer overflow=%d, want %d", overflow, count-accepted)
	}
	result, _, err := readAccountingDatagram(ep, 1)
	if err != nil || result.Count != 0 || result.Total != 0 {
		t.Fatalf("first Read = (%+v, %v), want one empty datagram", result, err)
	}
	before = snapshotUDPStats(stats)
	injectAccountingDatagram(t, dev, empty)
	after = snapshotUDPStats(stats)
	if after.acceptedSince(before) != 1 || after.overflow != before.overflow {
		t.Fatalf("after one Read: accepted=%d overflow=%d, want 1/0", after.acceptedSince(before), after.overflow-before.overflow)
	}
	for i := uint64(0); i < accepted; i++ {
		result, _, err := readAccountingDatagram(ep, 1)
		if err != nil || result.Count != 0 || result.Total != 0 {
			t.Fatalf("Read %d = (%+v, %v), want one empty datagram", i, result, err)
		}
	}
	if _, _, err := readAccountingDatagram(ep, 1); err == nil {
		t.Fatal("queue remained readable after accepted datagrams were dequeued")
	} else if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
		t.Fatalf("after dequeues error=%v, want ErrWouldBlock", err)
	}
}
