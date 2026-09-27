package nettun

import (
	"bytes"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// This probes the pinned gVisor API, not the adapter. A waiter callback
// that re-enters the outer lock would block a synchronous HandleLocal write.
func TestUDPAccountingLocalWriteWithOuterLock(t *testing.T) {
	dev, err := Create(accountingLocal, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	var mu sync.Mutex
	var rxWQ waiter.Queue
	rx, terr := dev.stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &rxWQ)
	if terr != nil {
		t.Fatalf("receiver endpoint: %v", terr)
	}
	defer rx.Close()
	if terr := rx.Bind(fullAddr(netip.AddrPortFrom(accountingLocal, accountingPort))); terr != nil {
		t.Fatalf("receiver bind: %v", terr)
	}
	stats := rx.Stats().(*tcpip.TransportEndpointStats)
	callbackLockAvailable := make(chan bool, 1)
	entry := waiter.NewFunctionEntry(waiter.ReadableEvents, func(waiter.EventMask) {
		ok := mu.TryLock()
		if ok {
			mu.Unlock()
		}
		select {
		case callbackLockAvailable <- ok:
		default:
		}
	})
	rxWQ.EventRegister(&entry)
	defer rxWQ.EventUnregister(&entry)
	var txWQ waiter.Queue
	tx, terr := dev.stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &txWQ)
	if terr != nil {
		t.Fatalf("sender endpoint: %v", terr)
	}
	defer tx.Close()
	if terr := tx.Connect(fullAddr(netip.AddrPortFrom(accountingLocal, accountingPort))); terr != nil {
		t.Fatalf("sender connect: %v", terr)
	}
	payload := []byte("local")
	mu.Lock()
	before := snapshotUDPStats(stats)
	n, writeErr := tx.Write(bytes.NewReader(payload), tcpip.WriteOptions{})
	after := snapshotUDPStats(stats)
	mu.Unlock()
	if writeErr != nil || n != int64(len(payload)) || after.acceptedSince(before) != 1 {
		t.Fatalf("local Write = (%d, %v), accepted=%d", n, writeErr, after.acceptedSince(before))
	}
	select {
	case available := <-callbackLockAvailable:
		if available {
			t.Fatal("readable callback ran after the outer lock was released")
		}
	default:
		t.Fatal("synchronous readable callback did not run")
	}
	mu.Lock()
	result, data, readErr := readAccountingDatagram(rx, len(payload))
	mu.Unlock()
	if readErr != nil || result.Total != len(payload) || !bytes.Equal(data, payload) {
		t.Fatalf("Read = (%+v, %q, %v)", result, data, readErr)
	}
}

// Read and Close must serialize with the same lock after a local write. The
// allowed outcome is one dequeue or Close discarding the queued datagram.
func TestUDPAccountingLocalReadCloseRace(t *testing.T) {
	for i := 0; i < 8; i++ {
		func() {
			dev, rx, stats := newAccountingEndpoint(t)
			var mu sync.Mutex
			var txWQ waiter.Queue
			tx, terr := dev.stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &txWQ)
			if terr != nil {
				t.Fatalf("sender endpoint: %v", terr)
			}
			defer tx.Close()
			if terr := tx.Connect(fullAddr(netip.AddrPortFrom(accountingLocal, accountingPort))); terr != nil {
				t.Fatalf("sender connect: %v", terr)
			}
			mu.Lock()
			before := snapshotUDPStats(stats)
			_, writeErr := tx.Write(bytes.NewReader([]byte("x")), tcpip.WriteOptions{})
			after := snapshotUDPStats(stats)
			mu.Unlock()
			if writeErr != nil || after.acceptedSince(before) != 1 {
				t.Fatalf("local Write error=%v accepted=%d", writeErr, after.acceptedSince(before))
			}
			const cost = 1 + 64 // payload and the fixed charge per datagram
			reserved := cost
			fifo := []int{cost}
			start := make(chan struct{})
			done := make(chan struct{}, 2)
			go func() {
				<-start
				mu.Lock()
				result, _, readErr := readAccountingDatagram(rx, 1)
				if readErr == nil && result.Total == 1 {
					reserved -= fifo[0]
					fifo = fifo[1:]
				}
				mu.Unlock()
				done <- struct{}{}
			}()
			go func() {
				<-start
				mu.Lock()
				rx.Close()
				for _, v := range fifo {
					reserved -= v
				}
				fifo = nil
				mu.Unlock()
				done <- struct{}{}
			}()
			close(start)
			for j := 0; j < 2; j++ {
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("local Read/Close did not finish")
				}
			}
			mu.Lock()
			if reserved != 0 || len(fifo) != 0 {
				t.Errorf("reservation leaked after Read/Close: reserved=%d fifo=%v", reserved, fifo)
			}
			mu.Unlock()
		}()
	}
}

// Binding and connecting the same local tuple probes whether a single UDP
// endpoint can receive its own locally generated datagram in this pinned API.
func TestUDPAccountingReflexiveEndpoint(t *testing.T) {
	dev, err := Create(accountingLocal, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	var wq waiter.Queue
	ep, terr := dev.stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if terr != nil {
		t.Fatalf("NewEndpoint: %v", terr)
	}
	defer ep.Close()
	addr := fullAddr(netip.AddrPortFrom(accountingLocal, accountingPort))
	if terr := ep.Bind(addr); terr != nil {
		t.Fatalf("Bind: %v", terr)
	}
	if terr := ep.Connect(addr); terr != nil {
		t.Fatalf("Connect to own tuple: %v", terr)
	}
	stats := ep.Stats().(*tcpip.TransportEndpointStats)
	var mu sync.Mutex
	mu.Lock()
	before := snapshotUDPStats(stats)
	n, writeErr := ep.Write(bytes.NewReader([]byte("self")), tcpip.WriteOptions{})
	after := snapshotUDPStats(stats)
	mu.Unlock()
	if writeErr != nil || n != 4 {
		t.Fatalf("reflexive Write = (%d, %v)", n, writeErr)
	}
	if got := after.acceptedSince(before); got != 1 {
		t.Fatalf("reflexive accepted=%d, before=%+v after=%+v", got, before, after)
	}
	mu.Lock()
	result, data, readErr := readAccountingDatagram(ep, 4)
	mu.Unlock()
	if readErr != nil || result.Total != 4 || !bytes.Equal(data, []byte("self")) {
		t.Fatalf("reflexive Read = (%+v, %q, %v)", result, data, readErr)
	}
}

// An unbound local destination can synchronously generate an ICMP port
// unreachable. Probe whether its UDP error notification also runs under the
// writer's outer lock.
func TestUDPAccountingLocalICMPCallback(t *testing.T) {
	dev, err := Create(accountingLocal, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	var mu sync.Mutex
	var wq waiter.Queue
	tx, terr := dev.stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if terr != nil {
		t.Fatalf("sender endpoint: %v", terr)
	}
	defer tx.Close()
	if terr := tx.Connect(fullAddr(netip.AddrPortFrom(accountingLocal, accountingPort))); terr != nil {
		t.Fatalf("sender connect: %v", terr)
	}
	callbackLockAvailable := make(chan bool, 1)
	entry := waiter.NewFunctionEntry(waiter.EventErr, func(waiter.EventMask) {
		ok := mu.TryLock()
		if ok {
			mu.Unlock()
		}
		select {
		case callbackLockAvailable <- ok:
		default:
		}
	})
	wq.EventRegister(&entry)
	defer wq.EventUnregister(&entry)
	mu.Lock()
	n, writeErr := tx.Write(bytes.NewReader([]byte("lost")), tcpip.WriteOptions{})
	mu.Unlock()
	if writeErr != nil || n != 4 {
		t.Fatalf("unbound local Write = (%d, %v)", n, writeErr)
	}
	select {
	case available := <-callbackLockAvailable:
		if available {
			t.Fatal("ICMP callback ran after the outer lock was released")
		}
	default:
		t.Fatal("local port-unreachable did not synchronously notify UDP error")
	}
}
