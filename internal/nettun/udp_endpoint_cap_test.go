package nettun

import (
	"bytes"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// These tests pin the per-endpoint (per-generation) cap of the UDP
// accounting: one receiving endpoint cannot hold more than its cap of
// the Device budget, other endpoints keep reserving, and Read and Close
// return the endpoint's share.

func endpointUsage(t *testing.T, r *udpRegistry, c *rawUDPAdapter) (int, int) {
	t.Helper()
	acc := r.accounting
	acc.mu.Lock()
	defer acc.mu.Unlock()
	g := acc.generations[c]
	if g == nil {
		t.Fatal("generation missing")
	}
	return g.usedBytes, g.usedPackets
}

func injectN(t *testing.T, r *udpRegistry, n int, payload []byte, src, dst uint16) (kept int) {
	t.Helper()
	for i := 0; i < n; i++ {
		ok, err := r.inject(registryPacket(payload, src, dst))
		if err != nil {
			t.Fatalf("inject %d: %v", i, err)
		}
		if ok {
			kept++
		}
	}
	return kept
}

func readOne(t *testing.T, c *rawUDPAdapter) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ReadFrom(make([]byte, 64)); err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
}

func TestUDPEndpointCapStopsOneEndpointOthersStillReserve(t *testing.T) {
	_, r := registryFixture(t) // Device budget 4096 bytes, 64 packets
	r.accounting.setEndpointLimits(4096, 3)
	a := registryListen(t, r, 40001)
	b := registryListen(t, r, 40002)

	if kept := injectN(t, r, 5, []byte("abc"), 50000, 40001); kept != 3 {
		t.Fatalf("stalled endpoint kept %d datagrams, want its cap 3", kept)
	}
	if _, p := endpointUsage(t, r, a); p != 3 {
		t.Fatalf("endpoint A usage %d packets, want 3", p)
	}
	assertRegistryUsage(t, r, 3*67, 3)
	if kept := injectN(t, r, 2, []byte("abc"), 50001, 40002); kept != 2 {
		t.Fatalf("other endpoint kept %d, want 2 while A is at its cap", kept)
	}
	assertRegistryUsage(t, r, 5*67, 5)
	_ = b
}

func TestUDPEndpointCapReadAndCloseReturnTheShare(t *testing.T) {
	_, r := registryFixture(t)
	r.accounting.setEndpointLimits(4096, 2)
	a := registryListen(t, r, 40003)
	if kept := injectN(t, r, 3, []byte("x"), 50000, 40003); kept != 2 {
		t.Fatalf("kept %d, want 2", kept)
	}
	readOne(t, a)
	if b, p := endpointUsage(t, r, a); p != 1 || b != 65 {
		t.Fatalf("after Read endpoint usage %d/%d, want 65/1", b, p)
	}
	if kept := injectN(t, r, 2, []byte("x"), 50000, 40003); kept != 1 {
		t.Fatalf("after Read kept %d, want 1 (one slot returned)", kept)
	}
	assertRegistryUsage(t, r, 2*65, 2)
	a.Close()
	assertRegistryUsage(t, r, 0, 0)
	// A new generation on the same port starts from zero.
	a2 := registryListen(t, r, 40003)
	if kept := injectN(t, r, 3, []byte("x"), 50000, 40003); kept != 2 {
		t.Fatalf("new generation kept %d, want 2", kept)
	}
	if _, p := endpointUsage(t, r, a2); p != 2 {
		t.Fatalf("new generation usage %d, want 2", p)
	}
}

func TestUDPEndpointCapBoundaries(t *testing.T) {
	// Packet cap: the cap-th datagram is kept, the next is refused.
	_, r := registryFixture(t)
	r.accounting.setEndpointLimits(4096, 4)
	registryListen(t, r, 40004)
	if kept := injectN(t, r, 4, []byte("x"), 50000, 40004); kept != 4 {
		t.Fatalf("packet cap: kept %d of 4", kept)
	}
	if kept := injectN(t, r, 1, []byte("x"), 50000, 40004); kept != 0 {
		t.Fatal("packet cap: datagram past the cap was kept")
	}

	// Byte cap: a cost exactly equal to the remaining share is kept, one byte
	// more is refused. Payload 3 costs 67.
	_, r = registryFixture(t)
	r.accounting.setEndpointLimits(2*67, 64)
	registryListen(t, r, 40005)
	if kept := injectN(t, r, 2, []byte("abc"), 50000, 40005); kept != 2 {
		t.Fatalf("byte cap exact fit: kept %d of 2", kept)
	}
	if kept := injectN(t, r, 1, []byte{}, 50000, 40005); kept != 0 {
		t.Fatal("byte cap: datagram past the byte cap was kept")
	}
	_, r = registryFixture(t)
	r.accounting.setEndpointLimits(2*67-1, 64)
	registryListen(t, r, 40006)
	if kept := injectN(t, r, 2, []byte("abc"), 50000, 40006); kept != 1 {
		t.Fatalf("byte cap one short: kept %d, want 1", kept)
	}

	// Caps above the Device budget are clamped; negative caps fault.
	_, r = registryFixture(t)
	r.accounting.setEndpointLimits(1<<30, 1<<30)
	if r.accounting.maxEndpointBytes != 4096 || r.accounting.maxEndpointPackets != 64 {
		t.Fatalf("caps not clamped: %d/%d", r.accounting.maxEndpointBytes, r.accounting.maxEndpointPackets)
	}
	_, r = registryFixture(t)
	r.accounting.setEndpointLimits(-1, 1)
	if r.accounting.fault == nil {
		t.Fatal("negative endpoint cap accepted")
	}
}

// The Device's own values: a quarter of the Device budget. A
// flood of tiny datagrams at one endpoint whose reader never reads stops at
// 1024 packets, and another endpoint on the same Device still reserves.
func TestUDPEndpointCapIntegratedDevice(t *testing.T) {
	d := ingressDevice(t)
	acc := d.registry.accounting
	if acc.maxEndpointPackets != 1024 || acc.maxEndpointBytes != 1<<20 {
		t.Fatalf("integrated caps %d bytes / %d packets, want 1048576/1024", acc.maxEndpointBytes, acc.maxEndpointPackets)
	}
	stalled := listenAdapter(t, d, 40010)
	quiet := listenAdapter(t, d, 40011)
	for i := 0; i < 1500; i++ {
		sendIngress(t, d, registryPacket([]byte("abc"), 50000, 40010))
	}
	acc.mu.Lock()
	sp := acc.generations[stalled].usedPackets
	acc.mu.Unlock()
	if sp != 1024 {
		t.Fatalf("stalled endpoint holds %d packets, want 1024", sp)
	}
	assertDeviceUsage(t, d, 1024*67, 1024)
	sendIngress(t, d, registryPacket([]byte("q"), 50001, 40011))
	readOne(t, quiet)
	assertDeviceUsage(t, d, 1024*67, 1024)
}

// A stream of large datagrams at one endpoint whose reader never reads stops
// at the accounting's endpoint cap, not at gVisor's own receive buffer: the
// gVisor limit counts payload bytes only and is set to the cap's bytes when
// the endpoint opens, so every drop at one endpoint is a counted refusal.
// With gVisor's default buffer, datagrams of this size overflowed it while
// the accounting still had room, and that drop was not counted.
func TestUDPEndpointCapBindsBeforeGVisorReceiveBuffer(t *testing.T) {
	d := ingressDevice(t)
	acc := d.registry.accounting
	x := listenAdapter(t, d, 40030)
	stats := x.ep.Stats().(*tcpip.TransportEndpointStats)
	payload := bytes.Repeat([]byte{'x'}, 1300)
	cost := len(payload) + udpDatagramCharge
	fit := acc.maxEndpointBytes / cost
	for i := 1; i <= fit+10; i++ {
		sendIngress(t, d, registryPacket(payload, 50000, 40030))
		if o := stats.ReceiveErrors.ReceiveBufferOverflow.Value(); o != 0 {
			t.Fatalf("gVisor's receive buffer dropped datagram %d with %d endpoint refusals", i, acc.refusedEndpoint.Load())
		}
	}
	if got := acc.refusedEndpoint.Load(); got != 10 {
		t.Fatalf("endpoint refusals = %d, want 10", got)
	}
	if got := acc.refusedDevice.Load(); got != 0 {
		t.Fatalf("device refusals = %d, want 0", got)
	}
	assertDeviceUsage(t, d, fit*cost, fit)
	if got := x.ep.SocketOptions().GetReceiveBufferSize(); got != int64(acc.maxEndpointBytes) {
		t.Fatalf("gVisor receive buffer = %d, want the endpoint cap %d", got, acc.maxEndpointBytes)
	}
	readOne(t, x)
	assertDeviceUsage(t, d, (fit-1)*cost, fit-1)
	// An endpoint opened by DialUDP takes the same path through open.
	dialed := dialAdapter(t, d, netip.AddrPortFrom(accountingRemote, 9))
	if got := dialed.ep.SocketOptions().GetReceiveBufferSize(); got != int64(acc.maxEndpointBytes) {
		t.Fatalf("dialed endpoint's gVisor receive buffer = %d, want the endpoint cap %d", got, acc.maxEndpointBytes)
	}
}

// Concurrent injections into a capped endpoint and a drained endpoint, with
// reads and a final Close, under -race: no fault, the capped endpoint never
// exceeds its cap, and everything is returned at the end.
func TestUDPEndpointCapConcurrent(t *testing.T) {
	_, r := registryFixture(t)
	r.accounting.setEndpointLimits(4096, 8)
	a := registryListen(t, r, 40020)
	b := registryListen(t, r, 40021)
	var wg sync.WaitGroup
	var readsB int
	var mu sync.Mutex
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				if _, err := r.inject(registryPacket([]byte("a"), uint16(51000+w), 40020)); err != nil {
					t.Error(err)
					return
				}
				if _, err := r.inject(registryPacket([]byte("b"), uint16(52000+w), 40021)); err != nil {
					t.Error(err)
					return
				}
			}
		}(w)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 16)
		for {
			b.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			if _, _, err := b.ReadFrom(buf); err != nil {
				return
			}
			mu.Lock()
			readsB++
			mu.Unlock()
		}
	}()
	wg.Wait()
	<-done
	if _, p := endpointUsage(t, r, a); p > 8 {
		t.Fatalf("capped endpoint holds %d > 8", p)
	}
	a.Close()
	b.Close()
	assertRegistryUsage(t, r, 0, 0)
	if readsB == 0 {
		t.Fatal("the drained endpoint received nothing")
	}
}
