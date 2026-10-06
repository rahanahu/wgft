package nettun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func registryFixture(t *testing.T) (*Device, *udpRegistry) {
	t.Helper()
	dev, err := Create(accountingLocal, 1420)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dev.Close() })
	// The integrated pull link has a finite nonblocking output queue, so the
	// fixture can capture ICMP without a synchronous WriteNotify reader wait.
	r, err := newUDPRegistry(dev, accountingLocal, 4096, 64, 64)
	if err != nil {
		t.Fatal(err)
	}
	return dev, r
}

func registryListen(t *testing.T, r *udpRegistry, port uint16) *rawUDPAdapter {
	t.Helper()
	c, err := r.listen(port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func registryDial(t *testing.T, r *udpRegistry, remote netip.AddrPort) *rawUDPAdapter {
	t.Helper()
	c, err := r.dial(remote)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func registryPacket(payload []byte, sourcePort, destPort uint16) []byte {
	p := accountingDatagram(payload, 0, 0)
	binary.BigEndian.PutUint16(p[20:22], sourcePort)
	binary.BigEndian.PutUint16(p[22:24], destPort)
	return p
}

func assertRegistryUsage(t *testing.T, r *udpRegistry, bytes, packets int) {
	t.Helper()
	b, p, fault := r.usage()
	if b != bytes || p != packets || fault != nil {
		t.Fatalf("registry usage = %d/%d fault %v, want %d/%d", b, p, fault, bytes, packets)
	}
	if err := udpLedgerMismatch(r.accounting); err != nil {
		t.Fatal(err)
	}
}

// udpLedgerMismatch reports where the accounting's three views of the queued
// datagrams disagree: the Device totals, each generation's share, and each
// generation's FIFO of reservations. Callers use it only while nothing is in
// flight; a send racing a Close keeps its reservation on a generation that is
// already out of the table until it returns, so the totals differ meanwhile.
func udpLedgerMismatch(a *udpAccounting) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	sumBytes, sumPackets := 0, 0
	for _, g := range a.generations {
		cost := 0
		for _, res := range g.fifo {
			if res.g != g {
				return errors.New("ledger: a FIFO holds a reservation charged to another generation")
			}
			cost += res.cost
		}
		if g.usedPackets != len(g.fifo) || g.usedBytes != cost {
			return fmt.Errorf("ledger: a generation counts %d/%d but its FIFO holds %d/%d", g.usedBytes, g.usedPackets, cost, len(g.fifo))
		}
		sumBytes += g.usedBytes
		sumPackets += g.usedPackets
	}
	if a.usedBytes != sumBytes || a.usedPackets != sumPackets {
		return fmt.Errorf("ledger: the Device counts %d/%d but its generations add up to %d/%d", a.usedBytes, a.usedPackets, sumBytes, sumPackets)
	}
	return nil
}

func requirePortUnreachable(t *testing.T, dev *Device, original []byte) {
	t.Helper()
	pkt := dev.ep.Read()
	if pkt == nil {
		t.Fatal("expected ICMP output")
	}
	v := pkt.ToView()
	b := append([]byte(nil), v.AsSlice()...)
	v.Release()
	pkt.DecRef()
	if len(b) < 20 || b[9] != 1 {
		t.Fatalf("output is not IPv4 ICMP: %x", b)
	}
	outerLen := int(b[0]&15) * 4
	if outerLen < 20 || len(b) < outerLen+8+28 {
		t.Fatalf("short ICMP error: %x", b)
	}
	if b[outerLen] != 3 || b[outerLen+1] != 3 {
		t.Fatalf("ICMP type/code = %d/%d, want Destination Unreachable/Port Unreachable", b[outerLen], b[outerLen+1])
	}
	quote := b[outerLen+8:]
	if quote[9] != 17 || !bytes.Equal(quote[12:20], original[12:20]) ||
		!bytes.Equal(quote[20:24], original[20:24]) {
		t.Fatalf("ICMP quote does not identify original UDP tuple: %x", quote)
	}
}

func TestUDPRegistryConcurrentConnectUniquePorts(t *testing.T) {
	_, r := registryFixture(t)
	const count = 16
	type opened struct {
		c   *rawUDPAdapter
		err error
	}
	results := make(chan opened, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := r.dial(netip.AddrPortFrom(accountingRemote, uint16(41000+i)))
			results <- opened{c, err}
		}(i)
	}
	wg.Wait()
	close(results)
	seen := map[uint16]bool{}
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		c := result.c
		t.Cleanup(func() { c.Close() })
		ap := c.LocalAddr().(*net.UDPAddr).AddrPort()
		if ap.Addr() != accountingLocal || ap.Port() == 0 || seen[ap.Port()] {
			t.Fatalf("duplicate/nonlocal ephemeral port: %v", ap)
		}
		seen[ap.Port()] = true
		if r.endpoint(ap.Port()) != c {
			t.Fatalf("port %d not registered", ap.Port())
		}
	}
	if len(seen) != count {
		t.Fatalf("registered %d/%d", len(seen), count)
	}
}

func TestUDPRegistryUnknownAndConnectedMismatchICMP(t *testing.T) {
	dev, r := registryFixture(t)
	unknown := registryPacket([]byte("unknown"), 41000, accountingPort)
	if accepted, err := r.inject(unknown); err != nil || accepted {
		t.Fatalf("unknown = %v/%v", accepted, err)
	}
	requirePortUnreachable(t, dev, unknown)
	assertRegistryUsage(t, r, 0, 0)
	c := registryDial(t, r, netip.AddrPortFrom(accountingRemote, 41001))
	port := c.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	mismatch := registryPacket([]byte("wrong peer"), 41000, port)
	if accepted, err := r.inject(mismatch); err != nil || accepted {
		t.Fatalf("mismatch = %v/%v", accepted, err)
	}
	requirePortUnreachable(t, dev, mismatch)
	assertRegistryUsage(t, r, 0, 0)
	if accepted, err := r.inject(registryPacket([]byte("match"), 41001, port)); err != nil || !accepted {
		t.Fatalf("connected match = %v/%v", accepted, err)
	}
	if n, err := c.Read(make([]byte, 5)); err != nil || n != 5 {
		t.Fatalf("connected Read = %d/%v", n, err)
	}
	assertRegistryUsage(t, r, 0, 0)
}

func TestUDPRegistryUnknownBindAndRebind(t *testing.T) {
	dev, r := registryFixture(t)
	p := registryPacket([]byte("race"), 41000, accountingPort)
	// Both operations contend on the same lock. Either ordering is valid; a
	// half-bound, unregistered endpoint would violate the observation below.
	r.accounting.mu.Lock()
	type ingress struct {
		accepted bool
		err      error
	}
	in := make(chan ingress, 1)
	op := make(chan *rawUDPAdapter, 1)
	openErr := make(chan error, 1)
	go func() { a, e := r.inject(p); in <- ingress{a, e} }()
	go func() {
		c, e := r.listen(accountingPort)
		if e != nil {
			openErr <- e
			return
		}
		op <- c
	}()
	r.accounting.mu.Unlock()
	var c *rawUDPAdapter
	select {
	case c = <-op:
		defer c.Close()
	case err := <-openErr:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("Bind stalled")
	}
	var result ingress
	select {
	case result = <-in:
	case <-time.After(time.Second):
		t.Fatal("Inject stalled")
	}
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.accepted {
		b := make([]byte, 4)
		if n, _, err := c.ReadFrom(b); err != nil || n != 4 || !bytes.Equal(b, []byte("race")) {
			t.Fatalf("bound read = %d/%q/%v", n, b, err)
		}
	} else {
		requirePortUnreachable(t, dev, p)
	}
	assertRegistryUsage(t, r, 0, 0)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	current := registryListen(t, r, accountingPort)
	if accepted, err := r.inject(registryPacket([]byte("new"), 41000, accountingPort)); err != nil || !accepted {
		t.Fatalf("rebind input = %v/%v", accepted, err)
	}
	if _, _, err := c.ReadFrom(make([]byte, 3)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("old reader = %v", err)
	}
	assertRegistryUsage(t, r, 67, 1)
	if n, _, err := current.ReadFrom(make([]byte, 3)); err != nil || n != 3 {
		t.Fatalf("new read = %d/%v", n, err)
	}
	assertRegistryUsage(t, r, 0, 0)
}

func TestUDPRegistryZeroAndShortRead(t *testing.T) {
	_, r := registryFixture(t)
	c := registryListen(t, r, accountingPort)
	if accepted, err := r.inject(registryPacket([]byte("abcde"), 41000, accountingPort)); err != nil || !accepted {
		t.Fatalf("input = %v/%v", accepted, err)
	}
	if accepted, err := r.inject(registryPacket(nil, 41000, accountingPort)); err != nil || !accepted {
		t.Fatalf("zero input = %v/%v", accepted, err)
	}
	assertRegistryUsage(t, r, 133, 2)
	b := make([]byte, 2)
	if n, _, err := c.ReadFrom(b); err != nil || n != 2 || string(b) != "ab" {
		t.Fatalf("short read = %d/%q/%v", n, b, err)
	}
	assertRegistryUsage(t, r, 64, 1)
	if n, _, err := c.ReadFrom(make([]byte, 1)); err != nil || n != 0 {
		t.Fatalf("zero read = %d/%v", n, err)
	}
	assertRegistryUsage(t, r, 0, 0)
}

func (r *udpRegistry) listen(port uint16) (*rawUDPAdapter, error) {
	local := netip.AddrPortFrom(r.accounting.local, port)
	return r.open(&local, nil)
}

func (r *udpRegistry) usage() (bytes, packets int, fault error) {
	t := r.accounting
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.usedBytes, t.usedPackets, t.fault
}

func (r *udpRegistry) endpoint(port uint16) *rawUDPAdapter {
	t := r.accounting
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.localPorts[port]
}
