package nettun

import (
	"bytes"
	"errors"
	"math"
	"net"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// These tests pin the ledger with small budgets, through a registry of their
// own on a Device, so every datagram enters by the registry's inject or a
// product path.

func newLedger(t *testing.T, bytesLimit, packetLimit int) *udpRegistry {
	t.Helper()
	dev, err := Create(accountingLocal, 1420)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dev.Close() })
	r, err := newUDPRegistry(dev, accountingLocal, bytesLimit, packetLimit, 64)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func ledgerOpen(t *testing.T, r *udpRegistry, local, remote *netip.AddrPort) *rawUDPAdapter {
	t.Helper()
	c, err := r.open(local, remote)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func ledgerReceiver(t *testing.T, r *udpRegistry) *rawUDPAdapter {
	t.Helper()
	addr := netip.AddrPortFrom(accountingLocal, accountingPort)
	return ledgerOpen(t, r, &addr, nil)
}

func ledgerInject(t *testing.T, r *udpRegistry, p []byte, want bool) {
	t.Helper()
	if accepted, err := r.inject(p); err != nil || accepted != want {
		t.Fatalf("inject: accepted=%v err=%v, want accepted=%v", accepted, err, want)
	}
}

func TestUDPAccountingLedgerInputBudgetFIFOAndTruncation(t *testing.T) {
	r := newLedger(t, 170, 2)
	rx := ledgerReceiver(t, r)
	for _, payload := range [][]byte{bytes.Repeat([]byte{'a'}, 10), bytes.Repeat([]byte{'b'}, 20)} {
		ledgerInject(t, r, accountingDatagram(payload, 0, 0), true)
	}
	assertRegistryUsage(t, r, 158, 2)
	third := accountingDatagram(bytes.Repeat([]byte{'c'}, 5), 0, 0)
	ledgerInject(t, r, third, false)
	assertRegistryUsage(t, r, 158, 2)
	short := make([]byte, 2)
	if n, _, err := rx.ReadFrom(short); err != nil || n != 2 || !bytes.Equal(short, []byte("aa")) {
		t.Fatalf("truncated ReadFrom = (%d, %q, %v)", n, short, err)
	}
	assertRegistryUsage(t, r, 84, 1)
	ledgerInject(t, r, third, true)
	assertRegistryUsage(t, r, 153, 2)
	for _, want := range []string{string(bytes.Repeat([]byte{'b'}, 20)), "ccccc"} {
		b := make([]byte, 32)
		n, _, err := rx.ReadFrom(b)
		if err != nil || string(b[:n]) != want {
			t.Fatalf("FIFO ReadFrom = (%q, %v), want %q", b[:n], err, want)
		}
	}
	assertRegistryUsage(t, r, 0, 0)
}

func TestUDPAccountingLedgerPaddedDatagram(t *testing.T) {
	r := newLedger(t, 1000, 2)
	rx := ledgerReceiver(t, r)
	p := accountingDatagram([]byte("data-and-padding"), 0, 0)
	// The UDP length covers only the first four payload bytes. The remaining
	// IPv4 bytes may be retained by the packet and must still be charged.
	p[24], p[25] = 0, 12
	ledgerInject(t, r, p, true)
	assertRegistryUsage(t, r, len(p)-20-8+64, 1)
	b := make([]byte, 32)
	n, _, err := rx.ReadFrom(b)
	if err != nil || n != 4 || string(b[:n]) != "data" {
		t.Fatalf("padded ReadFrom = (%q, %v), want data", b[:n], err)
	}
	assertRegistryUsage(t, r, 0, 0)
}

func TestUDPAccountingLedgerEmptyCountBoundAndBadBuffer(t *testing.T) {
	r := newLedger(t, 1000, 3)
	rx := ledgerReceiver(t, r)
	empty := accountingDatagram(nil, 0, 0)
	for i := 0; i < 3; i++ {
		ledgerInject(t, r, empty, true)
	}
	assertRegistryUsage(t, r, 192, 3)
	ledgerInject(t, r, empty, false)
	for i := 0; i < 3; i++ {
		if n, _, err := rx.ReadFrom(make([]byte, 1)); err != nil || n != 0 {
			t.Fatalf("empty ReadFrom %d = (%d, %v)", i, n, err)
		}
	}
	assertRegistryUsage(t, r, 0, 0)
	ledgerInject(t, r, accountingDatagram([]byte("bad"), 0, 0), true)
	if _, _, err := rx.ReadFrom(nil); err == nil {
		t.Fatal("zero-size writer did not report an error")
	}
	assertRegistryUsage(t, r, 0, 0) // ErrBadBuffer still dequeues.
	w := tcpip.SliceWriter(make([]byte, 1))
	if _, terr := rx.ep.Read(&w, tcpip.ReadOptions{}); terr == nil {
		t.Fatal("ErrBadBuffer left the packet queued")
	} else if _, ok := terr.(*tcpip.ErrWouldBlock); !ok {
		t.Fatalf("after ErrBadBuffer: %v", terr)
	}
}

func TestUDPAccountingLedgerChecksumAndEndpointOverflowRefund(t *testing.T) {
	r := newLedger(t, 10000, 10)
	rx := ledgerReceiver(t, r)
	ledgerInject(t, r, accountingDatagram([]byte("bad"), 0, 1), false)
	assertRegistryUsage(t, r, 0, 0)
	p := accountingDatagram(make([]byte, 800), 0, 0)
	rx.ep.SocketOptions().SetReceiveBufferSize(int64(2*(len(p)+stack.PacketBufferStructSize)), false)
	for i := 0; i < 3; i++ {
		ledgerInject(t, r, p, i < 2)
	}
	assertRegistryUsage(t, r, 1728, 2)
	for i := 0; i < 2; i++ {
		if n, _, err := rx.ReadFrom(make([]byte, 800)); err != nil || n != 800 {
			t.Fatalf("overflow drain %d = (%d, %v)", i, n, err)
		}
	}
	assertRegistryUsage(t, r, 0, 0)
}

func TestUDPAccountingLedgerExactTupleOnly(t *testing.T) {
	r := newLedger(t, 1000, 3)
	ledgerReceiver(t, r)
	local := netip.AddrPortFrom(accountingLocal, accountingPort+2)
	remote := netip.AddrPortFrom(accountingRemote, 41001)
	connected := ledgerOpen(t, r, &local, &remote)
	// A datagram from another source reaches gVisor, which refuses it for the
	// connected tuple; the reservation is returned.
	ledgerInject(t, r, registryPacket([]byte("tuple"), 41000, local.Port()), false)
	assertRegistryUsage(t, r, 0, 0)
	ledgerInject(t, r, registryPacket([]byte("tuple"), remote.Port(), local.Port()), true)
	if n, _, err := connected.ReadFrom(make([]byte, 5)); err != nil || n != 5 {
		t.Fatalf("connected ReadFrom = (%d, %v)", n, err)
	}
	assertRegistryUsage(t, r, 0, 0)
	unbound, err := newRawUDPAdapter(r.accounting.device, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer unbound.Close()
	if err := r.accounting.attach(unbound); err == nil {
		t.Fatal("unbound endpoint entered the ledger")
	}
	wildcard := netip.MustParseAddrPort("0.0.0.0:32103")
	wild, err := newRawUDPAdapter(r.accounting.device, &wildcard, nil)
	if err == nil {
		defer wild.Close()
		if err := r.accounting.attach(wild); err == nil {
			t.Fatal("wildcard endpoint entered the ledger")
		}
	}
	// A duplicate bind is normally rejected by gVisor; the ledger itself also
	// rejects duplicate ports if a future socket option permits one.
	dupAddr := netip.AddrPortFrom(accountingLocal, accountingPort)
	duplicate, err := newRawUDPAdapter(r.accounting.device, &dupAddr, nil)
	if err == nil {
		defer duplicate.Close()
		if err := r.accounting.attach(duplicate); err == nil {
			t.Fatal("duplicate local port entered the ledger")
		}
	}
	assertRegistryUsage(t, r, 0, 0)
}

func TestUDPAccountingLedgerCloseRaceAndNewGeneration(t *testing.T) {
	r := newLedger(t, 1000, 3)
	old := ledgerReceiver(t, r)
	for i := 0; i < 2; i++ {
		ledgerInject(t, r, accountingDatagram([]byte("old"), 0, 0), true)
	}
	start := make(chan struct{})
	readDone := make(chan error, 1)
	closeDone := make(chan struct{})
	go func() {
		<-start
		_, _, err := old.ReadFrom(make([]byte, 3))
		readDone <- err
	}()
	go func() {
		<-start
		old.Close()
		close(closeDone)
	}()
	close(start)
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("Close blocked")
	}
	select {
	case err := <-readDone:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("racing ReadFrom = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("racing ReadFrom blocked")
	}
	assertRegistryUsage(t, r, 0, 0)
	current := ledgerReceiver(t, r)
	ledgerInject(t, r, accountingDatagram([]byte("new"), 0, 0), true)
	if _, _, err := old.ReadFrom(make([]byte, 3)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("old reader touched new generation: %v", err)
	}
	if _, err := old.WriteTo([]byte("late"), &net.UDPAddr{IP: net.IP(accountingLocal.AsSlice()), Port: int(accountingPort)}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("old writer touched new generation: %v", err)
	}
	if err := old.Close(); err != nil {
		t.Fatalf("old Close after rebind: %v", err)
	}
	assertRegistryUsage(t, r, 67, 1)
	if n, _, err := current.ReadFrom(make([]byte, 3)); err != nil || n != 3 {
		t.Fatalf("new generation ReadFrom = (%d, %v)", n, err)
	}
	assertRegistryUsage(t, r, 0, 0)
}

func TestUDPAccountingLedgerFailStopAndInvalidBudget(t *testing.T) {
	r := newLedger(t, 1000, 3)
	rx := ledgerReceiver(t, r)
	acc := r.accounting
	acc.mu.Lock()
	if _, why := acc.reserveLocked(acc.generations[rx], math.MaxInt); why == udpReserved {
		t.Fatal("overflowed payload cost was reserved")
	}
	acc.fault = errors.New("accounting mismatch")
	acc.mu.Unlock()
	if accepted, err := r.inject(accountingDatagram([]byte("x"), 0, 0)); accepted || err == nil {
		t.Fatalf("injection after fault: %v, %v", accepted, err)
	}
	if _, err := r.listen(accountingPort + 3); err == nil {
		t.Fatal("open after fault succeeded")
	}
	if err := rx.Close(); err != nil {
		t.Fatalf("Close after fault: %v", err)
	}
	for _, c := range []struct{ bytes, packets, overhead int }{{-1, 3, 64}, {1, -1, 64}, {1, 1, -1}} {
		if _, err := newUDPRegistry(acc.device, accountingLocal, c.bytes, c.packets, c.overhead); err == nil {
			t.Fatalf("budget %+v was accepted", c)
		}
	}
}

// attach is attachLocked with t.mu taken.
func (t *udpAccounting) attach(c *rawUDPAdapter) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.attachLocked(c)
}
