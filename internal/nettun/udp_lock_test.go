package nettun

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// These tests pin the lock structure of the Device: the
// accounting lock is held only for ledger work, each endpoint's lock only for
// its own [Stats, send, Stats], Read and Close, and TCP, ICMP, fragments,
// nonlocal packets and Sweep take no accounting lock.

func listenAdapter(t *testing.T, d *Device, port uint16) *rawUDPAdapter {
	t.Helper()
	pc, err := d.ListenUDP(netip.AddrPortFrom(accountingLocal, port))
	if err != nil {
		t.Fatal(err)
	}
	c := pc.(*rawUDPAdapter)
	t.Cleanup(func() { c.Close() })
	return c
}

func dialAdapter(t *testing.T, d *Device, remote netip.AddrPort) *rawUDPAdapter {
	t.Helper()
	conn, err := d.DialUDP(remote)
	if err != nil {
		t.Fatal(err)
	}
	c := conn.(*rawUDPAdapter)
	t.Cleanup(func() { c.Close() })
	return c
}

func assertDeviceUsage(t *testing.T, d *Device, bytes, packets int) {
	t.Helper()
	b, p, fault := d.registry.usage()
	if b != bytes || p != packets || fault != nil {
		t.Fatalf("device UDP usage = %d/%d fault %v, want %d/%d", b, p, fault, bytes, packets)
	}
}

func lockTestTCPSYN() []byte {
	p := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)
	ip := header.IPv4(p)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(p)), TTL: 64, Protocol: uint8(tcp.ProtocolNumber),
		SrcAddr: tcpip.AddrFromSlice(accountingRemote.AsSlice()), DstAddr: tcpip.AddrFromSlice(accountingLocal.AsSlice()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	h := header.TCP(p[header.IPv4MinimumSize:])
	h.Encode(&header.TCPFields{SrcPort: 40000, DstPort: 5555, SeqNum: 1, DataOffset: header.TCPMinimumSize, Flags: header.TCPFlagSyn, WindowSize: 65535})
	xsum := header.PseudoHeaderChecksum(tcp.ProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(), header.TCPMinimumSize)
	h.SetChecksum(^h.CalculateChecksum(xsum))
	return p
}

func lockTestICMPEcho() []byte {
	p := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize)
	ip := header.IPv4(p)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(p)), TTL: 64, Protocol: uint8(header.ICMPv4ProtocolNumber),
		SrcAddr: tcpip.AddrFromSlice(accountingRemote.AsSlice()), DstAddr: tcpip.AddrFromSlice(accountingLocal.AsSlice()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	icmp := header.ICMPv4(p[header.IPv4MinimumSize:])
	icmp.SetType(header.ICMPv4Echo)
	icmp.SetIdent(7)
	icmp.SetSequence(1)
	icmp.SetChecksum(^header.ICMPv4Checksum(icmp, 0))
	return p
}

func lockTestNonlocalUDP() []byte {
	p := registryPacket([]byte("elsewhere"), 41000, accountingPort)
	copy(p[16:20], []byte{10, 1, 1, 99})
	ipv4SetChecksum(p[:20])
	return p
}

// timed runs fn in a goroutine and reports whether it returned within limit.
type timed struct {
	name string
	done chan error
}

func startTimed(name string, fn func() error) timed {
	r := timed{name: name, done: make(chan error, 1)}
	go func() { r.done <- fn() }()
	return r
}

func (r timed) within(t *testing.T, limit time.Duration) {
	t.Helper()
	select {
	case err := <-r.done:
		if err != nil {
			t.Fatalf("%s: %v", r.name, err)
		}
	case <-time.After(limit):
		t.Fatalf("%s did not return within %v", r.name, limit)
	}
}

func (r timed) stillPending(t *testing.T, wait time.Duration) {
	t.Helper()
	select {
	case err := <-r.done:
		t.Fatalf("%s returned (%v) although its lock was held", r.name, err)
	case <-time.After(wait):
	}
}

// releaseOnce returns a function that runs unlock exactly once, either where
// the test calls it or at test exit, so a failing assertion cannot leave a
// Device lock held and deadlock the Device's own Cleanup.
func releaseOnce(t *testing.T, unlock func()) func() {
	t.Helper()
	once := sync.OnceFunc(unlock)
	t.Cleanup(once)
	return once
}

// firstError keeps the first error any goroutine reports. (An atomic.Value
// panics when errors of different dynamic types are stored, which took a
// whole package run down during a mutation run.)
type firstError struct {
	mu  sync.Mutex
	err error
}

func (f *firstError) set(err error) {
	f.mu.Lock()
	if f.err == nil {
		f.err = err
	}
	f.mu.Unlock()
}

func (f *firstError) get() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

func writeOne(d *Device, p []byte) func() error {
	return func() error {
		n, err := d.Write([][]byte{p}, 0)
		if err != nil || n != 1 {
			return fmt.Errorf("Device.Write = %d/%v", n, err)
		}
		return nil
	}
}

// Invariant: with the accounting lock and one endpoint's lock both held,
// TCP, ICMP, nonlocal UDP, a fragment that evicts (the D-1 worst case), Sweep
// and a nonlocal adapter write all progress. Only a UDP datagram for a managed
// port waits, because it must reserve under the accounting lock.
func TestUDPLockUnrelatedPathsProgressWhileAccountingLocked(t *testing.T) {
	d := ingressDevice(t)
	x := listenAdapter(t, d, accountingPort)
	remote := dialAdapter(t, d, netip.AddrPortFrom(accountingRemote, 4000))
	for k := 0; k < reassemblyEntries; k++ {
		sendIngress(t, d, reasmIPv4Fragment(99, uint16(2000+k), 0, true, 0, nil, []byte("pppppppp")))
	}
	acc := d.registry.accounting
	acc.mu.Lock()
	x.opMu.Lock()
	release := releaseOnce(t, func() { x.opMu.Unlock(); acc.mu.Unlock() })
	free := []timed{
		startTimed("TCP SYN", writeOne(d, lockTestTCPSYN())),
		startTimed("ICMP echo", writeOne(d, lockTestICMPEcho())),
		startTimed("nonlocal UDP", writeOne(d, lockTestNonlocalUDP())),
		startTimed("evicting fragment", writeOne(d, reasmIPv4Fragment(99, 5000, 0, true, 0, nil, []byte("qqqqqqqq")))),
		startTimed("Sweep", func() error { d.reassembly.Sweep(time.Now()); return nil }),
		startTimed("nonlocal adapter write", func() error { _, err := remote.Write([]byte("out")); return err }),
	}
	toX := startTimed("UDP to managed port", writeOne(d, registryPacket([]byte("waits"), 41000, accountingPort)))
	for _, r := range free {
		r.within(t, time.Second)
	}
	toX.stillPending(t, 50*time.Millisecond)
	release()
	toX.within(t, time.Second)
	b := make([]byte, 8)
	if n, _, err := x.ReadFrom(b); err != nil || string(b[:n]) != "waits" {
		t.Fatalf("delayed datagram = %q/%v", b[:n], err)
	}
	if got := d.reassembly.Evicted(); got != 1 {
		t.Fatalf("fragment under held locks evicted %d, want 1", got)
	}
	assertDeviceUsage(t, d, 0, 0)
}

// Invariant: one endpoint's lock serializes only that endpoint. Another
// managed endpoint keeps receiving from the TUN and from a local write.
func TestUDPLockOtherEndpointProgressesWhileOneIsLocked(t *testing.T) {
	d := ingressDevice(t)
	x := listenAdapter(t, d, accountingPort)
	y := listenAdapter(t, d, accountingPort+1)
	toY := dialAdapter(t, d, netip.AddrPortFrom(accountingLocal, accountingPort+1))
	x.opMu.Lock()
	release := releaseOnce(t, x.opMu.Unlock)
	viaTUN := startTimed("UDP to other endpoint", writeOne(d, registryPacket([]byte("tun"), 41000, accountingPort+1)))
	viaLocal := startTimed("local write to other endpoint", func() error { _, err := toY.Write([]byte("loc")); return err })
	toX := startTimed("UDP to locked endpoint", writeOne(d, registryPacket([]byte("x"), 41000, accountingPort)))
	viaTUN.within(t, time.Second)
	viaLocal.within(t, time.Second)
	got := map[string]bool{}
	for i := 0; i < 2; i++ {
		b := make([]byte, 8)
		n, _, err := y.ReadFrom(b)
		if err != nil {
			t.Fatal(err)
		}
		got[string(b[:n])] = true
	}
	if !got["tun"] || !got["loc"] {
		t.Fatalf("other endpoint received %v", got)
	}
	toX.stillPending(t, 50*time.Millisecond)
	release()
	toX.within(t, time.Second)
	if n, _, err := x.ReadFrom(make([]byte, 8)); err != nil || n != 1 {
		t.Fatalf("locked endpoint after release = %d/%v", n, err)
	}
	assertDeviceUsage(t, d, 0, 0)
}

// Invariant: the reassembly table's own mutex is not the accounting lock. A
// long Process (modelled by holding that mutex) delays only fragments.
func TestUDPLockReassemblyMutexDoesNotBlockUDPOrTCP(t *testing.T) {
	d := ingressDevice(t)
	x := listenAdapter(t, d, accountingPort)
	sender := dialAdapter(t, d, netip.AddrPortFrom(accountingLocal, accountingPort))
	d.reassembly.mu.Lock()
	release := releaseOnce(t, d.reassembly.mu.Unlock)
	free := []timed{
		startTimed("UDP to managed port", writeOne(d, registryPacket([]byte("udp"), 41000, accountingPort))),
		startTimed("local write", func() error { _, err := sender.Write([]byte("loc")); return err }),
		startTimed("TCP SYN", writeOne(d, lockTestTCPSYN())),
	}
	first, _ := splitIngressIPv4(registryPacket([]byte("abcdefgh12345678"), 41000, accountingPort), 16)
	frag := startTimed("fragment", writeOne(d, first))
	for _, r := range free {
		r.within(t, time.Second)
	}
	frag.stillPending(t, 50*time.Millisecond)
	release()
	frag.within(t, time.Second)
	for i := 0; i < 2; i++ {
		if _, _, err := x.ReadFrom(make([]byte, 8)); err != nil {
			t.Fatal(err)
		}
	}
	assertDeviceUsage(t, d, 0, 0)
}

// Invariant: the sweeper never waits for the accounting lock. An expired entry
// is swept, and its Time Exceeded reaches the output, while the lock is held.
func TestUDPLockSweeperRunsWhileAccountingLocked(t *testing.T) {
	d := ingressDevice(t)
	x := listenAdapter(t, d, accountingPort)
	first, _ := splitIngressIPv4(registryPacket([]byte("abcdefgh12345678"), 41000, accountingPort), 16)
	sendIngress(t, d, first)
	d.reassembly.mu.Lock()
	for i := range d.reassembly.entries {
		if d.reassembly.entries[i].used {
			d.reassembly.entries[i].deadline = time.Now().Add(-time.Second)
		}
	}
	d.reassembly.mu.Unlock()
	acc := d.registry.accounting
	acc.mu.Lock()
	x.opMu.Lock()
	release := releaseOnce(t, func() { x.opMu.Unlock(); acc.mu.Unlock() })
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, entries, _ := d.reassembly.Usage()
		if entries == 0 && d.ep.NumQueued() == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sweeper did not run while the accounting lock was held: entries=%d queued=%d", entries, d.ep.NumQueued())
		}
		time.Sleep(10 * time.Millisecond)
	}
	release()
	out := readIngressOutput(t, d, time.Second)
	if out[9] != 1 || out[20] != 11 || out[21] != 1 {
		t.Fatalf("swept entry did not produce Time Exceeded: %x", out)
	}
}

// Race: Close and an injection into the same endpoint. The injection has
// reserved and waits for the endpoint lock; Close waits for it too. Whichever
// wins, the budget is whole afterwards: either the datagram was delivered and
// Close refunded it, or the injection saw the closed generation, refunded, and
// gVisor answered Port Unreachable for the now unknown port.
func TestUDPLockCloseRacesInjection(t *testing.T) {
	d := ingressDevice(t)
	x := listenAdapter(t, d, accountingPort)
	x.opMu.Lock()
	release := releaseOnce(t, x.opMu.Unlock)
	closing := startTimed("Close", func() error { return x.Close() })
	p := registryPacket([]byte("racing"), 41000, accountingPort)
	injecting := startTimed("injection", writeOne(d, p))
	deadline := time.Now().Add(time.Second)
	for {
		if _, packets, _ := d.registry.usage(); packets == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("injection did not reserve while waiting for the endpoint lock")
		}
		time.Sleep(time.Millisecond)
	}
	closing.stillPending(t, 5*time.Millisecond)
	injecting.stillPending(t, 0)
	release()
	closing.within(t, time.Second)
	injecting.within(t, time.Second)
	assertDeviceUsage(t, d, 0, 0)
	switch queued := d.ep.NumQueued(); queued {
	case 1:
		t.Log("Close won: the injection refunded and gVisor answered Port Unreachable")
		requirePortUnreachable(t, d, p)
	case 0:
		t.Log("injection won: delivered, then dropped and refunded by Close")
	default:
		t.Fatalf("unexpected output after Close race: %d packets", queued)
	}
}

// Race, pinned at the unit: a reservation whose generation was closed (and
// then replaced on the same port) before the endpoint lock was taken must be
// refunded and must not send. Otherwise the new generation would receive a
// datagram nobody reserved for it, and its next Read would fail-stop.
func TestUDPLockRevalidatesGenerationAfterClose(t *testing.T) {
	d := ingressDevice(t)
	acc := d.registry.accounting
	x := listenAdapter(t, d, accountingPort)
	acc.mu.Lock()
	g := acc.generations[x]
	r, why := acc.reserveLocked(g, 3)
	acc.mu.Unlock()
	if g == nil || why != udpReserved {
		t.Fatal("fixture: generation or reservation missing")
	}
	x.Close()
	sent := false
	kept, stale, err := acc.accountedSend(x, g, r, func() { sent = true })
	if kept || !stale || err != nil || sent {
		t.Fatalf("closed generation: kept=%v stale=%v err=%v sent=%v", kept, stale, err, sent)
	}
	assertDeviceUsage(t, d, 0, 0)

	y := listenAdapter(t, d, accountingPort)
	p := registryPacket([]byte("new"), 41000, accountingPort)
	acc.mu.Lock()
	r, why = acc.reserveLocked(g, 3)
	acc.mu.Unlock()
	if why != udpReserved {
		t.Fatal("fixture: reservation failed")
	}
	kept, stale, err = acc.accountedSend(x, g, r, func() { injectInbound(d.ep, p) })
	if kept || !stale || err != nil {
		t.Fatalf("replaced generation: kept=%v stale=%v err=%v", kept, stale, err)
	}
	assertDeviceUsage(t, d, 0, 0)
	if err := y.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := y.ReadFrom(make([]byte, 8)); err == nil {
		t.Fatal("stale send reached the new generation")
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("new generation Read = %v, want timeout", err)
	}
	if err := y.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	sendIngress(t, d, p)
	assertDeviceUsage(t, d, 67, 1)
	b := make([]byte, 8)
	if n, _, err := y.ReadFrom(b); err != nil || string(b[:n]) != "new" {
		t.Fatalf("new generation after a proper injection = %q/%v", b[:n], err)
	}
	assertDeviceUsage(t, d, 0, 0)
}

// The counterexample as a test. Eight senders (TUN injections and local
// writes) and two readers share one endpoint whose receive buffer is small
// enough to overflow. If the [Stats, send, Stats] window were not serialized
// per endpoint, two senders would read one combined delta and the ledger
// would end with a fault (accepted > 1, FIFO payload mismatch or unreserved
// dequeue) or leak. Run with -race as well.
func TestUDPLockConcurrentSendersAndReadersOneEndpoint(t *testing.T) {
	d := ingressDevice(t)
	x := listenAdapter(t, d, accountingPort)
	x.ep.SocketOptions().SetReceiveBufferSize(8192, false)
	const perSender = 400
	sizes := []int{0, 7, 300, 1200, 1, 64, 900}
	var accepted atomic.Int64
	var sendErr firstError
	var wg sync.WaitGroup
	for s := 0; s < 4; s++ {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			for i := 0; i < perSender; i++ {
				payload := bytes.Repeat([]byte{byte('a' + s)}, sizes[(s+i)%len(sizes)])
				ok, err := d.registry.inject(registryPacket(payload, uint16(41000+s), accountingPort))
				if err != nil {
					sendErr.set(err)
					return
				}
				if ok {
					accepted.Add(1)
				}
			}
		}(s)
	}
	for s := 0; s < 4; s++ {
		sender := dialAdapter(t, d, netip.AddrPortFrom(accountingLocal, accountingPort))
		wg.Add(1)
		go func(s int, sender *rawUDPAdapter) {
			defer wg.Done()
			for i := 0; i < perSender; i++ {
				payload := bytes.Repeat([]byte{byte('A' + s)}, sizes[(s+2*i)%len(sizes)])
				if _, err := sender.Write(payload); err != nil {
					sendErr.set(err)
					return
				}
			}
		}(s, sender)
	}
	stop := make(chan struct{})
	var reads atomic.Int64
	var readErr firstError
	var readers sync.WaitGroup
	for r := 0; r < 2; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			b := make([]byte, 2048)
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = x.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
				if _, _, err := x.ReadFrom(b); err != nil {
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						continue
					}
					readErr.set(err)
					return
				}
				reads.Add(1)
			}
		}()
	}
	wg.Wait()
	// Drain: two consecutive idle windows after the senders stopped.
	idle := 0
	for idle < 2 {
		_, packets, _ := d.registry.usage()
		if packets == 0 {
			idle++
		} else {
			idle = 0
		}
		time.Sleep(30 * time.Millisecond)
	}
	close(stop)
	readers.Wait()
	if err := sendErr.get(); err != nil {
		t.Fatalf("sender: %v", err)
	}
	if err := readErr.get(); err != nil {
		t.Fatalf("reader: %v", err)
	}
	if reads.Load() < accepted.Load() || reads.Load() == 0 {
		t.Fatalf("reads %d, TUN injections accepted %d", reads.Load(), accepted.Load())
	}
	assertDeviceUsage(t, d, 0, 0)
	if _, _, fault := d.registry.usage(); fault != nil {
		t.Fatal(fault)
	}
}

// Race: Close in the middle of concurrent injections. Close holds the
// endpoint lock across the endpoint drain and the bulk refund, so no
// reservation can be appended after the refund. A Close that skipped the lock
// would leak whatever a concurrent injection settled after the refund.
func TestUDPLockCloseDuringConcurrentInjectionsRefundsAll(t *testing.T) {
	d := ingressDevice(t)
	for iter := 0; iter < 40; iter++ {
		x := listenAdapter(t, d, accountingPort)
		x.ep.SocketOptions().SetReceiveBufferSize(4096, false)
		var wg sync.WaitGroup
		for s := 0; s < 4; s++ {
			wg.Add(1)
			go func(s int) {
				defer wg.Done()
				p := registryPacket(bytes.Repeat([]byte{'z'}, 100+s), uint16(41000+s), accountingPort)
				for i := 0; i < 30; i++ {
					if _, err := d.registry.inject(p); err != nil {
						return
					}
				}
			}(s)
		}
		time.Sleep(time.Duration(iter%5) * 50 * time.Microsecond)
		x.Close()
		wg.Wait()
		for d.ep.NumQueued() > 0 {
			pkt := d.ep.Read()
			pkt.DecRef()
		}
		assertDeviceUsage(t, d, 0, 0)
	}
}

// Notification re-entry: a local write holds the receiver's lock while gVisor
// delivers synchronously and wakes the reader; the reader then waits for that
// same lock. The writer never waits for the reader, so both finish.
func TestUDPLockLocalWriterAndReaderDoNotDeadlock(t *testing.T) {
	d := ingressDevice(t)
	x := listenAdapter(t, d, accountingPort)
	sender := dialAdapter(t, d, netip.AddrPortFrom(accountingLocal, accountingPort))
	const count = 300
	writer := startTimed("writer", func() error {
		for i := 0; i < count; i++ {
			if _, err := sender.Write([]byte("ping")); err != nil {
				return err
			}
		}
		return nil
	})
	reader := startTimed("reader", func() error {
		b := make([]byte, 8)
		for i := 0; i < count; i++ {
			if i%2 == 0 {
				if err := x.WaitReadable(); err != nil {
					return err
				}
			}
			if _, _, err := x.ReadFrom(b); err != nil {
				return err
			}
		}
		return nil
	})
	writer.within(t, 5*time.Second)
	reader.within(t, 5*time.Second)
	assertDeviceUsage(t, d, 0, 0)
}

// HandleLocal, third form: a self-addressed send to a port nobody registered
// (TUN input and adapter write) is handed to gVisor while the accounting lock
// is held, so a port registered concurrently cannot receive it unreserved.
// The synchronous EventErr callback takes no lock, so the write returns.
func TestUDPLockUnmanagedLocalSendStaysUnderAccountingLock(t *testing.T) {
	d := ingressDevice(t)
	acc := d.registry.accounting
	var calls, unlocked atomic.Int32
	acc.sendUnmanagedHook = func() {
		calls.Add(1)
		if acc.mu.TryLock() {
			acc.mu.Unlock()
			unlocked.Add(1)
		}
	}
	const port = accountingPort + 9
	p := registryPacket([]byte("nobody"), 41000, port)
	sendIngress(t, d, p)
	requirePortUnreachable(t, d, p)
	sender := dialAdapter(t, d, netip.AddrPortFrom(accountingLocal, port))
	if n, err := sender.Write([]byte("lost")); err != nil || n != 4 {
		t.Fatalf("self-addressed write to an unregistered port = %d/%v", n, err)
	}
	ready := startTimed("WaitReadable after ICMP error", sender.WaitReadable)
	ready.within(t, time.Second)
	if _, err := sender.Read(make([]byte, 8)); err == nil {
		t.Fatal("Read after the local Port Unreachable returned no error")
	}
	if calls.Load() != 2 || unlocked.Load() != 0 {
		t.Fatalf("unmanaged sends = %d, of which %d ran without the accounting lock", calls.Load(), unlocked.Load())
	}
	assertDeviceUsage(t, d, 0, 0)
	late := listenAdapter(t, d, port)
	if err := late.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := late.ReadFrom(make([]byte, 8)); err == nil {
		t.Fatal("a later listener received an earlier unmanaged datagram")
	} else if !errors.As(err, new(net.Error)) {
		t.Fatal(err)
	}
}

// Lock order and the Read window. A Read dequeues under the endpoint lock
// and keeps it until its FIFO head is popped under the accounting lock, so
// a second reader cannot dequeue the next datagram in between (its pop would
// take the first datagram's reservation). With the accounting lock held by
// the test, the first reader waits holding the endpoint lock, the second
// reader waits for the endpoint lock, and the second datagram stays queued.
// Releasing the accounting lock alone lets both finish: the accounting
// holder never needs an endpoint lock.
func TestUDPLockOrderEndpointThenAccounting(t *testing.T) {
	d := ingressDevice(t)
	x := listenAdapter(t, d, accountingPort)
	sendIngress(t, d, registryPacket([]byte("first"), 41000, accountingPort))
	sendIngress(t, d, registryPacket(bytes.Repeat([]byte{'s'}, 300), 41000, accountingPort))
	acc := d.registry.accounting
	acc.mu.Lock()
	release := releaseOnce(t, acc.mu.Unlock)
	first := startTimed("first Read", func() error {
		b := make([]byte, 512)
		n, _, err := x.ReadFrom(b)
		if err == nil && string(b[:n]) != "first" {
			return fmt.Errorf("first Read got %d bytes", n)
		}
		return err
	})
	// Wait, bounded, until the first reader holds the endpoint lock. It then
	// waits for the accounting lock the test holds and must keep opMu.
	deadline := time.Now().Add(time.Second)
	for x.opMu.TryLock() {
		x.opMu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("first Read did not hold the endpoint lock while waiting for the accounting lock")
		}
		time.Sleep(time.Millisecond)
	}
	first.stillPending(t, 0)
	second := startTimed("second Read", func() error {
		b := make([]byte, 512)
		n, _, err := x.ReadFrom(b)
		if err == nil && n != 300 {
			return fmt.Errorf("second Read got %d bytes", n)
		}
		return err
	})
	second.stillPending(t, 20*time.Millisecond)
	if x.ep.Readiness(waiter.ReadableEvents) == 0 {
		t.Fatal("the second datagram was dequeued before the first Read popped its reservation")
	}
	release()
	first.within(t, time.Second)
	second.within(t, time.Second)
	assertDeviceUsage(t, d, 0, 0)
}

// The send window holds the receiver's endpoint lock and nothing else. gVisor
// delivers a local datagram synchronously and notifies the receiver's waiters
// inside that delivery, so a function entry on the receiver's queue runs
// inside the window and can observe which locks are held there: the
// accounting lock must be free (another endpoint's reservation can proceed
// while this one is being delivered) and the receiver's lock must be held.
func TestUDPLockSendWindowHoldsOnlyTheEndpointLock(t *testing.T) {
	d := ingressDevice(t)
	acc := d.registry.accounting
	x := listenAdapter(t, d, accountingPort)
	sender := dialAdapter(t, d, netip.AddrPortFrom(accountingLocal, accountingPort))
	type seen struct{ accountingFree, endpointHeld bool }
	observed := make(chan seen, 4)
	entry := waiter.NewFunctionEntry(waiter.ReadableEvents, func(waiter.EventMask) {
		var s seen
		if acc.mu.TryLock() {
			acc.mu.Unlock()
			s.accountingFree = true
		}
		if x.opMu.TryLock() {
			x.opMu.Unlock()
		} else {
			s.endpointHeld = true
		}
		select {
		case observed <- s:
		default:
		}
	})
	x.wq.EventRegister(&entry)
	defer x.wq.EventUnregister(&entry)
	// gVisor notifies readability when the receive list becomes non-empty,
	// so each delivery is read before the next one is sent.
	for _, step := range []struct {
		name string
		send func()
	}{
		{"TUN injection", func() { sendIngress(t, d, registryPacket([]byte("tun"), 41000, accountingPort)) }},
		{"local write", func() {
			if _, err := sender.Write([]byte("loc")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		step.send()
		select {
		case s := <-observed:
			if !s.accountingFree {
				t.Errorf("%s: the accounting lock was held during the send window", step.name)
			}
			if !s.endpointHeld {
				t.Errorf("%s: the receiver's endpoint lock was not held during the send window", step.name)
			}
		default:
			t.Fatalf("%s: the readable callback did not run synchronously inside the send", step.name)
		}
		if _, _, err := x.ReadFrom(make([]byte, 8)); err != nil {
			t.Fatal(err)
		}
	}
	assertDeviceUsage(t, d, 0, 0)
}

// open creates and binds the endpoint under the accounting lock, so a port
// is never bound before it is registered. With the lock held by the test, a
// pending ListenUDP has not bound its port yet: a probe endpoint can still
// bind it. (If it were bound, a datagram for that port could reach an
// endpoint nobody reserved for; that is why unregistered-port sends stay
// under the same lock.)
func TestUDPLockOpenBindsUnderTheAccountingLock(t *testing.T) {
	d := ingressDevice(t)
	acc := d.registry.accounting
	local := netip.AddrPortFrom(accountingLocal, accountingPort)
	acc.mu.Lock()
	release := releaseOnce(t, acc.mu.Unlock)
	opened := make(chan net.PacketConn, 1)
	opening := startTimed("ListenUDP", func() error {
		pc, err := d.ListenUDP(local)
		if err == nil {
			opened <- pc
		}
		return err
	})
	opening.stillPending(t, 50*time.Millisecond)
	var wq waiter.Queue
	probe, terr := d.stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if terr != nil {
		t.Fatal(terr)
	}
	if terr := probe.Bind(fullAddr(local)); terr != nil {
		probe.Close()
		t.Fatalf("the port was bound while open waited for the accounting lock: %v", terr)
	}
	probe.Close()
	release()
	opening.within(t, time.Second)
	pc := <-opened
	defer pc.Close()
	sendIngress(t, d, registryPacket([]byte("after"), 41000, accountingPort))
	b := make([]byte, 8)
	if n, _, err := pc.ReadFrom(b); err != nil || string(b[:n]) != "after" {
		t.Fatalf("listener after the lock = %q/%v", b[:n], err)
	}
	assertDeviceUsage(t, d, 0, 0)
}

// Device.Close marks the Device closed under the accounting lock before it
// lists the endpoints to close, so an open that races Close either fails or
// is in the list. An endpoint opened during Close must not survive it. Close
// is queued on the lock first; the open is queued behind it and runs right
// after Close's critical section, which is the window a wrong order leaves.
func TestUDPLockCloseMarksClosedBeforeListingEndpoints(t *testing.T) {
	local := netip.AddrPortFrom(accountingLocal, accountingPort)
	for iter := 0; iter < 20; iter++ {
		d, err := Create(accountingLocal, 1420)
		if err != nil {
			t.Fatal(err)
		}
		acc := d.registry.accounting
		acc.mu.Lock()
		release := releaseOnce(t, acc.mu.Unlock)
		closing := startTimed("Device.Close", d.Close)
		time.Sleep(2 * time.Millisecond)
		opened := make(chan net.PacketConn, 1)
		opening := startTimed("ListenUDP", func() error {
			pc, err := d.ListenUDP(local)
			if err == nil {
				opened <- pc
			}
			return err
		})
		time.Sleep(2 * time.Millisecond)
		release()
		closing.within(t, 2*time.Second)
		select {
		case err := <-opening.done:
			if err == nil {
				c := (<-opened).(*rawUDPAdapter)
				select {
				case <-c.closed:
				default:
					c.Close()
					t.Fatalf("iteration %d: an endpoint opened during Device.Close survived it", iter)
				}
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("iteration %d: ListenUDP did not return after Device.Close", iter)
		}
	}
}

// A local write whose receiver is closed between the lookup and the endpoint
// lock must look the port up again, like a TUN injection. With the port gone,
// gVisor answers the sender with a synchronous Port Unreachable, which the
// sender observes as an error; a write that returned success without sending
// would leave the sender waiting. Close is queued on the endpoint lock before
// the write so Close wins; the branch is checked by the receiver's Stats.
func TestUDPLockLocalWriteRelooksUpAfterClose(t *testing.T) {
	d := ingressDevice(t)
	local := netip.AddrPortFrom(accountingLocal, accountingPort)
	closeFirst := 0
	const iterations = 10
	for iter := 0; iter < iterations; iter++ {
		x := listenAdapter(t, d, accountingPort)
		sender := dialAdapter(t, d, local)
		x.opMu.Lock()
		release := releaseOnce(t, x.opMu.Unlock)
		closing := startTimed("Close", x.Close)
		time.Sleep(2 * time.Millisecond)
		writing := startTimed("local Write", func() error { _, err := sender.Write([]byte("late")); return err })
		deadline := time.Now().Add(time.Second)
		for {
			if _, packets, _ := d.registry.usage(); packets == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("iteration %d: the local write did not reserve while waiting for the endpoint lock", iter)
			}
			time.Sleep(time.Millisecond)
		}
		release()
		closing.within(t, time.Second)
		var writeErr error
		select {
		case writeErr = <-writing.done:
		case <-time.After(time.Second):
			t.Fatalf("iteration %d: local Write did not return", iter)
		}
		if writeErr != nil {
			t.Fatalf("iteration %d: local Write = %v", iter, writeErr)
		}
		if x.ep.Stats().(*tcpip.TransportEndpointStats).PacketsReceived.Value() == 0 {
			closeFirst++
			ready := startTimed("WaitReadable", sender.WaitReadable)
			ready.within(t, time.Second)
			if _, err := sender.Read(make([]byte, 8)); err == nil {
				t.Fatalf("iteration %d: no Port Unreachable reached the sender after its receiver closed", iter)
			}
		}
		assertDeviceUsage(t, d, 0, 0)
		sender.Close()
	}
	t.Logf("Close won in %d of %d iterations", closeFirst, iterations)
	if closeFirst == 0 {
		t.Fatal("Close never won the endpoint lock although it was queued first")
	}
}

// The Port Unreachable for an unregistered port is written by gVisor inside
// the injection, so the output queue's notification runs inside it too. It
// must run with the accounting lock held: the injection stays under that
// lock so a port registered concurrently cannot receive the datagram
// unreserved.
type lockProbeNotify struct {
	acc  *udpAccounting
	seen chan bool
}

func (n *lockProbeNotify) WriteNotify() {
	held := !n.acc.mu.TryLock()
	if !held {
		n.acc.mu.Unlock()
	}
	select {
	case n.seen <- held:
	default:
	}
}

func TestUDPLockUnregisteredPortInjectedUnderTheAccountingLock(t *testing.T) {
	d := ingressDevice(t)
	probe := &lockProbeNotify{acc: d.registry.accounting, seen: make(chan bool, 1)}
	h := d.ep.AddNotify(probe)
	defer d.ep.RemoveNotify(h)
	p := registryPacket([]byte("nobody"), 41000, accountingPort+9)
	sendIngress(t, d, p)
	select {
	case held := <-probe.seen:
		if !held {
			t.Fatal("gVisor answered an unregistered port with the accounting lock released")
		}
	default:
		t.Fatal("no Port Unreachable was written during the injection")
	}
	requirePortUnreachable(t, d, p)
}

// Device.Close marks the Device closed before it closes the listed endpoints,
// so an open that runs between the listing and the Closes fails instead of
// leaving an endpoint that outlives the Device.
func TestUDPLockOpenAfterCloseListedFails(t *testing.T) {
	d, err := Create(accountingLocal, 1420)
	if err != nil {
		t.Fatal(err)
	}
	var openErr error
	d.registry.closeListedHook = func() {
		pc, err := d.ListenUDP(netip.AddrPortFrom(accountingLocal, accountingPort))
		if err == nil {
			pc.Close()
		}
		openErr = err
	}
	d.Close()
	if !errors.Is(openErr, net.ErrClosed) {
		t.Fatalf("ListenUDP during Device.Close = %v, want net.ErrClosed", openErr)
	}
}
