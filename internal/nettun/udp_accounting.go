package nettun

// UDP の受信の会計(設計文書 7 節)。Device の全ての UDP endpoint の受信のキューに溜まる datagram を、
// Device 全体の予算と endpoint 1 つの上限の 2 段で数える。予算の単位は IPv4 の UDP header 後の
// 全 byte に 1 件あたり固定の byte を足したものと件数であり、Go のヒープの実際の費用ではない。

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"math"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/rahanahu/wgft/internal/lograte"
)

// logf is where the UDP accounting logs. Tests replace it.
var logf = log.Printf

// udpAccounting keeps the ledger of every UDP datagram queued in the Device's
// endpoints. It is not a general UDP demultiplexer: gVisor still delivers, and
// the endpoint's public Stats decide whether one delivery was accepted.
//
// Lock structure. mu guards only the ledger and the tables below and is held
// for O(1) map and counter work, never across InjectInbound, endpoint Write or
// Read, or a waiter callback. The one exception is a datagram addressed to an
// unregistered local port: open registers endpoints under mu, so that send
// stays under mu to keep an unreserved datagram out of an endpoint that is
// registered concurrently. Each adapter (one generation) has its own opMu that
// serializes the [Stats, one send, Stats] window, Read with its FIFO pop, and
// Close with its bulk refund. The only nesting is opMu -> mu; mu is never held
// while taking an opMu, and two opMu are never held together.
//
// Invariants. A datagram is reserved before it is delivered to a managed
// endpoint; one delivery's acceptance is read from that endpoint's Stats
// delta; a generation's FIFO matches its receive queue in order and length;
// Close refunds the whole FIFO; every managed endpoint is created by open. A
// violation is a fault: it stops the Device's UDP until the Device is closed.
type udpAccounting struct {
	mu            sync.Mutex
	device        *Device
	local         netip.Addr
	maxBytes      int
	maxPackets    int
	fixedOverhead int // budget unit, not measured heap usage
	usedBytes     int
	usedPackets   int
	// Per-generation (one receiving endpoint) caps on the same units as the
	// Device budget. They default to the Device budget, which adds no limit;
	// setEndpointLimits lowers them so one endpoint whose reader stopped cannot
	// hold the whole Device budget. Budget units, not measured heap usage.
	maxEndpointBytes   int
	maxEndpointPackets int
	generations        map[*rawUDPAdapter]*udpGeneration
	localPorts         map[uint16]*rawUDPAdapter
	fault              error
	// Test-only observation of a send to an unregistered local port, called
	// while mu is held. Nil in the Device.
	sendUnmanagedHook func()

	// Refusals by the endpoint cap and by the Device budget, counted under mu
	// and read without it by the log.
	refusedEndpoint atomic.Uint64
	refusedDevice   atomic.Uint64
	refusalLog      lograte.Gate
	faultLog        sync.Once
}

type udpGeneration struct {
	stats       *tcpip.TransportEndpointStats
	fifo        []udpReservation
	local       tcpip.FullAddress
	remote      *tcpip.FullAddress
	usedBytes   int // this generation's share of the Device usage, guarded by mu
	usedPackets int
}

// A reservation records the generation it was charged to, so every refund
// path (settle, stale send, Read, Close) returns both the Device and the
// generation usage without its caller naming the generation again.
type udpReservation struct {
	payload int
	cost    int
	g       *udpGeneration
}

// udpRefusal is why reserveLocked did not reserve. udpReserved means it did.
type udpRefusal int

const (
	udpReserved udpRefusal = iota
	udpRefusedEndpoint
	udpRefusedDevice
	udpRefusedFault // a fault, or a request no budget can hold
)

type udpEndpointStats struct{ received, closed, overflow uint64 }

func snapshotEndpointStats(s *tcpip.TransportEndpointStats) udpEndpointStats {
	return udpEndpointStats{
		received: s.PacketsReceived.Value(),
		closed:   s.ReceiveErrors.ClosedReceiver.Value(),
		overflow: s.ReceiveErrors.ReceiveBufferOverflow.Value(),
	}
}

func acceptedDelta(before, after udpEndpointStats) (uint64, error) {
	if after.received < before.received || after.closed < before.closed || after.overflow < before.overflow {
		return 0, errors.New("UDP stats moved backwards")
	}
	received := after.received - before.received
	rejected := after.closed - before.closed + after.overflow - before.overflow
	if rejected > received {
		return 0, errors.New("UDP reject counters exceeded received count")
	}
	return received - rejected, nil
}

func newUDPAccounting(dev *Device, local netip.Addr, maxBytes, maxPackets, fixedOverhead int) *udpAccounting {
	t := &udpAccounting{
		device: dev, local: local, maxBytes: maxBytes, maxPackets: maxPackets, fixedOverhead: fixedOverhead,
		maxEndpointBytes: maxBytes, maxEndpointPackets: maxPackets,
		generations: make(map[*rawUDPAdapter]*udpGeneration),
		localPorts:  make(map[uint16]*rawUDPAdapter),
	}
	if maxBytes < 0 || maxPackets < 0 || fixedOverhead < 0 || !local.Is4() || local.IsMulticast() || local.IsUnspecified() {
		t.fault = errors.New("invalid UDP accounting configuration")
	}
	return t
}

// attach registers the adapter as a new generation. A new adapter is a new
// generation even if it binds the same tuple after a prior Close.
func (t *udpAccounting) attach(c *rawUDPAdapter) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.attachLocked(c)
}

func (t *udpAccounting) attachLocked(c *rawUDPAdapter) error {
	if t.fault != nil {
		return t.fault
	}
	if c.accounting != nil {
		return errors.New("adapter is already attached")
	}
	stats, ok := c.ep.Stats().(*tcpip.TransportEndpointStats)
	if !ok {
		return errors.New("UDP endpoint stats unavailable")
	}
	local, terr := c.ep.GetLocalAddress()
	if terr != nil || local.Addr != tcpip.AddrFromSlice(t.local.AsSlice()) || local.Port == 0 {
		return errors.New("UDP accounting requires an exact local IPv4 address and port")
	}
	if t.localPorts[local.Port] != nil {
		return errors.New("UDP accounting does not permit duplicate local UDP ports")
	}
	g := &udpGeneration{stats: stats, local: local}
	if remote, terr := c.ep.GetRemoteAddress(); terr == nil {
		g.remote = &remote
	} else if _, ok := terr.(*tcpip.ErrNotConnected); !ok {
		return errors.New(terr.String())
	}
	t.generations[c] = g
	t.localPorts[local.Port] = c
	c.accounting = t
	return nil
}

// setEndpointLimits sets the per-generation caps. Called before any endpoint
// is opened; values above the Device budget are clamped to it.
func (t *udpAccounting) setEndpointLimits(maxBytes, maxPackets int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if maxBytes < 0 || maxPackets < 0 {
		t.fault = errors.New("invalid UDP endpoint limit")
		return
	}
	t.maxEndpointBytes = min(maxBytes, t.maxBytes)
	t.maxEndpointPackets = min(maxPackets, t.maxPackets)
}

// reserveLocked charges one datagram to the Device budget and to generation
// g's cap. Either limit refuses it; nothing is charged on refusal. A refusal
// by a limit is counted by kind: the endpoint's cap when g is at it, the
// Device budget otherwise.
func (t *udpAccounting) reserveLocked(g *udpGeneration, payload int) (udpReservation, udpRefusal) {
	return t.reserveWithChargeLocked(g, payload, payload)
}

// delivered is the payload length returned by Read. charged includes any
// bytes after UDP Length that may still be retained by the packet buffer.
func (t *udpAccounting) reserveWithChargeLocked(g *udpGeneration, delivered, charged int) (udpReservation, udpRefusal) {
	if t.fault != nil || g == nil || delivered < 0 || charged < delivered || charged > math.MaxInt-t.fixedOverhead {
		return udpReservation{}, udpRefusedFault
	}
	r := udpReservation{payload: delivered, cost: charged + t.fixedOverhead, g: g}
	if g.usedPackets >= t.maxEndpointPackets || r.cost > t.maxEndpointBytes-g.usedBytes {
		t.refusedEndpoint.Add(1)
		return udpReservation{}, udpRefusedEndpoint
	}
	if t.usedPackets >= t.maxPackets || r.cost > t.maxBytes-t.usedBytes {
		t.refusedDevice.Add(1)
		return udpReservation{}, udpRefusedDevice
	}
	t.usedPackets++
	t.usedBytes += r.cost
	g.usedPackets++
	g.usedBytes += r.cost
	return r, udpReserved
}

// failLocked records a ledger violation and returns the fault in effect. The
// first violation is kept, so the one log line and every later report name
// the same one.
func (t *udpAccounting) failLocked(err error) error {
	if t.fault == nil {
		t.fault = err
	}
	return t.fault
}

func (t *udpAccounting) refundLocked(r udpReservation) {
	t.usedPackets--
	t.usedBytes -= r.cost
	r.g.usedPackets--
	r.g.usedBytes -= r.cost
}

func (t *udpAccounting) settleLocked(g *udpGeneration, r udpReservation, before, after udpEndpointStats) (bool, error) {
	accepted, err := acceptedDelta(before, after)
	if err != nil || accepted > 1 {
		t.refundLocked(r)
		if err == nil {
			err = fmt.Errorf("one injection accepted %d UDP datagrams", accepted)
		}
		return false, t.failLocked(err)
	}
	if accepted == 0 {
		t.refundLocked(r)
		return false, nil
	}
	g.fifo = append(g.fifo, r)
	return true, nil
}

// noteRefusal writes the refusal counts to the log at most once a minute. It
// is called without mu after a refusal by a limit, so the log line never
// waits inside the ledger.
func (t *udpAccounting) noteRefusal(why udpRefusal) {
	if why != udpRefusedEndpoint && why != udpRefusedDevice {
		return
	}
	if !t.refusalLog.Allow() {
		return
	}
	logf("userspace tunnel: dropped UDP datagrams because receiving sockets are not read fast enough; "+
		"%d refused at one socket's cap of %d bytes or %d datagrams, %d refused at the tunnel's total of %d bytes or %d datagrams, since the tunnel was built",
		t.refusedEndpoint.Load(), t.maxEndpointBytes, t.maxEndpointPackets, t.refusedDevice.Load(), t.maxBytes, t.maxPackets)
}

// reportFault writes the fault to the log once. It is called without mu by
// every path that detects a fault, after that path has released mu.
func (t *udpAccounting) reportFault() {
	t.mu.Lock()
	err := t.fault
	t.mu.Unlock()
	if err == nil {
		return
	}
	t.faultLog.Do(func() {
		logf("userspace tunnel: UDP receive accounting found an internal inconsistency and stopped all UDP on this tunnel: %v; "+
			"TCP keeps working; restart wgft to resume UDP, and report this as a bug", err)
	})
}

// faultErr is the fault, or nil while the ledger is consistent.
func (t *udpAccounting) faultErr() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.fault
}

// accountedSend performs one reserved delivery into receiver's generation g
// and settles the reservation from the receiver's public Stats delta. The
// receiver's opMu makes that delta attributable to this one send: two
// unserialized sends into one endpoint read the same combined delta and cannot
// tell which of them was refused. The caller looked g up and reserved under mu
// without holding opMu, so g is checked again here; stale reports that the
// generation was closed or replaced in between, in which case the reservation
// is refunded and nothing is sent. The send callback runs under opMu only.
func (t *udpAccounting) accountedSend(receiver *rawUDPAdapter, g *udpGeneration, r udpReservation, send func()) (kept, stale bool, err error) {
	receiver.opMu.Lock()
	defer receiver.opMu.Unlock()
	t.mu.Lock()
	if t.generations[receiver] != g {
		t.refundLocked(r)
		t.mu.Unlock()
		return false, true, nil
	}
	t.mu.Unlock()
	before := snapshotEndpointStats(g.stats)
	send()
	after := snapshotEndpointStats(g.stats)
	t.mu.Lock()
	defer t.mu.Unlock()
	kept, err = t.settleLocked(g, r, before, after)
	return kept, false, err
}

// errUDPBudget is returned to a local writer whose datagram to a local
// receiver was refused by the receive budget.
var errUDPBudget = errors.New("UDP receive budget exceeded")

// localWrite is rawUDPAdapter.WriteTo under accounting. A destination that is
// not this Device's address never loops back (the stack has one address and
// picks the loopback route only for it), so it is written with no lock. A
// managed local receiver gets the reserve, window, settle shape of an
// injection under the receiver's opMu; the sender's own opMu is not taken, so
// a reflexive write holds one lock once. The sender's write deadline is
// checked again inside the window so an expired write that waited for the
// receiver's lock sends nothing.
func (t *udpAccounting) localWrite(sender *rawUDPAdapter, data []byte, opts tcpip.WriteOptions) (int64, tcpip.Error, error) {
	if t.device.closed.Load() {
		return 0, nil, errDeviceClosed
	}
	dst := opts.To
	if dst == nil {
		a, err := sender.ep.GetRemoteAddress()
		if err != nil {
			return 0, nil, errors.New(err.String())
		}
		dst = &a
	}
	if dst.Addr != tcpip.AddrFromSlice(t.local.AsSlice()) {
		n, terr := sender.ep.Write(bytes.NewReader(data), opts)
		return n, terr, nil
	}
	for {
		t.mu.Lock()
		if t.fault != nil {
			t.mu.Unlock()
			return 0, nil, t.fault
		}
		receiver := t.localPorts[dst.Port]
		if receiver == nil {
			// A local port nobody registered: gVisor answers with Port
			// Unreachable. Stay under mu so a concurrent open cannot
			// register this port and receive the datagram unreserved.
			if t.sendUnmanagedHook != nil {
				t.sendUnmanagedHook()
			}
			n, terr := sender.ep.Write(bytes.NewReader(data), opts)
			t.mu.Unlock()
			return n, terr, nil
		}
		g := t.generations[receiver]
		r, why := t.reserveLocked(g, len(data))
		t.mu.Unlock()
		if why != udpReserved {
			t.noteRefusal(why)
			return 0, nil, errUDPBudget
		}
		var n int64
		var terr tcpip.Error
		expired := false
		_, stale, err := t.accountedSend(receiver, g, r, func() {
			if at, _ := sender.deadline(false); !at.IsZero() && !time.Now().Before(at) {
				expired = true
				return
			}
			n, terr = sender.ep.Write(bytes.NewReader(data), opts)
		})
		if stale {
			continue
		}
		if err != nil {
			t.reportFault()
			return n, terr, err
		}
		if expired {
			return 0, nil, osDeadlineError{}
		}
		return n, terr, nil
	}
}

// afterRead charges exactly one dequeue, including zero-length packets and
// ErrBadBuffer after the endpoint has already removed a packet. The caller
// holds c.opMu, so the FIFO head is the datagram gVisor just dequeued.
func (t *udpAccounting) afterRead(c *rawUDPAdapter, result tcpip.ReadResult, terr tcpip.Error) error {
	_, badBuffer := terr.(*tcpip.ErrBadBuffer)
	if terr != nil && !badBuffer {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	g := t.generations[c]
	if g == nil || len(g.fifo) == 0 {
		return t.failLocked(errors.New("unreserved UDP dequeue"))
	}
	r := g.fifo[0]
	g.fifo = g.fifo[1:]
	t.refundLocked(r)
	if result.Total != r.payload {
		return t.failLocked(fmt.Errorf("UDP FIFO payload mismatch: read %d, reserved %d", result.Total, r.payload))
	}
	return nil
}

// closeGeneration refunds every queued reservation and removes the generation.
// The caller holds c.opMu and has closed the endpoint, so no send can add to
// the FIFO between the endpoint drain and this refund.
func (t *udpAccounting) closeGeneration(c *rawUDPAdapter) {
	t.mu.Lock()
	defer t.mu.Unlock()
	g := t.generations[c]
	if g == nil {
		return
	}
	for _, r := range g.fifo {
		t.refundLocked(r)
	}
	delete(t.generations, c)
	delete(t.localPorts, g.local.Port)
}
