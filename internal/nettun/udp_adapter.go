package nettun

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// rawUDPAdapter is the Device's UDP connection, the net.Conn of DialUDP and
// the net.PacketConn of ListenUDP. It replaces gonet.UDPConn so that every
// Read and every local write passes the accounting. opMu is this endpoint's
// (generation's) lock: it serializes deliveries into this endpoint with each
// other, with Read and with Close, so that the accounting can attribute the
// endpoint's public Stats delta to one delivery. It is held for one
// nonblocking endpoint call at a time and never while waiting; waiter
// callbacks never acquire it. See udpAccounting for the lock order.
type rawUDPAdapter struct {
	ep     tcpip.Endpoint
	wq     *waiter.Queue
	opMu   sync.Mutex
	closed chan struct{}
	once   sync.Once

	deadlineMu sync.Mutex
	readBy     time.Time
	writeBy    time.Time
	changed    chan struct{}
	accounting *udpAccounting
	// Test-only observation after an actual raw endpoint ErrWouldBlock.
	wouldBlockObserved chan struct{}
}

// newRawUDPAdapter creates, binds or connects the endpoint. The registry calls
// it under the accounting lock so creation and registration stay one step.
func newRawUDPAdapter(t *Device, local, remote *netip.AddrPort) (*rawUDPAdapter, error) {
	wq := new(waiter.Queue)
	ep, terr := t.stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if terr != nil {
		return nil, errors.New(terr.String())
	}
	// The newer stack defaults UDP to PMTUDiscoveryWant. Its local IPv4
	// fragmentation retains DF on fragments, which remote stacks reject.
	if terr := ep.SetSockOptInt(tcpip.MTUDiscoverOption, int(tcpip.PMTUDiscoveryDont)); terr != nil {
		ep.Close()
		return nil, errors.New(terr.String())
	}
	if local != nil {
		if terr := ep.Bind(fullAddr(*local)); terr != nil {
			ep.Close()
			return nil, &net.OpError{Op: "bind", Net: "udp", Addr: net.UDPAddrFromAddrPort(*local), Err: errors.New(terr.String())}
		}
	}
	if remote != nil {
		if terr := ep.Connect(fullAddr(*remote)); terr != nil {
			ep.Close()
			return nil, &net.OpError{Op: "connect", Net: "udp", Addr: net.UDPAddrFromAddrPort(*remote), Err: errors.New(terr.String())}
		}
	}
	return &rawUDPAdapter{ep: ep, wq: wq, closed: make(chan struct{}), changed: make(chan struct{})}, nil
}

func (c *rawUDPAdapter) deadline(read bool) (time.Time, <-chan struct{}) {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if read {
		return c.readBy, c.changed
	}
	return c.writeBy, c.changed
}

func (c *rawUDPAdapter) setDeadline(read, write bool, at time.Time) error {
	c.deadlineMu.Lock()
	if read {
		c.readBy = at
	}
	if write {
		c.writeBy = at
	}
	close(c.changed)
	c.changed = make(chan struct{})
	c.deadlineMu.Unlock()
	return nil
}

func (c *rawUDPAdapter) SetDeadline(at time.Time) error      { return c.setDeadline(true, true, at) }
func (c *rawUDPAdapter) SetReadDeadline(at time.Time) error  { return c.setDeadline(true, false, at) }
func (c *rawUDPAdapter) SetWriteDeadline(at time.Time) error { return c.setDeadline(false, true, at) }

// waitEvent rechecks the current deadline after any notification. A deadline
// update closes changed, including when a finite deadline is cleared.
func (c *rawUDPAdapter) waitEvent(read bool, notify <-chan struct{}) error {
	at, changed := c.deadline(read)
	if !at.IsZero() && !time.Now().Before(at) {
		return osDeadlineError{}
	}
	var timer *time.Timer
	var timeout <-chan time.Time
	if !at.IsZero() {
		timer = time.NewTimer(time.Until(at))
		timeout = timer.C
		defer timer.Stop()
	}
	return c.waitReady(read, changed, notify, timeout)
}

func (c *rawUDPAdapter) waitReady(read bool, changed <-chan struct{}, notify <-chan struct{}, timeout <-chan time.Time) error {
	select {
	case <-c.closed:
		return net.ErrClosed
	case <-changed:
	case <-notify:
	case <-timeout:
		return c.currentDeadlineError(read)
	}
	return nil
}

// A timer from an older deadline may fire at the same time as an extension or
// clear. Timeout is only final if the current deadline has also expired.
func (c *rawUDPAdapter) currentDeadlineError(read bool) error {
	select {
	case <-c.closed:
		return net.ErrClosed
	default:
	}
	at, _ := c.deadline(read)
	if !at.IsZero() && !time.Now().Before(at) {
		return osDeadlineError{}
	}
	return nil
}

// osDeadlineError keeps net.Error timeout semantics without copying gonet's
// private deadline timer.
type osDeadlineError struct{}

func (osDeadlineError) Error() string   { return "i/o timeout" }
func (osDeadlineError) Timeout() bool   { return true }
func (osDeadlineError) Temporary() bool { return true }

func (c *rawUDPAdapter) opError(op string, addr net.Addr, err error) error {
	if errors.Is(err, net.ErrClosed) {
		return net.ErrClosed
	}
	return &net.OpError{Op: op, Net: "udp", Source: c.LocalAddr(), Addr: addr, Err: err}
}

// readOne dequeues at most one datagram under this endpoint's opMu and, under
// accounting, pops the matching FIFO head before the lock is released. The
// deadline is checked again under the lock so an expired Read that waited for
// the lock does not consume a datagram.
func (c *rawUDPAdapter) readOne(b []byte) (tcpip.ReadResult, tcpip.Error, error) {
	w := tcpip.SliceWriter(b)
	opts := tcpip.ReadOptions{NeedRemoteAddr: true}
	c.opMu.Lock()
	defer c.opMu.Unlock()
	select {
	case <-c.closed:
		return tcpip.ReadResult{}, nil, net.ErrClosed
	default:
	}
	if at, _ := c.deadline(true); !at.IsZero() && !time.Now().Before(at) {
		return tcpip.ReadResult{}, nil, osDeadlineError{}
	}
	result, terr := c.ep.Read(&w, opts)
	if c.accounting != nil {
		if err := c.accounting.afterRead(c, result, terr); err != nil {
			// reportFault takes the accounting lock, which the order opMu ->
			// mu allows while opMu is held.
			c.accounting.reportFault()
			return result, terr, err
		}
	}
	return result, terr, nil
}

func (c *rawUDPAdapter) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

func (c *rawUDPAdapter) ReadFrom(b []byte) (int, net.Addr, error) {
	entry, notify := waiter.NewChannelEntry(waiter.ReadableEvents | waiter.EventErr | waiter.EventHUp)
	c.wq.EventRegister(&entry)
	defer c.wq.EventUnregister(&entry)
	for {
		at, _ := c.deadline(true)
		if !at.IsZero() && !time.Now().Before(at) {
			return 0, nil, c.opError("read", nil, osDeadlineError{})
		}
		result, terr, err := c.readOne(b)
		if err != nil {
			return 0, nil, c.opError("read", nil, err)
		}
		if _, ok := terr.(*tcpip.ErrWouldBlock); ok {
			if err := c.waitEvent(true, notify); err != nil {
				return 0, nil, c.opError("read", nil, err)
			}
			continue
		}
		if _, ok := terr.(*tcpip.ErrClosedForReceive); ok {
			return 0, nil, io.EOF
		}
		if terr != nil {
			return 0, nil, c.opError("read", nil, errors.New(terr.String()))
		}
		return result.Count, udpAddress(result.RemoteAddr), nil
	}
}

func udpAddress(a tcpip.FullAddress) net.Addr {
	return &net.UDPAddr{IP: net.IP(a.Addr.AsSlice()), Port: int(a.Port), Zone: ""}
}

func (c *rawUDPAdapter) Write(b []byte) (int, error) { return c.WriteTo(b, nil) }

// WriteTo does not take this adapter's own opMu: a write into another local
// endpoint is serialized by that receiver's lock inside the accounting, and a
// remote write needs no lock. A closed sender is refused before writing; a
// Close that races the write makes the endpoint itself refuse it.
func (c *rawUDPAdapter) WriteTo(b []byte, addr net.Addr) (int, error) {
	var opts tcpip.WriteOptions
	if addr != nil {
		ua, ok := addr.(*net.UDPAddr)
		if !ok || ua.Port <= 0 || ua.Port > 65535 || ua.IP.To4() == nil {
			return 0, c.opError("write", addr, errors.New("invalid UDP address"))
		}
		opts.To = &tcpip.FullAddress{Addr: tcpip.AddrFromSlice(ua.IP.To4()), Port: uint16(ua.Port)}
	}
	entry, notify := waiter.NewChannelEntry(waiter.WritableEvents | waiter.EventErr | waiter.EventHUp)
	c.wq.EventRegister(&entry)
	defer c.wq.EventUnregister(&entry)
	for {
		at, _ := c.deadline(false)
		if !at.IsZero() && !time.Now().Before(at) {
			return 0, c.opError("write", addr, osDeadlineError{})
		}
		select {
		case <-c.closed:
			return 0, net.ErrClosed
		default:
		}
		var n int64
		var terr tcpip.Error
		var accountingErr error
		if c.accounting != nil {
			n, terr, accountingErr = c.accounting.localWrite(c, b, opts)
		} else {
			n, terr = c.ep.Write(bytes.NewReader(b), opts)
		}
		if accountingErr != nil {
			return int(n), c.opError("write", addr, accountingErr)
		}
		if _, ok := terr.(*tcpip.ErrWouldBlock); ok {
			if c.wouldBlockObserved != nil {
				select {
				case c.wouldBlockObserved <- struct{}{}:
				default:
				}
			}
			if err := c.waitEvent(false, notify); err != nil {
				return int(n), c.opError("write", addr, err)
			}
			continue
		}
		if terr != nil {
			return int(n), c.opError("write", addr, errors.New(terr.String()))
		}
		return int(n), nil
	}
}

// WaitReadable returns when the next Read can return data or an endpoint error
// without waiting. It also observes EventErr so a synchronous ICMP failure
// does not leave a relay waiting.
func (c *rawUDPAdapter) WaitReadable() error {
	entry, notify := waiter.NewChannelEntry(waiter.ReadableEvents | waiter.EventErr | waiter.EventHUp)
	c.wq.EventRegister(&entry)
	defer c.wq.EventUnregister(&entry)
	for {
		c.opMu.Lock()
		select {
		case <-c.closed:
			c.opMu.Unlock()
			return net.ErrClosed
		default:
		}
		ready := c.ep.Readiness(waiter.ReadableEvents | waiter.EventErr | waiter.EventHUp)
		c.opMu.Unlock()
		if ready != 0 {
			return nil
		}
		select {
		case <-c.closed:
			return net.ErrClosed
		case <-notify:
		}
	}
}

// Close drains the endpoint and refunds the whole FIFO under opMu, so no
// delivery can enter between the two.
func (c *rawUDPAdapter) Close() error {
	c.once.Do(func() {
		c.opMu.Lock()
		close(c.closed)
		c.ep.Close()
		if c.accounting != nil {
			c.accounting.closeGeneration(c)
		}
		c.opMu.Unlock()
	})
	return nil
}

func (c *rawUDPAdapter) LocalAddr() net.Addr {
	a, err := c.ep.GetLocalAddress()
	if err != nil {
		return nil
	}
	return udpAddress(a)
}

func (c *rawUDPAdapter) RemoteAddr() net.Addr {
	a, err := c.ep.GetRemoteAddress()
	if err != nil {
		return nil
	}
	return udpAddress(a)
}

var _ net.Conn = (*rawUDPAdapter)(nil)
var _ net.PacketConn = (*rawUDPAdapter)(nil)
