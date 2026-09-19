package nettun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// DialTCP は、この device の stack 越しに ap へつなぐ(仕様 6.3 節:vpsd からエージェントへの dial)。
func (t *Device) DialTCP(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
	return gonet.DialContextTCP(ctx, t.stack, fullAddr(ap), ipv4.ProtocolNumber)
}

// DialUDP は、この device の stack 越しに接続済みの UDP を作る。返す接続は ReadWaiter
// (WaitReadable) を満たし、次のデータグラムが届くまでバッファを持たずに待てる(仕様 7 節)。
func (t *Device) DialUDP(ap netip.AddrPort) (net.Conn, error) {
	var wq waiter.Queue
	ep, terr := t.stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if terr != nil {
		return nil, errors.New(terr.String())
	}
	if terr := ep.Connect(fullAddr(ap)); terr != nil {
		ep.Close()
		return nil, &net.OpError{Op: "connect", Net: "udp", Addr: net.UDPAddrFromAddrPort(ap), Err: errors.New(terr.String())}
	}
	c := &udpConn{UDPConn: gonet.NewUDPConn(&wq, ep), ep: ep, wq: &wq, closed: make(chan struct{})}
	c.entry, c.readable = waiter.NewChannelEntry(waiter.ReadableEvents)
	wq.EventRegister(&c.entry)
	return c, nil
}

// udpConn は、次のデータグラムが届くまでバッファを持たずに待てる UDP の接続。
type udpConn struct {
	*gonet.UDPConn
	ep       tcpip.Endpoint
	wq       *waiter.Queue
	entry    waiter.Entry
	readable chan struct{}
	once     sync.Once
	closed   chan struct{}
}

// WaitReadable は次の Read が待たずに戻る状態になるまで待つ。
func (c *udpConn) WaitReadable() error {
	for {
		select {
		case <-c.closed:
			return net.ErrClosed
		default:
		}
		if c.ep.Readiness(waiter.ReadableEvents)&waiter.ReadableEvents != 0 {
			return nil
		}
		select {
		case <-c.readable: // 古い通知のこともあるので、もう一度 Readiness を見る
		case <-c.closed:
			return net.ErrClosed
		}
	}
}

func (c *udpConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
		c.wq.EventUnregister(&c.entry)
	})
	return c.UDPConn.Close()
}
