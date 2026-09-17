package utun

// netstack と wireguard-go の device をつなぐ TUN。wireguard-go の tun/netstack(MIT License、
// Copyright (C) 2017-2025 WireGuard LLC)の CreateNetTUN から、IPv4 と dial に要る部分だけを写したもの。
// 写した理由は、netstack.Net が stack を公開しないため。UDP のセッションが「届くまでバッファを持たずに待つ」
// (仕様 7 節)には、エンドポイントの waiter.Queue に触る必要がある。

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type netTun struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan tun.Event
	notifyHandle   *channel.NotificationHandle
	incomingPacket chan *buffer.View
	mtu            int
}

// createNetTUN は addr(IPv4)を持つ netstack と、その TUN を作る。
func createNetTUN(addr netip.Addr, mtu int) (*netTun, error) {
	if !addr.Is4() {
		return nil, fmt.Errorf("tunnel address %s is not IPv4", addr)
	}
	dev := &netTun{
		ep: channel.New(1024, uint32(mtu), ""),
		stack: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
			HandleLocal:        true,
		}),
		events:         make(chan tun.Event, 10),
		incomingPacket: make(chan *buffer.View),
		mtu:            mtu,
	}
	sack := tcpip.TCPSACKEnabled(true) // 既定では無効
	if err := dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return nil, fmt.Errorf("could not enable TCP SACK: %v", err)
	}
	dev.notifyHandle = dev.ep.AddNotify(dev)
	if err := dev.stack.CreateNIC(1, dev.ep); err != nil {
		return nil, fmt.Errorf("CreateNIC: %v", err)
	}
	pa := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix()}
	if err := dev.stack.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("AddProtocolAddress(%v): %v", addr, err)
	}
	dev.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	dev.events <- tun.EventUp
	return dev, nil
}

func (t *netTun) Name() (string, error)    { return "go", nil }
func (t *netTun) File() *os.File           { return nil }
func (t *netTun) Events() <-chan tun.Event { return t.events }
func (t *netTun) MTU() (int, error)        { return t.mtu, nil }
func (t *netTun) BatchSize() int           { return 1 }

func (t *netTun) Read(buf [][]byte, sizes []int, offset int) (int, error) {
	view, ok := <-t.incomingPacket
	if !ok {
		return 0, os.ErrClosed
	}
	n, err := view.Read(buf[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (t *netTun) Write(buf [][]byte, offset int) (int, error) {
	for _, b := range buf {
		packet := b[offset:]
		if len(packet) == 0 {
			continue
		}
		if packet[0]>>4 != 4 {
			return 0, syscall.EAFNOSUPPORT
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		t.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
	}
	return len(buf), nil
}

func (t *netTun) WriteNotify() {
	pkt := t.ep.Read()
	if pkt == nil {
		return
	}
	view := pkt.ToView()
	pkt.DecRef()
	t.incomingPacket <- view
}

func (t *netTun) Close() error {
	t.stack.RemoveNIC(1)
	t.stack.Close()
	t.ep.RemoveNotify(t.notifyHandle)
	t.ep.Close()
	close(t.events)
	close(t.incomingPacket)
	return nil
}

func fullAddr(ap netip.AddrPort) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(ap.Addr().AsSlice()), Port: ap.Port()}
}

func (t *netTun) dialTCP(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
	return gonet.DialContextTCP(ctx, t.stack, fullAddr(ap), ipv4.ProtocolNumber)
}

// dialUDP は接続済みの UDP を作る。返す接続は relay.ReadWaiter を満たす。
func (t *netTun) dialUDP(ap netip.AddrPort) (net.Conn, error) {
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
