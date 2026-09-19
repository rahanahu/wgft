// Package nettun は、エージェントのトンネル(internal/agent/tunnel)とサーバのユーザー空間モードの
// トンネル(internal/dataplane/userspace/utun)が共有する、netstack と TUN の接着部。どちらも wireguard-go の
// device を支える gVisor の stack.Stack への直接アクセスを要る。サーバ側は UDP の応答をバッファ
// なしで待つため(waiter.Queue)、エージェント側は拒んだ TCP 接続を RST で即座に終える(Abort)
// ため(listen.go)である。wireguard-go 自身の tun/netstack パッケージは組み立てた stack を
// 公開しない(型 Net は非公開の netTun を包む)ため、このパッケージは tun/netstack.CreateNetTUN の
// 必要な部分を写したもの(MIT License、Copyright (C) 2017-2025 WireGuard LLC)に、Stack を返す
// アクセサを足したものである。
package nettun

import (
	"fmt"
	"net/netip"
	"os"
	"syscall"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// Device は 1 つの IPv4 アドレスを持つ gVisor netstack 上の tun.Device で、wireguard-go の
// device.Device に組み込める。wireguard-go 自身の netstack.Net と違い、Stack を公開する。
type Device struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan tun.Event
	notifyHandle   *channel.NotificationHandle
	incomingPacket chan *buffer.View
	mtu            int
}

// Create は addr (IPv4 のみ) を唯一のアドレスとする Device を作る。
func Create(addr netip.Addr, mtu int) (*Device, error) {
	if !addr.Is4() {
		return nil, fmt.Errorf("tunnel address %s is not IPv4", addr)
	}
	dev := &Device{
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

// Stack はこの device を支える gVisor の stack を返す。
func (t *Device) Stack() *stack.Stack { return t.stack }

func (t *Device) Name() (string, error)    { return "go", nil }
func (t *Device) File() *os.File           { return nil }
func (t *Device) Events() <-chan tun.Event { return t.events }
func (t *Device) MTU() (int, error)        { return t.mtu, nil }
func (t *Device) BatchSize() int           { return 1 }

func (t *Device) Read(buf [][]byte, sizes []int, offset int) (int, error) {
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

func (t *Device) Write(buf [][]byte, offset int) (int, error) {
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

func (t *Device) WriteNotify() {
	pkt := t.ep.Read()
	if pkt == nil {
		return
	}
	view := pkt.ToView()
	pkt.DecRef()
	t.incomingPacket <- view
}

func (t *Device) Close() error {
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
