// Package nettun は、エージェントのトンネル(internal/dataplane/userspace/tunnel)とサーバのユーザー空間モードの
// トンネル(internal/dataplane/userspace/utun)が共有する、netstack と TUN の接続部分。どちらも wireguard-go の
// device を支える gVisor の stack.Stack への package 内のアクセスを要る。サーバ側は UDP の応答をバッファ
// なしで待つため(waiter.Queue)、エージェント側は拒んだ TCP 接続を RST で即座に終える(Abort)
// ため(listen.go)、どちらも UDP の受信を会計に通すため(udp_accounting.go)と、TCP の送信と受信の
// バッファに上限を置くため(tcpbuf.go)である。wireguard-go 自身の
// tun/netstack パッケージは組み立てた stack を公開しない(型 Net は非公開の netTun を包む)ため、この
// パッケージは tun/netstack.CreateNetTUN の必要な部分を写したもの(MIT License、Copyright (C) 2017-2025
// WireGuard LLC)を基にする。stack はこのパッケージの外に出さない。外で UDP の endpoint を作れると、
// 会計の外で datagram を受け取れるためである。
package nettun

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.zx2c4.com/wireguard/tun"
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
// device.Device に組み込める。UDP の endpoint は DialUDP と ListenUDP だけが登録表を通して作る。
//
// 出力は channel.Endpoint の有限キューから Read が直接引き取る。入力の IPv4 の断片は有限な
// 再組み立て(ingress.go)を通し、完成した datagram だけを stack に渡す。この Device 宛ての UDP は
// 受信の会計(udp_accounting.go)を通す。Close は読み取りを取り消す。
type Device struct {
	ep         *channel.Endpoint
	stack      *stack.Stack
	events     chan tun.Event
	readCtx    context.Context
	cancelRead context.CancelFunc
	closeOnce  sync.Once
	mtu        int
	local      netip.Addr
	registry   *udpRegistry
	reassembly *ipv4Reassembly
	sweepStop  chan struct{}
	sweepDone  chan struct{}
	closed     atomic.Bool
	pool       *boostPool // TCP のバッファの枠。プロセスで 1 つ(tcpbuf.go)
}

// Create は addr (IPv4 のみ) を唯一のアドレスとする Device を作る。
func Create(addr netip.Addr, mtu int) (*Device, error) {
	if !addr.Is4() {
		return nil, fmt.Errorf("tunnel address %s is not IPv4", addr)
	}
	readCtx, cancelRead := context.WithCancel(context.Background())
	dev := &Device{
		ep: channel.New(1024, uint32(mtu), ""),
		stack: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
			HandleLocal:        true,
		}),
		events:     make(chan tun.Event, 10),
		readCtx:    readCtx,
		cancelRead: cancelRead,
		mtu:        mtu,
		local:      addr,
		pool:       processTCPBoost,
	}
	// TCP の endpoint を作る前に設定する。失敗した stack は閉じて使わない
	if err := setTCPBufferRanges(dev.stack); err != nil {
		dev.Close()
		dev.Wait()
		return nil, err
	}
	sack := tcpip.TCPSACKEnabled(true) // 既定では無効
	if err := dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return nil, fmt.Errorf("could not enable TCP SACK: %v", err)
	}
	if err := dev.stack.CreateNIC(1, dev.ep); err != nil {
		return nil, fmt.Errorf("CreateNIC: %v", err)
	}
	pa := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix()}
	if err := dev.stack.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("AddProtocolAddress(%v): %v", addr, err)
	}
	dev.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	if err := dev.initUDP(); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.initReassembly(); err != nil {
		dev.Close()
		return nil, err
	}
	dev.events <- tun.EventUp
	return dev, nil
}

// Wait は stack の goroutine の終了を待つ。Close の後に呼ぶ。stack そのものは公開しない。
func (t *Device) Wait() { t.stack.Wait() }

// UDPReceiveFault は、UDP の受信の会計が不変条件の違反を検出してこの Device の UDP を止めた
// ときの誤りを返す。会計が健全な間は nil である(設計文書 7 節)。
func (t *Device) UDPReceiveFault() error {
	if t.registry == nil {
		return nil
	}
	return t.registry.accounting.faultErr()
}

func (t *Device) Name() (string, error)    { return "go", nil }
func (t *Device) File() *os.File           { return nil }
func (t *Device) Events() <-chan tun.Event { return t.events }
func (t *Device) MTU() (int, error)        { return t.mtu, nil }
func (t *Device) BatchSize() int           { return 1 }

func (t *Device) Read(buf [][]byte, sizes []int, offset int) (int, error) {
	if t.readCtx.Err() != nil {
		return 0, os.ErrClosed
	}
	pkt := t.ep.ReadContext(t.readCtx)
	if pkt == nil {
		return 0, os.ErrClosed
	}
	defer pkt.DecRef()
	// 取り消しとキューの受信が同時に選ばれた場合、確認時に閉鎖済みなら捨てる。
	if t.readCtx.Err() != nil {
		return 0, os.ErrClosed
	}
	view := pkt.ToView()
	defer view.Release()
	n, err := view.Read(buf[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (t *Device) Write(buf [][]byte, offset int) (int, error) {
	// A failed packet must not starve later packets in the same WireGuard
	// batch. Return the number accepted and the first error after trying all.
	accepted := 0
	var firstErr error
	for _, b := range buf {
		packet := b[offset:]
		if len(packet) == 0 {
			accepted++
			continue
		}
		if packet[0]>>4 != 4 {
			if firstErr == nil {
				firstErr = syscall.EAFNOSUPPORT
			}
			continue
		}
		if err := t.writeIPv4(packet); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		accepted++
	}
	return accepted, firstErr
}

// Close は device を閉じる。2 回目以降の呼び出しは何もしない。
//
// 読み取りの取り消しを先に行い、停止中の TUN.Read を解除する。再組み立ての sweeper は stack を
// 閉じる前に止めて待つ。UDP の endpoint は、閉じた印を付けてから全部閉じる。
func (t *Device) Close() error {
	t.closeOnce.Do(func() {
		t.cancelRead()
		t.closeIngress()
		t.stack.RemoveNIC(1)
		t.stack.Close()
		t.ep.Close()
		close(t.events)
	})
	return nil
}

func fullAddr(ap netip.AddrPort) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(ap.Addr().AsSlice()), Port: ap.Port()}
}
