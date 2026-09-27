package nettun

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// DialPing は laddr から raddr への、接続済みの ICMP echo をつなぐ(エージェントの keepalive の
// ping。仕様 7 節の Tunnel.Run)。包むのに gonet.UDPConn をそのまま使う。tcpip.Endpoint の汎用の
// Read/Write/deadline の操作を呼ぶだけなので、エンドポイントのトランスポートプロトコルによらず動く。
//
// endpoint は bind せずに接続する(仕様 7 節「keepalive の ping の endpoint」)。固定版の gVisor の
// ICMP の endpoint は、bind で登録した identifier を接続でも Close でも解放しないので、bind してから
// 接続すると ping ごとに endpoint と identifier が 1 つずつ残る。送信元は接続の経路が Device の
// ただ 1 つのアドレスから選ぶので、接続の後にそれが laddr であることを確かめる。
func (t *Device) DialPing(laddr, raddr netip.Addr) (net.Conn, error) {
	var wq waiter.Queue
	ep, terr := t.stack.NewEndpoint(icmp.ProtocolNumber4, ipv4.ProtocolNumber, &wq)
	if terr != nil {
		return nil, errors.New(terr.String())
	}
	if terr := ep.Connect(fullAddr(netip.AddrPortFrom(raddr, 0))); terr != nil {
		ep.Close()
		return nil, fmt.Errorf("ping connect: %s", terr.String())
	}
	// 固定版の gVisor の ICMP の endpoint の GetLocalAddress は誤りを返さない。
	// 返したとしても、空のアドレスは laddr と一致しないので下の検査で落ちる。
	local, _ := ep.GetLocalAddress()
	if src, _ := netip.AddrFromSlice(local.Addr.AsSlice()); src != laddr {
		ep.Close()
		return nil, fmt.Errorf("ping source address is %v, want %v", src, laddr)
	}
	return gonet.NewUDPConn(&wq, ep), nil
}
