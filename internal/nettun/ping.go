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
func (t *Device) DialPing(laddr, raddr netip.Addr) (net.Conn, error) {
	var wq waiter.Queue
	ep, terr := t.stack.NewEndpoint(icmp.ProtocolNumber4, ipv4.ProtocolNumber, &wq)
	if terr != nil {
		return nil, errors.New(terr.String())
	}
	if terr := ep.Bind(fullAddr(netip.AddrPortFrom(laddr, 0))); terr != nil {
		ep.Close()
		return nil, fmt.Errorf("ping bind: %s", terr.String())
	}
	if terr := ep.Connect(fullAddr(netip.AddrPortFrom(raddr, 0))); terr != nil {
		ep.Close()
		return nil, fmt.Errorf("ping connect: %s", terr.String())
	}
	return gonet.NewUDPConn(&wq, ep), nil
}
