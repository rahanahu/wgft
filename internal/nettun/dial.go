package nettun

import (
	"context"
	"net"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

// DialTCP は、この device の stack 越しに ap へつなぐ(仕様 6.3 節:vpsd からエージェントへの dial)。
func (t *Device) DialTCP(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
	return gonet.DialContextTCP(ctx, t.stack, fullAddr(ap), ipv4.ProtocolNumber)
}

// DialUDP は、この device の stack 越しに接続済みの UDP を作る。endpoint は登録表を通して作り、
// 受信の会計に登録する(仕様 7 節)。返す接続は ReadWaiter (WaitReadable) を満たし、次の
// データグラムが届くまでバッファを持たずに待てる。
func (t *Device) DialUDP(ap netip.AddrPort) (net.Conn, error) {
	return t.registry.dial(ap)
}
