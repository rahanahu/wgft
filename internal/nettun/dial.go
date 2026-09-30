package nettun

import (
	"net"
	"net/netip"
)

// DialUDP は、この device の stack 越しに接続済みの UDP を作る。endpoint は登録表を通して作り、
// 受信の会計に登録する(仕様 7 節)。返す接続は ReadWaiter (WaitReadable) を満たし、次の
// データグラムが届くまでバッファを持たずに待てる。
func (t *Device) DialUDP(ap netip.AddrPort) (net.Conn, error) {
	return t.registry.dial(ap)
}
