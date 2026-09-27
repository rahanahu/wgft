package nettun

import (
	"context"
	"net"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// dialedConn は DialTCP が返す接続。*gonet.TCPConn に dial した tcpip.Endpoint へのアクセスを足し、
// Close だけを閉じた後の endpoint の天井(tcp_closing.go)に通す。accept 側の TCPConn と違って
// Abort を持たない。中継(relay の cutConn)は Abort を持つ接続だけを RST で切るので、vpsd が
// 中継を切るときの netstack の側の閉じ方は今までどおり Close(FIN)のままである。天井の判定と
// keepalive に要るのは endpoint への参照だけで、Abort は要らない(仕様 7 節)。
type dialedConn struct {
	*gonet.TCPConn
	ep  tcpip.Endpoint
	dev *Device
}

func (c *dialedConn) endpoint() tcpip.Endpoint { return c.ep }

// Close は net.Conn の実装。TCPConn.Close と同じく、閉じかけの endpoint の数が Device の天井に
// 達している間はこの endpoint を RST で直ちに解放し、それ以外は gonet の Close に落とす。
func (c *dialedConn) Close() error {
	if c.dev != nil && c.dev.closeTCP(c.ep) {
		return nil
	}
	return c.TCPConn.Close()
}

// DialTCP は、この device の stack 越しに ap へつなぐ(仕様 6.3 節:vpsd からエージェントへの dial)。
// 返す接続は Abort を持たず、Close だけが閉じた後の endpoint の天井(tcp_closing.go)を通る。
// dial した endpoint には gVisor の既定値の TCP keepalive を有効にする(仕様 7 節「接続の寿命」)。
// 相手のエージェントが黙って消えたとき、クライアントも黙ったままの接続が同時フロー数の枠を永久に
// 占めないためで、値は gVisor の既定(idle 2 時間、間隔 75 秒、9 回)のまま変えない。wgft のタイマーと
// goroutine は増えず、endpoint 自身の keepalive のタイマーを使う。エージェントの accept した endpoint にも
// TCPListener.Accept が同じ設定を行う。
func (t *Device) DialTCP(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
	c, err := t.dialTCP(ctx, fullAddr(ap))
	if err != nil {
		return nil, err
	}
	c.ep.SocketOptions().SetKeepAlive(true)
	return c, nil
}

// DialUDP は、この device の stack 越しに接続済みの UDP を作る。endpoint は登録表を通して作り、
// 受信の会計に登録する(仕様 7 節)。返す接続は ReadWaiter (WaitReadable) を満たし、次の
// データグラムが届くまでバッファを持たずに待てる。
func (t *Device) DialUDP(ap netip.AddrPort) (net.Conn, error) {
	return t.registry.dial(ap)
}
