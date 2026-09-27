package nettun

import (
	"errors"
	"net"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// maxListenBacklog は gonet 自身の定数(非公開)と同じ値。根拠は同じ(一般的な Linux ディストリの
// /proc/sys/net/core/somaxconn の既定値)。
const maxListenBacklog = 4096

// ListenUDP は ap で未接続の UDP リスナーを開く(エージェントの公開側リスナー。仕様 7 節)。
// endpoint は DialUDP と同じく登録表を通して作る。
func (t *Device) ListenUDP(ap netip.AddrPort) (net.PacketConn, error) {
	return t.registry.open(&ap, nil)
}

// TCPListener は、Accept が *TCPConn を返す net.Listener。呼び出し側は、拒む接続をグレース
// フルクローズの代わりに RST(TCPConn.Abort)で終えられる。
type TCPListener struct {
	dev *Device
	ep  tcpip.Endpoint
	wq  *waiter.Queue
}

// ListenTCP は ap で TCP リスナーを開く。gonet.ListenTCP の Bind+Listen をそのまま写したもの
// (gonet.ListenTCP 自体を使わない理由は、その Accept が accept した tcpip.Endpoint を公開せず、
// TCPConn.Abort に要るため。パッケージ doc を見よ)。
func (t *Device) ListenTCP(ap netip.AddrPort) (*TCPListener, error) {
	var wq waiter.Queue
	ep, err := t.stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		return nil, errors.New(err.String())
	}
	addr := fullAddr(ap)
	if err := ep.Bind(addr); err != nil {
		ep.Close()
		return nil, &net.OpError{Op: "bind", Net: "tcp", Addr: net.TCPAddrFromAddrPort(ap), Err: errors.New(err.String())}
	}
	if err := ep.Listen(maxListenBacklog); err != nil {
		ep.Close()
		return nil, &net.OpError{Op: "listen", Net: "tcp", Addr: net.TCPAddrFromAddrPort(ap), Err: errors.New(err.String())}
	}
	return &TCPListener{dev: t, ep: ep, wq: &wq}, nil
}

// Accept は net.Listener の実装。
func (l *TCPListener) Accept() (net.Conn, error) {
	n, wq, err := l.ep.Accept(nil)
	if _, ok := err.(*tcpip.ErrWouldBlock); ok {
		waitEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
		l.wq.EventRegister(&waitEntry)
		defer l.wq.EventUnregister(&waitEntry)
		for {
			n, wq, err = l.ep.Accept(nil)
			if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
				break
			}
			<-notifyCh
		}
	}
	if err != nil {
		return nil, &net.OpError{Op: "accept", Net: "tcp", Addr: l.Addr(), Err: errors.New(err.String())}
	}
	// accept した endpoint にも gVisor の既定値の TCP keepalive を有効にする(仕様 7 節「接続の寿命」)。
	// 待ち受けの endpoint に設定しても accept した endpoint には引き継がれないので、1 本ごとに設定する。
	// vpsd が再起動してもハンドシェイクは止まらず netstack は作り直されないため、両側が黙った接続が
	// 同時フロー数の枠を永久に占めないためである。値は既定のまま変えず、wgft のタイマーと goroutine は
	// 増えない。probe に ACK を返す生きた相手は切らず、未確認応答のデータがある間はタイマーが止まるので
	// 読みの遅い相手も切らない。
	n.SocketOptions().SetKeepAlive(true)
	return &TCPConn{TCPConn: gonet.NewTCPConn(wq, n), ep: n, dev: l.dev}, nil
}

// Close は net.Listener の実装。
func (l *TCPListener) Close() error {
	l.ep.Close()
	return nil
}

// Addr は net.Listener の実装。
func (l *TCPListener) Addr() net.Addr {
	a, err := l.ep.GetLocalAddress()
	if err != nil {
		return nil
	}
	return &net.TCPAddr{IP: net.IP(a.Addr.AsSlice()), Port: int(a.Port)}
}

// TCPConn は *gonet.TCPConn に、accept か dial した tcpip.Endpoint へのアクセスを足したもの。
// これにより、拒む接続をグレースフルクローズ(FIN の後、既定で 60 秒の tcp.DefaultTCPTimeWaitTimeout
// の TIME_WAIT)ではなく Abort(RST)で終えられる。relay パッケージでの Abort の使用と、
// GitHub issue #25、仕様 7 節を見よ。
type TCPConn struct {
	*gonet.TCPConn
	ep  tcpip.Endpoint
	dev *Device
}

func (c *TCPConn) endpoint() tcpip.Endpoint { return c.ep }

// Abort は RST を送り、Close が行うグレースフルシャットダウン(とその結果の TIME_WAIT)を
// 経ずに、接続の資源を即座に解放する。
func (c *TCPConn) Abort() { c.ep.Abort() }

// Close は net.Conn の実装。閉じかけの endpoint の数が Device の天井に達している間は、この
// endpoint を graceful close の代わりに RST で直ちに解放する(tcp_closing.go、仕様 7 節)。
// それ以外は gonet の Close、つまり gVisor の Close で、endpoint は FIN と TIME_WAIT を経て消える。
func (c *TCPConn) Close() error {
	if c.dev != nil && c.dev.closeTCP(c.ep) {
		return nil
	}
	return c.TCPConn.Close()
}
