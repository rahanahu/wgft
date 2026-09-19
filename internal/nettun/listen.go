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
// DialUDP と違い ReadWaiter は要らない。リスナーの Read はデータグラムが実際に届いてから
// しか戻らないので、無通信の間バッファを持つ必要が無いためである。
func (t *Device) ListenUDP(ap netip.AddrPort) (net.PacketConn, error) {
	a := fullAddr(ap)
	return gonet.DialUDP(t.stack, &a, nil, ipv4.ProtocolNumber)
}

// TCPListener は、Accept が *TCPConn を返す net.Listener。呼び出し側は、拒む接続をグレース
// フルクローズの代わりに RST(TCPConn.Abort)で終えられる。
type TCPListener struct {
	ep tcpip.Endpoint
	wq *waiter.Queue
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
	return &TCPListener{ep: ep, wq: &wq}, nil
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
	return &TCPConn{TCPConn: gonet.NewTCPConn(wq, n), ep: n}, nil
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

// TCPConn は *gonet.TCPConn に、accept した tcpip.Endpoint へのアクセスを足したもの。これにより、
// 拒む接続をグレースフルクローズ(FIN の後、既定で 60 秒の tcp.DefaultTCPTimeWaitTimeout の
// TIME_WAIT)ではなく Abort(RST)で終えられる。relay パッケージでの Abort の使用と、
// GitHub issue #25、仕様 7 節を見よ。
type TCPConn struct {
	*gonet.TCPConn
	ep tcpip.Endpoint
}

// Abort は RST を送り、Close が行うグレースフルシャットダウン(とその結果の TIME_WAIT)を
// 経ずに、接続の資源を即座に解放する。
func (c *TCPConn) Abort() { c.ep.Abort() }
