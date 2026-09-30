package nettun

import (
	"errors"
	"net"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
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
	ep   tcpip.Endpoint
	wq   *waiter.Queue
	pool *boostPool
}

// ListenTCP は ap で TCP リスナーを開く。gonet.ListenTCP の Bind+Listen をそのまま写したもの
// (gonet.ListenTCP 自体を使わない理由は、その Accept が accept した tcpip.Endpoint を公開せず、
// TCPConn.Abort と TCP のバッファの floor の設定に要るため。パッケージ doc を見よ)。
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
	return &TCPListener{ep: ep, wq: &wq, pool: t.pool}, nil
}

// Accept は net.Listener の実装。返す接続には握手の後に TCP のバッファの floor を設定する
// (tcpbuf.go)。通常の握手と SYN cookie のどちらで成立した接続も、gVisor の Accept から
// この経路を通る。floor を設定できなかった接続は RST で閉じ、次の接続を待つ。
func (l *TCPListener) Accept() (net.Conn, error) {
	for {
		n, wq, err := l.accept()
		if err != nil {
			return nil, err
		}
		c, herr := newTCPConn(wq, n, l.pool)
		if herr != nil {
			n.Abort()
			continue
		}
		return &TCPConn{c}, nil
	}
}

func (l *TCPListener) accept() (tcpip.Endpoint, *waiter.Queue, error) {
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
		return nil, nil, &net.OpError{Op: "accept", Net: "tcp", Addr: l.Addr(), Err: errors.New(err.String())}
	}
	return n, wq, nil
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
