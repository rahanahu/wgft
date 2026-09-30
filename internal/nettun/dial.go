package nettun

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// DialTCP は、この device の stack 越しに ap へつなぐ(仕様 6.3 節:vpsd からエージェントへの dial)。
// 返す接続は ListenTCP の Accept と同じ *TCPConn で、中継が切るときは Abort の RST で切れる
// (仕様 6.2 節)。手順は gonet.DialContextTCP を写したもの。gonet.DialContextTCP は作った
// tcpip.Endpoint を公開せず、Abort に要るため自分で作る。
func (t *Device) DialTCP(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
	var wq waiter.Queue
	ep, terr := t.stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if terr != nil {
		return nil, errors.New(terr.String())
	}
	// Connect は常に誤りを返すので、書けるようになるのを待つ登録を先に済ませる
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)
	select {
	case <-ctx.Done():
		ep.Close()
		return nil, ctx.Err()
	default:
	}
	terr = ep.Connect(fullAddr(ap))
	if _, ok := terr.(*tcpip.ErrConnectStarted); ok {
		select {
		case <-ctx.Done():
			ep.Close()
			return nil, ctx.Err()
		case <-notifyCh:
		}
		terr = ep.LastError()
	}
	if terr != nil {
		ep.Close()
		return nil, &net.OpError{Op: "connect", Net: "tcp", Addr: net.TCPAddrFromAddrPort(ap), Err: errors.New(terr.String())}
	}
	return &TCPConn{TCPConn: gonet.NewTCPConn(&wq, ep), ep: ep}, nil
}

// DialUDP は、この device の stack 越しに接続済みの UDP を作る。endpoint は登録表を通して作り、
// 受信の会計に登録する(仕様 7 節)。返す接続は ReadWaiter (WaitReadable) を満たし、次の
// データグラムが届くまでバッファを持たずに待てる。
func (t *Device) DialUDP(ap netip.AddrPort) (net.Conn, error) {
	return t.registry.dial(ap)
}
