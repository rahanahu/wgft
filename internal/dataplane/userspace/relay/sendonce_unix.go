//go:build unix

package relay

import (
	"errors"
	"net"
	"syscall"
)

// sendto は 1 回の送信の syscall である。単体試験だけが差し替える。
var sendto = syscall.Sendto

// onceSender は、公開側のカーネルの UDP ソケットへ応答を 1 回だけ送ろうとする(設計文書 7 節)。
// Go の WriteTo は送信バッファが満杯(EAGAIN)のとき netpoller で書けるようになるまで待つが、
// その間、送る側は応答のバッファの枠を持ち続ける。カーネルモードでは転送される応答はソケットの
// 送信バッファを持たず、経路が詰まればカーネルが捨てる。ユーザー空間モードも同じ意味にし、
// 満杯ならそのデータグラムを捨てて枠を直ちに返す。EINTR はやり直す。それ以外の誤りは、今までの
// WriteTo と同じく送信の失敗として返す。
//
// RawConn.Write は、渡した関数が真を返す限り待たない。閉じたソケットでは関数を呼ばずに誤りを返す。
type onceSender struct {
	rc syscall.RawConn
	to syscall.Sockaddr
}

// newReplySender は公開側 pc への応答の送り手を作る。pc がカーネルの UDP ソケットで、送信元が
// IPv4 なら、待たずに 1 回だけ送る形にする。それ以外(エージェントの netstack の待ち受け)は
// WriteTo で送る。
func newReplySender(pc net.PacketConn, from net.Addr) replySender {
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		return waitingSender{pc: pc, to: from}
	}
	ua, ok := from.(*net.UDPAddr)
	if !ok || ua.IP.To4() == nil {
		return waitingSender{pc: pc, to: from}
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		return waitingSender{pc: pc, to: from}
	}
	sa := &syscall.SockaddrInet4{Port: ua.Port}
	copy(sa.Addr[:], ua.IP.To4())
	return onceSender{rc: rc, to: sa}
}

func (s onceSender) send(b []byte) (bool, error) {
	var full bool
	var sendErr error
	err := s.rc.Write(func(fd uintptr) bool {
		for {
			err := sendto(int(fd), b, 0, s.to)
			switch {
			case err == nil:
				return true
			case errors.Is(err, syscall.EINTR):
				continue
			case errors.Is(err, syscall.EAGAIN):
				full = true
				return true
			default:
				sendErr = err
				return true
			}
		}
	})
	if err != nil {
		return false, err
	}
	return full, sendErr
}
