//go:build unix

package relay

import (
	"net"
	"syscall"
)

// rawWaiter はカーネルのソケットが読めるようになるまで、バッファを持たずに待つ。
type rawWaiter struct{ rc syscall.RawConn }

// kernelReadWaiter はカーネルのソケットなら ReadWaiter を返す。
func kernelReadWaiter(c net.Conn) ReadWaiter {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return nil
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return nil
	}
	return rawWaiter{rc}
}

// WaitReadable は 1 バイトの MSG_PEEK で届いたかを見る。データグラムは取り出さないので、
// 続く Read が全体を受け取る。ソケットの誤り(ICMP の到達不能など)でも戻り、続く Read がその誤りを返す。
func (w rawWaiter) WaitReadable() error {
	return w.rc.Read(func(fd uintptr) bool {
		var b [1]byte
		_, _, err := syscall.Recvfrom(int(fd), b[:], syscall.MSG_PEEK)
		return err != syscall.EAGAIN && err != syscall.EWOULDBLOCK && err != syscall.EINTR
	})
}
