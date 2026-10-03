//go:build linux

package netpipe

import (
	"net"

	"golang.org/x/sys/unix"
)

// holdable は c が PipeHold の止めて残す接続(Linux のカーネルの TCP の接続)かを返す。
func holdable(c net.Conn) (*net.TCPConn, bool) {
	tc, ok := c.(*net.TCPConn)
	return tc, ok
}

// stopKernel は、読まれていない受信のデータを持つ接続を Close で閉じ、それ以外は shutdown(SHUT_RDWR)
// で読み書きを止める。読み取りで待つ向きは EOF を、書き込みで待つ向きは誤りを受け取る。止めた後に
// 相手がデータを送ると、Linux はその場で RST を返して接続を CLOSE にする。
func stopKernel(tc *net.TCPConn) {
	rc, err := tc.SyscallConn()
	if err != nil {
		tc.Close()
		return
	}
	unread := true
	rc.Control(func(fd uintptr) {
		n, err := unix.IoctlGetInt(int(fd), unix.SIOCINQ)
		unread = err != nil || n > 0
	})
	if unread {
		tc.Close()
		return
	}
	rc.Control(func(fd uintptr) { unix.Shutdown(int(fd), unix.SHUT_RDWR) })
}

// tcpClose は Linux の include/net/tcp_states.h の TCP_CLOSE。golang.org/x/sys は定義しない。
const tcpClose = 7

// kernelDelivered は、送信のキューの量が 0 か、状態が CLOSE か、閉じられて読めないときに真を返す。
// テストが差し替える。
var kernelDelivered = func(tc *net.TCPConn) bool {
	rc, err := tc.SyscallConn()
	if err != nil {
		return true
	}
	done := true
	if cerr := rc.Control(func(fd uintptr) {
		if info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO); err == nil && info.State == tcpClose {
			return
		}
		n, err := unix.IoctlGetInt(int(fd), unix.SIOCOUTQ)
		done = err == nil && n == 0
	}); cerr != nil {
		return true
	}
	return done
}
