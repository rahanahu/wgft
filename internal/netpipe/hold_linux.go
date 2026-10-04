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

// stopKernel は接続の読み書きを止めて残すか、RST で終える。受信のメモリ(SO_MEMINFO の
// SK_MEMINFO_RMEM_ALLOC。受信のキューと順序外のキューの和)が 0 でないか読めない接続は、SO_LINGER を
// 0 にして Close し、RST で即座に終える。今読めるデータの量(SIOCINQ)は順序外のキューを数えないので
// 使わない。通常の Close は、順序外のデータだけを持つ接続を読まれていないデータとみなさず、FIN を
// 送って孤児にするので使わない。受信のメモリが 0 なら shutdown(SHUT_RDWR)で読み書きを止め、その後に
// もう一度読む。確かめと shutdown の間に届いたデータがあれば、ここで RST で終える。shutdown の後に
// 届くデータは、Linux がその場で RST を返して接続を CLOSE にする。読み取りで待つ向きは EOF を、
// 書き込みで待つ向きは誤りを受け取る。
func stopKernel(tc *net.TCPConn) {
	if receiveMemory(tc) != 0 {
		resetKernel(tc)
		return
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		resetKernel(tc)
		return
	}
	var stopErr error
	if err := rc.Control(func(fd uintptr) { stopErr = unix.Shutdown(int(fd), unix.SHUT_RDWR) }); err != nil || stopErr != nil {
		resetKernel(tc)
		return
	}
	if receiveMemory(tc) != 0 {
		resetKernel(tc)
	}
}

// receiveMemory は接続の受信のメモリを返す。読めなければ -1 を返す。
func receiveMemory(tc *net.TCPConn) int {
	rc, err := tc.SyscallConn()
	if err != nil {
		return -1
	}
	rmem := -1
	rc.Control(func(fd uintptr) {
		if m, _, ok := sockMemInfo(int(fd)); ok {
			rmem = m
		}
	})
	return rmem
}

// resetKernel は接続を RST で終え、資源を即座に解放する。
func resetKernel(tc *net.TCPConn) {
	tc.SetLinger(0)
	tc.Close()
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
