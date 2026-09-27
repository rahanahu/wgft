package userspace

import (
	"net"
	"syscall"
)

// readSendBuffer は、ソケットの実効の送信バッファ(SO_SNDBUF の getsockopt の値。Linux は要求の
// 2 倍を返す)を読む。読めなければ 0 を返す。
func readSendBuffer(uc *net.UDPConn) int {
	rc, err := uc.SyscallConn()
	if err != nil {
		return 0
	}
	var v int
	var gerr error
	if err := rc.Control(func(fd uintptr) { v, gerr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF) }); err != nil || gerr != nil {
		return 0
	}
	return v
}
