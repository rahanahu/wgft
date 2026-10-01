package netpipe

import "syscall"

// isPlatformReset は、Windows のソケットが RST を受けたときの誤り(WSAECONNRESET)かを返す。
func isPlatformReset(errno syscall.Errno) bool { return errno == syscall.WSAECONNRESET }
