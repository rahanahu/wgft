//go:build !windows

package netpipe

import "syscall"

// isPlatformReset は、ECONNRESET のほかに RST を表す誤りかを返す。Windows 以外には無い。
func isPlatformReset(syscall.Errno) bool { return false }
