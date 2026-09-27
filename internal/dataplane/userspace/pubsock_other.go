//go:build !linux

package userspace

import "net"

// readSendBuffer は Linux 以外では読まない。vpsd は Linux でしか動かない(設計文書 6.3 節)。
func readSendBuffer(*net.UDPConn) int { return 0 }
