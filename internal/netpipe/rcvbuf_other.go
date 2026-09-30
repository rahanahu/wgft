//go:build !linux

package netpipe

import (
	"net"
	"syscall"
)

// Linux 以外では受信のバッファを固定しない。OS の既定の自動調整に任せる。Windows と macOS で
// 固定したときの速さと、ホスト全体の TCP のメモリの上限の働き方を確かめていないためである
// (設計文書 7 節)。
func followBoost(syscall.RawConn, boostReporter) {}

// fixAtAccept は Linux 以外では固定も確かめもせず、接続を通す。
func fixAtAccept(*net.TCPConn) bool { return true }
