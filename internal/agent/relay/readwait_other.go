//go:build !unix

package relay

import "net"

// kernelReadWaiter は unix 以外では使えない。呼び出し側はセッションごとに最大長のバッファを持つ。
func kernelReadWaiter(net.Conn) ReadWaiter { return nil }
