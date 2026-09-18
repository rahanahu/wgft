//go:build !unix && !windows

package relay

import "net"

// kernelReadWaiter は unix でも windows でもない GOOS では使えない。
// 呼び出し側はセッションごとに最大長のバッファを持つ。
func kernelReadWaiter(net.Conn) ReadWaiter { return nil }
