//go:build !linux

package netpipe

import "net"

// Linux 以外では、カーネルの TCP の接続を止めて残さず、PipeHold も今までどおり閉じる。Windows と
// macOS で送信のキューの量を確かめる手段を確かめていないためである(設計文書 7 節)。
func holdable(net.Conn) (*net.TCPConn, bool) { return nil, false }

func stopKernel(tc *net.TCPConn) { tc.Close() }

var kernelDelivered = func(*net.TCPConn) bool { return true }
