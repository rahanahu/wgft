//go:build !darwin

package relay

import "net"

// raiseUDPSendBuffer は macOS 以外では何もしない。Linux の UDP の送信バッファの既定(約 208 KiB)は
// udpBufMax より大きく、設定すると逆に小さくなる。
func raiseUDPSendBuffer(net.Conn) {}
