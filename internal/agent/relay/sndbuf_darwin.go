//go:build darwin

package relay

import "net"

// raiseUDPSendBuffer は宛先へのカーネルの UDP ソケットの SO_SNDBUF を udpBufMax まで上げる(仕様 7 節)。
// macOS の既定は net.inet.udp.maxdgram(9216 バイト)で、これより大きいデータグラムの書き込みは
// EMSGSIZE で即座に失敗する。BSD のカーネルは UDP の送信バッファにデータを溜めないので、
// SO_SNDBUF は 1 個のデータグラムの最大長として効くだけで、上げてもメモリは増えない。
// netstack の接続(vpsd のエージェント側)は *net.UDPConn ではないので触らない。
//
// 誤りは無視する。失敗しても既定の 9216 バイトのまま動くだけで、それを超える書き込みは
// 呼び出し側の書き込み失敗のログに現れる。セッションごとにログを出すとフラッドでログが溢れる。
func raiseUDPSendBuffer(c net.Conn) {
	if uc, ok := c.(*net.UDPConn); ok {
		_ = uc.SetWriteBuffer(udpBufMax)
	}
}
