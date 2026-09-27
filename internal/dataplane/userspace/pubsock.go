package userspace

import (
	"fmt"
	"net"

	"github.com/rahanahu/wgft/internal/lograte"
)

// publicSendBufferRequest は、公開側の UDP ソケットを開くたびに setsockopt に渡す送信バッファの
// 大きさ(SO_SNDBUF、バイト)である。設定項目にはしない(設計文書 7 節「公開側のソケットの送信バッファ」)。
// 応答の送信は待たない(relay の sendonce)ので、1 回の入力に対する正常な応答の burst を吸収するのは
// このバッファだけである。Linux はこの値の 2 倍をソケットに割り当て、getsockopt もその 2 倍を返す。
// net.core.wmem_max が要求より小さければ、要求はその値に切り詰められる。
const publicSendBufferRequest = 2 << 20

// publicSendBufferExpected は、要求が切り詰められなかったときに Linux の getsockopt が返す実効の値である。
const publicSendBufferExpected = 2 * publicSendBufferRequest

// requestPublicSendBuffer は、開いたばかりの公開側の UDP ソケットに送信バッファを要求し、実効の値を
// 読み返す。読めない OS では 0 を返す。要求の失敗は誤りにしない。ソケットは既定の送信バッファのまま
// 動き、切り詰めと同じく警告の対象になる。
func requestPublicSendBuffer(uc *net.UDPConn) (effective int) {
	_ = uc.SetWriteBuffer(publicSendBufferRequest)
	return readSendBuffer(uc)
}

// shortSendBufferText は、実効の送信バッファが要求どおりでないときの英語の 1 行である。要求どおりか
// 読めなかった(0)ときは空を返す。文面は WireGuard のソケットのバッファの警告(sockbuf)に揃える。
func shortSendBufferText(port uint16, effective int) string {
	if effective <= 0 || effective >= publicSendBufferExpected {
		return ""
	}
	return fmt.Sprintf("warning: the public UDP socket on port %d got a send buffer of %d bytes; wgft requested %d bytes so that large reply bursts are not cut, "+
		"and the kernel grants twice the request when net.core.wmem_max allows it. Set net.core.wmem_max to %d or more on this host, then restart; wgft never changes this sysctl",
		port, effective, publicSendBufferRequest, publicSendBufferRequest)
}

// warnShortSendBuffer は、切り詰められた送信バッファの警告を 1 分に 1 回まで出す。ルールの本数だけ
// 待ち受けを開くので、行が並ばないように門を Backend に 1 つ持つ。
func warnShortSendBuffer(g *lograte.Gate, port uint16, effective int, logf func(format string, args ...any)) {
	msg := shortSendBufferText(port, effective)
	if msg == "" || g == nil || logf == nil || !g.Allow() {
		return
	}
	logf("%s", msg)
}
