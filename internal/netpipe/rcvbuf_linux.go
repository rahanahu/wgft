//go:build linux

package netpipe

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// followBoost は、枠の知らせごとに受信のバッファを固定し直し、続けて窓の上限を KernelBoostWindow に
// 置く。受信のバッファを固定すると自動調整が止まり、自動調整が広げていた窓の上限も広がらなくなる。
// Linux 6.1 は握手の時点の受信のバッファから決めた窓の上限を持ち続け、7.2 は SO_RCVBUF のたびに
// 窓の上限をバッファに合わせて置き直す。どちらでも窓の上限を明示して置けば、窓はこの上限と受信の
// バッファの小さい方で決まる。接続を閉じた後の知らせでは、Control が誤りを返して何もしない。
func followBoost(c syscall.RawConn, b boostReporter) {
	b.OnBoost(func(boosted bool) {
		n := KernelRecvFloor
		if boosted {
			n = KernelRecvBoost
		}
		c.Control(func(fd uintptr) {
			setRecvBuf(int(fd), n)
			unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP, KernelBoostWindow)
		})
	})
}

// setRecvBuf は受信のバッファを n に固定する。SO_RCVBUF は net.core.rmem_max で切り詰められるので、
// 先に SO_RCVBUFFORCE で要求し、権限が無ければ SO_RCVBUF に落ちる。wireguard-go が WireGuard の
// ソケットに要求するのと同じ順である(設計文書 7 節)。
func setRecvBuf(fd, n int) {
	if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, n) != nil {
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, n)
	}
}
