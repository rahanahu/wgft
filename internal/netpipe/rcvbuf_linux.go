//go:build linux

package netpipe

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// followBoost は、枠の知らせごとに受信と送信のバッファを固定し直し、続けて窓の上限を
// KernelBoostWindow に置く。受信のバッファを固定すると自動調整が止まり、自動調整が広げていた窓の上限も
// 広がらなくなる。Linux 6.1 は握手の時点の受信のバッファから決めた窓の上限を持ち続け、7.2 は
// SO_RCVBUF のたびに窓の上限をバッファに合わせて置き直す。どちらでも窓の上限を明示して置けば、窓は
// この上限と受信のバッファの小さい方で決まる。
//
// floor に戻る知らせでは、先に送信のバッファを floor に下げ、その後で送信のキューが floor 以下かを
// 読む。以下でなければ送信のバッファを boost に戻して偽を返し、netstack の接続に枠を持たせたままに
// する。送信のバッファを下げてもキューにあるデータは減らないので、枠を返した後のキューを floor 以下に
// 保つにはこの確かめが要る。下げた後に読むのは、下げた後のカーネルは、キューが送信のバッファより
// 小さいときにだけ新しいデータを受け入れるためである。下げる前に読むと、読んだ後に中継が書き足した分を
// 見落とす。接続を閉じた後の知らせでは Control が誤りを返し、何もせずに真を返す。ソケットが無いので
// 枠を持たせる理由が無いためである(設計文書 7 節「送信のキューと枠の返却」)。
func followBoost(c syscall.RawConn, b boostReporter) {
	b.OnBoost(func(boosted bool) bool {
		ok := true
		if err := c.Control(func(fd uintptr) { ok = refix(int(fd), boosted) }); err != nil {
			return true
		}
		return ok
	})
}

// refix は fd のバッファを枠に合わせて固定し直す。floor に戻せなかったときは偽を返し、送信のバッファを
// boost に戻す。そのとき受信のバッファは変えない。
func refix(fd int, boosted bool) bool {
	if boosted {
		setBuf(fd, unix.SO_SNDBUFFORCE, unix.SO_SNDBUF, KernelSendBoost)
		setBuf(fd, unix.SO_RCVBUFFORCE, unix.SO_RCVBUF, KernelRecvBoost)
	} else {
		setBuf(fd, unix.SO_SNDBUFFORCE, unix.SO_SNDBUF, KernelSendFloor)
		if !sendQueueWithinBuffer(fd) {
			setBuf(fd, unix.SO_SNDBUFFORCE, unix.SO_SNDBUF, KernelSendBoost)
			return false
		}
		setBuf(fd, unix.SO_RCVBUFFORCE, unix.SO_RCVBUF, KernelRecvFloor)
	}
	unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP, KernelBoostWindow)
	return true
}

// setBuf はバッファを n に固定する。SO_RCVBUF と SO_SNDBUF は net.core.rmem_max と wmem_max で
// 切り詰められるので、先に FORCE の側で要求し、権限が無ければ切り詰められる側に落ちる。wireguard-go が
// WireGuard のソケットに要求するのと同じ順である(設計文書 7 節)。
func setBuf(fd, force, plain, n int) {
	if unix.SetsockoptInt(fd, unix.SOL_SOCKET, force, n) != nil {
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, plain, n)
	}
}

// sendQueueWithinBuffer は、送信のキューが使うメモリが今の送信のバッファ以下かを返す。どちらも
// SO_MEMINFO の 1 回の読み取りから取る。キューのメモリ(SK_MEMINFO_WMEM_QUEUED)は、送信を待つ
// segment と相手の確認を待つ segment の大きさの和で、カーネルが新しいデータを受け入れるときに送信の
// バッファと比べる量であり、tcp_mem に数えられる量でもある。SIOCOUTQ はデータの byte だけを数え、
// segment ごとの管理の費用を数えないので、送信のバッファと同じ尺度にならない。読めないときは偽を返す。
func sendQueueWithinBuffer(fd int) bool {
	var m [unix.SK_MEMINFO_VARS]uint32
	l := uint32(unsafe.Sizeof(m))
	if _, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_SOCKET, unix.SO_MEMINFO,
		uintptr(unsafe.Pointer(&m)), uintptr(unsafe.Pointer(&l)), 0); e != 0 {
		return false
	}
	if l < (unix.SK_MEMINFO_WMEM_QUEUED+1)*4 {
		return false
	}
	return m[unix.SK_MEMINFO_WMEM_QUEUED] <= m[unix.SK_MEMINFO_SNDBUF]
}
