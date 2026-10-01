//go:build linux

package netpipe

import (
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// followBoost は、枠の知らせごとに受信のバッファを固定し直し、続けて窓の上限を KernelBoostWindow に
// 置く。受信のバッファを固定すると自動調整が止まり、自動調整が広げていた窓の上限も広がらなくなる。
// Linux 6.1 は握手の時点の受信のバッファから決めた窓の上限を持ち続け、7.2 は SO_RCVBUF のたびに
// 窓の上限をバッファに合わせて置き直す。どちらでも窓の上限を明示して置けば、窓はこの上限と受信の
// バッファの小さい方で決まる。
//
// boost から floor に戻す知らせには、戻せたかを返す。SO_RCVBUF を下げても、ソケットがすでに持つ
// 受信のデータ(順序外のキューを含む)は解放されないので、floor に下げた後の受信のメモリが floor を
// 超えていれば boost に戻し、偽を返す。netstack の接続は偽を受けて枠を持ち続ける(設計文書 7 節)。
// 接続を閉じた後の知らせでは、Control が誤りを返して何もせず、floor への戻りは偽になる。
// 知らせは netstack の接続の排他の中で順に届くので、boosted を錠なしで読み書きできる。
func followBoost(c syscall.RawConn, b boostReporter) {
	boosted := false
	b.OnBoost(func(on bool) bool {
		ok := false
		c.Control(func(fd uintptr) { ok = refix(int(fd), on, boosted) })
		if ok {
			boosted = on
		}
		return ok
	})
}

// refix は受信のバッファを on に合わせて固定し直す。was は今の固定である。boost から floor に
// 戻すときだけ受信のメモリを確かめ、floor に収まらなければ boost のまま偽を返す。
func refix(fd int, on, was bool) bool {
	if on || !was {
		fix(fd, on)
		return true
	}
	// 先に確かめ、収まらなければバッファに触らない。下げると、次に届く segment でカーネルが
	// 順序外のキューを捨て、相手に再送させるためである
	if rmem, _, ok := sockMemInfo(fd); !ok || rmem > kernelFloorBytes {
		return false
	}
	// 下げた後にもう一度確かめる。下げる前の確かめだけでは、その後に古い大きさで受け入れた
	// segment を見落とす
	fix(fd, false)
	if rmem, rcvbuf, ok := sockMemInfo(fd); ok && rcvbuf <= kernelFloorBytes && rmem <= kernelFloorBytes {
		return true
	}
	fix(fd, true)
	return false
}

// fix は受信のバッファを floor か boost に固定し、窓の上限を置く。受信のバッファを固定できなければ
// 誤りを返す。
func fix(fd int, boost bool) error {
	n := KernelRecvFloor
	if boost {
		n = KernelRecvBoost
	}
	err := setRecvBuf(fd, n)
	unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP, KernelBoostWindow)
	return err
}

// setRecvBuf は受信のバッファを n に固定し、固定できなければ誤りを返す。SO_RCVBUF は
// net.core.rmem_max で切り詰められるので、先に SO_RCVBUFFORCE で要求し、権限が無ければ SO_RCVBUF に
// 落ちる。wireguard-go が WireGuard のソケットに要求するのと同じ順である(設計文書 7 節)。テストが
// 差し替える。
var setRecvBuf = func(fd, n int) error {
	if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, n) == nil {
		return nil
	}
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, n)
}

// kernelFloorBytes は floor の実効の値。Linux は SO_RCVBUF の要求の 2 倍を sk_rcvbuf に置き、
// 受信の segment を受け入れるかを、受信のメモリ(segment の truesize の和)とこの値の比較で決める。
const kernelFloorBytes = 2 * KernelRecvFloor

// Linux の include/uapi/linux/sock_diag.h の SK_MEMINFO_* の位置。golang.org/x/sys は定義しない。
const (
	skMeminfoRmemAlloc = 0
	skMeminfoRcvbuf    = 1
	skMeminfoVars      = 9
)

// sockMemInfo は SO_MEMINFO で受信のメモリと受信のバッファ(sk_rcvbuf)を読み、読めなければ偽を
// 返す。受信のメモリは SK_MEMINFO_RMEM_ALLOC(sk_rmem_alloc)で、受信のキューと順序外のキューの
// segment の truesize の和である。今読めるデータの量(SIOCINQ)は順序外のキューを含まないので
// 使わない。テストが差し替える。
var sockMemInfo = func(fd int) (rmem, rcvbuf int, ok bool) {
	var m [skMeminfoVars]uint32
	l := uint32(unsafe.Sizeof(m))
	_, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_SOCKET, unix.SO_MEMINFO,
		uintptr(unsafe.Pointer(&m[0])), uintptr(unsafe.Pointer(&l)), 0)
	if e != 0 || l < 4*(skMeminfoRcvbuf+1) {
		return 0, 0, false
	}
	return int(m[skMeminfoRmemAlloc]), int(m[skMeminfoRcvbuf]), true
}

// fixAtAccept は受信のバッファを floor に固定してから受信のメモリを読み、固定できて、受信のバッファと
// 受信のメモリがどちらも floor 以下かを返す。固定できないか読めなければ偽を返す。固定できないソケットは
// Linux が受信のバッファを広げうるので、通さない。
func fixAtAccept(tc *net.TCPConn) bool {
	rc, err := tc.SyscallConn()
	if err != nil {
		return false
	}
	ok := false
	rc.Control(func(fd uintptr) {
		if fix(int(fd), false) != nil {
			return
		}
		rmem, rcvbuf, read := sockMemInfo(int(fd))
		ok = read && rcvbuf <= kernelFloorBytes && rmem <= kernelFloorBytes
	})
	return ok
}
