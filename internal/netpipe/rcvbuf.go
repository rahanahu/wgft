package netpipe

// 中継が持つカーネルの TCP ソケットの受信のバッファ(設計文書 7 節「中継のカーネルの TCP ソケットの
// 受信のバッファ」)。相手の側が止まった中継では、カーネルの TCP ソケットは受信のバッファを自動調整の
// 上限(net.ipv4.tcp_rmem の最大値)まで広げて溜める。カーネルの TCP のメモリはホスト全体で 1 つの
// 上限(net.ipv4.tcp_mem)を持ち、それを使い切ると同じホストの無関係な TCP まで遅くなるので、
// 中継のカーネルのソケットは受信のバッファを固定し、組にした netstack の接続の boost の枠に合わせる。
// Linux だけで固定し、他の OS では何もしない。

import (
	"net"
)

// 値はどれも設定項目にしない(設計文書 7 節)。
const (
	// KernelRecvFloor は、組にした netstack の接続が boost の枠を持たない間に SO_RCVBUF で要求する
	// 受信のバッファ。Linux は要求の 2 倍の 256 KiB をソケットに割り当て、その値がソケットの溜められる
	// 量の上限になる
	KernelRecvFloor = 128 << 10
	// KernelRecvBoost は、組にした netstack の接続が boost の枠を持つ間に要求する受信のバッファ。
	// Linux の実効の値は 8 MiB である
	KernelRecvBoost = 4 << 20
	// KernelBoostWindow は、FollowBoost が TCP_WINDOW_CLAMP で置く窓の上限。netstack の boost の
	// 受信のバッファと同じ 4 MiB である
	KernelBoostWindow = 4 << 20
)

// boostReporter は、boost の枠を得たときと floor に戻ったときを知らせる netstack の接続が満たす
// (nettun.TCPConn.OnBoost)。
type boostReporter interface {
	OnBoost(f func(boosted bool))
}

// FollowBoost は、中継の組 a、b の一方がカーネルの TCP の接続で、もう一方が枠を知らせる netstack の
// 接続のとき、カーネルの側の受信のバッファを netstack の側の枠に合わせる。netstack の接続が boost の
// 枠を持つ間は KernelRecvBoost に、それ以外は KernelRecvFloor に固定し、窓の上限は
// KernelBoostWindow に置く。vpsd では公開側で accept した接続が、エージェントでは LAN の宛先へ
// dial した接続がカーネルの側である。どちらも握手を終えた後に固定するので、窓の scale は握手の
// ときの Linux の既定から決まり、boost の窓を広告できる。中継を始める前、カーネルの側を最初に読む前に
// 呼ぶ。組がこの形でなければ何もしない(カーネルモードのプロキシモードの中継は両側がカーネルの
// ソケットである)。Linux 以外でも何もしない。
func FollowBoost(a, b net.Conn) {
	if linkBoost(a, b) {
		return
	}
	linkBoost(b, a)
}

func linkBoost(k, peer net.Conn) bool {
	tc, ok := k.(*net.TCPConn)
	if !ok {
		return false
	}
	r, ok := peer.(boostReporter)
	if !ok {
		return false
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return true
	}
	followBoost(rc, r)
	return true
}
