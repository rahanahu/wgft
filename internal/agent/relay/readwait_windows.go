//go:build windows

package relay

import (
	"net"
	"syscall"
)

// rawWaiter は、Windows のオーバーラップ I/O が持つゼロバイトの MSG_PEEK 待ちを使う。
//
// net.Conn の SyscallConn().Read(f) は、GOROOT/src/internal/poll/fd_windows.go の RawRead を呼ぶ。
// RawRead は f を呼び、f が false を返すたびにゼロバイトの WSARecv(MSG_PEEK 付き、データグラムの場合)を
// オーバーラップ I/O で発行してソケットが読める状態になるまで待ち(スレッドは塞がない。完了は IOCP の
// 通知で受け取る)、完了したら f をもう一度呼ぶ。f が true を返すと RawRead はそこで抜ける。
// Windows のソケットはノンブロッキングではなくオーバーラップなので、f の中で同期の recv を呼ぶと
// スレッドを 1 本ずつ塞いでしまい、数千セッションでは使えない。zero-byte MSG_PEEK は完了までデータを
// 取り出さないので、バッファは要らない。
//
// f は 1 回目は false を返して待たせ、2 回目(待ちが完了して呼び直された回)で true を返して抜ける。
// 毎回 false を返すと、待ちが完了した直後(データが既にある状態)にまた別のゼロバイト peek を発行して
// 即座に完了し、また f を呼び直す、という busy loop になるため。
type rawWaiter struct{ rc syscall.RawConn }

// kernelReadWaiter はカーネルのソケットなら ReadWaiter を返す。
func kernelReadWaiter(c net.Conn) ReadWaiter {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return nil
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return nil
	}
	return rawWaiter{rc}
}

// WaitReadable はデータグラムが届くまで、バッファを持たずに待つ。Go の net パッケージは Windows の
// UDP ソケットで SIO_UDP_CONNRESET を無効にしている(https://go.dev/issue/5834)ため、target が
// ICMP port unreachable を返しても WSAECONNRESET には現れず、応答の無い相手と見分けが付かない。
// そのセッションは待ち続け、無通信タイムアウト(仕様 7 節)の sweep が conn を閉じることで終わる。
// ゼロバイトの peek 自体が別の誤りを返すこともあり、その場合は RawRead がその誤りをそのまま返す。
// 呼び出し側 (udp.go) はいずれの経路でもセッションを閉じるだけなので、挙動に差はない。
func (w rawWaiter) WaitReadable() error {
	waited := false
	return w.rc.Read(func(uintptr) bool {
		if !waited {
			waited = true
			return false
		}
		return true
	})
}
