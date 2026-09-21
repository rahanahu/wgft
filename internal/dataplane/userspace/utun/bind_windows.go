//go:build windows

package utun

import "golang.zx2c4.com/wireguard/conn"

// newBind は、Windows でだけ conn.NewDefaultBind() の既定(Registered I/O を使う
// WinRingBind)を避け、conn.NewStdNetBind() を明示して使う。
//
// WinRingBind は Winsock のソケットを自前で開き、SIO_UDP_CONNRESET を無効にしない。
// このため、到達できない宛先へ送った UDP に対する ICMP port unreachable の通知を、
// Windows は次の受信で WSAECONNRESET として返す。この誤りは net.Error として
// Temporary()=false になり、wireguard-go の device.RoutineReceiveIncoming は
// net.ErrClosed 以外の非一時的な誤りを回復不能と判定して受信ループをそのまま
// 終える。以後そのトンネルはプロセスを再起動するまで一切受信できなくなる
// (実験で確認。docs/design.md の改訂の記録 2026-09-21)。
//
// conn.NewStdNetBind() は Go の net パッケージ経由でソケットを開き、net パッケージが
// 自分で開くすべての UDP ソケットで SIO_UDP_CONNRESET を無効にしているため、同じ
// 操作をしても受信が止まらないことを確認した。この選択はバッチ処理の速さを犠牲に
// しない。依存するこの版の golang.zx2c4.com/wireguard では、WinRingBind.BatchSize()
// も StdNetBind.BatchSize() も Windows で 1 を返し、バッチサイズに差が無いためである。
// 残る差は、自前のリングバッファと Go の netpoller 経由の UDP ソケットとの間の、
// パケットごとの syscall や I/O 完了通知のオーバーヘッドであり、その大きさは未測定
// である。
//
// vpsd 自体は Linux でしか動かないが、この package は CI の windows-test が
// ビルドと単体テストの対象にしている。internal/dataplane/userspace/tunnel は
// 同じ理由でこの対を複製している。5 行程度のこの選択のためだけに新しい package を
// 設けると、v1.0 まで固定する package 境界(CLAUDE.md、docs/design.md 7a 節)に
// 触れるため、共有はしない。
func newBind() conn.Bind {
	return conn.NewStdNetBind()
}
