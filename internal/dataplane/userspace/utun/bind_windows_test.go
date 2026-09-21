//go:build windows

package utun

import (
	"testing"

	"golang.zx2c4.com/wireguard/conn"
)

// newBind が Windows で WinRingBind ではなく StdNetBind を返すことを確かめる。
// WinRingBind は SIO_UDP_CONNRESET を無効にせず、bind_windows.go のコメントが
// 説明する受信の永久停止を招くため、この選択を後戻りさせない回帰試験にする。
func TestNewBindIsStdNetBindOnWindows(t *testing.T) {
	got := newBind()
	if _, ok := got.(*conn.StdNetBind); !ok {
		t.Fatalf("newBind() = %T, want *conn.StdNetBind", got)
	}
}
