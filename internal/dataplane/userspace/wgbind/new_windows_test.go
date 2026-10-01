//go:build windows

package wgbind

import (
	"testing"

	"golang.zx2c4.com/wireguard/conn"
)

// New が Windows で WinRingBind ではなく StdNetBind を返すことを確かめる。
// WinRingBind は SIO_UDP_CONNRESET を無効にせず、new_windows.go のコメントが
// 説明する受信の永久停止を招くため、この選択を後戻りさせない回帰試験にする。
func TestNewIsStdNetBindOnWindows(t *testing.T) {
	got := New()
	if _, ok := got.(*conn.StdNetBind); !ok {
		t.Fatalf("New() = %T, want *conn.StdNetBind", got)
	}
}
