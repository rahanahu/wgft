//go:build !windows

package tunnel

import (
	"github.com/rahanahu/wgft/internal/dataplane/userspace/wgbind"
	"golang.zx2c4.com/wireguard/conn"
)

// newBind は Windows 以外では conn.NewDefaultBind() を wgbind.BatchOne で包んで使う。包みは
// wireguard-go に 1 回の受信で 1 件だけを渡し、受信の向きの滞留の上限を決める(設計文書 7 節の
// 「WireGuard の受信の 1 回の件数」)。Windows で標準のバインドを明示する理由は bind_windows.go を
// 参照。
func newBind() conn.Bind {
	return wgbind.BatchOne(conn.NewDefaultBind())
}
