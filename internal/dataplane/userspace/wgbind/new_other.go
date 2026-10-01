//go:build !windows

package wgbind

import (
	"golang.zx2c4.com/wireguard/conn"
)

// New は wireguard-go の device に渡す UDP のバインドを作る。Windows 以外では
// conn.NewDefaultBind() を BatchOne で包んで使う。包みは wireguard-go に 1 回の受信で 1 件だけを
// 渡し、受信の向きの滞留の上限を決める(設計文書 7 節の「WireGuard の受信の 1 回の件数」)。
// Windows で標準のバインドを明示する理由は new_windows.go を参照。
func New() conn.Bind {
	return BatchOne(conn.NewDefaultBind())
}
