//go:build !windows

package tunnel

import "golang.zx2c4.com/wireguard/conn"

// newBind は Windows 以外では conn.NewDefaultBind() をそのまま使う。理由は
// bind_windows.go を参照。
func newBind() conn.Bind {
	return conn.NewDefaultBind()
}
