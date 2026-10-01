//go:build linux

package vpsd

import (
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/store"
)

// ユーザー空間モードの server はカーネルで転送しないので、ip_forward を管理用 API に載せない。載せると、
// 関係の無い値で診断が転送の停止を述べうる(設計文書 10.2a 節)。
func TestIPForwardOnlyInKernelMode(t *testing.T) {
	d := &Daemon{opts: Options{Mode: store.ModeUserspace}}
	if _, ok := d.IPForward(); ok {
		t.Error("a userspace-mode server reports ip_forward")
	}
	d = &Daemon{opts: Options{Mode: store.ModeKernel}}
	st, ok := d.IPForward()
	if !ok {
		t.Fatal("a kernel-mode server does not report ip_forward")
	}
	if st.Value == "" && st.Error == "" {
		t.Error("the report carries neither a value nor why it could not be read")
	}
}
