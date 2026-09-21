//go:build linux

package wg

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/startup"
)

func TestPortConflict(t *testing.T) {
	devs := []*wgtypes.Device{
		{Name: "wg0", ListenPort: 51820},
		{Name: "wgft0", ListenPort: 51821},
	}
	// 自分のインタフェースは衝突扱いしない。
	if name, ok := portConflict(devs, "wgft0", 51821); ok {
		t.Errorf("自分自身を衝突とした: %s", name)
	}
	// 他のインタフェースが同じポートを使っていれば衝突。
	if name, ok := portConflict(devs, "wgft0", 51820); !ok || name != "wg0" {
		t.Errorf("衝突を検出できない: name=%q ok=%v", name, ok)
	}
	// 誰も使っていないポートは衝突なし。
	if name, ok := portConflict(devs, "wgft0", 51822); ok {
		t.Errorf("衝突でないのに検出: %s", name)
	}
}

// 他の所有者との衝突は、相手が資源を手放せば次の起動で通るので、起動の拒否(終了コード 3)ではなく
// 普通のエラー(終了コード 1)である(設計文書 11b 節)。ドライランの差分は文面に残す。
func TestConflictError(t *testing.T) {
	e := conflictError([]string{"replace the private key", "delete peer X"}, "wg0 already exists but was not created by wgft")
	s := e.Error()
	if !strings.Contains(s, "was not created by wgft") || !strings.Contains(s, "replace the private key") || !strings.Contains(s, "delete peer X") {
		t.Errorf("Error() の文面が不足: %s", s)
	}
	if startup.IsRefusal(e) {
		t.Error("資源の衝突が起動の拒否になっている(再試行で直りうるので終了コード 1 のはず)")
	}
	// ドライランが空なら差分の節は出さない。
	if strings.Contains(conflictError(nil, "x").Error(), "would have converged") {
		t.Error("ドライラン空なのに差分節が出た")
	}
}

// TestClassifyPrivilege is the regression test for kernel mode started without root or
// CAP_NET_ADMIN (docs/design.md 9, 11b 節): nothing checked privileges before the first privileged
// netlink or wgctrl write, so the generic EPERM/EACCES reached cmd/wgft as exit code 1, and the
// shipped server.service (Restart=on-failure, RestartSec=2, RestartPreventExitStatus=3, which does
// not include 1) restarted it every 2 seconds forever. classifyPrivilege must turn exactly that
// class of error into a prerequisite refusal (exit code 3 via cmd/wgft's exitCode) and leave
// every other error, including nil, alone.
func TestClassifyPrivilege(t *testing.T) {
	if got := classifyPrivilege(nil); got != nil {
		t.Errorf("classifyPrivilege(nil) = %v, want nil", got)
	}

	unrelated := errors.New("cannot create wgft0: link already exists")
	if got := classifyPrivilege(unrelated); got != unrelated {
		t.Errorf("classifyPrivilege(unrelated) = %v, want the same unchanged error", got)
	}

	for _, errno := range []syscall.Errno{syscall.EPERM, syscall.EACCES} {
		wrapped := fmt.Errorf("netlink: %w", errno)
		got := classifyPrivilege(wrapped)
		refusal := startup.Of(got)
		if refusal == nil {
			t.Fatalf("classifyPrivilege(%v) = %v (%T), want a *startup.Refusal", errno, got, got)
		}
		if refusal.Category != startup.CategoryPrerequisite {
			t.Errorf("category = %q, want %q", refusal.Category, startup.CategoryPrerequisite)
		}
		if !strings.Contains(refusal.Reason, "CAP_NET_ADMIN") {
			t.Errorf("reason = %q, want it to name CAP_NET_ADMIN", refusal.Reason)
		}
		if !strings.Contains(refusal.Reason, "root") {
			t.Errorf("reason = %q, want it to name root as the other way to get the capability", refusal.Reason)
		}
		if !strings.Contains(refusal.Reason, "WGFT_MODE=userspace") {
			t.Errorf("reason = %q, want it to name WGFT_MODE=userspace as the way out that needs neither", refusal.Reason)
		}
		if !strings.Contains(refusal.Reason, errno.Error()) {
			t.Errorf("reason = %q, want it to keep the original error (%v) for diagnosis", refusal.Reason, errno)
		}
	}

	// An already-classified refusal must not be reclassified or wrapped again.
	already := startup.Prerequisite("wireguard module", "this kernel has no WireGuard support")
	if got := classifyPrivilege(already); got != error(already) {
		t.Errorf("classifyPrivilege(already-a-refusal) = %v, want it unchanged", got)
	}
}
