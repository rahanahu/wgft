package wg

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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

func TestStartupRefusalError(t *testing.T) {
	e := &StartupRefusal{Reason: "wg0 は既存だが wgft のものではない", DryRun: []string{"replace the private key", "delete peer X"}}
	s := e.Error()
	if !strings.Contains(s, "refusing to start") || !strings.Contains(s, "replace the private key") || !strings.Contains(s, "delete peer X") {
		t.Errorf("Error() の文面が不足: %s", s)
	}
	// DryRun が空なら差分の節は出さない。
	if strings.Contains((&StartupRefusal{Reason: "x"}).Error(), "would have converged") {
		t.Error("DryRun 空なのに差分節が出た")
	}
}

// TestClassifyPrivilege is the regression test for kernel mode started without root or
// CAP_NET_ADMIN (docs/design.md 9, 11a 節): nothing checked privileges before the first privileged
// netlink or wgctrl write, so the generic EPERM/EACCES reached cmd/wgft as exit code 1, and the
// shipped server.service (Restart=on-failure, RestartSec=2, RestartPreventExitStatus=3, which does
// not include 1) restarted it every 2 seconds forever. classifyPrivilege must turn exactly that
// class of error into a *StartupRefusal (exit code 3 via cmd/wgft's isStartupRefusal) and leave
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
		var refusal *StartupRefusal
		if !errors.As(got, &refusal) {
			t.Fatalf("classifyPrivilege(%v) = %v (%T), want a *StartupRefusal", errno, got, got)
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

	// An already-classified StartupRefusal must not be reclassified or wrapped again.
	already := &StartupRefusal{Reason: "wg0 already exists but was not created by wgft"}
	if got := classifyPrivilege(already); got != error(already) {
		t.Errorf("classifyPrivilege(already-a-StartupRefusal) = %v, want it unchanged", got)
	}
}
