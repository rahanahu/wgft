package wg

import (
	"strings"
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
