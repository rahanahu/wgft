//go:build linux

package servercheck

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// TestOwnPortTargets は、vpsd 自身の待ち受けポートの一覧が WireGuard(UDP)と agent API(TCP)の
// 2 つだけであり、admin API(既定 Unix ソケット。design.md 6.1 節参照)を含まないことを確かめる。
func TestOwnPortTargets(t *testing.T) {
	opts := Options{WGPort: 51820, AgentAPIAddr: "0.0.0.0:8443"}
	got := OwnPortTargets(opts.WGPort, opts.AgentAPIAddr)
	if len(got) != 2 {
		t.Fatalf("targets = %+v, want 2 (WireGuard, agent API)", got)
	}
	if got[0].Purpose != "WireGuard" || got[0].Proto != proto.UDP || got[0].Port != 51820 {
		t.Errorf("WireGuard target = %+v", got[0])
	}
	if got[1].Purpose != "agent API" || got[1].Proto != proto.TCP || got[1].Port != 8443 {
		t.Errorf("agent API target = %+v", got[1])
	}
	for _, target := range got {
		if target.Purpose == "admin API" {
			t.Errorf("admin API must not be a target: %+v", got)
		}
	}
}

// TestCheckRecordedModeWording は、記録済みモードと設定の食い違いを知らせる文言を確かめる。
func TestCheckRecordedModeWording(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wgft.sqlite")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SetMeta(store.MetaMode, []byte(store.ModeKernel)); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	checkRecordedMode(&out, st, store.ModeUserspace)
	// 文言には拒否の種別を添える(設計文書 11b 節)。運用者が check の出力だけで、起動が止まる場合の
	// 種別を選べるようにするためである。
	want := "warning: the recorded mode is kernel but the setting is userspace; the mode change gate runs at start and refuses with [mode-gate] if leftovers of the old mode remain\n"
	if got := out.String(); got != want {
		t.Errorf("mismatch wording = %q, want %q", got, want)
	}

	out.Reset()
	checkRecordedMode(&out, st, store.ModeKernel)
	if got := out.String(); got != "recorded mode: kernel\n" {
		t.Errorf("matching mode = %q", got)
	}
}
