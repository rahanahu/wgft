package vpsd

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
	"github.com/rahanahu/wgft/internal/vpsd/store"
)

// modeGate:kernel→userspace は残骸ありで拒否・なしで許可・不明で許可(bind へ)、userspace→kernel は許可。
func TestModeGate(t *testing.T) {
	if allow, _ := modeGate(modeKernel, modeUserspace, true, true); allow {
		t.Error("kernel→userspace 残骸ありは拒否のはず")
	}
	if allow, _ := modeGate(modeKernel, modeUserspace, false, true); !allow {
		t.Error("kernel→userspace 残骸なしは許可のはず")
	}
	if allow, _ := modeGate(modeKernel, modeUserspace, false, false); !allow {
		t.Error("kernel→userspace 残骸不明は bind へ進むため許可のはず")
	}
	if allow, _ := modeGate(modeUserspace, modeKernel, true, true); !allow {
		t.Error("userspace→kernel は許可のはず")
	}
}

// reconcileModeAndAddress:初回記録、2 回目のアドレス帯変更は拒否、記録なし既存 SQLite は kernel。
func TestReconcileModeAndAddress(t *testing.T) {
	open := func() *store.Store {
		st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
		if err != nil {
			t.Fatal(err)
		}
		return st
	}

	// 初回:kernel と 10.200.0.1/24 を記録
	st := open()
	opts := Options{Mode: "kernel", WGInterface: "wgft0", WGAddress: "10.200.0.1/24"}
	if err := reconcileModeAndAddress(st, opts, false); err != nil {
		t.Fatalf("初回: %v", err)
	}
	if b, _ := st.GetMeta(modeMeta); string(b) != "kernel" {
		t.Errorf("mode 記録 = %q", b)
	}
	// 2 回目:アドレス帯を変えると拒否
	opts2 := opts
	opts2.WGAddress = "10.201.0.1/24"
	if err := reconcileModeAndAddress(st, opts2, true); !isRefusal(err) {
		t.Errorf("アドレス帯の変更が設定起因の拒否にならない: %v", err)
	}
	st.Close()

	// 記録なしの既存 SQLite(hadServerKey=true)で Mode 未指定 → kernel と記録
	st = open()
	if err := reconcileModeAndAddress(st, Options{WGInterface: "wgft0", WGAddress: "10.200.0.1/24"}, true); err != nil {
		t.Fatalf("legacy: %v", err)
	}
	if b, _ := st.GetMeta(modeMeta); string(b) != "kernel" {
		t.Errorf("legacy mode = %q", b)
	}
	st.Close()

	// 新規 SQLite(hadServerKey=false)で Mode 未指定 → エラー
	st = open()
	if err := reconcileModeAndAddress(st, Options{WGInterface: "wgft0", WGAddress: "10.200.0.1/24"}, false); !isRefusal(err) {
		t.Errorf("新規で Mode 未指定が設定起因の拒否にならない: %v", err)
	}
	if err := reconcileModeAndAddress(st, Options{Mode: "bogus", WGInterface: "wgft0", WGAddress: "10.200.0.1/24"}, false); !isRefusal(err) {
		t.Errorf("新規で不正な Mode が設定起因の拒否にならない: %v", err)
	}
	st.Close()

	// userspace は実装済み(仕様 6.3 節)。新規 SQLite ではそのまま記録される。未知のモードは拒否
	st = open()
	if err := reconcileModeAndAddress(st, Options{Mode: "userspace", WGInterface: "wgft0", WGAddress: "10.200.0.1/24"}, false); err != nil {
		t.Errorf("userspace が拒否された: %v", err)
	}
	if err := reconcileModeAndAddress(st, Options{Mode: "bogus", WGInterface: "wgft0", WGAddress: "10.200.0.1/24"}, true); !isRefusal(err) {
		t.Errorf("未知のモードが設定起因の拒否にならない: %v", err)
	}
	st.Close()
}

// isRefusal は、err が設定起因の拒否(終了コード 3 に写すもの。仕様 11a 節)かを返す。
func isRefusal(err error) bool {
	var r *wg.StartupRefusal
	return errors.As(err, &r)
}
