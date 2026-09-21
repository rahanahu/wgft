//go:build linux

package vpsd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rahanahu/wgft/internal/platform/linux"
)

// TestKernelDataplaneConntrackWarning は、kernelDataplane.ConntrackWarning が
// linux.ConntrackUsage.StartupWarning と同じ判定を返すことを確かめる。Run はこの値を、
// ip_forward の Finding と同じ場所(起動時のログ)に出す(vpsd.go、設計文書 7a.10 節)。
func TestKernelDataplaneConntrackWarning(t *testing.T) {
	dir := t.TempDir()
	oldMax, oldCount := linux.ConntrackMaxPath, linux.ConntrackCountPath
	t.Cleanup(func() { linux.ConntrackMaxPath, linux.ConntrackCountPath = oldMax, oldCount })
	linux.ConntrackMaxPath, linux.ConntrackCountPath = filepath.Join(dir, "max"), filepath.Join(dir, "count")

	k := &kernelDataplane{}
	if w := k.ConntrackWarning(); w != "" {
		t.Errorf("missing files: unexpected warning %q", w)
	}

	if err := os.WriteFile(linux.ConntrackMaxPath, []byte("4096\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := "nf_conntrack_max=4096 is below wgft's recommended minimum of 65536; a full conntrack table can reject new connections for the whole host"
	if w := k.ConntrackWarning(); w != want {
		t.Errorf("small table: warning = %q, want %q", w, want)
	}

	if err := os.WriteFile(linux.ConntrackMaxPath, []byte("262144\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if w := k.ConntrackWarning(); w != "" {
		t.Errorf("large table: unexpected warning %q", w)
	}
}

// TestUserspaceDataplaneConntrackWarning は、ユーザー空間モードがカーネルの conntrack を使わない
// ため、上限がどうであっても常に警告を出さないことを確かめる(仕様 6.3 節)。
func TestUserspaceDataplaneConntrackWarning(t *testing.T) {
	u := &userspaceDataplane{}
	if w := u.ConntrackWarning(); w != "" {
		t.Errorf("unexpected warning %q", w)
	}
}
