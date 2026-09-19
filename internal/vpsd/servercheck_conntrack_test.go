package vpsd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/platform/linux"
)

// TestCheckConntrackOutput は checkConntrack が internal/platform/linux.ReadConntrackUsage の結果を
// 正しく表示するか(閾値の判定そのものは internal/platform/linux.TestConntrackUsageFinding が持つ)。
func TestCheckConntrackOutput(t *testing.T) {
	dir := t.TempDir()
	oldMax, oldCount := linux.ConntrackMaxPath, linux.ConntrackCountPath
	t.Cleanup(func() { linux.ConntrackMaxPath, linux.ConntrackCountPath = oldMax, oldCount })
	linux.ConntrackMaxPath, linux.ConntrackCountPath = filepath.Join(dir, "max"), filepath.Join(dir, "count")

	var out bytes.Buffer
	checkConntrack(&out)
	if !strings.Contains(out.String(), "is the nf_conntrack module loaded") {
		t.Errorf("missing files: got %q", out.String())
	}

	os.WriteFile(linux.ConntrackMaxPath, []byte("16384\n"), 0o600)
	os.WriteFile(linux.ConntrackCountPath, []byte("212\n"), 0o600)
	out.Reset()
	checkConntrack(&out)
	if got := out.String(); !strings.Contains(got, "conntrack: 212 of 16384 entries in use") || !strings.Contains(got, "  - net.netfilter.nf_conntrack_max: is 16384") {
		t.Errorf("small table: got %q", got)
	}

	os.WriteFile(linux.ConntrackMaxPath, []byte("262144\n"), 0o600)
	out.Reset()
	checkConntrack(&out)
	if got := out.String(); strings.Contains(got, "  - ") {
		t.Errorf("large table: unexpected warning in %q", got)
	}
}
