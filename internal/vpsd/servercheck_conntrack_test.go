package vpsd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConntrackFinding(t *testing.T) {
	if f := conntrackFinding(262144); f != nil {
		t.Errorf("262144: unexpected finding %v", f)
	}
	if f := conntrackFinding(conntrackMinMax); f != nil {
		t.Errorf("%d: unexpected finding %v", conntrackMinMax, f)
	}
	f := conntrackFinding(16384)
	if f == nil || !strings.Contains(f.String(), "is 16384") || !strings.Contains(f.String(), "sysctl -w net.netfilter.nf_conntrack_max=") {
		t.Errorf("16384: finding = %v", f)
	}
}

func TestCheckConntrackOutput(t *testing.T) {
	dir := t.TempDir()
	oldMax, oldCount := conntrackMaxPath, conntrackCountPath
	t.Cleanup(func() { conntrackMaxPath, conntrackCountPath = oldMax, oldCount })
	conntrackMaxPath, conntrackCountPath = filepath.Join(dir, "max"), filepath.Join(dir, "count")

	var out bytes.Buffer
	checkConntrack(&out)
	if !strings.Contains(out.String(), "is the nf_conntrack module loaded") {
		t.Errorf("missing files: got %q", out.String())
	}

	os.WriteFile(conntrackMaxPath, []byte("16384\n"), 0o600)
	os.WriteFile(conntrackCountPath, []byte("212\n"), 0o600)
	out.Reset()
	checkConntrack(&out)
	if got := out.String(); !strings.Contains(got, "conntrack: 212 of 16384 entries in use") || !strings.Contains(got, "  - net.netfilter.nf_conntrack_max: is 16384") {
		t.Errorf("small table: got %q", got)
	}

	os.WriteFile(conntrackMaxPath, []byte("262144\n"), 0o600)
	out.Reset()
	checkConntrack(&out)
	if got := out.String(); strings.Contains(got, "  - ") {
		t.Errorf("large table: unexpected warning in %q", got)
	}
}
