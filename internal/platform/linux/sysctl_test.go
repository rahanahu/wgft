package linux

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConntrackUsageFinding(t *testing.T) {
	if f := (ConntrackUsage{Max: 262144}).Finding(); f != nil {
		t.Errorf("262144: unexpected finding %v", f)
	}
	if f := (ConntrackUsage{Max: ConntrackMinMax}).Finding(); f != nil {
		t.Errorf("%d: unexpected finding %v", ConntrackMinMax, f)
	}
	f := (ConntrackUsage{Max: 16384}).Finding()
	if f == nil || !strings.Contains(f.String(), "is 16384") || !strings.Contains(f.String(), "sysctl -w net.netfilter.nf_conntrack_max=") {
		t.Errorf("16384: finding = %v", f)
	}
}

func TestReadConntrackUsage(t *testing.T) {
	dir := t.TempDir()
	oldMax, oldCount := ConntrackMaxPath, ConntrackCountPath
	t.Cleanup(func() { ConntrackMaxPath, ConntrackCountPath = oldMax, oldCount })
	ConntrackMaxPath, ConntrackCountPath = filepath.Join(dir, "max"), filepath.Join(dir, "count")

	if _, err := ReadConntrackUsage(); err == nil {
		t.Error("missing files: want an error when max cannot be read")
	}

	os.WriteFile(ConntrackMaxPath, []byte("16384\n"), 0o600)
	os.WriteFile(ConntrackCountPath, []byte("212\n"), 0o600)
	u, err := ReadConntrackUsage()
	if err != nil {
		t.Fatal(err)
	}
	if u.Max != 16384 || !u.HaveCount || u.Count != 212 {
		t.Errorf("usage = %+v, want Max=16384 Count=212 HaveCount=true", u)
	}

	os.Remove(ConntrackCountPath)
	u, err = ReadConntrackUsage()
	if err != nil {
		t.Fatal(err)
	}
	if u.HaveCount {
		t.Errorf("usage = %+v, want HaveCount=false when the count file is missing", u)
	}
}

func TestIPForwardStatus(t *testing.T) {
	// IPForwardPath is a package const, not a var, so this test only exercises the "already 1"
	// and error paths against the real /proc file; the lab's e2e/lifecycle scripts exercise the
	// actual write through server startup on a real kernel.
	value, openErr, err := IPForwardStatus()
	if err != nil {
		t.Skipf("cannot read %s: %v", IPForwardPath, err)
	}
	if value != "0" && value != "1" {
		t.Errorf("value = %q, want 0 or 1", value)
	}
	if value == "1" && openErr != nil {
		t.Errorf("openErr = %v, want nil when value is already 1", openErr)
	}
}
