package linux

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// digitRe matches any ASCII digit, used to check that the finding carries no memory figures
// (no MiB, no bytes-per-entry, no bucket counts) besides the sysctl value itself.
var digitRe = regexp.MustCompile(`[0-9]`)

func TestConntrackUsageFinding(t *testing.T) {
	if f := (ConntrackUsage{Max: 262144}).Finding(); f != nil {
		t.Errorf("262144: unexpected finding %v", f)
	}
	if f := (ConntrackUsage{Max: ConntrackMinMax}).Finding(); f != nil {
		t.Errorf("%d: unexpected finding %v", ConntrackMinMax, f)
	}
	f := (ConntrackUsage{Max: 16384}).Finding()
	if f == nil {
		t.Fatal("16384: want a finding, got nil")
	}
	s := f.String()
	if !strings.Contains(s, "wgft recommends at least 65536") {
		t.Errorf("16384: finding = %q, want it to say wgft recommends at least 65536", s)
	}
	if !strings.Contains(s, "sysctl -w net.netfilter.nf_conntrack_max=65536") {
		t.Errorf("16384: finding = %q, want the suggested sysctl line at 65536", s)
	}
	// no memory figures: strip the two numbers that are allowed (the current value is not shown
	// here at all, and the recommended/suggested value 65536 appears twice) and check what is left
	// has no digits.
	stripped := strings.ReplaceAll(s, "65536", "")
	if digitRe.MatchString(stripped) {
		t.Errorf("16384: finding = %q, want no memory figures (MiB, bytes per entry, bucket count)", s)
	}
}

func TestConntrackUsageStartupWarning(t *testing.T) {
	if w := (ConntrackUsage{Max: ConntrackMinMax}).StartupWarning(); w != "" {
		t.Errorf("%d: unexpected warning %q", ConntrackMinMax, w)
	}
	if w := (ConntrackUsage{Max: 262144}).StartupWarning(); w != "" {
		t.Errorf("262144: unexpected warning %q", w)
	}
	w := (ConntrackUsage{Max: 4096}).StartupWarning()
	want := "nf_conntrack_max=4096 is below wgft's recommended minimum of 65536; a full conntrack table can reject new connections for the whole host"
	if w != want {
		t.Errorf("4096: warning = %q, want %q", w, want)
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
