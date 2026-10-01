//go:build linux

package teardown

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/flock"
	"github.com/rahanahu/wgft/internal/vpsd/store"
)

// captureLog redirects the standard logger into a buffer for the rest of the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

// TestRecordTeardownHintsLogsSetMetaFailure confirms that a failure to persist the teardown
// hints at startup is not silent. Before this fix, `_ = st.SetMeta(...)` discarded the error;
// an operator would have no way to know, until they ran `wgft server teardown` much later, that
// the interface name might not be found (design.md 10.3・10.5 節).
func TestRecordTeardownHintsLogsSetMetaFailure(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	st.Close() // force every subsequent SetMeta to fail

	buf := captureLog(t)
	RecordHints(st, Hints{WGInterface: "wgft0", WGPort: 51820, AgentAPIAddr: "0.0.0.0:8443"})

	got := buf.String()
	if !strings.Contains(got, "wg interface") {
		t.Errorf("expected a log line about the failed wg interface name recording, got %q", got)
	}
	if !strings.Contains(got, "wg port") {
		t.Errorf("expected a log line about the failed wg port recording, got %q", got)
	}
	if !strings.Contains(got, "agent API port") {
		t.Errorf("expected a log line about the failed agent API port recording, got %q", got)
	}
}

// TestTeardownWarnsWhenInterfaceNameNotRecorded confirms that, when the server database has no
// recorded wg interface name (whether RecordHints never ran or failed every time),
// teardown says so in its output instead of silently assuming the default name. Silently
// assuming it is dangerous together with --adopt-existing, which skips the key check: it could
// then delete an unrelated interface that happens to share the default name (design.md 10.3・
// 10.5 節). --adopt-existing and --dry-run keep this host-runnable: the ownership check (which
// needs CAP_NET_ADMIN) is skipped by Adopt, and DryRun returns before any real removal, the way
// the lab-only tests in teardown_lab_test.go exercise the destructive paths instead.
func TestTeardownWarnsWhenInterfaceNameNotRecorded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sqlite")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// 意図して store.MetaTeardownWGInterface を記録しない(RecordHints を呼ばない)。
	st.Close()

	var buf bytes.Buffer
	if err := Run(Options{DBPath: path, Adopt: true, DryRun: true}, &buf); err != nil {
		t.Fatalf("teardown: %v\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "no recorded wg interface name") {
		t.Errorf("expected a warning that the interface name was not recorded, got:\n%s", out)
	}
	if !strings.Contains(out, "wgft0") {
		t.Errorf("expected the warning to name the assumed default, got:\n%s", out)
	}
}

// TestTeardownDryRunReadsTheRecordedHints checks that teardown reads each record the server
// leaves in the server database under the key the server writes it with: the interface name, the
// two ports and the ip_forward time come back in the dry run's output, and an invalid recorded
// address range is named. --adopt-existing and --dry-run keep it host-runnable, as in
// TestTeardownWarnsWhenInterfaceNameNotRecorded.
func TestTeardownDryRunReadsTheRecordedHints(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sqlite")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	RecordHints(st, Hints{WGInterface: "wgtest0", WGPort: 51999, AgentAPIAddr: "0.0.0.0:9443"})
	for k, v := range map[string]string{store.MetaIPForwardSetAt: "2026-01-02T03:04:05Z", store.MetaWGAddress: "not-a-prefix"} {
		if err := st.SetMeta(k, []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()

	var buf bytes.Buffer
	if err := Run(Options{DBPath: path, Adopt: true, DryRun: true}, &buf); err != nil {
		t.Fatalf("teardown: %v\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{
		"removing: table inet wgft / wg wgtest0 /",
		`recorded wg address "not-a-prefix" is invalid`,
		"close UDP 51999 opened in the firewall for WireGuard",
		"close TCP 9443 opened in the firewall for the agent API",
		"wgft set it 0->1 at 2026-01-02T03:04:05Z",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "no recorded wg interface name") {
		t.Errorf("teardown did not find the recorded interface name:\n%s", out)
	}
}

// TestTeardownDryRunReadsTheRecordedUserspaceMode checks that a server database recording the
// userspace mode makes teardown remove nothing in the kernel.
func TestTeardownDryRunReadsTheRecordedUserspaceMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sqlite")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetMeta(store.MetaMode, []byte(store.ModeUserspace)); err != nil {
		t.Fatal(err)
	}
	st.Close()

	var buf bytes.Buffer
	if err := Run(Options{DBPath: path, Adopt: true, DryRun: true}, &buf); err != nil {
		t.Fatalf("teardown: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "userspace mode: nothing to remove in the kernel") {
		t.Errorf("teardown did not read the recorded userspace mode:\n%s", buf.String())
	}
}

// TestTeardownPurgeNeedsYes checks that --purge without --yes refuses before removing anything,
// the server database included. A database recording the userspace mode keeps the test free of
// the kernel.
func TestTeardownPurgeNeedsYes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sqlite")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetMeta(store.MetaMode, []byte(store.ModeUserspace)); err != nil {
		t.Fatal(err)
	}
	st.Close()

	var buf bytes.Buffer
	err = Run(Options{DBPath: path, Purge: true}, &buf)
	if err == nil || !strings.Contains(err.Error(), "pass --yes to continue") {
		t.Fatalf("--purge without --yes: err = %v\n%s", err, buf.String())
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the server database is gone after a refused --purge: %v", err)
	}
}

// TestTeardownRefusesWhileTheServerHoldsTheLock checks the refusal without the kernel: while the
// startup lock of the server database is held, teardown refuses before reading anything else.
// teardown_lab_test.go's TestTeardownRefusesWhenRunning checks the same in the lab.
func TestTeardownRefusesWhileTheServerHoldsTheLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sqlite")
	lock, err := flock.Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()

	var buf bytes.Buffer
	err = Run(Options{DBPath: path, Adopt: true, DryRun: true}, &buf)
	if err == nil || !strings.Contains(err.Error(), "server is running") {
		t.Fatalf("err = %v\n%s", err, buf.String())
	}
	if buf.Len() != 0 {
		t.Errorf("teardown wrote output before refusing:\n%s", buf.String())
	}
}
