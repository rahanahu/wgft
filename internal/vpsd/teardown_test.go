package vpsd

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/store"
)

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
	recordTeardownHints(st, Options{WGInterface: "wgft0", WGPort: 51820, AgentAPIAddr: "0.0.0.0:8443"})

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
// recorded wg interface name (whether recordTeardownHints never ran or failed every time),
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
	// 意図して metaWGInterface を記録しない(recordTeardownHints を呼ばない)。
	st.Close()

	var buf bytes.Buffer
	if err := Teardown(TeardownOptions{DBPath: path, Adopt: true, DryRun: true}, &buf); err != nil {
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
