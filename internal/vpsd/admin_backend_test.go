//go:build linux

package vpsd

import (
	"bytes"
	"database/sql"
	"log"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/internal/vpsd/stream"
)

// TestRulesGenerationRuleDropsWrapStoreErrors confirms that a store failure reading rules,
// the generation, or the rule-drop counters is reported with the name of the failed
// operation, not returned raw. admin.go's 500 response puts err.Error() straight into the
// response body, so before the fix an operator saw only the store's own message (e.g.
// "sql: database is closed") with no indication of which read had failed.
func TestRulesGenerationRuleDropsWrapStoreErrors(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	st.Close() // force every subsequent store call to fail

	d := &Daemon{st: st}

	if _, err := d.Rules(); err == nil || !strings.Contains(err.Error(), "reading rules") {
		t.Errorf(`Rules() = %v, want an error naming the operation ("reading rules")`, err)
	}
	if _, err := d.Generation(); err == nil || !strings.Contains(err.Error(), "reading generation") {
		t.Errorf(`Generation() = %v, want an error naming the operation ("reading generation")`, err)
	}
	if _, err := d.RuleDrops(); err == nil || !strings.Contains(err.Error(), "reading rule drops") {
		t.Errorf(`RuleDrops() = %v, want an error naming the operation ("reading rule drops")`, err)
	}
}

// TestAgentsLogsWarningsReadFailure confirms that when a single agent's warnings fail to
// read, Agents() still returns the full agent list (fail open, unchanged from before) but
// logs the cause, instead of silently reporting no warnings for that agent. Before the fix,
// the failure was swallowed with no trace: the WARN column and the dashboard's warning
// count would go quiet with nothing in the log to explain why.
func TestAgentsLogsWarningsReadFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sqlite")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	tok, err := st.IssueJoinToken("home", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Register(tok, "home", "203.0.113.2", netip.MustParsePrefix("10.200.0.0/24")); err != nil {
		t.Fatal(err)
	}

	// Break only the warnings table, through a second connection to the same file, so that
	// Agents() itself still succeeds while AgentWarnings("home") fails. This exercises a
	// genuine store failure rather than a mock, matching how this package tests this layer.
	db2, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db2.Exec("DROP TABLE warnings"); err != nil {
		t.Fatal(err)
	}
	db2.Close()

	d := &Daemon{st: st, dp: stubDataplane{}, hub: stream.New(nil)}

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	infos, err := d.Agents()
	if err != nil {
		t.Fatalf("Agents() = %v, want success (fail open)", err)
	}
	if len(infos) != 1 || infos[0].Name != "home" {
		t.Fatalf("Agents() = %+v, want the one registered agent", infos)
	}
	if infos[0].Warnings != nil {
		t.Errorf("Warnings = %+v, want none reported on a read failure", infos[0].Warnings)
	}
	if !strings.Contains(buf.String(), "home") || !strings.Contains(buf.String(), "warnings") {
		t.Errorf("expected a log line naming the agent and the failed warnings read, got %q", buf.String())
	}
}

// TestAgentsLogsWGStatusReadFailure confirms that Agents() still returns the full agent list
// when the wg peer-status read fails (fail open: the endpoint IP/last-handshake columns and the
// IP-mismatch comparison are display-only here, the periodic watch in watch.go is the actual
// detector, design.md 10.5 節), but that the failure is not silent: before this fix, `dev, _ :=
// d.dp.WGStatus()` discarded the cause and every agent's WGEndpoint/LastHandshake just went
// quietly blank with nothing in the log to explain why.
func TestAgentsLogsWGStatusReadFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sqlite")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	tok, err := st.IssueJoinToken("home", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Register(tok, "home", "203.0.113.2", netip.MustParsePrefix("10.200.0.0/24")); err != nil {
		t.Fatal(err)
	}

	d := &Daemon{st: st, dp: errWGStatusDataplane{}, hub: stream.New(nil)}

	buf := captureLog(t)

	infos, err := d.Agents()
	if err != nil {
		t.Fatalf("Agents() = %v, want success (fail open)", err)
	}
	if len(infos) != 1 || infos[0].Name != "home" {
		t.Fatalf("Agents() = %+v, want the one registered agent", infos)
	}
	if infos[0].WGEndpoint != "" {
		t.Errorf("WGEndpoint = %q, want empty when the wg status read failed", infos[0].WGEndpoint)
	}
	if !strings.Contains(buf.String(), "wg status") {
		t.Errorf("expected a log line naming the failed wg status read, got %q", buf.String())
	}
}
