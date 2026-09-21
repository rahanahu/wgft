//go:build linux

package vpsd

import (
	"bytes"
	"errors"
	"log"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/reconcile"
	"github.com/rahanahu/wgft/internal/vpsd/store"
)

// failingDataplane reports one rule-local failure with a reason the test changes between calls.
type failingDataplane struct{ reason string }

func (f *failingDataplane) Observe() (dataplane.Observed, error) { return dataplane.Observed{}, nil }
func (f *failingDataplane) Prepare(dataplane.Desired) (dataplane.Prepared, error) {
	return failingPrepared{errors.New(f.reason)}, nil
}
func (f *failingDataplane) Repair() dataplane.Committed { return dataplane.Committed{} }

type failingPrepared struct{ err error }

func (p failingPrepared) Failed() map[string]error { return map[string]error{"r_x": p.err} }
func (p failingPrepared) Commit([]dataplane.Retiring) (dataplane.Committed, error) {
	return dataplane.Committed{}, nil
}
func (p failingPrepared) Rollback() {}

// A retry that publishes nothing new (NoOp) still logs a rule-local failure whose reason changed
// (design.md 7a.3 節: 理由が変わったときに 1 行).
func TestApplyLogsReasonChangeOnNoOp(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	dp := &failingDataplane{reason: "bind failed: address already in use"}
	d := &Daemon{st: st, opts: Options{WGInterface: "wgft0"}, rec: reconcile.New(reconcile.Runtime{Dataplane: dp})}
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	if _, err := d.apply(nil, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "rule r_x: not active: bind failed: address already in use") {
		t.Fatalf("first failure not logged: %q", buf.String())
	}
	buf.Reset()
	dp.reason = "bind failed: permission denied"
	out, err := d.apply(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if !out.NoOp {
		t.Fatal("the retry should publish nothing new")
	}
	if !strings.Contains(buf.String(), "rule r_x: not active: bind failed: permission denied") {
		t.Errorf("reason change on a NoOp retry not logged: %q", buf.String())
	}
}
