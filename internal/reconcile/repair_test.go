package reconcile

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/proto"
)

// A step after the point of no return that fails in a way a retry can repair (a conntrack
// convergence, a peer removal, a read-back) keeps the rules active but asks for a retry and says so
// in LastError; the retry runs the dataplane's Repair even though it publishes the same, without a
// Commit, and clears the state once Repair succeeds. A retry with nothing pending stays a NoOp
// without Repair (design.md 7a.3 節: 戻れない地点の後の修復).
func TestRepairRetry(t *testing.T) {
	for _, failure := range []string{"conntrack converge: operation not permitted", "wgft0: removing peers: device busy"} {
		t.Run(failure, func(t *testing.T) {
			rec := &recorder{}
			dp := &fakeDataplane{rec: rec, committed: dataplane.Committed{RepairPending: true, Errors: []error{errors.New(failure)}}}
			r := New(Runtime{Dataplane: dp})
			in := Input{Plan: testPlan(t, 4, tcpRule("r_del", 25565, proto.ModeKernel))}
			if _, err := r.Reconcile(in); err != nil {
				t.Fatal(err)
			}
			st := r.Status()
			if !st.NeedsRetry || !strings.Contains(st.LastError, "published generation 4, but a repair after the publication failed: "+failure) {
				t.Fatalf("after a failed repair: NeedsRetry %v, LastError %q", st.NeedsRetry, st.LastError)
			}
			if st.Rules["r_del"].State != Active || st.ActiveGeneration != 4 {
				t.Errorf("the publication happened: %+v, active generation %d", st.Rules["r_del"], st.ActiveGeneration)
			}
			if _, due, _ := r.Observe(); !due {
				t.Error("Observe must be due while a repair is pending")
			}

			// the repair still fails: the retry runs Repair, not Commit, and stays pending
			dp.repaired = dataplane.Committed{RepairPending: true, Errors: []error{errors.New(failure)}}
			rec.calls = nil
			in.Retry = true
			out, err := r.Reconcile(in)
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"dataplane.Observe", "dataplane.Prepare", "dataplane.Rollback", "dataplane.Repair"}
			if !out.NoOp || !out.Repaired || !reflect.DeepEqual(rec.calls, want) {
				t.Fatalf("repair retry: NoOp %v, Repaired %v, calls %v, want %v", out.NoOp, out.Repaired, rec.calls, want)
			}
			if !r.Status().NeedsRetry {
				t.Fatal("a repair that still fails must keep asking for a retry")
			}

			// the repair succeeds: the state clears
			dp.repaired = dataplane.Committed{Closed: 2}
			rec.calls = nil
			out, err = r.Reconcile(in)
			if err != nil || !out.Repaired || out.Committed.Closed != 2 {
				t.Fatalf("successful repair retry: %+v, %v", out, err)
			}
			if st := r.Status(); st.NeedsRetry || st.LastError != "" {
				t.Fatalf("after the repair: NeedsRetry %v, LastError %q", st.NeedsRetry, st.LastError)
			}

			// nothing pending: a same-publication retry is a plain NoOp without Repair or Observe
			rec.calls = nil
			out, _ = r.Reconcile(in)
			if want := []string{"dataplane.Prepare", "dataplane.Rollback"}; !out.NoOp || out.Repaired || !reflect.DeepEqual(rec.calls, want) {
				t.Errorf("retry with nothing pending: NoOp %v, Repaired %v, calls %v", out.NoOp, out.Repaired, rec.calls)
			}
		})
	}
}

// A repair retry first observes; drift (such as a table whose read-back failed) turns it into a
// republication, a full Commit with Resync, which reruns every repair and clears the state.
func TestRepairRetryObservesDrift(t *testing.T) {
	rec := &recorder{}
	dp := &fakeDataplane{rec: rec, committed: dataplane.Committed{RepairPending: true,
		Errors: []error{errors.New("reading back table inet wgft: netlink: no buffer space available")}}}
	r := New(Runtime{Dataplane: dp})
	in := Input{Plan: testPlan(t, 1, tcpRule("r_a", 25565, proto.ModeKernel))}
	if _, err := r.Reconcile(in); err != nil {
		t.Fatal(err)
	}
	dp.drift = []string{"table inet wgft was not read back after the last publication"}
	dp.committed = dataplane.Committed{}
	rec.calls = nil
	in.Retry = true
	out, err := r.Reconcile(in)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"dataplane.Observe", "dataplane.Prepare", "dataplane.Commit"}
	if out.NoOp || !reflect.DeepEqual(rec.calls, want) || !dp.got.Resync || !reflect.DeepEqual(out.Drift, dp.drift) {
		t.Fatalf("repair retry with drift: NoOp %v, calls %v, Resync %v, Drift %v", out.NoOp, rec.calls, dp.got.Resync, out.Drift)
	}
	if st := r.Status(); st.NeedsRetry || st.LastError != "" {
		t.Errorf("after the republication: NeedsRetry %v, LastError %q", st.NeedsRetry, st.LastError)
	}
}
