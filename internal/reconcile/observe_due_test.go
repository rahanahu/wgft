package reconcile

import (
	"errors"
	"fmt"
	"math/rand"
	"testing"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/proto"
)

// emptyTextErr is an error whose text is empty.
type emptyTextErr struct{}

func (emptyTextErr) Error() string { return "" }

// formerObserveDue is the rule Observe decided by before the Reconciler kept unsettled: due while
// a drift is not republished yet, or while the status reports a LastError. It is the oracle for
// TestObserveDueMatchesTheFormerRule; the caller holds no lock, as the tests run on one goroutine.
func formerObserveDue(r *Reconciler) bool {
	if r.published == nil {
		return r.status.LastError != ""
	}
	return r.resync || r.status.LastError != ""
}

// dueStep is one thing that happens to a Reconciler between two Observes.
type dueStep int

const (
	commitOK           dueStep = iota // a transaction commits
	commitRepair                      // a transaction publishes and leaves a repair pending
	commitFails                       // a transaction fails as a whole
	commitFailsSilent                 // a transaction fails as a whole with an error whose text is empty
	retryCommitOK                     // a periodic retry commits, or finds nothing to publish
	observeFails                      // an Observe cannot read the state
	observeFailsSilent                // an Observe fails with an error whose text is empty
	driftFound                        // an Observe finds drift
	commitRuleFails                   // a transaction commits with one rule's Prepare failed
)

var dueStepNames = []string{"commit ok", "commit with a repair pending", "commit fails", "commit fails with an empty text",
	"retry", "observe fails", "observe fails with an empty text", "drift", "commit with a rule failed"}

func (s dueStep) String() string { return dueStepNames[s] }

// runDueStep applies s to r and leaves the fake dataplane reporting a clean state again.
func runDueStep(t *testing.T, r *Reconciler, dp *fakeDataplane, in Input, s dueStep) {
	t.Helper()
	switch s {
	case commitOK, retryCommitOK:
		in.Retry = s == retryCommitOK
		if _, err := r.Reconcile(in); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	case commitRepair:
		dp.committed = dataplane.Committed{RepairPending: true, Errors: []error{errors.New("conntrack flush failed")}}
		dp.repaired = dp.committed
		if _, err := r.Reconcile(in); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		dp.committed, dp.repaired = dataplane.Committed{}, dataplane.Committed{}
	case commitFails, commitFailsSilent:
		dp.commitErr = errors.New("nftables: transaction failed")
		if s == commitFailsSilent {
			dp.commitErr = emptyTextErr{}
		}
		if _, err := r.Reconcile(in); err == nil {
			t.Fatalf("%s: Reconcile succeeded", s)
		}
		dp.commitErr = nil
	case observeFails, observeFailsSilent:
		dp.observeErr = errors.New("wgft0: no such device")
		if s == observeFailsSilent {
			dp.observeErr = emptyTextErr{}
		}
		_, _, _ = r.Observe()
		dp.observeErr = nil
	case commitRuleFails:
		dp.failed = map[string]error{"r_a": errors.New("bind failed: address already in use")}
		if _, err := r.Reconcile(in); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		dp.failed = nil
	case driftFound:
		dp.drift = []string{"table inet wgft is missing"}
		_, _, _ = r.Observe()
		dp.drift = nil
	}
}

// Observe decides whether a transaction is due from the Reconciler's own state, not from the
// status's LastError. In every state the steps reach, the decision is the one the former rule
// (formerObserveDue) gave, including before the first commit and for an error whose text is empty.
func TestObserveDueMatchesTheFormerRule(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	seen := map[[2]bool]int{}
	for seq := 0; seq < 400; seq++ {
		rec := &recorder{}
		dp := &fakeDataplane{rec: rec}
		r := New(Runtime{Dataplane: dp})
		in := Input{Plan: testPlan(t, 3, tcpRule("r_a", 25565, proto.ModeKernel))}
		var steps []dueStep
		for i := 0; i < 8; i++ {
			s := dueStep(rng.Intn(len(dueStepNames)))
			steps = append(steps, s)
			runDueStep(t, r, dp, in, s)
			want := formerObserveDue(r)
			_, due, err := r.Observe()
			if err != nil {
				t.Fatalf("after %v: Observe: %v", steps, err)
			}
			if due != want {
				t.Fatalf("after %v: Observe due = %v, the former rule says %v (LastError %q, resync %v)",
					steps, due, want, r.status.LastError, r.resync)
			}
			seen[[2]bool{r.published != nil, due}]++
		}
	}
	for _, k := range [][2]bool{{false, false}, {false, true}, {true, false}, {true, true}} {
		if seen[k] == 0 {
			t.Errorf("no step sequence reached committed=%v due=%v: %v", k[0], k[1], seen)
		}
	}
}

// The decision for each case, spelled out.
func TestObserveDueCases(t *testing.T) {
	for _, tc := range []struct {
		steps []dueStep
		want  bool
	}{
		{nil, false},
		{[]dueStep{commitFails}, true},                                // the first transaction failed; retry it
		{[]dueStep{commitFailsSilent}, false},                         // no LastError to report, and Observe was never due for it
		{[]dueStep{commitOK}, false},                                  // committed and nothing drifted
		{[]dueStep{commitRepair}, true},                               // a repair is pending
		{[]dueStep{commitRepair, retryCommitOK}, false},               // the retry's repair finished
		{[]dueStep{commitOK, commitFails}, true},                      // a later transaction failed as a whole
		{[]dueStep{commitOK, commitFails, commitOK}, false},           // and a later one committed
		{[]dueStep{commitRepair, commitFails}, true},                  // a failure after a pending repair
		{[]dueStep{commitRepair, commitFailsSilent}, false},           // an empty-text failure hid the pending repair, as before
		{[]dueStep{commitOK, observeFails}, true},                     // the state could not be read; republish
		{[]dueStep{commitOK, observeFailsSilent}, true},               // republish after it, whatever the error says
		{[]dueStep{commitOK, driftFound}, true},                       // drift waits for the republication
		{[]dueStep{commitOK, driftFound, retryCommitOK}, false},       // which has committed
		{[]dueStep{commitOK, commitFails, retryCommitOK}, false},      // the retry committed
		{[]dueStep{commitRepair, observeFails, retryCommitOK}, false}, // the republication cleared the repair
		{[]dueStep{commitOK, commitRepair, commitFails, commitOK}, false},
		{[]dueStep{commitRuleFails}, false},               // a rule-local failure waits for the timer's retry (NeedsRetry), not Observe
		{[]dueStep{commitRepair, commitRuleFails}, false}, // and a commit clears the pending repair as before
	} {
		t.Run(fmt.Sprint(tc.steps), func(t *testing.T) {
			rec := &recorder{}
			dp := &fakeDataplane{rec: rec}
			r := New(Runtime{Dataplane: dp})
			in := Input{Plan: testPlan(t, 3, tcpRule("r_a", 25565, proto.ModeKernel))}
			for _, s := range tc.steps {
				runDueStep(t, r, dp, in, s)
			}
			if _, due, _ := r.Observe(); due != tc.want {
				t.Errorf("Observe due = %v, want %v (LastError %q)", due, tc.want, r.Status().LastError)
			}
		})
	}
}

// The status's LastError only reports: rewriting its text, which the admin API shows as
// apply_error, does not change whether Observe is due.
func TestObserveDueIgnoresLastErrorText(t *testing.T) {
	r, _, _, _ := committedReconciler(t)
	r.status.LastError = "a reworded message"
	if _, due, _ := r.Observe(); due {
		t.Error("Observe is due after a commit because LastError has text")
	}

	rec := &recorder{}
	dp := &fakeDataplane{rec: rec, commitErr: errors.New("nftables: transaction failed")}
	r = New(Runtime{Dataplane: dp})
	if _, err := r.Reconcile(Input{Plan: testPlan(t, 3, tcpRule("r_a", 25565, proto.ModeKernel))}); err == nil {
		t.Fatal("Reconcile succeeded")
	}
	r.status.LastError = ""
	if _, due, _ := r.Observe(); !due {
		t.Error("Observe is not due after a failed first transaction because LastError is empty")
	}
}
