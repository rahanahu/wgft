package reconcile

import (
	"errors"
	"reflect"
	"testing"

	"github.com/rahanahu/wgft/proto"
)

// A retry that would publish exactly what the last transaction published commits nothing, so the
// nftables table is not replaced and keeps its meters and ct count state (design.md 7a.3 節). A
// retry that changes something, and every non-retry transaction, commits as before.
func TestRetrySkipsUnchangedPublication(t *testing.T) {
	rec := &recorder{}
	fe := &fakeFrontend{rec: rec, listening: map[uint16]bool{25565: true},
		failed: map[string]error{"r_bind": errors.New("bind failed: address already in use")}}
	dp := &fakeDataplane{rec: rec}
	r := New(Runtime{Frontend: fe, Dataplane: dp})
	in := Input{Plan: testPlan(t, 1, tcpRule("r_bind", 8443, proto.ModeProxy), tcpRule("r_k", 25565, proto.ModeKernel))}
	if _, err := r.Reconcile(in); err != nil {
		t.Fatal(err)
	}
	if !r.Status().NeedsRetry {
		t.Fatal("a rule-local failure must ask for a retry")
	}

	rec.calls = nil
	in.Retry = true
	out, err := r.Reconcile(in)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"frontend.Prepare", "dataplane.Prepare", "dataplane.Rollback", "frontend.Rollback"}
	if !out.NoOp || !reflect.DeepEqual(rec.calls, want) {
		t.Errorf("unchanged retry: NoOp %v, calls %v, want a rollback without a commit", out.NoOp, rec.calls)
	}
	if got := r.Status().Rules["r_bind"]; got.State != NotActive {
		t.Errorf("r_bind after an unchanged retry = %+v, want still not_active", got)
	}

	// the same Desired value without Retry (an operator's change) is committed as before
	rec.calls = nil
	in.Retry = false
	if _, err := r.Reconcile(in); err != nil {
		t.Fatal(err)
	}
	if rec.calls[2] != "dataplane.Commit" {
		t.Errorf("non-retry calls = %v, want a commit", rec.calls)
	}

	// the port is free now: the retry publishes the rule and nothing asks for a retry any more
	fe.failed = nil
	fe.listening = map[uint16]bool{25565: true, 8443: true}
	rec.calls = nil
	in.Retry = true
	out, err = r.Reconcile(in)
	if err != nil {
		t.Fatal(err)
	}
	if out.NoOp || rec.calls[2] != "dataplane.Commit" {
		t.Errorf("changed retry: NoOp %v, calls %v, want a commit", out.NoOp, rec.calls)
	}
	st := r.Status()
	if st.Rules["r_bind"].State != Active || st.NeedsRetry {
		t.Errorf("after the port came back: %+v, NeedsRetry %v", st.Rules["r_bind"], st.NeedsRetry)
	}
}

// A backend-wide failure asks for a retry too; the retry after it publishes (nothing matched the
// failed attempt), and a success clears the request.
func TestRetryAfterBackendFailure(t *testing.T) {
	rec := &recorder{}
	dp := &fakeDataplane{rec: rec}
	r := New(Runtime{Dataplane: dp})
	in := Input{Plan: testPlan(t, 1, tcpRule("r_a", 8000, proto.ModeKernel))}
	if _, err := r.Reconcile(in); err != nil {
		t.Fatal(err)
	}
	if r.Status().NeedsRetry {
		t.Fatal("nothing failed; no retry wanted")
	}
	dp.commitErr = errors.New("nftables: transaction failed")
	in = Input{Plan: testPlan(t, 2, tcpRule("r_a", 8001, proto.ModeKernel))}
	if _, err := r.Reconcile(in); err == nil {
		t.Fatal("want the failure")
	}
	if !r.Status().NeedsRetry {
		t.Fatal("a backend-wide failure must ask for a retry")
	}
	dp.commitErr = nil
	in.Retry = true
	out, err := r.Reconcile(in)
	if err != nil || out.NoOp {
		t.Fatalf("retry after a failure: NoOp %v, err %v, want a commit", out.NoOp, err)
	}
	if st := r.Status(); st.NeedsRetry || st.ActiveGeneration != 2 {
		t.Errorf("after the retry: NeedsRetry %v, active generation %d", st.NeedsRetry, st.ActiveGeneration)
	}
}
