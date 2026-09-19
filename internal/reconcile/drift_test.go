package reconcile

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/proto"
)

// committedReconciler returns a Reconciler whose first transaction committed, with the calls so far
// cleared.
func committedReconciler(t *testing.T) (*Reconciler, *fakeDataplane, *recorder, Input) {
	t.Helper()
	rec := &recorder{}
	dp := &fakeDataplane{rec: rec}
	r := New(Runtime{Dataplane: dp})
	in := Input{Plan: testPlan(t, 3, tcpRule("r_a", 25565, proto.ModeKernel))}
	if _, err := r.Reconcile(in); err != nil {
		t.Fatal(err)
	}
	rec.calls = nil
	return r, dp, rec, in
}

// An Observe that finds the actual state as committed is not due: nothing is prepared or
// committed, so the nftables meters and ct count sets are kept (design.md 7a.3 節: 実際の状態への
// 収束).
func TestObserveNoDriftCommitsNothing(t *testing.T) {
	r, _, rec, _ := committedReconciler(t)
	for i := 0; i < 3; i++ {
		drift, due, err := r.Observe()
		if err != nil || due || len(drift) > 0 {
			t.Fatalf("Observe without drift: drift %v, due %v, err %v", drift, due, err)
		}
	}
	if want := []string{"dataplane.Observe", "dataplane.Observe", "dataplane.Observe"}; !reflect.DeepEqual(rec.calls, want) {
		t.Errorf("calls = %v, want Observe only", rec.calls)
	}
}

// Before anything is committed there is nothing to compare with: Observe does not call the
// dataplane and is not due.
func TestObserveBeforeFirstCommit(t *testing.T) {
	rec := &recorder{}
	r := New(Runtime{Dataplane: &fakeDataplane{rec: rec, drift: []string{"x"}}})
	if drift, due, err := r.Observe(); err != nil || due || drift != nil || len(rec.calls) > 0 {
		t.Errorf("Observe before the first commit: drift %v, due %v, err %v, calls %v", drift, due, err, rec.calls)
	}
}

// Drift makes Observe due and is reported once; the retry that follows commits the whole Plan with
// Resync even though it would publish the same as before, and afterwards nothing is due.
func TestObserveDriftRecommits(t *testing.T) {
	r, dp, rec, in := committedReconciler(t)
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	left := []dataplane.Peer{{PublicKey: key.PublicKey(), Address: netip.MustParseAddr("10.200.0.9")}}
	dp.drift, dp.observed = []string{"table inet wgft is missing"}, left

	drift, due, err := r.Observe()
	if err != nil || !due || !reflect.DeepEqual(drift, dp.drift) {
		t.Fatalf("first Observe with drift: drift %v, due %v, err %v", drift, due, err)
	}
	drift, due, _ = r.Observe()
	if !due || drift != nil {
		t.Fatalf("second Observe with the same drift: drift %v (want none, logged once), due %v", drift, due)
	}

	rec.calls = nil
	in.Retry = true
	out, err := r.Reconcile(in)
	if err != nil || out.NoOp {
		t.Fatalf("retry after drift: NoOp %v, err %v; want a commit", out.NoOp, err)
	}
	if want := []string{"dataplane.Prepare", "dataplane.Commit"}; !reflect.DeepEqual(rec.calls, want) {
		t.Errorf("calls = %v, want %v", rec.calls, want)
	}
	if !dp.got.Resync || !reflect.DeepEqual(dp.got.ActivePeers, left) {
		t.Errorf("Desired after drift: Resync %v, ActivePeers %v; want Resync and the observed peers", dp.got.Resync, dp.got.ActivePeers)
	}

	dp.drift = nil
	rec.calls = nil
	if _, due, _ := r.Observe(); due {
		t.Error("Observe after the recommit must not be due")
	}
	if _, err := r.Reconcile(in); err != nil {
		t.Fatal(err)
	}
	if dp.got.Resync {
		t.Error("a transaction after the recommit must not resync again")
	}
}

// While a recommit after drift fails, every rule is reported pending (what was Active may not be
// forwarding), and Observe stays due; once it commits, the rules are active again.
func TestObserveDriftRecommitFails(t *testing.T) {
	r, dp, _, in := committedReconciler(t)
	dp.drift = []string{"interface wgft0 is missing"}
	if _, due, _ := r.Observe(); !due {
		t.Fatal("drift must be due")
	}
	dp.commitErr = errors.New("nftables: table inet wgft is owned by another process")
	in.Retry = true
	if _, err := r.Reconcile(in); err == nil {
		t.Fatal("want the commit failure")
	}
	if st := r.Status().Rules["r_a"]; st.State != Pending {
		t.Errorf("r_a while the recommit fails = %+v, want pending", st)
	}
	dp.drift = nil
	if _, due, _ := r.Observe(); !due {
		t.Error("Observe must stay due while the recommit has not committed")
	}
	dp.commitErr = nil
	if _, err := r.Reconcile(in); err != nil {
		t.Fatal(err)
	}
	if st := r.Status(); st.Rules["r_a"].State != Active || st.LastError != "" {
		t.Errorf("after the recommit: %+v, LastError %q", st.Rules["r_a"], st.LastError)
	}
}

// An Observe error (a resource held by someone else) is not due, is recorded as a backend-wide
// failure with every rule pending, and the next transaction republishes as after drift.
func TestObserveError(t *testing.T) {
	r, dp, _, in := committedReconciler(t)
	dp.observeErr = errors.New("wgft0 is now a WireGuard interface wgft does not own")
	if _, due, err := r.Observe(); err == nil || due {
		t.Fatalf("Observe error: due %v, err %v; want the error, not due", due, err)
	}
	st := r.Status()
	if st.LastError == "" || st.Rules["r_a"].State != Pending {
		t.Errorf("after an Observe error: LastError %q, r_a %+v", st.LastError, st.Rules["r_a"])
	}
	dp.observeErr = nil
	in.Retry = true
	if _, err := r.Reconcile(in); err != nil {
		t.Fatal(err)
	}
	if !dp.got.Resync {
		t.Error("the transaction after an Observe error must resync")
	}
}
