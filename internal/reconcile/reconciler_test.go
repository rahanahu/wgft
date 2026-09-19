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

func peer(t *testing.T, addr string) dataplane.Peer {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return dataplane.Peer{PublicKey: k.PublicKey(), Address: netip.MustParseAddr(addr)}
}

// The active generation advances only when a transaction commits; a backend-wide failure leaves
// it, reports the changed rules pending with the reason, and a rule's own active_generation is the
// generation its current value was published at (design.md 7a.3 節).
func TestReconcilerGenerations(t *testing.T) {
	rec := &recorder{}
	dp := &fakeDataplane{rec: rec}
	r := New(Runtime{Dataplane: dp})

	if _, err := r.Reconcile(Input{Plan: testPlan(t, 3, tcpRule("r_a", 8000, proto.ModeKernel), tcpRule("r_b", 8001, proto.ModeKernel))}); err != nil {
		t.Fatal(err)
	}
	st := r.Status()
	if st.DesiredGeneration != 3 || st.ActiveGeneration != 3 {
		t.Fatalf("generations = desired %d, active %d, want 3 and 3", st.DesiredGeneration, st.ActiveGeneration)
	}
	for _, id := range []string{"r_a", "r_b"} {
		if got := st.Rules[id]; got != (RuleStatus{State: Active, ActiveGeneration: 3}) {
			t.Errorf("%s = %+v, want active at generation 3", id, got)
		}
	}

	// generation 4 changes r_b; the nftables transaction fails
	errSwap := errors.New("table inet wgft is owned by another process")
	dp.commitErr = errSwap
	rec.calls = nil
	if _, err := r.Reconcile(Input{Plan: testPlan(t, 4, tcpRule("r_a", 8000, proto.ModeKernel), tcpRule("r_b", 8002, proto.ModeKernel))}); !errors.Is(err, errSwap) {
		t.Fatalf("Reconcile error = %v, want the backend-wide failure", err)
	}
	if !reflect.DeepEqual(rec.calls, []string{"dataplane.Prepare", "dataplane.Commit", "dataplane.Rollback"}) {
		t.Errorf("calls = %v, want a rollback after the failed commit", rec.calls)
	}
	st = r.Status()
	if st.DesiredGeneration != 4 || st.ActiveGeneration != 3 {
		t.Errorf("after a backend-wide failure: desired %d, active %d, want 4 and 3", st.DesiredGeneration, st.ActiveGeneration)
	}
	if got := st.Rules["r_a"]; got.State != Active || got.ActiveGeneration != 3 {
		t.Errorf("unchanged r_a = %+v, want still active at 3", got)
	}
	if got := st.Rules["r_b"]; got.State != Pending || got.Reason != errSwap.Error() || got.ActiveGeneration != 3 {
		t.Errorf("changed r_b = %+v, want pending with the failure as reason, last active at 3", got)
	}
	if st.LastError != errSwap.Error() {
		t.Errorf("LastError = %q", st.LastError)
	}

	// generation 5 commits; r_b's new value becomes active at 5, r_a keeps 3
	dp.commitErr = nil
	if _, err := r.Reconcile(Input{Plan: testPlan(t, 5, tcpRule("r_a", 8000, proto.ModeKernel), tcpRule("r_b", 8002, proto.ModeKernel))}); err != nil {
		t.Fatal(err)
	}
	st = r.Status()
	if st.ActiveGeneration != 5 || st.LastError != "" {
		t.Errorf("active generation %d, last error %q, want 5 and none", st.ActiveGeneration, st.LastError)
	}
	if got := st.Rules["r_a"]; got != (RuleStatus{State: Active, ActiveGeneration: 3}) {
		t.Errorf("r_a = %+v, want active at 3 (its value did not change)", got)
	}
	if got := st.Rules["r_b"]; got != (RuleStatus{State: Active, ActiveGeneration: 5}) {
		t.Errorf("r_b = %+v, want active at 5", got)
	}
}

// A rule-local failure makes only that rule not_active; the other rules are published and the
// active generation advances. The failed rule retires to its previous value until it recovers
// (design.md 7a.3 節, 7a.8 節 Phase 4 completion criteria).
func TestReconcilerRuleLocalFailure(t *testing.T) {
	rec := &recorder{}
	fe := &fakeFrontend{rec: rec}
	dp := &fakeDataplane{rec: rec}
	r := New(Runtime{Frontend: fe, Dataplane: dp})
	if _, err := r.Reconcile(Input{Plan: testPlan(t, 1, tcpRule("r_relay", 8443, proto.ModeProxy), tcpRule("r_k", 25565, proto.ModeKernel))}); err != nil {
		t.Fatal(err)
	}

	fe.failed = map[string]error{"r_relay": errors.New("bind failed: address already in use")}
	out, err := r.Reconcile(Input{Plan: testPlan(t, 2, tcpRule("r_relay", 9443, proto.ModeProxy), tcpRule("r_k", 25566, proto.ModeKernel))})
	if err != nil {
		t.Fatalf("a rule-local failure must not be an error: %v", err)
	}
	st := r.Status()
	if st.ActiveGeneration != 2 {
		t.Errorf("active generation = %d, want 2 (the other rules committed)", st.ActiveGeneration)
	}
	if got := st.Rules["r_relay"]; got.State != NotActive || got.Reason != "bind failed: address already in use" || got.ActiveGeneration != 1 {
		t.Errorf("r_relay = %+v, want not_active with the bind failure, last active at 1", got)
	}
	if got := st.Rules["r_k"]; got != (RuleStatus{State: Active, ActiveGeneration: 2}) {
		t.Errorf("r_k = %+v, want active at 2", got)
	}
	want := []Resource{{RuleID: "r_relay", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 8443, Hi: 8443}, Forwarding: "relay"}}
	if !reflect.DeepEqual(st.Retiring, want) {
		t.Errorf("Retiring = %+v, want %+v", st.Retiring, want)
	}
	if len(out.Retiring) != 1 || out.Retiring[0].Previous.ListenPort.Lo != 8443 {
		t.Errorf("Outcome.Retiring = %+v", out.Retiring)
	}

	// Still failing at generation 3: it keeps retiring to the value last Active (8443), not to the
	// value that never became Active.
	if _, err := r.Reconcile(Input{Plan: testPlan(t, 3, tcpRule("r_relay", 9443, proto.ModeProxy), tcpRule("r_k", 25566, proto.ModeKernel))}); err != nil {
		t.Fatal(err)
	}
	if got := fe.retiring; len(got) != 1 || got[0].Previous.ListenPort.Lo != 8443 {
		t.Errorf("second failure: retiring = %+v, want the value last Active (8443)", got)
	}

	// The port is free again: the rule becomes active, nothing retires any more.
	fe.failed = nil
	if _, err := r.Reconcile(Input{Plan: testPlan(t, 4, tcpRule("r_relay", 9443, proto.ModeProxy), tcpRule("r_k", 25566, proto.ModeKernel))}); err != nil {
		t.Fatal(err)
	}
	st = r.Status()
	if got := st.Rules["r_relay"]; got != (RuleStatus{State: Active, ActiveGeneration: 4}) {
		t.Errorf("recovered r_relay = %+v, want active at 4", got)
	}
	if len(st.Retiring) != 0 || len(fe.retiring) != 0 {
		t.Errorf("Retiring = %+v / %+v, want none once the rule is active", st.Retiring, fe.retiring)
	}
}

// What is Active but no longer Desired is visible as active_only while a backend-wide failure
// keeps its removal from being published; a disabled rule that is still forwarding is pending.
func TestReconcilerActiveOnly(t *testing.T) {
	rec := &recorder{}
	dp := &fakeDataplane{rec: rec}
	r := New(Runtime{Dataplane: dp})
	if _, err := r.Reconcile(Input{Plan: testPlan(t, 1, tcpRule("r_del", 8000, proto.ModeKernel), tcpRule("r_off", 8001, proto.ModeKernel))}); err != nil {
		t.Fatal(err)
	}
	dp.commitErr = errors.New("nftables: transaction failed")
	off := tcpRule("r_off", 8001, proto.ModeKernel)
	off.Enabled = false
	_, err := r.Reconcile(Input{Plan: testPlan(t, 2, off), Excluded: map[string]string{"r_off": "disabled"}})
	if err == nil {
		t.Fatal("want the backend-wide failure")
	}
	st := r.Status()
	var ids []string
	for _, res := range st.ActiveOnly {
		ids = append(ids, res.RuleID)
	}
	if !reflect.DeepEqual(ids, []string{"r_del", "r_off"}) {
		t.Errorf("ActiveOnly = %v, want r_del and r_off", ids)
	}
	if got := st.Rules["r_off"]; got.State != Pending {
		t.Errorf("disabled but still forwarding r_off = %+v, want pending", got)
	}
	if _, ok := st.Rules["r_del"]; ok {
		t.Error("a deleted rule is not in the Desired set and has no rule state")
	}

	dp.commitErr = nil
	if _, err := r.Reconcile(Input{Plan: testPlan(t, 3, off), Excluded: map[string]string{"r_off": "disabled"}}); err != nil {
		t.Fatal(err)
	}
	st = r.Status()
	if len(st.ActiveOnly) != 0 {
		t.Errorf("ActiveOnly = %+v after the removal committed, want none", st.ActiveOnly)
	}
	if got := st.Rules["r_off"]; got.State != NotActive || got.Reason != "disabled" {
		t.Errorf("r_off = %+v, want not_active (disabled)", got)
	}
}

// Observe runs once, before the first transaction, and seeds the active peer set; afterwards the
// active peer set follows committed transactions only.
func TestReconcilerPeers(t *testing.T) {
	rec := &recorder{}
	stale, a, b := peer(t, "10.200.0.9"), peer(t, "10.200.0.2"), peer(t, "10.200.0.3")
	dp := &fakeDataplane{rec: rec, observed: []dataplane.Peer{stale}}
	r := New(Runtime{Dataplane: dp})
	wg := &dataplane.WGConfig{Peers: []dataplane.Peer{a}}
	if _, err := r.Reconcile(Input{Plan: testPlan(t, 1), WG: wg}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dp.got.ActivePeers, []dataplane.Peer{stale}) {
		t.Errorf("first transaction ActivePeers = %v, want what Observe found", dp.got.ActivePeers)
	}
	dp.commitErr = errors.New("failed")
	if _, err := r.Reconcile(Input{Plan: testPlan(t, 2), WG: &dataplane.WGConfig{Peers: []dataplane.Peer{a, b}}}); err == nil {
		t.Fatal("want failure")
	}
	dp.commitErr = nil
	if _, err := r.Reconcile(Input{Plan: testPlan(t, 3), WG: &dataplane.WGConfig{Peers: []dataplane.Peer{a, b}}}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dp.got.ActivePeers, []dataplane.Peer{a}) {
		t.Errorf("after a failed transaction ActivePeers = %v, want the last committed set", dp.got.ActivePeers)
	}
	if dp.observes != 1 {
		t.Errorf("Observe ran %d times, want once", dp.observes)
	}
}

// A failing Observe is backend-wide: nothing is prepared, and it is retried by the next reconcile.
func TestReconcilerObserveFailure(t *testing.T) {
	rec := &recorder{}
	dp := &fakeDataplane{rec: rec, observeErr: errors.New("wgft0: no such device")}
	r := New(Runtime{Dataplane: dp})
	if _, err := r.Reconcile(Input{Plan: testPlan(t, 1, tcpRule("r_a", 8000, proto.ModeKernel))}); err == nil {
		t.Fatal("want the Observe failure")
	}
	if !reflect.DeepEqual(rec.calls, []string{"dataplane.Observe"}) {
		t.Errorf("calls = %v, want Observe only", rec.calls)
	}
	if got := r.Status().Rules["r_a"]; got.State != Pending {
		t.Errorf("r_a = %+v, want pending", got)
	}
	dp.observeErr = nil
	if _, err := r.Reconcile(Input{Plan: testPlan(t, 1, tcpRule("r_a", 8000, proto.ModeKernel))}); err != nil {
		t.Fatal(err)
	}
	if dp.observes != 2 {
		t.Errorf("Observe ran %d times, want a retry", dp.observes)
	}
}
