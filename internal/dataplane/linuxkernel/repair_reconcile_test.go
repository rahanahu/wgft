//go:build linux

package linuxkernel

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/internal/reconcile"
)

func has(calls []string, c string) bool {
	for _, x := range calls {
		if x == c {
			return true
		}
	}
	return false
}

// A failed peer removal, driven through the Reconciler with the real kernel Backend: the repair
// retry observes, and the peer set that still differs is the known pending repair, not drift, so
// the retry runs Repair only, with no Commit and no nftables flush (the table keeps its meters and
// ct count sets). Once the removal succeeds the repair clears and a same-publication retry is a
// plain NoOp. A non-peer difference (the listen port) during a pending peer repair is still drift
// and republishes (design.md 7a.3 節: 戻れない地点の後の修復).
func TestPeerRepairThroughReconciler(t *testing.T) {
	keep, gone := testPeer(t, "10.200.0.2"), testPeer(t, "10.200.0.3")
	failRemoval := false
	k := &fakeKernel{table: "fp1", wgErr: func(peers []wg.Peer) error {
		if failRemoval && len(peers) == 1 {
			return errors.New("wgft0: device busy")
		}
		return nil
	}}
	w2 := testWG(t, keep, gone)
	k.dev = deviceAsDeclared(w2)
	b := newTestBackend(k)
	r := reconcile.New(reconcile.Runtime{Dataplane: b})
	if _, err := r.Reconcile(reconcile.Input{Plan: planner.Plan{Generation: 1}, WG: &w2}); err != nil {
		t.Fatal(err)
	}

	// the agent "gone" is revoked; the peer removal after the publication fails
	failRemoval = true
	w1 := w2.WithPeers([]dataplane.Peer{keep})
	in := reconcile.Input{Plan: planner.Plan{Generation: 2}, WG: &w1}
	if _, err := r.Reconcile(in); err != nil {
		t.Fatal(err)
	}
	if st := r.Status(); !st.NeedsRetry || !strings.Contains(st.LastError, "removing peers") {
		t.Fatalf("after the failed removal: NeedsRetry %v, LastError %q", st.NeedsRetry, st.LastError)
	}
	if len(k.dev.Peers) != 2 {
		t.Fatalf("the kernel should still have both peers, has %d", len(k.dev.Peers))
	}

	// the repair retry: Observe finds only the pending peer difference, so Repair runs alone
	in.Retry = true
	k.calls = nil
	out, err := r.Reconcile(in)
	if err != nil {
		t.Fatal(err)
	}
	if !out.NoOp || !out.Repaired || len(out.Drift) > 0 || has(k.calls, "flush") {
		t.Fatalf("repair retry while the removal still fails: NoOp %v, Repaired %v, Drift %v, calls %v; want Repair only",
			out.NoOp, out.Repaired, out.Drift, k.calls)
	}
	if want := []string{"stage", "ensure peers [10.200.0.2]"}; !reflect.DeepEqual(k.calls, want) {
		t.Errorf("calls = %v, want the staged table discarded and the removal retried: %v", k.calls, want)
	}
	if !r.Status().NeedsRetry {
		t.Fatal("the repair still fails; it must stay pending")
	}

	// the removal succeeds on the next retry: the repair clears, still without a flush
	failRemoval = false
	k.calls = nil
	if out, err = r.Reconcile(in); err != nil || !out.Repaired || has(k.calls, "flush") {
		t.Fatalf("successful repair retry: %+v, %v, calls %v", out, err, k.calls)
	}
	if st := r.Status(); st.NeedsRetry || st.LastError != "" || len(k.dev.Peers) != 1 {
		t.Fatalf("after the repair: NeedsRetry %v, LastError %q, kernel peers %d", st.NeedsRetry, st.LastError, len(k.dev.Peers))
	}
	k.calls = nil
	if out, _ = r.Reconcile(in); !out.NoOp || out.Repaired || !reflect.DeepEqual(k.calls, []string{"stage"}) {
		t.Errorf("retry with nothing pending: NoOp %v, Repaired %v, calls %v; want a plain NoOp", out.NoOp, out.Repaired, k.calls)
	}
}

// During a pending peer repair, a difference other than the peers (here the listen port) is still
// drift: the repair retry republishes and converges the whole device.
func TestPeerRepairStillDetectsOtherDrift(t *testing.T) {
	keep, gone := testPeer(t, "10.200.0.2"), testPeer(t, "10.200.0.3")
	failRemoval := false
	k := &fakeKernel{table: "fp1", wgErr: func(peers []wg.Peer) error {
		if failRemoval && len(peers) == 1 {
			return errors.New("wgft0: device busy")
		}
		return nil
	}}
	w2 := testWG(t, keep, gone)
	k.dev = deviceAsDeclared(w2)
	b := newTestBackend(k)
	r := reconcile.New(reconcile.Runtime{Dataplane: b})
	if _, err := r.Reconcile(reconcile.Input{Plan: planner.Plan{Generation: 1}, WG: &w2}); err != nil {
		t.Fatal(err)
	}
	failRemoval = true
	w1 := w2.WithPeers([]dataplane.Peer{keep})
	in := reconcile.Input{Plan: planner.Plan{Generation: 2}, WG: &w1}
	if _, err := r.Reconcile(in); err != nil {
		t.Fatal(err)
	}

	k.dev.ListenPort = 51821 // `wg set wgft0 listen-port 51821` while the peer repair is pending
	in.Retry = true
	k.calls = nil
	out, err := r.Reconcile(in)
	if err != nil {
		t.Fatal(err)
	}
	if out.NoOp || !has(k.calls, "flush") || len(out.Drift) != 1 || !strings.Contains(out.Drift[0], "listen port is 51821") {
		t.Fatalf("a port change during a pending peer repair: NoOp %v, Drift %v, calls %v; want a republication", out.NoOp, out.Drift, k.calls)
	}
}
