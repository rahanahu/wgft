//go:build linux

package linuxkernel

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
)

func commitOnce(t *testing.T, b *Backend, d dataplane.Desired) dataplane.Committed {
	t.Helper()
	p, err := b.Prepare(d)
	if err != nil {
		t.Fatal(err)
	}
	c, err := p.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func hasError(c dataplane.Committed, sub string) bool {
	for _, e := range c.Errors {
		if strings.Contains(e.Error(), sub) {
			return true
		}
	}
	return false
}

// A conntrack convergence that fails after the publication is a pending repair; Repair reruns
// only the convergence (the table is not staged or flushed again) until it succeeds (design.md
// 7a.3 節: 戻れない地点の後の修復).
func TestRepairConverge(t *testing.T) {
	w := testWG(t, testPeer(t, "10.200.0.2"))
	k := &fakeKernel{table: "fp1", dev: deviceAsDeclared(w), convergeErr: errors.New("conntrack: operation not permitted")}
	b := newTestBackend(k)
	c := commitOnce(t, b, dataplane.Desired{WG: &w, ActivePeers: w.Peers})
	if !c.RepairPending || !hasError(c, "conntrack converge") {
		t.Fatalf("commit with a failed convergence: %+v, want a pending repair", c)
	}
	k.calls = nil
	if c := b.Repair(); !c.RepairPending || !reflect.DeepEqual(k.calls, []string{"converge"}) {
		t.Fatalf("repair while still failing: %+v, calls %v", c, k.calls)
	}
	k.convergeErr, k.calls = nil, nil
	c = b.Repair()
	if c.RepairPending || c.Closed != 1 || !reflect.DeepEqual(k.calls, []string{"converge"}) {
		t.Fatalf("repair after the failure cleared: %+v, calls %v; want only the convergence", c, k.calls)
	}
	k.calls = nil
	if c := b.Repair(); c.RepairPending || len(k.calls) > 0 {
		t.Errorf("repair with nothing pending: %+v, calls %v", c, k.calls)
	}
}

// A peer removal that fails after the publication is a pending repair: Repair converges the peers
// again, and a transaction that does not change the peer set still converges them while the
// repair is pending.
func TestRepairPeerRemoval(t *testing.T) {
	keep, gone := testPeer(t, "10.200.0.2"), testPeer(t, "10.200.0.3")
	w := testWG(t, keep)
	removal := errors.New("wgft0: device busy")
	failRemoval := true
	k := &fakeKernel{table: "fp1", dev: deviceAsDeclared(w), wgErr: func(peers []wg.Peer) error {
		if failRemoval && len(peers) == 1 {
			return removal
		}
		return nil
	}}
	b := newTestBackend(k)
	c := commitOnce(t, b, dataplane.Desired{WG: &w, ActivePeers: []dataplane.Peer{keep, gone}})
	if !c.RepairPending || !hasError(c, "removing peers") {
		t.Fatalf("commit with a failed peer removal: %+v", c)
	}
	k.calls = nil
	if c := b.Repair(); !c.RepairPending || !reflect.DeepEqual(k.calls, []string{"ensure peers [10.200.0.2]"}) {
		t.Fatalf("repair while still failing: %+v, calls %v", c, k.calls)
	}

	// a transaction with the same peer set does not touch the peers before the publication (a
	// failure there would block it), but converges them after it while the repair is pending
	k.calls = nil
	c = commitOnce(t, b, dataplane.Desired{WG: &w, ActivePeers: w.Peers})
	want := []string{"stage", "read drops", "flush", "ensure peers [10.200.0.2]", "converge"}
	if !c.RepairPending || !reflect.DeepEqual(k.calls, want) {
		t.Errorf("commit with a pending peer repair: %+v, calls %v, want %v", c, k.calls, want)
	}

	failRemoval, k.calls = false, nil
	if c := b.Repair(); c.RepairPending || !reflect.DeepEqual(k.calls, []string{"ensure peers [10.200.0.2]"}) {
		t.Fatalf("repair after the failure cleared: %+v, calls %v", c, k.calls)
	}
}

// A failed read-back leaves the table's fingerprint unknown: the repair stays pending (Repair cannot
// fix it), Observe reports it as drift instead of "nothing to compare", and the republication that
// follows reads it back and clears it.
func TestRepairReadBack(t *testing.T) {
	w := testWG(t, testPeer(t, "10.200.0.2"))
	k := &fakeKernel{table: "fp1", dev: deviceAsDeclared(w), fpErr: errors.New("netlink: no buffer space available")}
	b := newTestBackend(k)
	c := commitOnce(t, b, dataplane.Desired{WG: &w, ActivePeers: w.Peers})
	if !c.RepairPending || !hasError(c, "reading back") {
		t.Fatalf("commit with a failed read-back: %+v", c)
	}
	k.fpErr = nil
	if c := b.Repair(); !c.RepairPending {
		t.Error("Repair cannot read the table back; the repair must stay pending")
	}
	obs, err := b.Observe()
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.Drift) != 1 || !strings.Contains(obs.Drift[0], "was not read back") {
		t.Fatalf("Observe with an unknown fingerprint: drift %v, want it reported", obs.Drift)
	}
	if c := commitOnce(t, b, dataplane.Desired{WG: &w, ActivePeers: w.Peers, Resync: true}); c.RepairPending {
		t.Fatalf("the republication read the table back: %+v, want nothing pending", c)
	}
	if obs, _ := b.Observe(); len(obs.Drift) > 0 {
		t.Errorf("Observe after the read-back: drift %v", obs.Drift)
	}
}
