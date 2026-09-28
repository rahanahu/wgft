//go:build linux

package vpsd

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/platform/linux"
	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/proto"
)

func ruleTarget(st *proto.State, id string) string {
	for _, r := range st.Rules {
		if r.ID == id {
			return r.Target
		}
	}
	return ""
}

// An earlier failed edit must not hitchhike on a later disable push. The
// disable may change only the disabled bit, rule enabled bits, and generation.
func TestFailedEditDoesNotEnterDisableDelivery(t *testing.T) {
	f := newDisableFixture(t)
	before, err := f.d.StateFor("home", proto.Negotiated{Legacy: true})
	if err != nil {
		t.Fatal(err)
	}
	rules := rulesOf(t, f.st)
	rules[0].Target = "192.0.2.10:25565"
	f.p.setErr(errors.New("publication failed"))
	if _, err := f.d.Batch(admin.BatchRequest{Upsert: []proto.Rule{rules[0]}}); err == nil {
		t.Fatal("failed publication reported success")
	}
	if _, err := f.d.DisableAgent("other"); err == nil {
		t.Fatal("failed disable publication reported success")
	}
	home, err := f.d.StateFor("home", proto.Negotiated{Legacy: true})
	if err != nil {
		t.Fatal(err)
	}
	other, err := f.d.AgentState("other")
	if err != nil {
		t.Fatal(err)
	}
	if ruleTarget(home, "r_a") != ruleTarget(before, "r_a") || home.WG != before.WG || home.AgentDisabled != before.AgentDisabled {
		t.Fatalf("failed edit entered delivery: before=%+v after=%+v", before, home)
	}
	if !other.AgentDisabled || other.Rules[0].Enabled {
		t.Fatalf("disable overlay absent: %+v", other)
	}
	if home.Generation != other.Generation || home.Generation <= before.Generation {
		t.Fatalf("disable generation not shared: home=%d other=%d before=%d", home.Generation, other.Generation, before.Generation)
	}
	f.p.setErr(nil)
	if _, err := f.d.Batch(admin.BatchRequest{}); err != nil {
		t.Fatal(err)
	}
	home, err = f.d.AgentState("home")
	if err != nil || ruleTarget(home, "r_a") != rules[0].Target {
		t.Fatalf("later full publication did not deliver edit: %+v, %v", home, err)
	}
}

func TestRevokeTombstonesBeforeFailedApplyAndReregistration(t *testing.T) {
	f := newDisableFixture(t)
	f.p.setErr(errors.New("publication failed"))
	if err := f.d.Revoke("home"); err == nil {
		t.Fatal("revoke apply failure was hidden")
	}
	f.d.delivery.mu.RLock()
	_, retained := f.d.delivery.full.entries["home"]
	f.d.delivery.mu.RUnlock()
	if retained {
		t.Fatal("revoked registration remained in the published projection")
	}
	if _, err := f.d.AgentState("home"); err == nil {
		t.Fatal("revoked registration retained a State")
	}
	if _, err := f.d.AgentState("other"); err != nil {
		t.Fatalf("unrelated published State was lost: %v", err)
	}
	token, err := f.st.IssueJoinToken("home", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.st.Register(token, "home", "203.0.113.3", netip.MustParsePrefix("10.200.0.0/24")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.AgentState("home"); err == nil {
		t.Fatal("new registration reused an old published State")
	}
	f.p.setErr(nil)
	f.d.mu.Lock()
	err = f.d.applyNFT(rulesOf(t, f.st))
	f.d.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.AgentState("home"); err != nil {
		t.Fatalf("new registration was not published: %v", err)
	}
}

func TestSavedKeyAfterFailedApplyCannotUseSameKeyReconnect(t *testing.T) {
	f := newDisableFixture(t)
	private, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	key := private.PublicKey()
	f.p.setErr(errors.New("publication failed"))
	if err := f.d.SetPublicKey("home", key); err == nil {
		t.Fatal("failed key publication reported success")
	}
	if err := f.d.SetPublicKey("home", key); err != nil {
		t.Fatalf("same-key path: %v", err)
	}
	if _, err := f.d.StateFor("home", proto.Negotiated{Legacy: true}); err == nil {
		t.Fatal("same-key reconnect obtained State from an unpublished key")
	}
	if _, err := f.d.AgentState("other"); err != nil {
		t.Fatalf("unrelated published State was lost: %v", err)
	}
}

func TestNoOpDeliveryMismatchForcesCommitAndRetainsOldStateOnFailure(t *testing.T) {
	f := newDisableFixture(t)
	initial, err := f.d.AgentState("home")
	if err != nil {
		t.Fatal(err)
	}
	f.p.mu.Lock()
	baseCommits := f.p.commits
	f.p.mu.Unlock()
	// This disabled rule's target is delivered but absent from the kernel plan.
	rules := rulesOf(t, f.st)
	rules[1].Target = "192.0.2.20:2456"
	f.p.mu.Lock()
	f.p.failCommit = true
	f.p.mu.Unlock()
	res, err := f.st.ApplyBatch(nil, func([]proto.Rule) ([]proto.Rule, error) { return rules, nil })
	if err != nil {
		t.Fatal(err)
	}
	f.d.mu.Lock()
	_, err = f.d.apply(res.Rules, true)
	f.d.mu.Unlock()
	if !errors.Is(err, ErrDeliveryProjectionMismatch) {
		t.Fatalf("NoOp mismatch error = %v", err)
	}
	status, ok := f.d.ApplyStatus()
	if !ok || status.AgentStateGeneration == nil || *status.AgentStateGeneration != initial.Generation ||
		status.AgentStatePending == nil || !*status.AgentStatePending {
		t.Fatalf("failed forced Commit reported full State published: %+v, %v", status, ok)
	}
	f.p.mu.Lock()
	commits := f.p.commits
	f.p.failCommit = false
	f.p.mu.Unlock()
	if commits != baseCommits+1 {
		t.Fatalf("forced Commit count = %d, want %d", commits, baseCommits+1)
	}
	st, err := f.d.AgentState("home")
	if err != nil || ruleTarget(st, "r_b") != ruleTarget(initial, "r_b") {
		t.Fatalf("failed forced Commit entered State: %+v, %v", st, err)
	}
	if _, err := f.d.Batch(admin.BatchRequest{}); err != nil {
		t.Fatal(err)
	}
	st, err = f.d.AgentState("home")
	if err != nil || ruleTarget(st, "r_b") != rules[1].Target {
		t.Fatalf("retry did not publish target: %+v, %v", st, err)
	}
}

func TestBootstrapBindsLatestSuccessfulProjection(t *testing.T) {
	f := newDisableFixture(t)
	f.d.delivery.mu.Lock()
	f.d.delivery.full = nil
	f.d.delivery.mu.Unlock()
	f.d.timeouts.Store(nil)
	old, err := f.st.Generation()
	if err != nil {
		t.Fatal(err)
	}
	f.p.setErr(errors.New("publication failed"))
	rules := rulesOf(t, f.st)
	rules[0].Target = "192.0.2.30:25565"
	if _, err := f.d.Batch(admin.BatchRequest{Upsert: []proto.Rule{rules[0]}}); err == nil {
		t.Fatal("failed publication reported success")
	}
	if _, err := f.d.AgentState("home"); err == nil {
		t.Fatal("State escaped before timeout binding")
	}
	timeouts, err := f.d.bindDeliveryTimeouts(func() (linux.UDPTimeouts, error) {
		return linux.UDPTimeouts{Timeout: 7, TimeoutStream: 19}, nil
	})
	if err != nil || timeouts.Timeout != 7 {
		t.Fatalf("timeout binding: %+v, %v", timeouts, err)
	}
	st, err := f.d.AgentState("home")
	if err != nil || st.Generation != old || st.WG.UDPTimeout != 7 || st.WG.UDPTimeoutStream != 19 || ruleTarget(st, "r_a") == rules[0].Target {
		t.Fatalf("bootstrap used failed saved edit or wrong timeouts: %+v, %v", st, err)
	}
}

func TestBootstrapReadSerializesWithAdminApply(t *testing.T) {
	f := newDisableFixture(t)
	f.d.delivery.mu.Lock()
	f.d.delivery.full = nil
	f.d.delivery.mu.Unlock()
	f.d.timeouts.Store(nil)
	rules := rulesOf(t, f.st)
	rules[0].Target = "192.0.2.40:25565"
	if _, err := f.d.Batch(admin.BatchRequest{Upsert: []proto.Rule{rules[0]}}); err != nil {
		t.Fatal(err)
	}
	f.p.setErr(errors.New("publication failed"))
	rules[0].Target = "192.0.2.41:25565"
	if _, err := f.d.Batch(admin.BatchRequest{Upsert: []proto.Rule{rules[0]}}); err == nil {
		t.Fatal("later failed edit reported success")
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	bound := make(chan error, 1)
	go func() {
		_, err := f.d.bindDeliveryTimeouts(func() (linux.UDPTimeouts, error) {
			close(entered)
			<-release
			return linux.UDPTimeouts{Timeout: 7, TimeoutStream: 19}, nil
		})
		bound <- err
	}()
	<-entered
	adminDone := make(chan error, 1)
	go func() {
		_, err := f.d.Batch(admin.BatchRequest{})
		adminDone <- err
	}()
	select {
	case err := <-adminDone:
		t.Fatalf("admin apply passed the timeout read lock: %v", err)
	default:
	}
	close(release)
	if err := <-bound; err != nil {
		t.Fatal(err)
	}
	st, err := f.d.AgentState("home")
	if err != nil || st.WG.UDPTimeout != 7 || st.WG.UDPTimeoutStream != 19 || ruleTarget(st, "r_a") != "192.0.2.40:25565" {
		t.Fatalf("timeout bound to failed declaration: %+v, %v", st, err)
	}
	<-adminDone // The failing participant cannot replace the bound token.
}

func TestNoOpMismatchSuccessfulForcedCommitNotifiesOnce(t *testing.T) {
	f := newDisableFixture(t)
	rules := rulesOf(t, f.st)
	rules[1].Target = "192.0.2.50:2456" // disabled: absent from the dataplane plan
	res, err := f.st.ApplyBatch(nil, func([]proto.Rule) ([]proto.Rule, error) { return rules, nil })
	if err != nil {
		t.Fatal(err)
	}
	f.p.mu.Lock()
	beforeCommits := f.p.commits
	f.p.mu.Unlock()
	beforeRevision := f.d.delivery.revision
	f.log.take()
	f.d.mu.Lock()
	_, err = f.d.apply(res.Rules, true)
	f.d.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	f.p.mu.Lock()
	commits := f.p.commits
	f.p.mu.Unlock()
	if commits != beforeCommits+1 || f.d.delivery.revision != beforeRevision+1 {
		t.Fatalf("forced publication: commits %d->%d, revision %d->%d", beforeCommits, commits, beforeRevision, f.d.delivery.revision)
	}
	if got := f.log.take(); !sameEvents(got, "publish r_a,r_c,r_o", "publish r_a,r_c,r_o", "deliver") {
		t.Fatalf("NoOp and forced Commit events = %v", got)
	}
	st, err := f.d.AgentState("home")
	if err != nil || ruleTarget(st, "r_b") != rules[1].Target {
		t.Fatalf("forced publication not selected: %+v, %v", st, err)
	}
	f.d.mu.Lock()
	_, err = f.d.apply(res.Rules, true)
	f.d.mu.Unlock()
	if err != nil || f.d.delivery.revision != beforeRevision+1 {
		t.Fatalf("equal NoOp advanced the revision: %v, %d", err, f.d.delivery.revision)
	}
}

func TestBootstrapTimeoutReadFailureLeavesStateUnservable(t *testing.T) {
	f := newDisableFixture(t)
	f.d.delivery.mu.Lock()
	f.d.delivery.full = nil
	f.d.delivery.mu.Unlock()
	f.d.timeouts.Store(nil)
	_, err := f.d.bindDeliveryTimeouts(func() (linux.UDPTimeouts, error) {
		return linux.UDPTimeouts{}, errors.New("timeout read failed")
	})
	if err == nil || f.d.timeouts.Load() != nil {
		t.Fatalf("failed bind = %v, timeouts = %+v", err, f.d.timeouts.Load())
	}
	if _, err := f.d.AgentState("home"); err == nil {
		t.Fatal("State escaped after timeout read failure")
	}
}

func TestMatchingNoOpClearsPendingAfterTransientRepairFailure(t *testing.T) {
	f := newDisableFixture(t)
	f.p.setErr(errors.New("temporary publication failure"))
	f.d.mu.Lock()
	err := f.d.applyNFT(rulesOf(t, f.st))
	f.d.mu.Unlock()
	if err == nil {
		t.Fatal("failed apply reported success")
	}
	_, pending := f.d.delivery.status()
	if !pending {
		t.Fatal("failed apply did not report pending")
	}
	f.p.setErr(nil)
	f.d.mu.Lock()
	_, err = f.d.apply(rulesOf(t, f.st), true)
	f.d.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	_, pending = f.d.delivery.status()
	if pending {
		t.Fatal("matching successful NoOp retained stale pending status")
	}
}
