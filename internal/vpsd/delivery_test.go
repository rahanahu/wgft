//go:build linux

package vpsd

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
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
	before, err := f.d.AgentState("home")
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
	home, err := f.d.AgentState("home")
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
	_, retained := f.d.delivery.latest.entries["home"]
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

// Revoke installs a copy of the published snapshot without the revoked
// agent. The copy keeps the generation, so when the apply after the revoke
// fails, the diagnostics and the remaining agents still see the generation of
// the last successful publication.
func TestRevokeKeepsPublishedGenerationWhenApplyFails(t *testing.T) {
	f := newDisableFixture(t)
	before, err := f.d.AgentState("other")
	if err != nil {
		t.Fatal(err)
	}
	if before.Generation == 0 {
		t.Fatal("fixture published generation 0")
	}
	f.p.setErr(errors.New("publication failed"))
	if err := f.d.Revoke("home"); err == nil {
		t.Fatal("revoke apply failure was hidden")
	}
	status, ok := f.d.ApplyStatus()
	if !ok || status.AgentStateGeneration == nil || *status.AgentStateGeneration != before.Generation ||
		status.AgentStatePending == nil || !*status.AgentStatePending {
		t.Fatalf("diagnostics after failed revoke apply: %+v, %v; want generation %d and pending", status, ok, before.Generation)
	}
	other, err := f.d.AgentState("other")
	if err != nil || other.Generation != before.Generation {
		t.Fatalf("remaining agent after failed revoke apply: %+v, %v; want generation %d", other, err, before.Generation)
	}
}

func TestSavedKeyAfterFailedApplyCannotUseSameKeyReconnect(t *testing.T) {
	f := newDisableFixture(t)
	agent, err := f.st.AgentByName("home")
	if err != nil {
		t.Fatal(err)
	}
	private, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	key := private.PublicKey()
	f.p.setErr(errors.New("publication failed"))
	if err := f.d.SetPublicKey("home", agent.Identity, key); err == nil {
		t.Fatal("failed key publication reported success")
	}
	if err := f.d.SetPublicKey("home", agent.Identity, key); err != nil {
		t.Fatalf("same-key path: %v", err)
	}
	if _, err := f.d.StateFor("home", agent.Identity, key, proto.Negotiated{Legacy: true}); err == nil {
		t.Fatal("same-key reconnect obtained State from an unpublished key")
	}
	if _, err := f.d.AgentState("other"); err != nil {
		t.Fatalf("unrelated published State was lost: %v", err)
	}
}

func TestFailedKeyRotationAllowsTemporaryOldKeyReconnectAndRetiresIt(t *testing.T) {
	f := newDisableFixture(t)
	f.d.onPushAll = nil
	f.d.onPush = nil
	srv := httptest.NewServer(f.d.hub)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	open := func(key wgtypes.Key) *websocket.Conn {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ws, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
			HTTPHeader: http.Header{"Authorization": {"Bearer " + f.tokens["home"]}},
		})
		if err != nil {
			t.Fatal(err)
		}
		msg, err := json.Marshal(proto.Message{Type: proto.MsgPublicKey, PublicKey: key.String()})
		if err != nil {
			t.Fatal(err)
		}
		if err := ws.Write(ctx, websocket.MessageText, msg); err != nil {
			t.Fatal(err)
		}
		return ws
	}
	read := func(ws *websocket.Conn) (proto.Message, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, data, err := ws.Read(ctx)
		if err != nil {
			return proto.Message{}, err
		}
		var msg proto.Message
		err = json.Unmarshal(data, &msg)
		return msg, err
	}
	oldPrivate, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	old := open(oldPrivate.PublicKey())
	defer old.CloseNow()
	if msg, err := read(old); err != nil || msg.Type != proto.MsgState || msg.State == nil || msg.State.AgentDisabled {
		t.Fatalf("old connection initial State: %+v, %v", msg, err)
	}
	newPrivate, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	f.p.setErr(errors.New("publication failed"))
	for attempt := 0; attempt < 2; attempt++ {
		candidate := open(newPrivate.PublicKey())
		if msg, err := read(candidate); err == nil || msg.Type == proto.MsgState {
			t.Fatalf("unpublished new key got State on attempt %d: %+v, %v", attempt, msg, err)
		}
		candidate.CloseNow()
		if !f.d.hub.Status("home").Connected {
			t.Fatal("unpublished new key displaced the old stream")
		}
	}
	old.CloseNow() // the previously authorized stream is lost
	deadline := time.Now().Add(5 * time.Second)
	for f.d.hub.Status("home").Connected && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if f.d.hub.Status("home").Connected {
		t.Fatal("lost old stream did not leave the hub")
	}
	temporary := open(oldPrivate.PublicKey())
	defer temporary.CloseNow()
	if msg, err := read(temporary); err != nil || msg.Type != proto.MsgState || msg.State == nil || msg.State.AgentDisabled {
		t.Fatalf("temporary old-key reconnect did not receive P: %+v, %v", msg, err)
	}
	saved, err := f.st.AgentByName("home")
	if err != nil || saved.PublicKey != newPrivate.PublicKey().String() {
		t.Fatalf("temporary reconnect overwrote saved new key: %+v, %v", saved, err)
	}
	if _, err := f.d.DisableAgent("home"); err == nil {
		t.Fatal("failed disable publication reported success")
	}
	msg, err := read(temporary)
	if err != nil || msg.Type != proto.MsgState || msg.State == nil || !msg.State.AgentDisabled {
		t.Fatalf("old key did not receive stop State: %+v, %v", msg, err)
	}
	for _, rule := range msg.State.Rules {
		if rule.Enabled {
			t.Fatalf("stop State retained enabled rule: %+v", msg.State)
		}
	}
	observed, err := f.d.AgentState("home")
	if err != nil || !observed.AgentDisabled || observed.WG != msg.State.WG {
		t.Fatalf("admin P/D observation lost after failed key save: %+v, %v", observed, err)
	}
	f.p.setErr(nil)
	// Retirement must happen during publication, even if no Push is queued.
	f.d.onPushAll = func() {}
	f.d.onPush = func([]string) {}
	if _, err := f.d.Batch(admin.BatchRequest{}); err != nil {
		t.Fatal(err)
	}
	if msg, err := read(temporary); err == nil || msg.Type == proto.MsgState {
		t.Fatalf("retired old key received new full State: %+v, %v", msg, err)
	}
	if f.d.hub.Status("home").Connected {
		t.Fatal("old-key stream remained installed after new-key publication")
	}
	current, err := f.st.AgentByName("home")
	if err != nil || current.PublicKey != newPrivate.PublicKey().String() {
		t.Fatalf("successful publication lost new key declaration: %+v, %v", current, err)
	}
	if _, err := f.d.StateFor("home", current.Identity, oldPrivate.PublicKey(), proto.Negotiated{Legacy: true}); err == nil {
		t.Fatal("retired old key selected the new full publication")
	}
	fresh := open(newPrivate.PublicKey())
	defer fresh.CloseNow()
	if msg, err := read(fresh); err != nil || msg.Type != proto.MsgState || msg.State == nil || !msg.State.AgentDisabled {
		t.Fatalf("new published key did not receive State: %+v, %v", msg, err)
	}
}

func TestAuthenticatedOldStreamCannotClaimReregisteredName(t *testing.T) {
	f := newDisableFixture(t)
	srv := httptest.NewServer(f.d.hub)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	old, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + f.tokens["home"]}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer old.CloseNow()
	// Dial completes only after Authenticate and Accept. Keep the first pubkey
	// withheld while this registration is revoked and the name is reused.
	prior, err := f.st.AgentByName("home")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.d.Revoke("home"); err != nil {
		t.Fatal(err)
	}
	join, err := f.st.IssueJoinToken("home", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	newToken, _, _, err := f.d.Register(join, "home", "203.0.113.3")
	if err != nil {
		t.Fatal(err)
	}
	current, err := f.st.AgentByName("home")
	if err != nil || current.Identity == prior.Identity || current.PublicKey != "" {
		t.Fatalf("new registration precondition: %+v, %v", current, err)
	}
	oldPrivate, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	first, err := json.Marshal(proto.Message{Type: proto.MsgPublicKey, PublicKey: oldPrivate.PublicKey().String()})
	if err != nil {
		t.Fatal(err)
	}
	if err := old.Write(ctx, websocket.MessageText, first); err != nil {
		t.Fatal(err)
	}
	if _, payload, err := old.Read(ctx); err == nil {
		t.Fatalf("old authenticated stream received a message from new registration: %s", payload)
	}
	current, err = f.st.AgentByName("home")
	if err != nil || current.Identity == prior.Identity || current.PublicKey != "" {
		t.Fatalf("old stream changed new registration: %+v, %v", current, err)
	}
	if f.d.hub.Status("home").Connected {
		t.Fatal("old stream was installed for the new registration")
	}
	// The new token and its key still have a normal publication path.
	fresh, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + newToken}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.CloseNow()
	newPrivate, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	first, err = json.Marshal(proto.Message{Type: proto.MsgPublicKey, PublicKey: newPrivate.PublicKey().String()})
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.Write(ctx, websocket.MessageText, first); err != nil {
		t.Fatal(err)
	}
	_, payload, err := fresh.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var msg proto.Message
	if err := json.Unmarshal(payload, &msg); err != nil || msg.Type != proto.MsgState || msg.State == nil {
		t.Fatalf("new registration did not receive State: %+v, %v", msg, err)
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
	f.d.delivery.bound = false
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

// Binding the timeouts installs a new snapshot and marks it bound. The
// snapshot committed installed keeps its entries, so a holder of its pointer
// never sees the timeouts change under it. The bound snapshot differs only in
// the timeouts.
func TestBootstrapBindLeavesCommittedSnapshotUnchanged(t *testing.T) {
	f := newDisableFixture(t)
	f.d.delivery.mu.Lock()
	f.d.delivery.bound = false
	f.d.delivery.mu.Unlock()
	f.d.timeouts.Store(nil)
	f.d.mu.Lock()
	err := f.d.applyNFT(rulesOf(t, f.st))
	f.d.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	f.d.delivery.mu.RLock()
	committed := f.d.delivery.latest
	f.d.delivery.mu.RUnlock()
	saved := make(map[string]deliveryEntry, len(committed.entries))
	for name, e := range committed.entries {
		if e.state.WG.UDPTimeout != 0 || e.state.WG.UDPTimeoutStream != 0 {
			t.Fatalf("%s committed with timeouts before binding: %+v", name, e.state.WG)
		}
		saved[name] = e
	}
	if len(saved) != 2 {
		t.Fatalf("committed snapshot has %d entries, want 2", len(saved))
	}
	if _, err := f.d.bindDeliveryTimeouts(func() (linux.UDPTimeouts, error) {
		return linux.UDPTimeouts{Timeout: 7, TimeoutStream: 19}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(committed.entries, saved) {
		t.Fatalf("binding modified the committed snapshot: %+v", committed.entries)
	}
	f.d.delivery.mu.RLock()
	bound, isBound := f.d.delivery.latest, f.d.delivery.bound
	f.d.delivery.mu.RUnlock()
	if bound == committed || !isBound {
		t.Fatalf("bound snapshot not installed as latest and marked bound: committed=%p latest=%p bound=%v", committed, bound, isBound)
	}
	if bound.generation != committed.generation || len(bound.entries) != len(saved) {
		t.Fatalf("bound snapshot: generation %d entries %d, want %d and %d", bound.generation, len(bound.entries), committed.generation, len(saved))
	}
	for name, e := range saved {
		e.state.WG.UDPTimeout, e.state.WG.UDPTimeoutStream = 7, 19
		if got, ok := bound.entries[name]; !ok || !reflect.DeepEqual(got, e) {
			t.Fatalf("bound entry %s = %+v, want %+v", name, got, e)
		}
	}
}

// A successful Commit before the timeouts are bound replaces latest but does
// not make it servable: no State is selected, and the diagnostics report no
// published generation, until bootstrap binding succeeds.
func TestSuccessfulCommitBeforeBindingStaysUnservable(t *testing.T) {
	f := newDisableFixture(t)
	f.d.delivery.mu.Lock()
	f.d.delivery.bound = false
	f.d.delivery.mu.Unlock()
	f.d.timeouts.Store(nil)
	rules := rulesOf(t, f.st)
	rules[0].Target = "192.0.2.60:25565"
	if _, err := f.d.Batch(admin.BatchRequest{Upsert: []proto.Rule{rules[0]}}); err != nil {
		t.Fatal(err)
	}
	if st, err := f.d.AgentState("home"); err == nil {
		t.Fatalf("State escaped before timeout binding: %+v", st)
	}
	status, ok := f.d.ApplyStatus()
	if !ok || status.AgentStateGeneration != nil || status.AgentStatePending == nil || !*status.AgentStatePending {
		t.Fatalf("diagnostics before timeout binding: %+v, %v; want no generation and pending", status, ok)
	}
	if _, err := f.d.bindDeliveryTimeouts(func() (linux.UDPTimeouts, error) {
		return linux.UDPTimeouts{Timeout: 7, TimeoutStream: 19}, nil
	}); err != nil {
		t.Fatal(err)
	}
	st, err := f.d.AgentState("home")
	if err != nil || ruleTarget(st, "r_a") != rules[0].Target {
		t.Fatalf("bound State: %+v, %v", st, err)
	}
	status, ok = f.d.ApplyStatus()
	if !ok || status.AgentStateGeneration == nil || *status.AgentStateGeneration != st.Generation {
		t.Fatalf("diagnostics after timeout binding: %+v, %v; want generation %d", status, ok, st.Generation)
	}
}

// A successful Commit after the bind builds its snapshot with the bound
// timeouts, so every agent keeps receiving them once the bound snapshot is
// replaced.
func TestCommitAfterBindingCarriesTimeouts(t *testing.T) {
	f := newDisableFixture(t)
	f.d.delivery.mu.Lock()
	f.d.delivery.bound = false
	f.d.delivery.mu.Unlock()
	f.d.timeouts.Store(nil)
	if _, err := f.d.bindDeliveryTimeouts(func() (linux.UDPTimeouts, error) {
		return linux.UDPTimeouts{Timeout: 7, TimeoutStream: 19}, nil
	}); err != nil {
		t.Fatal(err)
	}
	before, err := f.d.AgentState("home")
	if err != nil {
		t.Fatal(err)
	}
	rules := rulesOf(t, f.st)
	rules[0].Target = "192.0.2.70:25565"
	if _, err := f.d.Batch(admin.BatchRequest{Upsert: []proto.Rule{rules[0]}}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"home", "other"} {
		st, err := f.d.AgentState(name)
		if err != nil || st.Generation <= before.Generation || st.WG.UDPTimeout != 7 || st.WG.UDPTimeoutStream != 19 {
			t.Fatalf("%s State after a Commit following the bind: %+v, %v; want generation above %d and timeouts 7 and 19", name, st, err, before.Generation)
		}
		if name == "home" && ruleTarget(st, "r_a") != rules[0].Target {
			t.Fatalf("home State does not carry the committed target: %+v", st)
		}
	}
}

func TestBootstrapReadSerializesWithAdminApply(t *testing.T) {
	f := newDisableFixture(t)
	f.d.delivery.mu.Lock()
	f.d.delivery.bound = false
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
	f.d.delivery.bound = false
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

// Without a successful publication, binding fails before it stores the
// timeouts or marks anything bound: the timeouts stay unset and no State is
// served.
func TestBootstrapBindWithoutPublicationStoresNoTimeouts(t *testing.T) {
	f := newDisableFixture(t)
	f.d.delivery.mu.Lock()
	f.d.delivery.latest = nil
	f.d.delivery.bound = false
	f.d.delivery.mu.Unlock()
	f.d.timeouts.Store(nil)
	_, err := f.d.bindDeliveryTimeouts(func() (linux.UDPTimeouts, error) {
		return linux.UDPTimeouts{Timeout: 7, TimeoutStream: 19}, nil
	})
	if err == nil || f.d.timeouts.Load() != nil {
		t.Fatalf("bind without a publication = %v, timeouts = %+v", err, f.d.timeouts.Load())
	}
	if generation, _ := f.d.delivery.status(); generation != nil {
		t.Fatalf("bind without a publication marked generation %d bound", *generation)
	}
}

// The bootstrap read runs under Daemon.mu.
func TestBootstrapReadHoldsDaemonLock(t *testing.T) {
	f := newDisableFixture(t)
	held := false
	if _, err := f.d.bindDeliveryTimeouts(func() (linux.UDPTimeouts, error) {
		if f.d.mu.TryLock() {
			f.d.mu.Unlock()
		} else {
			held = true
		}
		return linux.UDPTimeouts{Timeout: 7, TimeoutStream: 19}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if !held {
		t.Fatal("the timeout read ran without Daemon.mu")
	}
}

// The bind, and with it the store of the timeouts, runs under Daemon.mu, so
// no apply can build a candidate between the read and the bind. The read
// takes deliveryOwner.mu, which keeps the bind from finishing; while it is
// held, Daemon.mu must stay held. The test cannot reach publish, a closure
// inside bindDeliveryTimeouts, so it checks Daemon.mu while the bind waits.
func TestBootstrapBindHoldsDaemonLock(t *testing.T) {
	f := newDisableFixture(t)
	released := make(chan bool, 1)
	_, err := f.d.bindDeliveryTimeouts(func() (linux.UDPTimeouts, error) {
		f.d.delivery.mu.Lock()
		go func() {
			defer f.d.delivery.mu.Unlock()
			for deadline := time.Now().Add(200 * time.Millisecond); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
				if f.d.mu.TryLock() {
					f.d.mu.Unlock()
					released <- true
					return
				}
			}
			released <- false
		}()
		return linux.UDPTimeouts{Timeout: 7, TimeoutStream: 19}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if <-released {
		t.Fatal("Daemon.mu was released before the bind finished")
	}
	if got := f.d.timeouts.Load(); got == nil || got.Timeout != 7 || got.TimeoutStream != 19 {
		t.Fatalf("timeouts after the bind = %+v", got)
	}
}

// bind calls publish under deliveryOwner.mu after it has installed the
// snapshot with the timeouts and before it marks latest bound, so no
// selection sees latest bound before the caller has stored the timeouts.
func TestDeliveryOwnerBindPublishesBeforeMarkingBound(t *testing.T) {
	committed := &deliverySnapshot{entries: map[string]deliveryEntry{"home": {identity: "i", key: "k"}}, generation: 3}
	o := &deliveryOwner{latest: committed}
	called := false
	err := o.bind(linux.UDPTimeouts{Timeout: 7, TimeoutStream: 19}, func() {
		called = true
		if o.mu.TryRLock() {
			o.mu.RUnlock()
			t.Error("publish ran without deliveryOwner.mu")
		}
		if o.bound {
			t.Error("latest was marked bound before publish")
		}
		if e := o.latest.entries["home"]; o.latest == committed || e.state.WG.UDPTimeout != 7 || e.state.WG.UDPTimeoutStream != 19 {
			t.Errorf("snapshot with the timeouts not installed before publish: %+v", o.latest)
		}
	})
	if err != nil || !called || !o.bound || o.latest.generation != committed.generation {
		t.Fatalf("bind = %v, publish called %v, bound %v, generation %d", err, called, o.bound, o.latest.generation)
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

// The disable overlay decides both what committed compares and what state
// delivers. The two must agree for every agent, or a commit that changes
// nothing the agent receives is reported as a change, or the reverse.
func TestOverlayAgreesBetweenStateAndEffectiveDelivery(t *testing.T) {
	rules := func(ids ...string) []proto.AgentRule {
		out := make([]proto.AgentRule, 0, len(ids))
		for _, id := range ids {
			out = append(out, proto.AgentRule{ID: id, Proto: proto.TCP, Target: "192.0.2.10:25565", Enabled: true})
		}
		return out
	}
	entry := func(identity, key string, gen uint64, ids ...string) deliveryEntry {
		return deliveryEntry{identity: identity, key: key, state: proto.State{Generation: gen, Rules: rules(ids...)}}
	}
	cases := []struct {
		name     string
		entries  map[string]deliveryEntry
		disabled map[string]disableOverlay
	}{
		{
			name: "overlay generation above the snapshot",
			entries: map[string]deliveryEntry{
				"home":   entry("id-home", "key-home", 5, "r_a", "r_b"),
				"other":  entry("id-other", "key-other", 5, "r_c"),
				"stale":  entry("id-stale-new", "key-stale", 5, "r_d"),
				"plain":  entry("id-plain", "key-plain", 5, "r_e"),
				"norule": entry("id-norule", "key-norule", 5),
			},
			disabled: map[string]disableOverlay{
				"home":   {identity: "id-home", generation: 7},
				"other":  {identity: "id-other", generation: 9},
				"stale":  {identity: "id-stale-old", generation: 8},
				"norule": {identity: "id-norule", generation: 6},
				"gone":   {identity: "id-gone", generation: 4},
			},
		},
		{
			name: "overlay generation below the snapshot",
			entries: map[string]deliveryEntry{
				"home":  entry("id-home", "key-home", 12, "r_a"),
				"other": entry("id-other", "key-other", 12, "r_c"),
				"stale": entry("id-stale-new", "key-stale", 12, "r_d"),
			},
			disabled: map[string]disableOverlay{
				"home":  {identity: "id-home", generation: 10},
				"stale": {identity: "id-stale-old", generation: 11},
			},
		},
		{
			name: "no overlay",
			entries: map[string]deliveryEntry{
				"home":  entry("id-home", "key-home", 3, "r_a"),
				"other": entry("id-other", "key-other", 3, "r_c"),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := &deliverySnapshot{entries: tc.entries, generation: tc.entries["home"].state.Generation}
			o := &deliveryOwner{latest: snap, bound: true, disabled: tc.disabled}
			original := make(map[string]deliveryEntry, len(tc.entries))
			for name, e := range tc.entries {
				e.state.Rules = append([]proto.AgentRule{}, e.state.Rules...)
				original[name] = e
			}
			want := effectiveDelivery(snap, tc.disabled)
			if len(want) != len(tc.entries) {
				t.Fatalf("effectiveDelivery returned %d agents, want %d", len(want), len(tc.entries))
			}
			disabledSeen := 0
			for name, e := range tc.entries {
				for _, key := range []*string{&e.key, nil} {
					got, err := o.state(name, e.identity, key)
					if err != nil {
						t.Fatalf("%s: state: %v", name, err)
					}
					if !reflect.DeepEqual(*got, want[name].state) {
						t.Fatalf("%s: state and effectiveDelivery disagree:\nstate     %+v\neffective %+v", name, *got, want[name].state)
					}
				}
				if want[name].state.AgentDisabled {
					disabledSeen++
				}
			}
			if !reflect.DeepEqual(snap.entries, original) {
				t.Fatal("the overlay modified the published snapshot")
			}
			// Guard against a vacuous pass: the overlay must have acted where
			// the case expects it to.
			for name, ov := range tc.disabled {
				e, ok := tc.entries[name]
				if !ok {
					continue
				}
				if (ov.identity == e.identity) != want[name].state.AgentDisabled {
					t.Fatalf("%s: AgentDisabled = %v with overlay identity %q and entry identity %q", name, want[name].state.AgentDisabled, ov.identity, e.identity)
				}
			}
			if len(tc.disabled) > 0 && disabledSeen == 0 {
				t.Fatal("no agent was disabled by the overlay")
			}
			wantGen := snap.generation
			for _, ov := range tc.disabled {
				wantGen = max(wantGen, ov.generation)
			}
			for name := range tc.entries {
				if want[name].state.Generation != wantGen {
					t.Fatalf("%s: generation %d, want %d", name, want[name].state.Generation, wantGen)
				}
			}
		})
	}
}
