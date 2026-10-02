//go:build linux

package vpsd

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/stream"
	"github.com/rahanahu/wgft/proto"
)

// The bucket passes keyChangeBurst changes in a row, then one per keyChangeEvery, and refills up to
// keyChangeBurst. Registrations do not share a bucket, and a new registration of the same name
// starts full.
func TestKeyChangeLimiterBucket(t *testing.T) {
	// The values are design.md 5.2 節's; changing them is a design change.
	if keyChangeBurst != 3 || keyChangeEvery != 10*time.Minute {
		t.Fatalf("limit = %d then one per %s, want design.md 5.2 節's 3 then one per 10m", keyChangeBurst, keyChangeEvery)
	}
	var l keyChangeLimiter
	t0 := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	for i := 0; i < keyChangeBurst; i++ {
		if !l.allow("home", "id1", t0) {
			t.Fatalf("change %d of the burst was refused", i+1)
		}
	}
	if l.allow("home", "id1", t0) {
		t.Fatal("a change past the burst was allowed")
	}
	if l.allow("home", "id1", t0.Add(keyChangeEvery-time.Second)) {
		t.Fatal("a change was allowed before one interval passed")
	}
	if !l.allow("home", "id1", t0.Add(keyChangeEvery)) {
		t.Fatal("a change was refused after one interval")
	}
	if l.allow("home", "id1", t0.Add(keyChangeEvery)) {
		t.Fatal("one interval gave more than one change")
	}
	if !l.allow("home", "id2", t0) || !l.allow("other", "id3", t0) {
		t.Fatal("another registration shared the exhausted bucket")
	}
	later := t0.Add(time.Duration(keyChangeBurst+5) * keyChangeEvery)
	for i := 0; i < keyChangeBurst; i++ {
		if !l.allow("home", "id1", later) {
			t.Fatalf("change %d after a long pause was refused", i+1)
		}
	}
	if l.allow("home", "id1", later) {
		t.Fatal("a long pause refilled past the burst")
	}
}

// Full buckets are dropped, so the table only holds registrations that changed keys lately.
func TestKeyChangeLimiterDropsFullBuckets(t *testing.T) {
	var l keyChangeLimiter
	t0 := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	l.allow("a", "1", t0)
	l.allow("b", "2", t0)
	l.allow("c", "3", t0.Add(time.Duration(keyChangeBurst)*keyChangeEvery))
	if len(l.byReg) != 1 {
		t.Fatalf("buckets kept = %d, want only the one used last", len(l.byReg))
	}
}

func newKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey()
}

func (f *disableFixture) commitCount() int {
	f.p.mu.Lock()
	defer f.p.mu.Unlock()
	return f.p.commits
}

func (f *disableFixture) savedKey(t *testing.T, name string) string {
	t.Helper()
	a, err := f.st.AgentByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return a.PublicKey
}

// SetPublicKey limits only the declarations that change a saved key (design.md 5.2 節). The first
// declaration and a reconnect with the saved key take no change, alternating two keys takes one
// change each, and a refused change saves nothing, publishes nothing and returns
// stream.ErrKeyChangeLimited, while a reconnect with the saved key still passes.
func TestSetPublicKeyLimitsKeyChanges(t *testing.T) {
	f := newDisableFixture(t)
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	f.d.clock = func() time.Time { return now }
	home, err := f.st.AgentByName("home")
	if err != nil {
		t.Fatal(err)
	}
	k0, k1 := newKey(t), newKey(t)

	if err := f.d.SetPublicKey("home", home.Identity, k0); err != nil {
		t.Fatalf("first declaration: %v", err)
	}
	commits := f.commitCount()
	for i := 0; i < 3; i++ {
		if err := f.d.SetPublicKey("home", home.Identity, k0); err != nil {
			t.Fatalf("reconnect with the saved key: %v", err)
		}
	}
	if f.commitCount() != commits {
		t.Fatal("a reconnect with the saved key published")
	}
	// Alternating two keys: each declaration changes the saved key.
	for i, k := range []wgtypes.Key{k1, k0, k1} {
		if err := f.d.SetPublicKey("home", home.Identity, k); err != nil {
			t.Fatalf("change %d within the burst: %v (the first declaration or reconnects were counted?)", i+1, err)
		}
		if f.commitCount() != commits+i+1 {
			t.Fatalf("change %d did not publish once", i+1)
		}
	}
	err = f.d.SetPublicKey("home", home.Identity, k0)
	if !errors.Is(err, stream.ErrKeyChangeLimited) {
		t.Fatalf("change past the burst: %v, want ErrKeyChangeLimited", err)
	}
	if f.commitCount() != commits+3 {
		t.Fatal("a refused change published")
	}
	if got := f.savedKey(t, "home"); got != k1.String() {
		t.Fatalf("saved key after a refused change = %s, want the last allowed key", got)
	}
	if _, err := f.d.StateFor("home", home.Identity, k1, proto.Negotiated{Legacy: true}); err != nil {
		t.Fatalf("the published key lost its State after a refused change: %v", err)
	}
	if err := f.d.SetPublicKey("home", home.Identity, k1); err != nil {
		t.Fatalf("reconnect with the saved key while limited: %v", err)
	}
	// Another agent's first declaration and changes are not limited by home's bucket.
	other, err := f.st.AgentByName("other")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.d.SetPublicKey("other", other.Identity, newKey(t)); err != nil {
		t.Fatalf("other's first declaration: %v", err)
	}
	if err := f.d.SetPublicKey("other", other.Identity, newKey(t)); err != nil {
		t.Fatalf("other's change: %v", err)
	}
	now = now.Add(keyChangeEvery)
	if err := f.d.SetPublicKey("home", home.Identity, k0); err != nil {
		t.Fatalf("change after one interval: %v", err)
	}
	if got := f.savedKey(t, "home"); got != k0.String() {
		t.Fatalf("saved key = %s, want the key allowed after the interval", got)
	}
}

// A change whose apply fails is counted, since a failed apply may still replace the table. The
// recovery paths are not: a reconnect with the saved but unpublished key, and a reconnect with the
// last published key, pass even with the bucket empty, and the retry publishes the saved key.
func TestFailedKeyChangeCountsAndRecoveryIsFree(t *testing.T) {
	f := newDisableFixture(t)
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	f.d.clock = func() time.Time { return now }
	home, err := f.st.AgentByName("home")
	if err != nil {
		t.Fatal(err)
	}
	k0 := newKey(t)
	if err := f.d.SetPublicKey("home", home.Identity, k0); err != nil {
		t.Fatal(err)
	}
	// Two successful changes, then one whose apply fails: the bucket is empty.
	last := k0
	for i := 0; i < 2; i++ {
		last = newKey(t)
		if err := f.d.SetPublicKey("home", home.Identity, last); err != nil {
			t.Fatal(err)
		}
	}
	saved := newKey(t)
	f.p.setErr(errors.New("publication failed"))
	err = f.d.SetPublicKey("home", home.Identity, saved)
	if err == nil || errors.Is(err, stream.ErrKeyChangeLimited) {
		t.Fatalf("change with a failing apply: %v, want the apply error", err)
	}
	if err := f.d.SetPublicKey("home", home.Identity, newKey(t)); !errors.Is(err, stream.ErrKeyChangeLimited) {
		t.Fatalf("a change after the failed one: %v, want ErrKeyChangeLimited (the failed change was not counted?)", err)
	}
	if err := f.d.SetPublicKey("home", home.Identity, saved); err != nil {
		t.Fatalf("reconnect with the saved unpublished key: %v", err)
	}
	if err := f.d.SetPublicKey("home", home.Identity, last); err != nil {
		t.Fatalf("reconnect with the last published key: %v", err)
	}
	if got := f.savedKey(t, "home"); got != saved.String() {
		t.Fatalf("saved key = %s, want the unpublished new key kept", got)
	}
	f.p.setErr(nil)
	if _, err := f.d.Batch(admin.BatchRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.StateFor("home", home.Identity, saved, proto.Negotiated{Legacy: true}); err != nil {
		t.Fatalf("the retry did not publish the saved key: %v", err)
	}
}

// A new registration of the same name starts with a full bucket: its first declaration is free and
// its changes are not limited by the revoked registration's.
func TestReregistrationStartsANewKeyChangeBucket(t *testing.T) {
	f := newDisableFixture(t)
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	f.d.clock = func() time.Time { return now }
	home, err := f.st.AgentByName("home")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.d.SetPublicKey("home", home.Identity, newKey(t)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < keyChangeBurst; i++ {
		if err := f.d.SetPublicKey("home", home.Identity, newKey(t)); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.d.SetPublicKey("home", home.Identity, newKey(t)); !errors.Is(err, stream.ErrKeyChangeLimited) {
		t.Fatalf("want the old registration limited, got %v", err)
	}
	if err := f.d.Revoke("home"); err != nil {
		t.Fatal(err)
	}
	reregister(t, f, "home")
	again, err := f.st.AgentByName("home")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.d.SetPublicKey("home", again.Identity, newKey(t)); err != nil {
		t.Fatalf("first declaration of the new registration: %v", err)
	}
	for i := 0; i < keyChangeBurst; i++ {
		if err := f.d.SetPublicKey("home", again.Identity, newKey(t)); err != nil {
			t.Fatalf("change %d of the new registration: %v", i+1, err)
		}
	}
}

// A key declaration delivers only to the declaring agent; a rule change, which moves the shared
// generation, still delivers to every agent (design.md 5.2 節).
func TestKeyDeclarationDeliversOnlyToTheDeclaringAgent(t *testing.T) {
	f := newDisableFixture(t)
	var pushed [][]string
	f.d.onPush = func(names []string) { pushed = append(pushed, append([]string(nil), names...)) }
	home, err := f.st.AgentByName("home")
	if err != nil {
		t.Fatal(err)
	}
	other, err := f.st.AgentByName("other")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.d.SetPublicKey("other", other.Identity, newKey(t)); err != nil {
		t.Fatal(err)
	}
	for _, k := range []wgtypes.Key{newKey(t), newKey(t)} {
		if err := f.d.SetPublicKey("home", home.Identity, k); err != nil {
			t.Fatal(err)
		}
	}
	want := [][]string{{"other"}, {"home"}, {"home"}}
	if !equalPushes(pushed, want) {
		t.Fatalf("pushes after key declarations = %v, want %v", pushed, want)
	}
	pushed = nil
	rules := rulesOf(t, f.st)
	rules[0].Target = "192.0.2.10:25565" // r_a belongs to home
	if _, err := f.d.Batch(admin.BatchRequest{Upsert: []proto.Rule{rules[0]}}); err != nil {
		t.Fatal(err)
	}
	if !equalPushes(pushed, [][]string{{"home", "other"}}) {
		t.Fatalf("pushes after a rule change = %v, want both agents", pushed)
	}
	pushed = nil
	if _, err := f.d.Batch(admin.BatchRequest{}); err != nil {
		t.Fatal(err)
	}
	if len(pushed) != 0 {
		t.Fatalf("an apply with nothing new pushed %v", pushed)
	}
}

func equalPushes(got, want [][]string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if len(got[i]) != len(want[i]) {
			return false
		}
		for j := range got[i] {
			if got[i][j] != want[i][j] {
				return false
			}
		}
	}
	return true
}

func reregister(t *testing.T, f *disableFixture, name string) {
	t.Helper()
	token, err := f.st.IssueJoinToken(name, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.st.Register(token, name, "203.0.113.3", netip.MustParsePrefix("10.200.0.0/24")); err != nil {
		t.Fatal(err)
	}
}

// Through the real stream hub: home alternates two keys over fresh streams. The changes within the
// burst connect and get a State; the next is closed with 1008 and leaves home's saved key alone.
// Meanwhile the other agent's established stream receives nothing from home's key changes: its
// next message is the following rule change.
func TestAlternatingKeysOverTheStream(t *testing.T) {
	f := newDisableFixture(t)
	f.d.onPushAll, f.d.onPush = nil, nil
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	f.d.clock = func() time.Time { return now }
	srv := httptest.NewServer(f.d.hub)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	open := func(agent string, key wgtypes.Key) *websocket.Conn {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ws, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
			HTTPHeader: http.Header{"Authorization": {"Bearer " + f.tokens[agent]}},
		})
		if err != nil {
			t.Fatal(err)
		}
		msg, _ := json.Marshal(proto.Message{Type: proto.MsgPublicKey, PublicKey: key.String()})
		if err := ws.Write(ctx, websocket.MessageText, msg); err != nil {
			t.Fatal(err)
		}
		return ws
	}
	read := func(ws *websocket.Conn, wait time.Duration) (proto.Message, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), wait)
		defer cancel()
		_, data, err := ws.Read(ctx)
		if err != nil {
			return proto.Message{}, err
		}
		var msg proto.Message
		return msg, json.Unmarshal(data, &msg)
	}
	other := open("other", newKey(t))
	defer other.CloseNow()
	if msg, err := read(other, 5*time.Second); err != nil || msg.Type != proto.MsgState {
		t.Fatalf("other's first State: %+v, %v", msg, err)
	}
	k0, k1 := newKey(t), newKey(t)
	keys := []wgtypes.Key{k0, k1, k0, k1}
	for i, k := range keys {
		ws := open("home", k)
		msg, err := read(ws, 5*time.Second)
		if err != nil || msg.Type != proto.MsgState {
			t.Fatalf("home declaration %d: %+v, %v", i, msg, err)
		}
		ws.CloseNow()
	}
	ws := open("home", k0)
	_, err := read(ws, 5*time.Second)
	ws.CloseNow()
	if websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("change past the burst: %v, want close 1008", err)
	}
	if got := f.savedKey(t, "home"); got != k1.String() {
		t.Fatalf("saved key = %s, want the last allowed key", got)
	}
	// A read with a deadline would close the stream, so other's next message is checked instead: it
	// must be the rule change below, not a State queued by one of home's key changes. The pause gives
	// such a State time to be written before the rule change.
	time.Sleep(200 * time.Millisecond)
	rules := rulesOf(t, f.st)
	rules[3].Target = "192.168.2.21:3000" // r_o belongs to other
	if _, err := f.d.Batch(admin.BatchRequest{Upsert: []proto.Rule{rules[3]}}); err != nil {
		t.Fatal(err)
	}
	if msg, err := read(other, 5*time.Second); err != nil || msg.Type != proto.MsgState || ruleTarget(msg.State, "r_o") != rules[3].Target {
		t.Fatalf("other's next message is not the rule change: %+v, %v", msg.State, err)
	}
}

// The agent list carries the hub's refusal record (design.md 5.2 and 7a.11 節): key_change_refused_at
// appears for the refused agent only, stays while it makes no further accepted declaration, and is
// gone once a change comes back and its key is accepted.
func TestAgentsReportKeyChangeRefusal(t *testing.T) {
	f := newDisableFixture(t)
	f.d.onPushAll, f.d.onPush = nil, nil
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	f.d.clock = func() time.Time { return now }
	srv := httptest.NewServer(f.d.hub)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	declare := func(agent string, key wgtypes.Key) error {
		t.Helper()
		return declareKey(t, url, f.tokens[agent], key)
	}
	refusedAt := func(agent string) string {
		t.Helper()
		list, err := f.d.Agents()
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range list {
			if a.Name == agent {
				return a.KeyChangeRefusedAt
			}
		}
		t.Fatalf("no agent %s", agent)
		return ""
	}

	if err := declare("other", newKey(t)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if err := declare("home", newKey(t)); err != nil {
			t.Fatalf("home declaration %d: %v", i, err)
		}
	}
	if got := refusedAt("home"); got != "" {
		t.Fatalf("never refused: key_change_refused_at = %q", got)
	}
	pending := newKey(t)
	for i := 0; i < 2; i++ {
		if err := declare("home", pending); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
			t.Fatalf("over the limit, attempt %d: %v, want 1008", i, err)
		}
	}
	got := refusedAt("home")
	if _, err := time.Parse(time.RFC3339, got); err != nil {
		t.Fatalf("refused: key_change_refused_at = %q, want an RFC3339 time", got)
	}
	if got := refusedAt("other"); got != "" {
		t.Fatalf("another agent: key_change_refused_at = %q, want none", got)
	}
	now = now.Add(10 * time.Minute)
	if err := declare("home", pending); err != nil {
		t.Fatalf("after a change came back: %v", err)
	}
	if got := refusedAt("home"); got != "" {
		t.Fatalf("accepted since: key_change_refused_at = %q, want none", got)
	}
}

// declareKey opens a stream with token, declares key and returns nil when a State comes back, or the
// error the read ended with.
func declareKey(t *testing.T, url, token string, key wgtypes.Key) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + token}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	msg, _ := json.Marshal(proto.Message{Type: proto.MsgPublicKey, PublicKey: key.String()})
	if err := ws.Write(ctx, websocket.MessageText, msg); err != nil {
		t.Fatal(err)
	}
	_, data, err := ws.Read(ctx)
	if err != nil {
		return err
	}
	var m proto.Message
	if err := json.Unmarshal(data, &m); err != nil || m.Type != proto.MsgState {
		t.Fatalf("declaration: %s, %v", data, err)
	}
	return nil
}

// A refusal recorded for a registration that has since been revoked is not reported for the name's
// next registration (design.md 5.2 節). Revoke drops the hub's state, but a refusal written between
// the limit check and that drop can outlive it; the store's revoke here, without the hub's drop,
// leaves the hub in that state.
func TestAgentsIgnoreARefusalOfAnotherRegistration(t *testing.T) {
	f := newDisableFixture(t)
	f.d.onPushAll, f.d.onPush = nil, nil
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	f.d.clock = func() time.Time { return now }
	srv := httptest.NewServer(f.d.hub)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	for i := 0; i < 4; i++ {
		if err := declareKey(t, url, f.tokens["home"], newKey(t)); err != nil {
			t.Fatalf("home declaration %d: %v", i, err)
		}
	}
	if err := declareKey(t, url, f.tokens["home"], newKey(t)); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("over the limit: %v, want 1008", err)
	}
	if st := f.d.hub.Status("home"); st.KeyChangeRefusedAt.IsZero() {
		t.Fatal("the refusal was not recorded")
	}
	if err := f.st.RevokeAgent("home"); err != nil {
		t.Fatal(err)
	}
	tok, err := f.st.IssueJoinToken("home", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.st.Register(tok, "home", "203.0.113.2", netip.MustParsePrefix("10.200.0.0/24")); err != nil {
		t.Fatal(err)
	}
	list, err := f.d.Agents()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range list {
		if a.Name == "home" && a.KeyChangeRefusedAt != "" {
			t.Fatalf("the new registration shows the old registration's refusal: %q", a.KeyChangeRefusedAt)
		}
	}
}
