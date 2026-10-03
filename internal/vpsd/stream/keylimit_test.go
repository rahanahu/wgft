package stream

import (
	"errors"
	"fmt"
	"log"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/proto"
)

// A key change refused by the backend's rate limit (design.md 5.2 節) closes the new stream with
// 1008, the code agents already treat as a refused public key, and leaves the established stream of
// the same agent in place. Any other SetPublicKey failure stays an internal error (1011), so an
// agent backs off from a server fault the way it always did.
func TestKeyChangeLimitClosesWithPolicyViolation(t *testing.T) {
	server, _ := wgtypes.GeneratePrivateKey()
	b := &fakeBackend{server: server, keys: map[string]wgtypes.Key{}, gen: 1}
	h := New(b)
	srv := httptest.NewServer(h)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")

	var buf syncBuffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	k0, _ := wgtypes.GeneratePrivateKey()
	old, _, err := dial(t, url, "tok-home")
	if err != nil {
		t.Fatal(err)
	}
	defer old.CloseNow()
	sendJSON(t, old, proto.Message{Type: proto.MsgPublicKey, PublicKey: k0.PublicKey().String()})
	if m, err := readMsg(t, old); err != nil || m.Type != proto.MsgState {
		t.Fatalf("first stream: %+v, %v", m, err)
	}

	for _, tc := range []struct {
		name   string
		err    error
		status websocket.StatusCode
		reason string
	}{
		{"rate limited", fmt.Errorf("agent %q: %w", "home", ErrKeyChangeLimited), websocket.StatusPolicyViolation, "limited"},
		{"other failure", errBackendFailure, websocket.StatusInternalError, "peer setup failed"},
	} {
		b.mu.Lock()
		b.setKeyErr = tc.err
		b.mu.Unlock()
		k1, _ := wgtypes.GeneratePrivateKey()
		c, _, err := dial(t, url, "tok-home")
		if err != nil {
			t.Fatal(err)
		}
		sendJSON(t, c, proto.Message{Type: proto.MsgPublicKey, PublicKey: k1.PublicKey().String()})
		_, err = readMsg(t, c)
		c.CloseNow()
		var ce websocket.CloseError
		if websocket.CloseStatus(err) != tc.status || !errors.As(err, &ce) || !strings.Contains(ce.Reason, tc.reason) {
			t.Errorf("%s: close = %v, want status %d with a reason containing %q", tc.name, err, tc.status, tc.reason)
		}
		if st := h.Status("home"); !st.Connected {
			t.Errorf("%s: the refused key change displaced the established stream", tc.name)
		}
	}
	b.mu.Lock()
	saved := b.keys["home"]
	b.mu.Unlock()
	if saved != k0.PublicKey() {
		t.Error("a refused key change was saved")
	}
	if !strings.Contains(buf.String(), "refusing a public key change") {
		t.Errorf("the refusal was not logged: %q", buf.String())
	}
}

// The refusal line is limited to one a minute: a token holder retrying the change cannot flood
// the server log.
func TestKeyChangeLimitLogIsRateLimited(t *testing.T) {
	server, _ := wgtypes.GeneratePrivateKey()
	b := &fakeBackend{server: server, keys: map[string]wgtypes.Key{}, gen: 1,
		setKeyErr: fmt.Errorf("agent %q: %w", "home", ErrKeyChangeLimited)}
	h := New(b)
	srv := httptest.NewServer(h)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")

	var buf syncBuffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	for i := 0; i < 3; i++ {
		waitNoPending(t, h, "home")
		k, _ := wgtypes.GeneratePrivateKey()
		c, _, err := dial(t, url, "tok-home")
		if err != nil {
			t.Fatal(err)
		}
		sendJSON(t, c, proto.Message{Type: proto.MsgPublicKey, PublicKey: k.PublicKey().String()})
		if _, err := readMsg(t, c); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
			t.Fatalf("attempt %d: %v, want 1008", i, err)
		}
		c.CloseNow()
	}
	if n := strings.Count(buf.String(), "refusing a public key change"); n != 1 {
		t.Errorf("refusal lines = %d over 3 attempts within a minute, want 1", n)
	}
}

// declare opens a stream for agent with a new key and returns how the server answered: the State
// message, or the close error. It first waits until no earlier stream of the agent holds a slot of
// the per-agent limit on streams not yet established (maxPendingPerAgent), so that the new stream
// is not turned away with 429 by a slot the server returns only after its side of the previous
// close has finished, which can come after the client has read the close.
func declare(t *testing.T, h *Hub, url, agent string) (proto.Message, error) {
	t.Helper()
	waitNoPending(t, h, agent)
	k, _ := wgtypes.GeneratePrivateKey()
	c, _, err := dial(t, url, "tok-"+agent)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.CloseNow() })
	sendJSON(t, c, proto.Message{Type: proto.MsgPublicKey, PublicKey: k.PublicKey().String()})
	return readMsg(t, c)
}

// waitNoPending polls the hub until agent holds no slot of the per-agent limit on streams not yet
// established.
func waitNoPending(t *testing.T, h *Hub, agent string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		h.mu.Lock()
		n := h.pending[agent]
		h.mu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d slots for streams not yet established were never returned", agent, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitStatus polls h.Status(agent) until ok returns true.
func waitStatus(t *testing.T, h *Hub, agent string, ok func(Status) bool) Status {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		st := h.Status(agent)
		if ok(st) {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("status of %s never reached the expected state: %+v", agent, st)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The hub records when it last refused an agent's key change by the limit, and only an accepted key
// declaration or connection clears that record (design.md 5.2 節). The record is a past event: it
// stays while the agent is disconnected and makes no further attempt, and it never appears for an
// agent that was not refused.
func TestKeyChangeRefusalRecord(t *testing.T) {
	server, _ := wgtypes.GeneratePrivateKey()
	b := &fakeBackend{server: server, keys: map[string]wgtypes.Key{}, gen: 1}
	h := New(b)
	srv := httptest.NewServer(h)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	limited := fmt.Errorf("agent %q: %w", "home", ErrKeyChangeLimited)
	setErrs := func(key, state error) {
		b.mu.Lock()
		b.setKeyErr, b.stateErr = key, state
		b.mu.Unlock()
	}

	// Never refused: no record. The established stream is opened directly, not by replacing another
	// one: a replaced stream whose client does not answer the close keeps a slot of the per-agent
	// limit taken until the WebSocket library gives up the close handshake, which is longer than this
	// test runs (TestReplacedStreamHoldsPendingSlot).
	k0, _ := wgtypes.GeneratePrivateKey()
	old := establishStream(t, url, "tok-home", k0)
	if st := h.Status("home"); !st.Connected || !st.KeyChangeRefusedAt.IsZero() {
		t.Fatalf("never refused: %+v", st)
	}

	// Refused while the established stream is up: recorded, the stream stays.
	setErrs(limited, nil)
	before := time.Now()
	if _, err := declare(t, h, url, "home"); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("over the limit: %v, want 1008", err)
	}
	st := h.Status("home")
	if !st.Connected || st.KeyChangeRefusedAt.Before(before) || st.KeyChangeRefusedBy != "tok-home" {
		t.Fatalf("refused while connected: %+v", st)
	}
	refusedAt := st.KeyChangeRefusedAt

	// The established stream drops: the record stays, as a past event with its time.
	old.CloseNow()
	st = waitStatus(t, h, "home", func(s Status) bool { return !s.Connected })
	if !st.KeyChangeRefusedAt.Equal(refusedAt) {
		t.Fatalf("after the drop the record is %v, want %v", st.KeyChangeRefusedAt, refusedAt)
	}

	// Another failure that is not the limit does not clear it.
	setErrs(errBackendFailure, nil)
	if _, err := declare(t, h, url, "home"); websocket.CloseStatus(err) != websocket.StatusInternalError {
		t.Fatalf("backend failure: %v, want 1011", err)
	}
	if st := h.Status("home"); !st.KeyChangeRefusedAt.Equal(refusedAt) {
		t.Fatalf("a 1011 failure changed the record: %+v", st)
	}

	// An accepted key whose connection is then turned away clears it: the key itself was accepted.
	setErrs(nil, errBackendFailure)
	if _, err := declare(t, h, url, "home"); err == nil {
		t.Fatal("the connection was not turned away")
	}
	if st := h.Status("home"); !st.KeyChangeRefusedAt.IsZero() {
		t.Fatalf("an accepted key left the record: %+v", st)
	}

	// Refused again, then accepted with a connection: cleared.
	setErrs(limited, nil)
	if _, err := declare(t, h, url, "home"); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("over the limit again: %v, want 1008", err)
	}
	if st := h.Status("home"); st.Connected || st.KeyChangeRefusedAt.IsZero() {
		t.Fatalf("refused while disconnected: %+v", st)
	}
	setErrs(nil, nil)
	if m, err := declare(t, h, url, "home"); err != nil || m.Type != proto.MsgState {
		t.Fatalf("accepted declaration: %+v, %v", m, err)
	}
	if st := h.Status("home"); !st.Connected || !st.KeyChangeRefusedAt.IsZero() || st.KeyChangeRefusedBy != "" {
		t.Fatalf("accepted since: %+v", st)
	}

	// An agent that never had a status entry gets one holding only the record.
	setErrs(limited, nil)
	if _, err := declare(t, h, url, "other"); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("other agent: %v, want 1008", err)
	}
	if st := h.Status("other"); st.Connected || st.KeyChangeRefusedAt.IsZero() {
		t.Fatalf("refused agent without a stream: %+v", st)
	}
}

// The refusal line is gated per agent: one agent's line within the minute does not hide another
// agent's.
func TestKeyChangeLimitLogIsPerAgent(t *testing.T) {
	server, _ := wgtypes.GeneratePrivateKey()
	b := &fakeBackend{server: server, keys: map[string]wgtypes.Key{}, gen: 1,
		setKeyErr: ErrKeyChangeLimited}
	h := New(b)
	srv := httptest.NewServer(h)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")

	var buf syncBuffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	for _, agent := range []string{"home", "home", "other", "other", "home"} {
		if _, err := declare(t, h, url, agent); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
			t.Fatalf("%s: %v, want 1008", agent, err)
		}
	}
	for _, agent := range []string{"home", "other"} {
		if n := strings.Count(buf.String(), "stream: "+agent+": refusing a public key change"); n != 1 {
			t.Errorf("%s: refusal lines = %d within a minute, want 1", agent, n)
		}
	}
}

// Expired entries of the per-agent gate are dropped when another line is logged, and an agent whose
// minute has passed is logged again.
func TestKeyChangeLogGateExpires(t *testing.T) {
	h := New(&fakeBackend{})
	t0 := time.Now()
	if !h.noteKeyChangeRefused("a", "tok-a", t0) || h.noteKeyChangeRefused("a", "tok-a", t0.Add(59*time.Second)) {
		t.Fatal("the same agent was not gated within a minute")
	}
	if !h.noteKeyChangeRefused("b", "tok-b", t0.Add(30*time.Second)) {
		t.Fatal("another agent was gated")
	}
	if !h.noteKeyChangeRefused("c", "tok-c", t0.Add(80*time.Second)) {
		t.Fatal("a new agent was gated")
	}
	h.mu.Lock()
	_, a := h.keyChangeLogNext["a"]
	_, bb := h.keyChangeLogNext["b"]
	n := len(h.keyChangeLogNext)
	h.mu.Unlock()
	if a || !bb || n != 2 {
		t.Fatalf("after a's minute passed: a kept=%v b kept=%v entries=%d, want false true 2", a, bb, n)
	}
	if !h.noteKeyChangeRefused("a", "tok-a", t0.Add(61*time.Second)) {
		t.Fatal("the agent was not logged again after its minute")
	}
	if st := h.Status("a"); !st.KeyChangeRefusedAt.Equal(t0.Add(61 * time.Second)) {
		t.Fatalf("the record is %v, want the latest refusal", st.KeyChangeRefusedAt)
	}
}
