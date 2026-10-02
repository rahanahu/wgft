package stream

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net/http/httptest"
	"strings"
	"testing"

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

	var buf bytes.Buffer
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

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	for i := 0; i < 3; i++ {
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
