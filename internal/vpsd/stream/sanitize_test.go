package stream

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/proto"
)

// TestSanitizeHeartbeatEscapesAndClips is a table test on sanitizeHeartbeat itself, independent of
// the hub, covering the control characters and the length caps design.md 5.2 節 documents.
func TestSanitizeHeartbeatEscapesAndClips(t *testing.T) {
	in := &proto.Heartbeat{
		Generation: 42,
		Tunnel: proto.TunnelStatus{
			// State and Endpoint are hostile here too (not just Reason and Rules[].ID/Reason as
			// an earlier version of this test had them): every one of the six fields
			// sanitizeHeartbeat touches gets its own escape-survives check below, so removing any
			// single clipAndSanitize call in sanitizeHeartbeat fails this test, not just the
			// fields that call already covered (レビューの指摘, 2026-09-26).
			State:    "ok\x1bmalicious",
			Reason:   "escape\x1b[31mme",
			Endpoint: "198.51.100.1:51820\x07evil",
		},
		Rules: []proto.RuleStatus{
			{ID: "r_ok", State: "ok"},
			{ID: "r_bad\x07id", State: "error\x1bevil", Reason: "bind failed\rFAKE"},
		},
	}
	out := sanitizeHeartbeat(in)

	if out.Generation != 42 {
		t.Errorf("Generation = %d, want unchanged 42", out.Generation)
	}
	unsafe := func(name, s string) {
		t.Helper()
		if strings.ContainsAny(s, "\x1b\x07\r\x00") {
			t.Errorf("%s still has a raw control byte: %q", name, s)
		}
	}
	unsafe("Tunnel.State", out.Tunnel.State)
	unsafe("Tunnel.Reason", out.Tunnel.Reason)
	unsafe("Tunnel.Endpoint", out.Tunnel.Endpoint)
	if !strings.Contains(out.Tunnel.Endpoint, "198.51.100.1:51820") {
		t.Errorf("Tunnel.Endpoint = %q, want it to still carry the reported endpoint text", out.Tunnel.Endpoint)
	}
	if len(out.Rules) != 2 {
		t.Fatalf("Rules has %d entries, want 2", len(out.Rules))
	}
	if out.Rules[0].ID != "r_ok" || out.Rules[0].State != "ok" {
		t.Errorf("Rules[0] = %+v, want the clean rule unchanged", out.Rules[0])
	}
	unsafe("Rules[1].ID", out.Rules[1].ID)
	unsafe("Rules[1].State", out.Rules[1].State)
	unsafe("Rules[1].Reason", out.Rules[1].Reason)

	// The original must not be mutated: sanitizeHeartbeat returns a copy.
	if in.Tunnel.Reason != "escape\x1b[31mme" {
		t.Errorf("sanitizeHeartbeat mutated its input's Tunnel.Reason: %q", in.Tunnel.Reason)
	}
	if in.Rules[1].ID != "r_bad\x07id" {
		t.Errorf("sanitizeHeartbeat mutated its input's Rules[1].ID: %q", in.Rules[1].ID)
	}
}

func TestSanitizeHeartbeatCapsLength(t *testing.T) {
	in := &proto.Heartbeat{
		Tunnel: proto.TunnelStatus{Reason: strings.Repeat("a", maxHeartbeatReasonLen*4)},
		Rules:  []proto.RuleStatus{{ID: strings.Repeat("b", maxHeartbeatIDLen*4)}},
	}
	out := sanitizeHeartbeat(in)
	if len(out.Tunnel.Reason) > maxHeartbeatReasonLen+len("... truncated") {
		t.Errorf("Tunnel.Reason is %d bytes, want capped near %d", len(out.Tunnel.Reason), maxHeartbeatReasonLen)
	}
	if len(out.Rules[0].ID) > maxHeartbeatIDLen+len("... truncated") {
		t.Errorf("Rules[0].ID is %d bytes, want capped near %d", len(out.Rules[0].ID), maxHeartbeatIDLen)
	}
}

// TestSanitizeHeartbeatCapsLengthEvenWhenEverythingEscapes confirms that the byte count actually
// stored stays at or near the cap even when every byte of the input needs escaping - not up to
// several times the cap. Mutation check: swapping clipAndSanitize back to
// SanitizeForTerminal(ClipText(s, max)) (clip, then escape) makes this fail, since clipping first
// keeps up to max raw ESC bytes, each of which then expands to the 4-byte escape `\x1b` on the
// second pass, growing the stored value to about 4x max (レビューの指摘, 2026-09-26).
func TestSanitizeHeartbeatCapsLengthEvenWhenEverythingEscapes(t *testing.T) {
	in := &proto.Heartbeat{
		Tunnel: proto.TunnelStatus{Reason: strings.Repeat("\x1b", maxHeartbeatReasonLen*4)},
		Rules:  []proto.RuleStatus{{ID: strings.Repeat("\x1b", maxHeartbeatIDLen*4)}},
	}
	out := sanitizeHeartbeat(in)
	if n := len(out.Tunnel.Reason); n > maxHeartbeatReasonLen+len("... truncated") {
		t.Errorf("Tunnel.Reason (all-ESC input) is %d bytes stored, want capped near %d, not several times over it", n, maxHeartbeatReasonLen)
	}
	if n := len(out.Rules[0].ID); n > maxHeartbeatIDLen+len("... truncated") {
		t.Errorf("Rules[0].ID (all-ESC input) is %d bytes stored, want capped near %d, not several times over it", n, maxHeartbeatIDLen)
	}
}

func TestSanitizeHeartbeatKeepsNormalTextUnchanged(t *testing.T) {
	in := &proto.Heartbeat{
		Generation: 1,
		Tunnel:     proto.TunnelStatus{State: proto.StatusError, Reason: "接続を確認できませんでした"},
		Rules:      []proto.RuleStatus{{ID: "r_01HXABCDEFGHJKMNPQRSTVWXYZ", State: proto.StatusOK}},
	}
	out := sanitizeHeartbeat(in)
	if out.Tunnel.Reason != in.Tunnel.Reason {
		t.Errorf("Japanese reason changed: got %q, want %q", out.Tunnel.Reason, in.Tunnel.Reason)
	}
	if out.Rules[0].ID != in.Rules[0].ID {
		t.Errorf("clean rule ID changed: got %q, want %q", out.Rules[0].ID, in.Rules[0].ID)
	}
}

// TestHubStoresSanitizedHeartbeat is an end-to-end check that a hostile heartbeat sent over the
// real WebSocket path comes back sanitized from Hub.Status, the read path every consumer (admin
// API, agent ls, rule ls, status, server doctor) shares.
func TestHubStoresSanitizedHeartbeat(t *testing.T) {
	server, _ := wgtypes.GeneratePrivateKey()
	b := &fakeBackend{server: server, keys: map[string]wgtypes.Key{}, gen: 1}
	h := New(b)
	srv := httptest.NewServer(h)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")

	key, _ := wgtypes.GeneratePrivateKey()
	c, _, err := dial(t, url, "tok-home")
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	sendJSON(t, c, proto.Message{Type: proto.MsgPublicKey, PublicKey: key.PublicKey().String()})
	if _, err := readMsg(t, c); err != nil {
		t.Fatalf("first state: %v", err)
	}
	sendJSON(t, c, proto.Message{
		Type: proto.MsgHeartbeat,
		Heartbeat: &proto.Heartbeat{
			Generation: 1,
			Tunnel:     proto.TunnelStatus{State: proto.StatusError, Reason: "hijacked\x1b[2Jreason"},
			Rules:      []proto.RuleStatus{{ID: "r_evil\x1b]0;pwned\x07", State: proto.StatusError, Reason: "bad\rCR"}},
		},
	})

	deadline := time.Now().Add(2 * time.Second)
	var st Status
	for time.Now().Before(deadline) {
		st = h.Status("home")
		if st.Heartbeat != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st.Heartbeat == nil {
		t.Fatal("heartbeat was never recorded")
	}
	if strings.ContainsAny(st.Heartbeat.Tunnel.Reason, "\x1b\r\x07\x00") {
		t.Errorf("stored Tunnel.Reason still has a raw control byte: %q", st.Heartbeat.Tunnel.Reason)
	}
	if strings.ContainsAny(st.Heartbeat.Rules[0].ID, "\x1b\r\x07\x00") {
		t.Errorf("stored Rules[0].ID still has a raw control byte: %q", st.Heartbeat.Rules[0].ID)
	}
	if strings.ContainsAny(st.Heartbeat.Rules[0].Reason, "\x1b\r\x07\x00") {
		t.Errorf("stored Rules[0].Reason still has a raw control byte: %q", st.Heartbeat.Rules[0].Reason)
	}
}
