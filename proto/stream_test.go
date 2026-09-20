package proto

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMessageRoundTrip(t *testing.T) {
	msgs := []Message{
		{Type: MsgPublicKey, PublicKey: "k"},
		{Type: MsgState, State: &State{Generation: 3, Rules: []AgentRule{{ID: "r", Proto: UDP, ListenPort: PortRange{1, 2}, Target: "h:1", Enabled: true}}}},
		{Type: MsgHeartbeat, Heartbeat: &Heartbeat{Generation: 3, Tunnel: TunnelStatus{State: StatusOK, Endpoint: "1.2.3.4:51820"},
			Rules: []RuleStatus{{ID: "r", State: StatusError, Reason: "bind: address in use"}}}},
	}
	for _, m := range msgs {
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		var back Message
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		if back.Type != m.Type || (m.State == nil) != (back.State == nil) || (m.Heartbeat == nil) != (back.Heartbeat == nil) {
			t.Errorf("round trip: %s -> %+v", b, back)
		}
	}
}

// TestTunnelStatusWireCompatibility is the DANGER item's compatibility proof (design.md 7a.11 節,
// item 1 of the 2026-09-21 JSON-contract fixes): TunnelStatus.LastHandshake travels agent -> server
// inside the heartbeat, so its wire shape is left untouched (the fix is only in the admin API's own
// view, internal/vpsd/admin/tunnelview.go). This test decodes byte strings shaped like what a
// v0.3.0, v0.5.0 and v0.5.1 agent actually sends (confirmed unchanged since v0.3.0 by "git show
// v0.3.0:proto/stream.go"): a zero handshake time written out in full, a real one, and the field
// missing entirely, and it re-encodes to confirm the wire's own JSON shape - including the
// "0001-01-01T00:00:00Z" zero-time literal this whole fix is about - did not change. A new server
// must decode all three from an old agent; an old server (the same unchanged struct) must decode
// what a new agent sends; both hold trivially here because nothing on the wire moved.
func TestTunnelStatusWireCompatibility(t *testing.T) {
	cases := []struct {
		name        string
		wire        string
		wantZero    bool
		wantHandshk time.Time
	}{
		{
			name:     "zero handshake, written out in full (a v0.3.0/v0.5.0/v0.5.1 agent that never shook hands)",
			wire:     `{"state":"error","reason":"handshake not established","last_handshake":"0001-01-01T00:00:00Z"}`,
			wantZero: true,
		},
		{
			name:        "a real handshake time",
			wire:        `{"state":"ok","endpoint":"1.2.3.4:51820","last_handshake":"2026-09-21T10:00:00Z"}`,
			wantZero:    false,
			wantHandshk: time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC),
		},
		{
			name:     "last_handshake absent entirely",
			wire:     `{"state":"error","reason":"no tunnel; full state not received"}`,
			wantZero: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var ts TunnelStatus
			if err := json.Unmarshal([]byte(c.wire), &ts); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if ts.LastHandshake.IsZero() != c.wantZero {
				t.Fatalf("LastHandshake.IsZero() = %v, want %v (decoded %v)", ts.LastHandshake.IsZero(), c.wantZero, ts.LastHandshake)
			}
			if !c.wantZero && !ts.LastHandshake.Equal(c.wantHandshk) {
				t.Fatalf("LastHandshake = %v, want %v", ts.LastHandshake, c.wantHandshk)
			}
			// Re-encoding must still be the wire's own (unfixed) shape: a zero time always
			// appears as the literal below, never omitted. This is exactly what makes the
			// wire type unsuitable for direct admin API output, and exactly why it must not
			// change: an old peer on either side decodes this same shape.
			b, err := json.Marshal(ts)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			var back map[string]json.RawMessage
			if err := json.Unmarshal(b, &back); err != nil {
				t.Fatal(err)
			}
			raw, ok := back["last_handshake"]
			if !ok {
				t.Fatalf("encode: want a last_handshake key on the wire always (encoding/json never omits a struct via omitempty), got none: %s", b)
			}
			if c.wantZero && string(raw) != `"0001-01-01T00:00:00Z"` {
				t.Errorf("encode: want the zero-time literal preserved on the wire, got %s", raw)
			}
		})
	}
}
