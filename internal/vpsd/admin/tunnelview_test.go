package admin

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/rahanahu/wgft/proto"
)

// TestTunnelStatusViewOmitsNeverObserved is the admin-API-side half of the fix (design.md 7a.11
// 節, item 1): a tunnel that never shook hands must not print "0001-01-01T00:00:00Z" (what the
// wire's proto.TunnelStatus does; see proto/stream_test.go's TestTunnelStatusWireCompatibility for
// why that type is left alone) or an RFC3339Nano timestamp anywhere it does have a value. It must
// follow the same rule every sibling timestamp in this API already does: RFC3339, omitted when
// IsZero().
func TestTunnelStatusViewOmitsNeverObserved(t *testing.T) {
	never := TunnelStatusView(proto.TunnelStatus{State: proto.StatusError, Reason: "handshake not established"})
	if never.LastHandshake != "" {
		t.Errorf("never-observed handshake: LastHandshake = %q, want empty", never.LastHandshake)
	}
	b, err := json.Marshal(never)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]json.RawMessage
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if _, ok := back["last_handshake"]; ok {
		t.Errorf("never-observed handshake: want no last_handshake key at all, got %s", b)
	}
	if got := string(back["state"]); got != `"error"` {
		t.Errorf("state = %s, want \"error\"", got)
	}

	observed := time.Date(2026, 9, 21, 10, 0, 0, 123456789, time.UTC)
	real := TunnelStatusView(proto.TunnelStatus{State: proto.StatusOK, Endpoint: "1.2.3.4:51820", LastHandshake: observed})
	want := "2026-09-21T10:00:00Z"
	if real.LastHandshake != want {
		t.Errorf("LastHandshake = %q, want %q (RFC3339, not RFC3339Nano, matching every sibling timestamp)", real.LastHandshake, want)
	}
}

// TestAgentInfoTunnelJSONNeverHandshook confirms the field the bug report is literally about: a
// disconnected/never-handshook agent's `agent ls --json` output for tunnel.last_handshake is
// absent, not "0001-01-01T00:00:00Z".
func TestAgentInfoTunnelJSONNeverHandshook(t *testing.T) {
	info := AgentInfo{Name: "home", Tunnel: TunnelStatusView(proto.TunnelStatus{State: proto.StatusError, Reason: "no tunnel; full state not received"})}
	b, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]json.RawMessage
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	var tunnel map[string]json.RawMessage
	if err := json.Unmarshal(back["tunnel"], &tunnel); err != nil {
		t.Fatal(err)
	}
	if _, ok := tunnel["last_handshake"]; ok {
		t.Errorf("agent ls --json: tunnel.last_handshake must be absent for a never-observed handshake, got %s", back["tunnel"])
	}
}
