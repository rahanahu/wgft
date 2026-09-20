package admin

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// agentRuleStatusBackend is a fakeBackend that also reports each rule's agent-side status. It
// ignores the rules argument and returns a fixed map: these tests exercise the handler's plumbing
// (JSON shape, optional-interface gating), not the rule-to-agent matching logic, which
// internal/vpsd/admin_backend_test.go covers against a real Daemon and a real stream.Hub.
type agentRuleStatusBackend struct {
	*fakeBackend
	status map[string]AgentRuleStatus
}

func (b *agentRuleStatusBackend) AgentRuleStatuses([]proto.Rule) map[string]AgentRuleStatus {
	return b.status
}

// AgentRuleStates is additive to API v1 (design.md 5.2、7a.11 節): the rules response keeps its
// fields and, only when the Backend reports agent-side rule status, adds agent_rule_states. It
// covers what rule_states (server apply) and resource_refusals (Resource Guard) do not: a rule
// refused by the agent's own target allowlist, and its listener/target errors, which used to show
// only through `agent ls` and the Web UI (v0.5.0/v0.5.1 Known issues).
func TestRulesResponseAgentRuleStates(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	base := &fakeBackend{st: st}

	// A Backend without the report (the test fakeBackend, tools/uidemo) must not add the field, even
	// though it does implement the always-present Agents().
	plain := getRulesJSON(t, base, st)
	if _, ok := plain["agent_rule_states"]; ok {
		t.Error("a Backend without AgentRuleStatusBackend must not add agent_rule_states")
	}

	status := map[string]AgentRuleStatus{
		// Refused by the agent's own WGFT_AGENT_ALLOW_TARGETS.
		"r_refused": {Agent: "home", State: "error", Reason: "target 192.168.1.99:80 is not in WGFT_AGENT_ALLOW_TARGETS", At: "2026-09-21T10:00:00Z", Connected: true},
		// A listener bind failure at the agent.
		"r_bind": {Agent: "home", State: "error", Reason: "udp/2456: bind: address already in use", At: "2026-09-21T10:00:00Z", Connected: true},
		// Reported fine.
		"r_ok": {Agent: "home", State: "ok", At: "2026-09-21T10:00:00Z", Connected: true},
		// Its agent's stream is down: the entry is that agent's last report, not current.
		"r_stale": {Agent: "office", State: "error", Reason: "tcp/8081: dial tcp 192.168.1.30:8081: connect: connection refused", At: "2026-09-21T09:57:00Z", Connected: false},
		// Its agent is connected but has not reported this rule yet: State/Reason/At absent,
		// Connected true (2026-09-21, owner's decision).
		"r_new_connected": {Agent: "home", Connected: true},
		// Its agent has never connected (or was revoked): State/Reason/At absent, Connected false.
		"r_new_offline": {Agent: "lab", Connected: false},
	}
	got := getRulesJSON(t, &agentRuleStatusBackend{fakeBackend: base, status: status}, st)
	var back map[string]AgentRuleStatus
	if err := json.Unmarshal(got["agent_rule_states"], &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, status) {
		t.Errorf("agent_rule_states = %+v, want %+v", back, status)
	}
	if _, ok := back["r_ok"]; !ok {
		t.Error("a rule reported ok must still have an entry (it is not indistinguishable from never reported)")
	}
	if back["r_stale"].Connected {
		t.Error("r_stale's agent (office) is disconnected; connected must be false")
	}

	// The never-reported entries' literal JSON: only "agent" and "connected", no "state"/"at".
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(got["agent_rule_states"], &raw); err != nil {
		t.Fatal(err)
	}
	if want := `{"agent":"home","connected":true}`; string(raw["r_new_connected"]) != want {
		t.Errorf("r_new_connected JSON = %s, want %s", raw["r_new_connected"], want)
	}
	if want := `{"agent":"lab","connected":false}`; string(raw["r_new_offline"]) != want {
		t.Errorf("r_new_offline JSON = %s, want %s", raw["r_new_offline"], want)
	}

	// A Backend that implements the interface but has nothing to report (e.g. no agent ever sent a
	// heartbeat) also omits the field: an empty map is "empty" to encoding/json's omitempty, the
	// same as FlowBudget/ResourceRefusals (resource_status.go). This is existing, established
	// behaviour, not something specific to this field.
	empty := getRulesJSON(t, &agentRuleStatusBackend{fakeBackend: base, status: map[string]AgentRuleStatus{}}, st)
	if _, ok := empty["agent_rule_states"]; ok {
		t.Error("an empty map must be omitted (omitempty), matching flow_budget/resource_refusals")
	}
}

// TestAgentRuleStatusJSONShape pins the AgentRuleStatus JSON shape directly. This package cannot
// import internal/vpsd (internal/vpsd already imports internal/vpsd/admin, so that would be a
// dependency cycle), so the Daemon implementation that sources these values from a rule's own
// agent's heartbeat is instead covered by internal/vpsd/admin_backend_test.go, against a real
// stream.Hub.
func TestAgentRuleStatusJSONShape(t *testing.T) {
	s := AgentRuleStatus{Agent: "home", State: "error", Reason: "target is not allowed", At: "2026-09-21T10:00:00Z", Connected: true}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"agent":"home","state":"error","reason":"target is not allowed","at":"2026-09-21T10:00:00Z","connected":true}`
	if string(b) != want {
		t.Errorf("JSON = %s\nwant  %s", b, want)
	}
	ok := AgentRuleStatus{Agent: "home", State: "ok", Connected: true}
	b, err = json.Marshal(ok)
	if err != nil {
		t.Fatal(err)
	}
	want = `{"agent":"home","state":"ok","connected":true}`
	if string(b) != want {
		t.Errorf("ok JSON = %s\nwant  %s", b, want)
	}

	// Never reported (2026-09-21, owner's decision): State/Reason/At all absent via omitempty, not a
	// fabricated state such as "unknown" or "pending" - an absent key already means "not observed"
	// throughout this API (design.md 7a.11 節), and State's only real values are the agent's own
	// ("ok"/"error"). Connected is always present and carries the only distinction available: online
	// (may still report) or offline/never-connected (will not).
	neverReportedConnected := AgentRuleStatus{Agent: "home", Connected: true}
	b, err = json.Marshal(neverReportedConnected)
	if err != nil {
		t.Fatal(err)
	}
	want = `{"agent":"home","connected":true}`
	if string(b) != want {
		t.Errorf("never reported, connected JSON = %s\nwant  %s", b, want)
	}
	neverReportedOffline := AgentRuleStatus{Agent: "home", Connected: false}
	b, err = json.Marshal(neverReportedOffline)
	if err != nil {
		t.Fatal(err)
	}
	want = `{"agent":"home","connected":false}`
	if string(b) != want {
		t.Errorf("never reported, offline JSON = %s\nwant  %s", b, want)
	}
}
