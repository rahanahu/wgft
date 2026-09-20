package main

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは、ルールごとの agent 側の状態(design.md 5.2、7a.11 節)が `rule ls` の人間向け表
// (AGENT_STATE 列)と `rule ls --json`(agent_rule_states)の両方に出ることを確かめる。この状態は
// これまで `agent ls` の RULES 列と Web UI にしか出ておらず(v0.5.0/v0.5.1 の Known issues)、
// admin.AgentRuleStatusBackend を実装する Backend のときだけ加わる加算的なフィールドである
// (internal/vpsd/admin/agent_rule_status_test.go がその Backend 単体の JSON 形を確かめる)。

// agentStateRuleBackend is fakeRuleBackend (rule_test.go) plus a reportable agent-side status per
// rule ID, mutated in place between calls (the rule's own generated ID is not known ahead of
// "rule add").
type agentStateRuleBackend struct {
	*fakeRuleBackend
	status map[string]admin.AgentRuleStatus
}

func (b *agentStateRuleBackend) AgentRuleStatuses([]proto.Rule) map[string]admin.AgentRuleStatus {
	return b.status
}

func TestRuleLsShowsAgentRuleState(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	backend := &agentStateRuleBackend{fakeRuleBackend: &fakeRuleBackend{st: st}, status: map[string]admin.AgentRuleStatus{}}
	srv := httptest.NewServer(admin.New(backend))
	t.Cleanup(srv.Close)
	adminURL := srv.URL

	if _, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--tcp", "25565", "--to", "192.168.1.20:25565"); err != nil {
		t.Fatalf("rule add: %v", err)
	}
	id := firstRuleID(t, adminURL)

	// Before any report at all (the Backend's map has no entry for this rule id, as if
	// AgentRuleStatusBackend were not implemented), the table shows "-" and no error text.
	stdout, _, err := runRuleCmd(t, adminURL, "ls")
	if err != nil {
		t.Fatalf("rule ls: %v", err)
	}
	if strings.Contains(stdout, "error:") {
		t.Errorf("rule ls before any agent report must not show an error, stdout:\n%s", stdout)
	}

	// The agent is connected but has not reported this rule yet (2026-09-21, owner's decision: every
	// current rule gets an entry, State/Reason/At absent, Connected reflecting the hub). The table
	// must show "-", not "error: " (State being empty is not itself an error).
	backend.status[id] = admin.AgentRuleStatus{Agent: "home", Connected: true}
	stdout, _, err = runRuleCmd(t, adminURL, "ls")
	if err != nil {
		t.Fatalf("rule ls: %v", err)
	}
	if strings.Contains(stdout, "error:") {
		t.Errorf("a connected, not-yet-reported rule must not show an error, stdout:\n%s", stdout)
	}
	if strings.Contains(stdout, "last:") {
		t.Errorf("a connected agent's not-yet-reported rule must not carry the last: prefix, stdout:\n%s", stdout)
	}

	// rule ls --json, for the same not-yet-reported-but-connected state, must show only "agent" and
	// "connected" - no "state", "reason" or "at" key at all (--json pretty-prints, so compare the
	// decoded field set rather than the raw bytes).
	jsonOut, _, err := runRuleCmd(t, adminURL, "ls", "--json")
	if err != nil {
		t.Fatalf("rule ls --json: %v", err)
	}
	var raw struct {
		AgentRuleStates map[string]map[string]json.RawMessage `json:"agent_rule_states"`
	}
	if err := json.Unmarshal([]byte(jsonOut), &raw); err != nil {
		t.Fatalf("decoding rule ls --json output: %v\n%s", err, jsonOut)
	}
	entry := raw.AgentRuleStates[id]
	if len(entry) != 2 {
		t.Fatalf("agent_rule_states[%s] = %v, want exactly the keys agent and connected", id, entry)
	}
	if string(entry["agent"]) != `"home"` || string(entry["connected"]) != "true" {
		t.Errorf("agent_rule_states[%s] = %v, want agent=home connected=true", id, entry)
	}
	if _, ok := entry["state"]; ok {
		t.Errorf("agent_rule_states[%s] has a state key, want none (never reported): %v", id, entry)
	}

	// The agent has never connected (or was revoked): same absent State, but Connected false, so the
	// table marks it as history with the last: prefix, reading "last:-".
	backend.status[id] = admin.AgentRuleStatus{Agent: "home", Connected: false}
	stdout, _, err = runRuleCmd(t, adminURL, "ls")
	if err != nil {
		t.Fatalf("rule ls: %v", err)
	}
	if !strings.Contains(stdout, "last:-") {
		t.Errorf("an offline agent that never reported this rule must show last:-, stdout:\n%s", stdout)
	}

	// The agent refused the target (WGFT_AGENT_ALLOW_TARGETS): connected, error.
	const reason = "target 192.168.1.20:25565 is not in WGFT_AGENT_ALLOW_TARGETS"
	backend.status[id] = admin.AgentRuleStatus{Agent: "home", State: "error", Reason: reason, At: "2026-09-21T10:00:00Z", Connected: true}
	stdout, _, err = runRuleCmd(t, adminURL, "ls")
	if err != nil {
		t.Fatalf("rule ls: %v", err)
	}
	if !strings.Contains(stdout, "error: "+reason) {
		t.Errorf("rule ls must show the agent's refusal reason, stdout:\n%s", stdout)
	}
	if strings.Contains(stdout, "last:error") {
		t.Errorf("a connected agent's report must not carry the last: prefix, stdout:\n%s", stdout)
	}

	// The reporting agent is now disconnected: the same report is history (design.md 5.2 節), shown
	// with the last: prefix like `agent ls`'s RULES column.
	backend.status[id] = admin.AgentRuleStatus{Agent: "home", State: "error", Reason: reason, At: "2026-09-21T09:55:00Z", Connected: false}
	stdout, _, err = runRuleCmd(t, adminURL, "ls")
	if err != nil {
		t.Fatalf("rule ls: %v", err)
	}
	if !strings.Contains(stdout, "last:error: "+reason) {
		t.Errorf("a disconnected agent's report must carry the last: prefix, stdout:\n%s", stdout)
	}

	// rule ls --json carries the same information machine-readably, under agent_rule_states.
	jsonOut, _, err = runRuleCmd(t, adminURL, "ls", "--json")
	if err != nil {
		t.Fatalf("rule ls --json: %v", err)
	}
	var res admin.BatchResponse
	if err := json.Unmarshal([]byte(jsonOut), &res); err != nil {
		t.Fatalf("decoding rule ls --json output: %v\n%s", err, jsonOut)
	}
	got, ok := res.AgentRuleStates[id]
	if !ok {
		t.Fatalf("agent_rule_states has no entry for %s: %+v", id, res.AgentRuleStates)
	}
	if got.Agent != "home" || got.State != "error" || got.Reason != reason || got.Connected {
		t.Errorf("agent_rule_states[%s] = %+v, want agent home, state error, the refusal reason, connected false", id, got)
	}
}
