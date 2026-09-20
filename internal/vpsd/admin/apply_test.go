package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// applyBackend is a fakeBackend that also reports the apply state.
type applyBackend struct {
	*fakeBackend
	status ApplyStatus
	ok     bool
}

func (b *applyBackend) ApplyStatus() (ApplyStatus, bool) { return b.status, b.ok }

func getRulesJSON(t *testing.T, backend Backend, st *store.Store) map[string]json.RawMessage {
	t.Helper()
	srv := httptest.NewServer(New(backend))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/v1/rules")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// The apply state is additive to API v1 (design.md 7a.3, 7a.6 節): the rules response keeps its
// fields and, when the Backend reports it, adds desired_generation, active_generation, the
// per-rule rule_states and the drift section.
func TestRulesResponseApplyFields(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	base := &fakeBackend{st: st}

	plain := getRulesJSON(t, base, st)
	for _, k := range []string{"desired_generation", "active_generation", "rule_states", "drift", "apply_error"} {
		if _, ok := plain[k]; ok {
			t.Errorf("a Backend without the report must not add %q", k)
		}
	}
	for _, k := range []string{"generation", "rules"} {
		if _, ok := plain[k]; !ok {
			t.Errorf("existing field %q is missing", k)
		}
	}

	notYet := getRulesJSON(t, &applyBackend{fakeBackend: base}, st)
	if _, ok := notYet["rule_states"]; ok {
		t.Error("before the first transaction the report must be left out")
	}

	status := ApplyStatus{
		DesiredGeneration: 7, ActiveGeneration: 6,
		Rules: map[string]RuleApply{
			"r_ok":   {ApplyState: ApplyActive, ActiveGeneration: u64p(6)},
			"r_bind": {ApplyState: ApplyNotActive, Reason: "bind failed: address already in use", ActiveGeneration: u64p(5)},
		},
		Drift: Drift{Retiring: []DriftResource{{RuleID: "r_bind", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 8443, Hi: 8443}, Forwarding: "relay"}}},
	}
	got := getRulesJSON(t, &applyBackend{fakeBackend: base, status: status, ok: true}, st)
	if string(got["desired_generation"]) != "7" || string(got["active_generation"]) != "6" {
		t.Errorf("generations = %s / %s, want 7 / 6", got["desired_generation"], got["active_generation"])
	}
	var states map[string]RuleApply
	if err := json.Unmarshal(got["rule_states"], &states); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(states, status.Rules) {
		t.Errorf("rule_states = %+v", states)
	}
	if !strings.Contains(string(got["rule_states"]), `"apply_state":"not_active"`) {
		t.Errorf("rule_states JSON = %s, want apply_state not_active", got["rule_states"])
	}
	want := `{"active_only":[],"retiring":[{"rule_id":"r_bind","proto":"tcp","listen_port":"8443","forwarding":"relay"}]}`
	if string(got["drift"]) != want {
		t.Errorf("drift = %s\nwant    %s", got["drift"], want)
	}
	if _, ok := got["apply_error"]; ok {
		t.Error("apply_error must be left out after a successful transaction")
	}
}

// The rule list shows a rule the server could not publish, before the agent's own state.
func TestRuleRunStateServerSide(t *testing.T) {
	r := &proto.Rule{ID: "r_bind", Agent: "home", Enabled: true}
	agents := map[string]ruleAgentStatus{"home": {Connected: true, Generation: 3, Rules: map[string]proto.RuleStatus{"r_bind": {ID: "r_bind"}}}}
	server := map[string]RuleApply{"r_bind": {ApplyState: ApplyNotActive, Reason: "bind failed: address already in use"}}
	badge, label, reason := ruleRunState(r, 3, agents, server, "en")
	if badge != "danger" || label != "Not active on server" || reason != "bind failed: address already in use" {
		t.Errorf("not_active: %q %q %q", badge, label, reason)
	}
	server["r_bind"] = RuleApply{ApplyState: ApplyPending, Reason: "nftables: transaction failed"}
	if badge, label, _ := ruleRunState(r, 3, agents, server, "ja"); badge != "warning" || label != "サーバーで反映待ち" {
		t.Errorf("pending: %q %q", badge, label)
	}
	server["r_bind"] = RuleApply{ApplyState: ApplyActive}
	if badge, _, _ := ruleRunState(r, 3, agents, server, "en"); badge != "success" {
		t.Errorf("active on the server, applied by the agent: badge %q, want success", badge)
	}
}

// TestRuleApplyActiveGenerationNeverPublishedVsZeroVsN confirms RuleApply.ActiveGeneration follows
// the same *uint64 convention as BatchResponse.DesiredGeneration/ActiveGeneration (design.md 7a.11
// 節, item 2 of the 2026-09-21 JSON-contract fixes): a rule that never published is absent from the
// JSON, distinct from a rule genuinely published at generation 0 (which the store can produce: 9
// 節, "0 while there are no rules") and from one at a later generation N.
func TestRuleApplyActiveGenerationNeverPublishedVsZeroVsN(t *testing.T) {
	cases := []struct {
		name string
		ag   *uint64
		want string // the whole encoded RuleApply, to also confirm the key is absent, not null
	}{
		{"never published", nil, `{"apply_state":"active"}`},
		{"published at generation 0", u64p(0), `{"apply_state":"active","active_generation":0}`},
		{"published at generation N", u64p(6), `{"apply_state":"active","active_generation":6}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, err := json.Marshal(RuleApply{ApplyState: ApplyActive, ActiveGeneration: c.ag})
			if err != nil {
				t.Fatal(err)
			}
			if string(b) != c.want {
				t.Errorf("got %s, want %s", b, c.want)
			}
		})
	}
}

func u64p(u uint64) *uint64 { return &u }
