package main

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// resourceRuleBackend is a fakeRuleBackend that also reports Resource Guard's status
// (design.md 7a.10 節「拒否の報告」), the way internal/vpsd.Daemon does.
type resourceRuleBackend struct {
	*fakeRuleBackend
	status admin.ResourceStatus
}

func (b *resourceRuleBackend) ResourceStatus() admin.ResourceStatus { return b.status }

func newResourceRuleCLITestServer(t *testing.T, status admin.ResourceStatus) (adminURL string, backend *resourceRuleBackend) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	backend = &resourceRuleBackend{fakeRuleBackend: &fakeRuleBackend{st: st}, status: status}
	srv := httptest.NewServer(admin.New(backend))
	t.Cleanup(srv.Close)
	return srv.URL, backend
}

// `rule ls` shows Resource Guard's status (design.md 7a.10 節): a REFUSED column with the total
// refusals of each rule, and a "flow budget" line after "generation" with the process-wide budget
// by protocol. Kernel mode never reports a "udp" entry (no Go-side UDP pool), and that must not
// print a udp part of the line.
func TestRuleLsShowsResourceStatus(t *testing.T) {
	status := admin.ResourceStatus{
		FlowBudget: map[proto.Proto]admin.FlowBudget{proto.TCP: {InUse: 3, Limit: 2048}},
		Refusals:   map[string]map[string]uint64{},
	}
	adminURL, backend := newResourceRuleCLITestServer(t, status)

	if _, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--tcp", "443", "--to", "192.168.1.20:443"); err != nil {
		t.Fatalf("rule add: %v", err)
	}
	id := firstRuleID(t, adminURL)

	// Zero refusals yet: the REFUSED column reads 0.
	stdout, _, err := runRuleCmd(t, adminURL, "ls")
	if err != nil {
		t.Fatalf("rule ls: %v", err)
	}
	if !strings.Contains(stdout, "REFUSED") {
		t.Errorf("rule ls must have a REFUSED column header, got: %q", stdout)
	}
	if !strings.Contains(stdout, "flow budget: tcp 3/2048") {
		t.Errorf("rule ls must print the flow budget line, got: %q", stdout)
	}
	if strings.Contains(stdout, "udp") {
		t.Errorf("kernel mode (no udp flow_budget entry) must not print a udp part: %q", stdout)
	}

	// Refusals of several reasons on that rule (design.md 7a.10 節: budget, rule_cap, reserve):
	// REFUSED shows their sum, mutating the same backend so the rule keeps its ID.
	backend.status.Refusals = map[string]map[string]uint64{id: {"budget": 5, "rule_cap": 2, "reserve": 1}}
	stdout, _, err = runRuleCmd(t, adminURL, "ls")
	if err != nil {
		t.Fatalf("rule ls: %v", err)
	}
	// DROPPED and REFUSED are the two trailing numbers before NOTE (empty here); RATES is also
	// empty (no rate set), so the row cannot be split on fixed column positions (tabwriter collapses
	// an empty cell's own width away). Anchor on the fields whose values are fixed by the rule instead
	// (kernel mode, enabled, 0 deny, 0 allow), then capture the two counts that follow.
	m := refusedRow.FindStringSubmatch(stdout)
	if m == nil {
		t.Fatalf("could not find the rule's DROPPED/REFUSED counts in: %q", stdout)
	}
	if m[1] != "0" {
		t.Errorf("DROPPED = %s, want 0", m[1])
	}
	if m[2] != "8" {
		t.Errorf("REFUSED = %s, want the sum 5+2+1=8 of all reasons; full output: %q", m[2], stdout)
	}
}

// refusedRow matches "... true  0  0  <rates>  <dropped>  <refused>  <note>" in a rule ls row and
// captures DROPPED and REFUSED. RATES and NOTE may be empty in the fixture rules these tests build.
var refusedRow = regexp.MustCompile(`kernel\s+true\s+0\s+0\s+\S*\s+(\d+)\s+(\d+)`)

// `rule ls --json` passes the admin API's response through unchanged (design.md 7a.10 節
// 「利用者から見て変わらないものと変わるもの」), so flow_budget and resource_refusals appear as
// additional keys.
func TestRuleLsJSONPassesThroughResourceStatus(t *testing.T) {
	status := admin.ResourceStatus{
		FlowBudget: map[proto.Proto]admin.FlowBudget{
			proto.UDP: {InUse: 12, Limit: 8192},
			proto.TCP: {InUse: 0, Limit: 2048},
		},
		Refusals: map[string]map[string]uint64{"r_x": {"budget": 7}},
	}
	adminURL, _ := newResourceRuleCLITestServer(t, status)

	stdout, _, err := runRuleCmd(t, adminURL, "ls", "--json")
	if err != nil {
		t.Fatalf("rule ls --json: %v", err)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("rule ls --json output is not valid JSON: %v\n%s", err, stdout)
	}
	fb, ok := out["flow_budget"]
	if !ok {
		t.Fatal("rule ls --json must include flow_budget")
	}
	if !strings.Contains(string(fb), `"udp"`) || !strings.Contains(string(fb), `"in_use": 12`) {
		t.Errorf("flow_budget = %s, want the udp entry with in_use 12", fb)
	}
	rr, ok := out["resource_refusals"]
	if !ok {
		t.Fatal("rule ls --json must include resource_refusals")
	}
	if !strings.Contains(string(rr), `"budget": 7`) {
		t.Errorf("resource_refusals = %s, want r_x's budget count 7", rr)
	}
}
