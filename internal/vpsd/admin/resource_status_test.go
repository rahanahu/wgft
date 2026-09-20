package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// resourceBackend is a fakeBackend that also reports Resource Guard's status.
type resourceBackend struct {
	*fakeBackend
	status ResourceStatus
}

func (b *resourceBackend) ResourceStatus() ResourceStatus { return b.status }

// The Resource Guard status is additive to API v1 (design.md 7a.10 節「拒否の報告」): the rules
// response keeps its fields and, when the Backend reports it, adds flow_budget and
// resource_refusals.
func TestRulesResponseResourceStatusFields(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	base := &fakeBackend{st: st}

	// A Backend without the report (e.g. the test fakeBackend, tools/uidemo) must not add the fields.
	plain := getRulesJSON(t, base, st)
	for _, k := range []string{"flow_budget", "resource_refusals"} {
		if _, ok := plain[k]; ok {
			t.Errorf("a Backend without the report must not add %q", k)
		}
	}

	// Kernel mode: no Go-side UDP pool (design.md 7a.10 節「kernel 側の保護」), so FlowBudget has no
	// "udp" entry, and a rule that Go never judges (e.g. a Transparent rule) never appears in
	// Refusals. This is exactly the shape internal/vpsd.Daemon.ResourceStatus produces in kernel mode.
	kernelStatus := ResourceStatus{
		FlowBudget: map[proto.Proto]FlowBudget{proto.TCP: {InUse: 3, Limit: 2048}},
		Refusals:   map[string]map[string]uint64{},
	}
	kernel := getRulesJSON(t, &resourceBackend{fakeBackend: base, status: kernelStatus}, st)
	var fb map[proto.Proto]FlowBudget
	if err := json.Unmarshal(kernel["flow_budget"], &fb); err != nil {
		t.Fatal(err)
	}
	if _, ok := fb[proto.UDP]; ok {
		t.Errorf("kernel mode must not report a udp flow_budget entry, got %+v", fb)
	}
	if got := fb[proto.TCP]; got.InUse != 3 || got.Limit != 2048 {
		t.Errorf("tcp flow_budget = %+v, want {InUse:3 Limit:2048}", got)
	}
	// No rule has ever been refused yet: the (empty) table is left out entirely (omitempty), the same
	// way a Backend without any report leaves it out.
	if _, ok := kernel["resource_refusals"]; ok {
		t.Errorf("resource_refusals with no refusals yet must be left out, got %s", kernel["resource_refusals"])
	}

	// Userspace mode, zero in_use and a rule refused for several reasons.
	status := ResourceStatus{
		FlowBudget: map[proto.Proto]FlowBudget{
			proto.UDP: {InUse: 0, Limit: 8192},
			proto.TCP: {InUse: 0, Limit: 2048},
		},
		Refusals: map[string]map[string]uint64{
			"r_flood": {"budget": 5, "rule_cap": 2, "reserve": 1},
		},
	}
	got := getRulesJSON(t, &resourceBackend{fakeBackend: base, status: status}, st)
	var fb2 map[proto.Proto]FlowBudget
	if err := json.Unmarshal(got["flow_budget"], &fb2); err != nil {
		t.Fatal(err)
	}
	if u := fb2[proto.UDP]; u.InUse != 0 || u.Limit != 8192 {
		t.Errorf("udp flow_budget = %+v, want {InUse:0 Limit:8192}", u)
	}
	var refusals map[string]map[string]uint64
	if err := json.Unmarshal(got["resource_refusals"], &refusals); err != nil {
		t.Fatal(err)
	}
	want := map[string]uint64{"budget": 5, "rule_cap": 2, "reserve": 1}
	for reason, n := range want {
		if refusals["r_flood"][reason] != n {
			t.Errorf("resource_refusals[r_flood][%s] = %d, want %d", reason, refusals["r_flood"][reason], n)
		}
	}
	if _, ok := refusals["r_flood"]["nonexistent"]; ok {
		t.Error("a reason with no refusal must be absent, not present with 0")
	}

	// The same fields must appear on the batch endpoint (POST /api/v1/rules/batch), which shares
	// BatchResponse and the same withResourceStatus call.
	batchStatus := ResourceStatus{FlowBudget: map[proto.Proto]FlowBudget{proto.TCP: {InUse: 1, Limit: 2048}}}
	srv := httptest.NewServer(New(st, &resourceBackend{fakeBackend: base, status: batchStatus}))
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/api/v1/rules/batch", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var batchGot map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&batchGot); err != nil {
		t.Fatal(err)
	}
	if _, ok := batchGot["flow_budget"]; !ok {
		t.Error("POST /api/v1/rules/batch must also report flow_budget when the Backend has it")
	}
}
