package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/store"
)

// forwardPolicyBackend is a fakeBackend that reports the forward chain check like a kernel-mode
// server.
type forwardPolicyBackend struct {
	*fakeBackend
	st ForwardPolicyStatus
	ok bool
}

func (b *forwardPolicyBackend) ForwardPolicy() (ForwardPolicyStatus, bool) { return b.st, b.ok }

// forward_policy is additive to API v1 (design.md 10.2a、7a.11 節): a Backend without it, and a
// server that does not forward through the kernel, serve the rules without the field.
func TestRulesResponseForwardPolicy(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	base := &fakeBackend{st: st}
	if _, ok := getRulesJSON(t, base, st)["forward_policy"]; ok {
		t.Error("a Backend without ForwardPolicyBackend must not add forward_policy")
	}
	if _, ok := getRulesJSON(t, &forwardPolicyBackend{fakeBackend: base, ok: false}, st)["forward_policy"]; ok {
		t.Error("a server that does not forward through the kernel must not add forward_policy")
	}
	want := ForwardPolicyDrop{Where: "ip filter FORWARD", Suggest: []string{"iptables -I DOCKER-USER -o wgft0 -j ACCEPT"}}
	got := getRulesJSON(t, &forwardPolicyBackend{fakeBackend: base, st: ForwardPolicyStatus{Drops: []ForwardPolicyDrop{want}}, ok: true}, st)
	var back ForwardPolicyStatus
	if err := json.Unmarshal(got["forward_policy"], &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Drops) != 1 || back.Drops[0].Where != want.Where || len(back.Drops[0].Suggest) != 1 || back.Drops[0].Suggest[0] != want.Suggest[0] || back.Error != "" {
		t.Errorf("forward_policy = %+v, want one drop %+v", back, want)
	}
	// 落とすチェーンが無い報告も、検査した事実として載る
	got = getRulesJSON(t, &forwardPolicyBackend{fakeBackend: base, ok: true}, st)
	if string(got["forward_policy"]) != "{}" {
		t.Errorf("a clear check = %s, want {}", got["forward_policy"])
	}

	// POST /api/v1/rules/batch shares BatchResponse and carries the same field
	srv := httptest.NewServer(New(&forwardPolicyBackend{fakeBackend: base, st: ForwardPolicyStatus{Drops: []ForwardPolicyDrop{want}}, ok: true}))
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
	if !strings.Contains(string(batchGot["forward_policy"]), `"where":"ip filter FORWARD"`) {
		t.Errorf("POST /api/v1/rules/batch forward_policy = %s, want the drop", batchGot["forward_policy"])
	}
}
