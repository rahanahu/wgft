package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// dotRules は、ID か agent が `.` か `..` のルールである。どれも Rule.Validate が拒む(仕様 10.2 節)。
func dotRules() []proto.Rule {
	base := func(id, agent string) proto.Rule {
		return proto.Rule{ID: id, Agent: agent, Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 3001, Hi: 3001},
			Target: "192.168.1.20:3001", VPSMode: proto.ModeKernel, Enabled: true}
	}
	return []proto.Rule{base(".", "home"), base("..", "home"), base("r_x", "."), base("r_x", "..")}
}

// TestBatchAPIRefusesDotIDs は、管理用 API のルールのバッチが、ID か agent が `.` か `..` のルールを
// 422 で拒み、何も保存しないことを確かめる。
// 変異の確認:Rule.Validate の `.` と `..` の検査を外すと、バッチが通って落ちる。
func TestBatchAPIRefusesDotIDs(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := httptest.NewServer(New(&fakeBackend{st: st}))
	defer srv.Close()
	for _, r := range dotRules() {
		body, _ := json.Marshal(BatchRequest{Upsert: []proto.Rule{r}})
		resp, err := http.Post(srv.URL+"/api/v1/rules/batch", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(string(b), "is not allowed") {
			t.Errorf("batch with id %q agent %q = %d %s, want 422 saying it is not allowed", r.ID, r.Agent, resp.StatusCode, b)
		}
	}
	if rules, _ := st.Rules(); len(rules) != 0 {
		t.Errorf("refused batches stored rules: %+v", rules)
	}
}

// TestImportIssuesRefusesDotIDs は、Web UI の読み込みの確認画面が、ID か agent が `.` か `..` の
// ルールを問題として示し、適用させないことを確かめる。
// 変異の確認:Rule.Validate の `.` と `..` の検査を外すと、問題が示されず落ちる。
func TestImportIssuesRefusesDotIDs(t *testing.T) {
	agents := map[string]bool{"home": true, ".": true, "..": true}
	for _, r := range dotRules() {
		got := importIssues([]proto.Rule{r}, nil, agents, nil)
		if len(got) != 1 || !strings.Contains(got[0], "is not allowed") {
			t.Errorf("import of id %q agent %q: issues = %v, want one saying it is not allowed", r.ID, r.Agent, got)
		}
	}
}
