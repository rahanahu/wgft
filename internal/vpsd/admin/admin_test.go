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

// fakeBackend はバッチをそのまま store に流す。nftables には触れない。
type fakeBackend struct{ st *store.Store }

func (b *fakeBackend) Rules() ([]proto.Rule, error) { return b.st.Rules() }
func (b *fakeBackend) Generation() (uint64, error)  { return b.st.Generation() }
func (b *fakeBackend) Agents() ([]AgentInfo, error) { return []AgentInfo{{Name: "home"}}, nil }
func (b *fakeBackend) RuleDrops() (map[string]uint64, error) {
	return map[string]uint64{"r_a": 42}, nil
}
func (b *fakeBackend) Warnings() ([]Warning, error) {
	return []Warning{{Agent: "home", Kind: store.WarnIPMismatch, Detail: "stream=9.9.9.9 wg=1.2.3.4"}}, nil
}
func (b *fakeBackend) DismissWarning(agent, kind, detail string) error { return nil }
func (b *fakeBackend) CheckConnectivity(ruleID string) (ConnCheck, error) {
	return ConnCheck{OK: true, Reach: "target", Detail: "ok"}, nil
}
func (b *fakeBackend) JoinString(name string) (JoinStringResponse, error) {
	return JoinStringResponse{JoinString: "wgft://h:1/t#sha256:00"}, nil
}
func (b *fakeBackend) Revoke(name string) error { return nil }
func (b *fakeBackend) AgentState(string) (*proto.State, error) {
	return &proto.State{Generation: 1}, nil
}
func (b *fakeBackend) ServerInfo() (ServerInfo, error) {
	return ServerInfo{Version: "test", WGInterface: "wgft0", WGPort: 51821, MTU: 1420, Kernel: "6.1.0", NFT: "v1.0.6"}, nil
}
func (b *fakeBackend) Batch(req BatchRequest) (*store.BatchResult, error) {
	return b.st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return append(rules, req.Upsert...), nil
	})
}

func TestHostOriginAndBatch(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := httptest.NewServer(New(st, &fakeBackend{st}))
	defer srv.Close()

	// Host 検査:許可されない Host は 403、localhost 系は通る。
	hostCases := []struct {
		host string
		want int
	}{
		{"evil.example", http.StatusForbidden},
		{"127.0.0.1", http.StatusOK},
		{"localhost", http.StatusOK},
		{"[::1]:8686", http.StatusOK},
	}
	for _, hc := range hostCases {
		req, _ := http.NewRequest("GET", srv.URL+"/api/v1/rules", nil)
		req.Host = hc.host
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != hc.want {
			t.Errorf("Host=%q status = %d, want %d", hc.host, resp.StatusCode, hc.want)
		}
	}

	// クロスオリジンの書き込みは拒否。GET は Host が通れば素通り。
	body := func() io.Reader { return bytes.NewReader([]byte(`{}`)) }
	originCases := []struct {
		name       string
		headers    map[string]string
		wantDenied bool
	}{
		{"cross-site fetch", map[string]string{"Sec-Fetch-Site": "cross-site"}, true},
		{"same-origin fetch", map[string]string{"Sec-Fetch-Site": "same-origin"}, false},
		{"no fetch header", nil, false},
		{"foreign origin", map[string]string{"Origin": "https://evil.example"}, true},
		{"local origin", map[string]string{"Origin": "http://localhost:8686"}, false},
	}
	for _, oc := range originCases {
		req, _ := http.NewRequest("POST", srv.URL+"/api/v1/rules/batch", body())
		req.Header.Set("Content-Type", "application/json")
		for k, v := range oc.headers {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		denied := resp.StatusCode == http.StatusForbidden
		if denied != oc.wantDenied {
			t.Errorf("%s: status = %d, wantDenied=%v", oc.name, resp.StatusCode, oc.wantDenied)
		}
	}

	c := &Client{Base: srv.URL}
	res, err := c.Rules()
	if err != nil || len(res.Rules) != 0 || res.Generation != 0 {
		t.Fatalf("initial rules: %+v %v", res, err)
	}
	r := proto.Rule{ID: "r_a", Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 1, Hi: 2}, Target: "h:1", VPSMode: proto.ModeKernel, Enabled: true}
	res, err = c.Batch(BatchRequest{Upsert: []proto.Rule{r}})
	if err != nil || res.Generation != 1 || !res.Changed || len(res.Rules) != 1 {
		t.Fatalf("batch: %+v %v", res, err)
	}
	// 検証エラーは 422 と本文のメッセージ
	if _, err := c.Batch(BatchRequest{Upsert: []proto.Rule{{ID: "bad"}}}); err == nil {
		t.Error("invalid rule must fail")
	}
	// JSON でないボディは 400
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/rules/batch", bytes.NewReader([]byte("nope")))
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad json status = %d", resp.StatusCode)
	}
	st2, err := c.AgentState("home")
	if err != nil || st2.Generation != 1 {
		t.Errorf("agent state: %+v %v", st2, err)
	}
	if names, err := c.Agents(); err != nil || len(names) != 1 || names[0].Name != "home" {
		t.Errorf("agents: %v %v", names, err)
	}
	if js, err := c.JoinString("home"); err != nil || js.JoinString == "" {
		t.Errorf("join string: %+v %v", js, err)
	}
	if err := c.Revoke("home"); err != nil {
		t.Errorf("revoke: %v", err)
	}
	_ = json.Marshal
}

// TestUIRenderLocales は UI ページが ja/en 両方で実行時エラーなく描画され、
// 言語に応じた文字列が出ることを確かめる(テンプレートの実行時エラー検出)。
func TestUIRenderLocales(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// ルールを 1 件入れておく(rules/check の経路も通す)
	if _, err := st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return append(rules, proto.Rule{ID: "r_a", Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 25565, Hi: 25565}, Target: "192.168.1.20:25565", VPSMode: proto.ModeKernel, Enabled: true}), nil
	}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(st, &fakeBackend{st}))
	defer srv.Close()

	get := func(path string) string {
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", path, resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}

	cases := []struct {
		path           string
		wantJA, wantEN string
	}{
		{"/", "エージェント", "Agents"},
		{"/ui/add-rule", "受信ポート", "Listen port"},
		{"/ui/add-agent", "エージェント名", "Agent name"},
		{"/ui/rules/r_a/check", "接続テスト", "Connection test"},
		{"/ui/rules/r_a/meta", "グループ・説明を編集", "Edit group / note"},
		{"/ui/agents", "最終ハートビート", "Last heartbeat"},
		{"/ui/warnings", "警告", "Warnings"},
	}
	for _, tc := range cases {
		if body := get(tc.path + "?lang=ja"); !strings.Contains(body, tc.wantJA) {
			t.Errorf("ja %s: missing %q", tc.path, tc.wantJA)
		}
		if body := get(tc.path + "?lang=en"); !strings.Contains(body, tc.wantEN) {
			t.Errorf("en %s: missing %q", tc.path, tc.wantEN)
		}
	}
}
