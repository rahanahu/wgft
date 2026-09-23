package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// fakeBackend はバッチをそのまま store に流す。nftables には触れない。
// mode は ServerInfo().Mode に使う("" のままなら kernel とみなされる。webui.go の serverMode 参照)。
type fakeBackend struct {
	st       *store.Store
	mode     string
	agents   []AgentInfo // 空なら未接続の "home" 1 台(既定)。ルールの適用状態のテストは差し替える
	warnings []Warning   // nil なら IP 食い違いの警告 1 件(既定)。ダッシュボードの警告バナーのテストは空スライスに差し替える
}

func (b *fakeBackend) Rules() ([]proto.Rule, error) { return b.st.Rules() }
func (b *fakeBackend) Generation() (uint64, error)  { return b.st.Generation() }
func (b *fakeBackend) Agents() ([]AgentInfo, error) {
	if b.agents != nil {
		return b.agents, nil
	}
	return []AgentInfo{{Name: "home"}}, nil
}
func (b *fakeBackend) RuleDrops() (map[string]uint64, error) {
	return map[string]uint64{"r_a": 42}, nil
}
func (b *fakeBackend) Warnings() ([]Warning, error) {
	if b.warnings != nil {
		return b.warnings, nil
	}
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
	return ServerInfo{Version: "test", Mode: b.mode, WGInterface: "wgft0", WGPort: 51821, MTU: 1420, Kernel: "6.1.0", NFT: "v1.0.6"}, nil
}

// Batch はテスト用の簡略な upsert/delete(ID で置き換え、なければ追加。仕様 5.4 節と同じ形)。
// 本物の Daemon.Batch と違い、エージェントの存在確認や nftables への反映は行わない。
// 組み立て自体は ApplyBatchToRules(admin.go)を、tools/uidemo の fakeBackend と共有する。
func (b *fakeBackend) Batch(req BatchRequest) (*store.BatchResult, error) {
	return b.st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return ApplyBatchToRules(rules, req)
	})
}
func TestHostOriginAndBatch(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := httptest.NewServer(New(&fakeBackend{st: st}))
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

// TestBatchExpectedDigestConflict は、BatchRequest.ExpectedDigest が今のルール集合の
// proto.RulesDigest と食い違うと Batch が何も変えず ErrBatchConflict(HTTP 409)を返すこと、
// 一致すれば通ることを確かめる(仕様 5.4、10.1 節)。この照合は ApplyBatchToRules/
// store.ApplyBatch のトランザクションの内側で行うため、ExpectedDigest を読んだ後に
// 割り込んだ別経路の変更(ここでは r_a.Group だけの、世代を上げない変更)を、
// 世代の一致だけでは見逃す状況でも正しく検出する。
func TestBatchExpectedDigestConflict(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := httptest.NewServer(New(&fakeBackend{st: st}))
	defer srv.Close()
	c := &Client{Base: srv.URL}

	r := proto.Rule{ID: "r_a", Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 1, Hi: 2}, Target: "h:1", VPSMode: proto.ModeKernel, Enabled: true}
	if _, err := c.Batch(BatchRequest{Upsert: []proto.Rule{r}}); err != nil {
		t.Fatal(err)
	}
	res, err := c.Rules()
	if err != nil {
		t.Fatal(err)
	}
	digest := proto.RulesDigest(res.Rules)

	// 割り込みの変更:group だけなので世代は上がらない(5.3 節)。ExpectedDigest はこれを見逃さない。
	r.Group = "changed-elsewhere"
	if _, err := c.Batch(BatchRequest{Upsert: []proto.Rule{r}}); err != nil {
		t.Fatal(err)
	}

	// 古い digest を渡すと拒まれ、HTTP は 409、何も変わらない。
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/rules/batch", bytes.NewReader(mustJSON(t, BatchRequest{
		Upsert:         []proto.Rule{{ID: "r_a", Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 1, Hi: 2}, Target: "h:9999", VPSMode: proto.ModeKernel, Enabled: true}},
		ExpectedDigest: digest,
	})))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("stale ExpectedDigest status = %d, want %d", resp.StatusCode, http.StatusConflict)
	}
	after, err := c.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Rules) != 1 || after.Rules[0].Target != "h:1" || after.Rules[0].Group != "changed-elsewhere" {
		t.Errorf("a refused batch must not undo the interleaved change or apply its own: %+v", after.Rules)
	}

	// 今の digest を渡せば通る。
	current := proto.RulesDigest(after.Rules)
	r2 := after.Rules[0]
	r2.Target = "h:2"
	if _, err := c.Batch(BatchRequest{Upsert: []proto.Rule{r2}, ExpectedDigest: current}); err != nil {
		t.Fatalf("Batch with the current digest must succeed: %v", err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
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
	srv := httptest.NewServer(New(&fakeBackend{st: st}))
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
		{"/ui/rules/r_a", "拒否リスト", "Deny list"},
		{"/ui/agents", "最終ハートビート", "Last heartbeat"},
		{"/ui/warnings", "警告", "Warnings"},
		{"/ui/rules", "拒否数", "Denied"},
		{"/ui/health", "警告があります", "Warnings present"},
		{"/ui/rules/import", "読み込み", "Import rules"},
	}
	for _, tc := range cases {
		if body := get(tc.path + "?lang=ja"); !strings.Contains(body, tc.wantJA) {
			t.Errorf("ja %s: missing %q", tc.path, tc.wantJA)
		}
		if body := get(tc.path + "?lang=en"); !strings.Contains(body, tc.wantEN) {
			t.Errorf("en %s: missing %q", tc.path, tc.wantEN)
		}
	}

	// ヘッダと本文の枠は同じ最大幅の枠 1 つに入る。戻るボタンが本文の枠の右端にそろうのは、
	// 両方がこの枠の幅に従うからである。幅はページの種類で決まる。
	frames := []struct {
		path  string
		width string
	}{
		{"/ui/add-rule", "640px"},
		{"/ui/add-agent", "640px"},
		{"/ui/rules/import", "640px"},
		{"/ui/rules/r_a", "900px"},
		{"/ui/doctor", "1200px"},
		{"/ui/doctor/r_a", "1200px"},
	}
	for _, f := range frames {
		body := get(f.path + "?lang=en")
		frame := `<div class="page-frame" style="max-width:` + f.width + `">`
		i := strings.Index(body, frame)
		if i < 0 {
			t.Errorf("%s: no %s", f.path, frame)
			continue
		}
		rest := body[i:]
		h, m := strings.Index(rest, `<header class="topbar">`), strings.Index(rest, "<main>")
		if h < 0 || m < 0 || h > m {
			t.Errorf("%s: the header and the main content are not both inside the page frame, header first", f.path)
		}
		if n := strings.Count(body, "max-width:"+f.width); n != 1 {
			t.Errorf("%s: max-width:%s appears %d times, want only on the page frame", f.path, f.width, n)
		}
	}
}
func findRuleT(t *testing.T, st *store.Store, id string) proto.Rule {
	t.Helper()
	rules, err := st.Rules()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("rule %q not found", id)
	return proto.Rule{}
}

// TestPageBreadcrumbs は、ダッシュボード以外の共通の枠のページが上部の移動を左寄せのパンくずで
// 行い、右上のダッシュボードへ戻るボタンを持たないことを確かめる(設計文書 10.1 節)。上位の項目は
// リンクで、今いるページの項目はリンクにしない。ルールの一覧のページは無いので、ルールの階層は
// 作らない。
func TestPageBreadcrumbs(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return append(rules, proto.Rule{ID: "r_a", Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 25565, Hi: 25565}, Target: "192.168.1.20:25565", VPSMode: proto.ModeKernel, Enabled: true}), nil
	}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(&fakeBackend{st: st}))
	defer srv.Close()

	dash := `<a href="/">Dashboard</a>`
	cases := []struct {
		path    string
		links   []string
		current string
	}{
		{"/ui/doctor", []string{dash}, "Diagnostics"},
		{"/ui/doctor/r_a", []string{dash, `<a href="/ui/doctor">Diagnostics</a>`}, "TCP 25565 → home"},
		{"/ui/rules/r_a", []string{dash}, "TCP 25565 → home"},
		{"/ui/rules/r_a/check", []string{dash, `<a href="/ui/rules/r_a">TCP 25565 → home</a>`}, "Connection test"},
		{"/ui/add-rule", []string{dash}, "Add rule"},
		{"/ui/add-agent", []string{dash}, "Add agent"},
		{"/ui/rules/import", []string{dash}, "Import rules"},
	}
	for _, tc := range cases {
		assertBreadcrumb(t, tc.path, getBody(t, srv.URL+tc.path+"?lang=en"), tc.links, tc.current)
	}

	// 接続文字列を発行した後のページは、同じ「エージェントを追加」のページの結果である。
	resp, err := http.PostForm(srv.URL+"/ui/add-agent?lang=en", url.Values{"name": {"home2"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	assertBreadcrumb(t, "POST /ui/add-agent", string(b), []string{dash}, "Add agent")

	// 日本語の見出しでも同じ形になる。
	assertBreadcrumb(t, "/ui/doctor/r_a ja", getBody(t, srv.URL+"/ui/doctor/r_a?lang=ja"),
		[]string{`<a href="/">ダッシュボード</a>`, `<a href="/ui/doctor">診断</a>`}, "TCP 25565 → home")
}

// assertBreadcrumb は、ページのパンくずが links のリンクをこの順に持ち、current を今いるページの
// 項目(リンクではない)として末尾に持ち、ページにダッシュボードへ戻るボタンが無いことを確かめる。
func assertBreadcrumb(t *testing.T, name, body string, links []string, current string) {
	t.Helper()
	i := strings.Index(body, `<nav class="crumbs"`)
	if i < 0 {
		t.Errorf("%s: no breadcrumb", name)
		return
	}
	nav := body[i : i+strings.Index(body[i:], "</nav>")]
	at := 0
	for _, l := range links {
		k := strings.Index(nav[at:], l)
		if k < 0 {
			t.Errorf("%s: breadcrumb lacks %s after the earlier items:\n%s", name, l, nav)
			return
		}
		at += k + len(l)
	}
	if want := `<span aria-current="page">` + current + `</span></li></ol>`; !strings.Contains(body[i:], want) {
		t.Errorf("%s: breadcrumb does not end with the current item %q:\n%s", name, current, nav)
	}
	if n := strings.Count(nav, "<a "); n != len(links) {
		t.Errorf("%s: breadcrumb has %d links, want %d; the current page must not be a link", name, n, len(links))
	}
	if strings.Contains(body, "Back to dashboard") || strings.Contains(body, "ダッシュボードへ戻る") {
		t.Errorf("%s: a back-to-dashboard button is still on the page", name)
	}
	if strings.Contains(body, `class="top-actions"`) {
		t.Errorf("%s: the header still has an action area on the right", name)
	}
}
