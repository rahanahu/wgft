package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
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
	st     *store.Store
	mode   string
	agents []AgentInfo // 空なら未接続の "home" 1 台(既定)。ルールの適用状態のテストは差し替える
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
func (b *fakeBackend) Batch(req BatchRequest) (*store.BatchResult, error) {
	return b.st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		del := make(map[string]bool, len(req.Delete))
		for _, id := range req.Delete {
			del[id] = true
		}
		kept := make([]proto.Rule, 0, len(rules))
		for _, r := range rules {
			if !del[r.ID] {
				kept = append(kept, r)
			}
		}
		byID := make(map[string]int, len(kept))
		for i, r := range kept {
			byID[r.ID] = i
		}
		for _, u := range req.Upsert {
			if i, ok := byID[u.ID]; ok {
				kept[i] = u
			} else {
				byID[u.ID] = len(kept)
				kept = append(kept, u)
			}
		}
		return kept, nil
	})
}

func TestHostOriginAndBatch(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := httptest.NewServer(New(st, &fakeBackend{st: st}))
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
	srv := httptest.NewServer(New(st, &fakeBackend{st: st}))
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

// TestAddRuleFormFollowsMode は、ルール追加フォームがサーバーの転送方式(kernel/userspace)に
// 応じて出し分けることを確かめる(仕様 6.3 節)。userspace ではルールごとの kernel/proxy の
// 選択に意味が無いので、ラジオ群を出さず PROXY protocol のチェックボックス 1 つにする。
func TestAddRuleFormFollowsMode(t *testing.T) {
	get := func(t *testing.T, mode string) string {
		t.Helper()
		st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		srv := httptest.NewServer(New(st, &fakeBackend{st: st, mode: mode}))
		defer srv.Close()
		resp, err := http.Get(srv.URL + "/ui/add-rule")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /ui/add-rule status = %d, want 200", resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}

	t.Run("kernel", func(t *testing.T) {
		body := get(t, "kernel")
		if !strings.Contains(body, `name="vps_mode" value="kernel"`) || !strings.Contains(body, `name="vps_mode" value="proxy"`) {
			t.Error("kernel mode: expected the vps_mode radio group to be present")
		}
		if strings.Contains(body, `id="f-proxy-userspace"`) {
			t.Error("kernel mode: unexpected userspace PROXY protocol checkbox")
		}
	})

	t.Run("userspace", func(t *testing.T) {
		body := get(t, "userspace")
		if strings.Contains(body, `name="vps_mode" value="kernel" checked`) || strings.Contains(body, `name="vps_mode" value="proxy"`) {
			t.Error("userspace mode: the vps_mode radio group must be absent")
		}
		if !strings.Contains(body, `id="f-proxy-userspace"`) || !strings.Contains(body, `type="checkbox"`) {
			t.Error("userspace mode: expected the PROXY protocol checkbox")
		}
		if !strings.Contains(body, `id="f-vps-mode-userspace"`) {
			t.Error("userspace mode: expected the hidden vps_mode field the checkbox drives")
		}
	})
}

// newDetailTestServer は 1 件のルール(r_a, UDP 2456-2457)を持つ管理 API サーバーを立てる。
// ルール詳細ページのテストで使う。
func newDetailTestServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return append(rules, proto.Rule{
			ID: "r_a", Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2456, Hi: 2457},
			Target: "192.168.1.20:2456", VPSMode: proto.ModeKernel, Enabled: true,
			SourceAllow: []netip.Prefix{}, SourceDeny: []netip.Prefix{},
		}), nil
	}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(st, &fakeBackend{st: st}))
	t.Cleanup(srv.Close)
	return srv, st
}

// newSplitMergeTestServer は r_a(UDP 2456-2457)に、r_a と統合できる隣接ルール
// r_b(2458-2459)を添える。r_c(2460-2461)は r_b にだけ隣接し、拒否リストが違うので
// r_b とは統合できず、r_a とは隣接すらしない(仕様 10.1、10.2 節)。
func newSplitMergeTestServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	rule := func(id string, lo, hi uint16, targetPort int) proto.Rule {
		return proto.Rule{
			ID: id, Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: lo, Hi: hi},
			Target: fmt.Sprintf("192.168.1.20:%d", targetPort), VPSMode: proto.ModeKernel, Enabled: true,
			SourceAllow: []netip.Prefix{}, SourceDeny: []netip.Prefix{},
		}
	}
	rC := rule("r_c", 2460, 2461, 2460)
	rC.SourceDeny = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	if _, err := st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return append(rules, rule("r_a", 2456, 2457, 2456), rule("r_b", 2458, 2459, 2458), rC), nil
	}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(st, &fakeBackend{st: st}))
	t.Cleanup(srv.Close)
	return srv, st
}

// TestRuleDetailShowsSplitAndMergeSections は詳細ページに分割・統合の両区画が出て、
// 統合区画には合う隣接ルール(r_b)だけが候補として出ることを確かめる(仕様 10.1 節)。
func TestRuleDetailShowsSplitAndMergeSections(t *testing.T) {
	srv, _ := newSplitMergeTestServer(t)

	resp, err := http.Get(srv.URL + "/ui/rules/r_a?lang=en")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	s := string(body)

	if !strings.Contains(s, `id="split-at"`) || !strings.Contains(s, `<option value="2457">2457</option>`) {
		t.Errorf("split section missing the split-point select with port 2457: %s", s)
	}
	if !strings.Contains(s, `action="/ui/rules/r_a/merge"`) || !strings.Contains(s, `value="r_b"`) {
		t.Errorf("merge section missing a candidate button for r_b: %s", s)
	}
	if strings.Contains(s, `value="r_c"`) {
		t.Errorf("merge section must not offer r_c (not adjacent to r_a): %s", s)
	}
}

// TestRuleDetailSplit はルール詳細ページからの分割を確かめる。head は元の ID のまま
// 縮まり、tail は実効宛先を保った新しい ID で作られ、どちらも 1 バッチで反映される
// (仕様 5.4、10.1 節)。
func TestRuleDetailSplit(t *testing.T) {
	srv, st := newSplitMergeTestServer(t)

	resp, err := http.PostForm(srv.URL+"/ui/rules/r_a/split", url.Values{"at": {"2457"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if req := resp.Request; req == nil || !strings.HasSuffix(req.URL.Path, "/ui/rules/r_a") {
		t.Errorf("split must redirect to the head's (unchanged) detail page, got %v", req)
	}

	rules, err := st.Rules()
	if err != nil {
		t.Fatal(err)
	}
	head := findRuleT(t, st, "r_a")
	if head.ListenPort != (proto.PortRange{Lo: 2456, Hi: 2456}) {
		t.Errorf("head listen_port = %v, want 2456", head.ListenPort)
	}
	var tail *proto.Rule
	for i := range rules {
		if rules[i].ListenPort == (proto.PortRange{Lo: 2457, Hi: 2457}) {
			tail = &rules[i]
		}
	}
	if tail == nil {
		t.Fatal("no rule covers the split-off port 2457")
	}
	if tail.Target != "192.168.1.20:2457" {
		t.Errorf("tail target = %q, want 192.168.1.20:2457 (unchanged effective target)", tail.Target)
	}
}

// TestRuleDetailSplitInvalid は範囲外の分割位置が誤りとして再表示され、何も変えないことを
// 確かめる。
func TestRuleDetailSplitInvalid(t *testing.T) {
	srv, st := newSplitMergeTestServer(t)
	before, err := st.Rules()
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.PostForm(srv.URL+"/ui/rules/r_a/split", url.Values{"at": {"9999"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("invalid split status = %d, want 200 (re-rendered with the error)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "must be inside range") {
		t.Errorf("expected an out-of-range error: %s", body)
	}
	after, err := st.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Errorf("an invalid split must not change the rule count: before=%d after=%d", len(before), len(after))
	}
}

// TestRuleDetailMerge は統合が self(パスの r_a)の ID を残し、other(r_b)を削除して
// listen_port を広げることを確かめる(仕様 10.1、10.2 節)。
func TestRuleDetailMerge(t *testing.T) {
	srv, st := newSplitMergeTestServer(t)

	resp, err := http.PostForm(srv.URL+"/ui/rules/r_a/merge", url.Values{"other": {"r_b"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if req := resp.Request; req == nil || !strings.HasSuffix(req.URL.Path, "/ui/rules/r_a") {
		t.Errorf("merge must redirect to self's (surviving) detail page, got %v", req)
	}

	merged := findRuleT(t, st, "r_a")
	if merged.ListenPort != (proto.PortRange{Lo: 2456, Hi: 2459}) {
		t.Errorf("merged listen_port = %v, want 2456-2459", merged.ListenPort)
	}
	rules, err := st.Rules()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.ID == "r_b" {
			t.Error("r_b must be deleted after merging into r_a")
		}
	}
}

// TestRuleDetailMergeRejectsBlocked は、条件の揃わない隣接ルールとの統合が誤りとして
// 再表示され、理由(拒否リストの違い)を含むことを確かめる(仕様 10.1 節)。
func TestRuleDetailMergeRejectsBlocked(t *testing.T) {
	srv, st := newSplitMergeTestServer(t)

	resp, err := http.PostForm(srv.URL+"/ui/rules/r_a/merge", url.Values{"other": {"r_c"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("blocked merge status = %d, want 200 (re-rendered with the error)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "not adjacent") {
		t.Errorf("expected the not-adjacent reason (r_a and r_c are not adjacent): %s", body)
	}
	if r := findRuleT(t, st, "r_a"); r.ListenPort != (proto.PortRange{Lo: 2456, Hi: 2457}) {
		t.Errorf("a rejected merge must not change r_a: %v", r.ListenPort)
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

// TestRuleDetailDenyList は拒否リストの追加・削除と、不正な行の扱いを確かめる(仕様 10.1 節)。
func TestRuleDetailDenyList(t *testing.T) {
	srv, st := newDetailTestServer(t)

	// 不正な行が 1 つでもあれば何も保存せず、その行番号と内容を含むエラーを返す
	resp, err := http.PostForm(srv.URL+"/ui/rules/r_a/deny/add", url.Values{"cidrs": {"203.0.113.7\nnot-a-cidr"}})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("invalid deny add status = %d, want 200 (re-rendered with the error)", resp.StatusCode)
	}
	if !strings.Contains(string(body), "line 2") || !strings.Contains(string(body), "not-a-cidr") {
		t.Errorf("error must name the bad line: %s", body)
	}
	if !strings.Contains(string(body), "203.0.113.7\nnot-a-cidr") {
		t.Error("the textarea must keep the entered input on error")
	}
	if len(findRuleT(t, st, "r_a").SourceDeny) != 0 {
		t.Fatal("invalid deny add must not save anything")
	}

	// 単独アドレスは /32 で補い、重複は加えない
	resp, err = http.PostForm(srv.URL+"/ui/rules/r_a/deny/add", url.Values{"cidrs": {"203.0.113.7\n203.0.113.7"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := findRuleT(t, st, "r_a").SourceDeny; len(got) != 1 || got[0].String() != "203.0.113.7/32" {
		t.Fatalf("deny add = %v, want a single 203.0.113.7/32", got)
	}

	resp, err = http.Get(srv.URL + "/ui/rules/r_a")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "203.0.113.7/32") {
		t.Errorf("detail page must list the deny entry: %s", body)
	}

	resp, err = http.PostForm(srv.URL+"/ui/rules/r_a/deny/rm", url.Values{"cidr": {"203.0.113.7"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := findRuleT(t, st, "r_a").SourceDeny; len(got) != 0 {
		t.Fatalf("deny rm = %v, want empty", got)
	}
}

// TestRuleDetailAllowListConfirm は、許可リストを空から作る操作と、最後の 1 件を外す操作に
// data-confirm が付くことを確かめる(全開放/全遮断に変わる操作。仕様 10.1 節)。
func TestRuleDetailAllowListConfirm(t *testing.T) {
	srv, st := newDetailTestServer(t)

	get := func() string {
		resp, err := http.Get(srv.URL + "/ui/rules/r_a")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}

	// リストが空の間、追加フォームは確認を求める
	body := get()
	if !strings.Contains(body, `action="/ui/rules/r_a/allow/add"`) || !strings.Contains(body, T("ja", "confirmAllowFirst")) {
		t.Errorf("the allow add form must carry a confirm message while the list is empty: %s", body)
	}

	resp, err := http.PostForm(srv.URL+"/ui/rules/r_a/allow/add", url.Values{"cidrs": {"198.51.100.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := findRuleT(t, st, "r_a").SourceAllow; len(got) != 1 {
		t.Fatalf("allow add = %v, want 1 entry", got)
	}

	// 1 件だけになった後は、追加フォームに確認は要らず、その 1 件の削除フォームに確認が付く
	body = get()
	if strings.Contains(body, `action="/ui/rules/r_a/allow/add" class="inline-form" data-confirm=`) {
		t.Errorf("the allow add form must not require confirmation once the list is non-empty: %s", body)
	}
	if !strings.Contains(body, `action="/ui/rules/r_a/allow/rm" data-confirm="`+T("ja", "confirmAllowLast")+`"`) {
		t.Errorf("removing the sole allow entry must carry a confirm message: %s", body)
	}

	resp, err = http.PostForm(srv.URL+"/ui/rules/r_a/allow/rm", url.Values{"cidr": {"198.51.100.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := findRuleT(t, st, "r_a").SourceAllow; len(got) != 0 {
		t.Fatalf("allow rm = %v, want empty", got)
	}
}

// TestRuleDetailRates はレート制限の保存と「制限しない」による解除を確かめる(仕様 10.1 節)。
func TestRuleDetailRates(t *testing.T) {
	srv, st := newDetailTestServer(t)

	post := func(vals url.Values) *http.Response {
		resp, err := http.PostForm(srv.URL+"/ui/rules/r_a/rates", vals)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// 値の入っていない欄は、no limit のチェックが無ければ誤りとして何も保存しない
	resp := post(url.Values{
		"per_source_count": {""}, "per_source_unit": {"second"},
		"new_flow_nolimit": {"1"}, "new_flow_unit": {"second"},
		"packet_nolimit": {"1"}, "packet_unit": {"second"},
	})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("missing value without no-limit: status = %d, want 200 (re-rendered with the error)", resp.StatusCode)
	}
	if !strings.Contains(string(body), T("ja", "rateRequired")) {
		t.Errorf("expected the rateRequired message: %s", body)
	}
	if r := findRuleT(t, st, "r_a"); r.PerSourceRate != nil || r.NewFlowRate != nil || r.PacketRate != nil {
		t.Fatalf("an invalid rate submission must not save anything: %+v", r)
	}

	// 有効な値は保存され、Rate.String() の形で読める
	resp = post(url.Values{
		"per_source_count": {"10"}, "per_source_unit": {"minute"},
		"new_flow_nolimit": {"1"}, "new_flow_unit": {"second"},
		"packet_nolimit": {"1"}, "packet_unit": {"second"},
	})
	resp.Body.Close()
	r := findRuleT(t, st, "r_a")
	if r.PerSourceRate == nil || r.PerSourceRate.String() != "10/minute" {
		t.Fatalf("per_source_rate = %v, want 10/minute", r.PerSourceRate)
	}
	if r.NewFlowRate != nil || r.PacketRate != nil {
		t.Fatalf("new_flow_rate/packet_rate must stay unset: %+v", r)
	}

	// no limit に切り替えると外れる
	resp = post(url.Values{
		"per_source_nolimit": {"1"}, "per_source_unit": {"minute"},
		"new_flow_nolimit": {"1"}, "new_flow_unit": {"second"},
		"packet_nolimit": {"1"}, "packet_unit": {"second"},
	})
	resp.Body.Close()
	if r := findRuleT(t, st, "r_a"); r.PerSourceRate != nil {
		t.Fatalf("per_source_rate after no-limit = %v, want nil", r.PerSourceRate)
	}
}

// TestRuleDetailMeta は、詳細ページに取り込まれたグループ/説明の編集がルール詳細ページへ戻ることを確かめる。
func TestRuleDetailMeta(t *testing.T) {
	srv, st := newDetailTestServer(t)
	resp, err := http.PostForm(srv.URL+"/ui/rules/r_a/meta", url.Values{"group": {"valheim"}, "note": {"weekend"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if req := resp.Request; req == nil || !strings.HasSuffix(req.URL.Path, "/ui/rules/r_a") {
		t.Errorf("saving meta must redirect back to the detail page, got %v", req)
	}
	r := findRuleT(t, st, "r_a")
	if r.Group != "valheim" || r.Note != "weekend" {
		t.Errorf("meta not saved: group=%q note=%q", r.Group, r.Note)
	}
}

// TestAddRuleDisabled は、追加フォームの「無効のまま追加する」チェックボックスが
// enabled=false でルールを作ることを確かめる(仕様 10.1 節、rule add --disabled 相当)。
func TestAddRuleDisabled(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := httptest.NewServer(New(st, &fakeBackend{st: st}))
	defer srv.Close()

	resp, err := http.PostForm(srv.URL+"/ui/add-rule", url.Values{
		"agent": {"home"}, "proto": {"tcp"}, "listen_port": {"25565"}, "target": {"192.168.1.20:25565"},
		"vps_mode": {"kernel"}, "disabled": {"1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	rules, err := st.Rules()
	if err != nil || len(rules) != 1 {
		t.Fatalf("rules = %v, %v", rules, err)
	}
	if rules[0].Enabled {
		t.Error("the disabled checkbox must add the rule with enabled=false")
	}
}
