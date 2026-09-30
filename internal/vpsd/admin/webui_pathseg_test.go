package admin

import (
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// oddRuleID は、そのままパスに埋めると、そのルールの無効化のボタンが別のルール r_b の削除へ送信する
// ルール ID である。ルール ID は取り込みのファイルと管理用 API から任意の文字列で入りうる。
const oddRuleID = "x/../r_b/delete?"

// sentinelRuleID は、そのままパスに埋めると、どのページにも無い経路 /ui/zz-sentinel へ解決する
// ルール ID である。ページのリンクがこの経路へ解決すれば、ID の中の `..` が区切りとして働いている。
const sentinelRuleID = "x/../../zz-sentinel?"

// newOddIDTestServer は、oddID(TCP 8080-8081)と r_b(TCP 8090)の 2 本のルールを持つサーバを立てる。エージェントの
// 無効化と有効化の呼び出しは返す一覧に記録する。
func newOddIDTestServer(t *testing.T, oddID string) (*httptest.Server, *store.Store, *[]string) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	rule := func(id string, lo, hi uint16) proto.Rule {
		return proto.Rule{
			ID: id, Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: lo, Hi: hi},
			Target: "192.168.1.20:80", VPSMode: proto.ModeKernel, Enabled: true,
			SourceAllow: []netip.Prefix{}, SourceDeny: []netip.Prefix{},
		}
	}
	if _, err := st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return append(rules, rule(oddID, 8080, 8081), rule("r_b", 8090, 8090)), nil
	}); err != nil {
		t.Fatal(err)
	}
	var changes []string
	b := &fakeBackend{st: st, agentChange: func(op, name string) (AgentDisabledResponse, error) {
		changes = append(changes, op+" "+name)
		return AgentDisabledResponse{Name: name, Changed: true, Generation: 1}, nil
	}}
	srv := httptest.NewServer(New(b))
	t.Cleanup(srv.Close)
	return srv, st, &changes
}

var linkAttr = regexp.MustCompile(`(?:href|action)="([^"]*)"`)

// pageLinks は、ページの href と action の値を、ブラウザと同じく base に対して解決した URL で返す。
func pageLinks(t *testing.T, base *url.URL, page string) []*url.URL {
	t.Helper()
	var out []*url.URL
	for _, m := range linkAttr.FindAllStringSubmatch(page, -1) {
		ref, err := url.Parse(html.UnescapeString(m[1]))
		if err != nil {
			t.Fatalf("unparsable link %q: %v", m[1], err)
		}
		out = append(out, base.ResolveReference(ref))
	}
	return out
}

func getPage(t *testing.T, u string) string {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", u, resp.StatusCode, b)
	}
	return string(b)
}

// TestRuleButtonsStayOnTheirOwnRule は、ルールの一覧のボタンが、ID に `/`、`..`、`?` を含むルールでも
// そのルール自身の経路へ送信することを確かめる(設計文書 10.1 節)。前の形では、oddRuleID の行の無効化
// のボタンが /ui/rules/r_b/delete へ送信し、別のルールを消した。同一オリジンなので、他オリジン発の
// 変更の拒否には掛からない。
// 変異の確認:rules.gohtml の無効化のボタンの PathSeg を外すと、r_b が消えて落ちる。
func TestRuleButtonsStayOnTheirOwnRule(t *testing.T) {
	srv, st, changes := newOddIDTestServer(t, oddRuleID)
	base, _ := url.Parse(srv.URL + "/ui/rules")
	var disables []*url.URL
	for _, u := range pageLinks(t, base, getPage(t, srv.URL+"/ui/rules")) {
		if strings.HasSuffix(u.EscapedPath(), "/disable") || strings.HasSuffix(u.RawQuery, "/disable") {
			disables = append(disables, u)
		}
	}
	if len(disables) != 2 {
		t.Fatalf("found %d disable buttons, want one per rule: %v", len(disables), disables)
	}
	for _, u := range disables {
		resp, err := http.PostForm(u.String(), url.Values{})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	rules, err := st.Rules()
	if err != nil {
		t.Fatal(err)
	}
	enabled := map[string]bool{}
	for _, r := range rules {
		enabled[r.ID] = r.Enabled
	}
	if len(rules) != 2 {
		t.Fatalf("rules after pressing both disable buttons: %v; want both rules kept", enabled)
	}
	if enabled[oddRuleID] || enabled["r_b"] {
		t.Errorf("each disable button must disable its own rule, got enabled = %v", enabled)
	}
	if len(*changes) != 0 {
		t.Errorf("a rule's button changed an agent: %v", *changes)
	}
}

// TestRuleIDIsOnePathSegmentOnEveryPage は、ルール ID をパスに埋めるどのページでも、ID が 1 つの
// パスの区切りとして埋まり、ブラウザが解決しても ID の中の `..` や `?` が区切りとして働かないことを
// 確かめる。
// 変異の確認:どれか 1 つのテンプレートか、Go の側で作るパンくず(疎通確認のページ)の pathSegment を
// 外すと落ちる。
func TestRuleIDIsOnePathSegmentOnEveryPage(t *testing.T) {
	srv, _, _ := newOddIDTestServer(t, sentinelRuleID)
	seg := pathSegment(sentinelRuleID)
	for _, p := range []string{"/ui/rules", "/ui/rules/" + seg, "/ui/rules/" + seg + "/check", "/ui/doctor", "/ui/doctor/" + seg, "/ui/agents/home"} {
		base, _ := url.Parse(srv.URL + p)
		found := false
		for _, u := range pageLinks(t, base, getPage(t, base.String())) {
			ep := u.EscapedPath()
			if strings.HasPrefix(ep, "/ui/zz-sentinel") {
				t.Errorf("%s: a link resolves outside its rule's route: %s", p, u)
			}
			if strings.Contains(ep, "/"+seg) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no link carries the rule ID as one escaped path segment %q", p, seg)
		}
	}
}

// TestRuleSettingsRedirectKeepsTheRuleID は、設定の保存、分割、統合、拒否リストの変更の後の戻り先(Location)が、ID をパスの区切りとして
// escape した詳細ページであることを確かめる。
// 変異の確認:uiSaveSettings、uiRuleSplit、uiRuleMerge、uiSourceAdd、uiSourceRm の戻り先の
// pathSegment を外すと、戻り先が別の経路になって落ちる。
func TestRuleSettingsRedirectKeepsTheRuleID(t *testing.T) {
	srv, st, _ := newOddIDTestServer(t, oddRuleID)
	seg := pathSegment(oddRuleID)
	resp, body := postSettings(t, srv.URL, seg, url.Values{"note": {"n"}})
	if req := resp.Request; req == nil || req.Method != http.MethodGet || req.URL.EscapedPath() != "/ui/rules/"+seg || resp.StatusCode != http.StatusOK {
		t.Fatalf("saving must redirect back to the rule's own detail page; got %v %d: %s", resp.Request.URL, resp.StatusCode, body)
	}
	// 分割と統合の後の戻り先も同じ。分割は元の ID を前半に残し、統合は元の ID で後半を取り込む
	resp, err := http.PostForm(srv.URL+"/ui/rules/"+seg+"/split", url.Values{"at": {"8081"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if req := resp.Request; req == nil || req.Method != http.MethodGet || req.URL.EscapedPath() != "/ui/rules/"+seg || resp.StatusCode != http.StatusOK {
		t.Fatalf("split must redirect back to the rule's own detail page; got %v %d", resp.Request.URL, resp.StatusCode)
	}
	var tail string
	rules, err := st.Rules()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.ID != oddRuleID && r.ID != "r_b" {
			tail = r.ID
		}
	}
	if tail == "" {
		t.Fatalf("split left no new rule: %v", rules)
	}
	resp, err = http.PostForm(srv.URL+"/ui/rules/"+seg+"/merge", url.Values{"other": {tail}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if req := resp.Request; req == nil || req.Method != http.MethodGet || req.URL.EscapedPath() != "/ui/rules/"+seg || resp.StatusCode != http.StatusOK {
		t.Fatalf("merge must redirect back to the rule's own detail page; got %v %d", resp.Request.URL, resp.StatusCode)
	}
	// 拒否リストの追加と削除の後の戻り先も同じ
	for _, step := range []struct{ path, field string }{{"deny/add", "cidrs"}, {"deny/rm", "cidr"}} {
		resp, err := http.PostForm(srv.URL+"/ui/rules/"+seg+"/"+step.path, url.Values{step.field: {"203.0.113.7"}})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if req := resp.Request; req == nil || req.Method != http.MethodGet || req.URL.EscapedPath() != "/ui/rules/"+seg || resp.StatusCode != http.StatusOK {
			t.Fatalf("%s must redirect back to the rule's own detail page; got %v %d", step.path, resp.Request.URL, resp.StatusCode)
		}
	}
}

// TestClientCheckConnectivityEscapesTheRuleID は、CLI の疎通確認の依頼が、ID をパスの 1 つの区切りと
// してサーバに届けることを確かめる。
// 変異の確認:client.go の url.PathEscape を外すと、サーバが別の ID を受け取るか、誤りになって落ちる。
func TestClientCheckConnectivityEscapesTheRuleID(t *testing.T) {
	var got string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/rules/{id}/check", func(w http.ResponseWriter, r *http.Request) {
		got = r.PathValue("id")
		writeJSON(w, http.StatusOK, ConnCheck{OK: true})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := &Client{Base: srv.URL}
	if _, err := c.CheckConnectivity(oddRuleID); err != nil {
		t.Fatalf("CheckConnectivity: %v", err)
	}
	if got != oddRuleID {
		t.Errorf("server received rule ID %q, want %q", got, oddRuleID)
	}
}

// TestPathSegment は、`/`、`?`、`#` と、区切り全体が `.` か `..` の ID を % の形にすることを確かめる。
func TestPathSegment(t *testing.T) {
	for in, want := range map[string]string{
		"r_01J":      "r_01J",
		"a/b?c#d":    "a%2Fb%3Fc%23d",
		".":          "%2E",
		"..":         "%2E%2E",
		"...":        "...",
		"x/../r_b/d": "x%2F..%2Fr_b%2Fd",
	} {
		if got := pathSegment(in); got != want {
			t.Errorf("pathSegment(%q) = %q, want %q", in, got, want)
		}
	}
}
