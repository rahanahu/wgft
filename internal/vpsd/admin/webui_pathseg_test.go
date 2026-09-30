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

// newOddIDTestServer は、oddID(TCP 8080-8081)と r_b(TCP 8082)の 2 本のルールを持つサーバを立てる。
// どちらも拒否リストと許可リストを 1 件ずつ持ち、r_b は oddID と統合できる隣なので、詳細ページには
// 拒否リストと許可リストの削除のボタンと、統合のボタンが出る。エージェントの無効化と有効化の呼び出しは
// 返す一覧に記録する。
func newOddIDTestServer(t *testing.T, oddID string) (*httptest.Server, *store.Store, *[]string) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	rule := func(id string, lo, hi uint16, target string) proto.Rule {
		return proto.Rule{
			ID: id, Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: lo, Hi: hi},
			Target: target, VPSMode: proto.ModeKernel, Enabled: true,
			SourceAllow: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
			SourceDeny:  []netip.Prefix{netip.MustParsePrefix("192.0.2.66/32")},
		}
	}
	if _, err := st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return append(rules, rule(oddID, 8080, 8081, "192.168.1.20:80"), rule("r_b", 8082, 8082, "192.168.1.20:82")), nil
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

// pageLinks は、ページの href と action の値を、base に対して RFC 3986 の規則(net/url)で解決した URL で
// 返す。ブラウザは WHATWG URL 標準で解決するので、この関数はブラウザの代わりにならない。両者は %2E を
// 区切りの `.` と見なすかどうかで異なることが分かっており、試験の ID はその形の区切りを含まない。
// 実際のブラウザでの解決は確かめていない。
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
// そのルール自身の経路へ送信することを確かめる(設計文書 10.2 節)。前の形では、oddRuleID の行の無効化
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
// パスの区切りとして埋まり、リンクを解決しても ID の中の `..` や `?` が区切りとして働かないことを
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
// してサーバに届けることを確かめる。`.` と `..` も、Go のクライアントとサーバの間では区切りとして
// 働かずに届く。
// 変異の確認:client.go の pathSegment を外すと、サーバが別の ID を受け取るか、誤りになって落ちる。
// url.PathEscape に変えると、`.` と `..` の依頼が別の経路になって落ちる。
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
	for _, id := range []string{oddRuleID, ".", ".."} {
		got = ""
		if _, err := c.CheckConnectivity(id); err != nil {
			t.Errorf("CheckConnectivity(%q): %v", id, err)
			continue
		}
		if got != id {
			t.Errorf("server received rule ID %q, want %q", got, id)
		}
	}
}

// formRe と hiddenRe は、ページのフォームの送信先と hidden の値を取り出す。
var (
	formRe   = regexp.MustCompile(`(?s)<form[^>]*action="([^"]*)"[^>]*>(.*?)</form>`)
	hiddenRe = regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)">`)
)

// TestOrphanBandButtonStaysOnItsAgent は、未登録のエージェントの帯の削除のボタンが、エージェント名に
// `/`、`..`、`?` を含んでも、その名前の経路へ送信することを確かめる。ルールの agent は空でない任意の
// 文字列で取り込めるので、帯の名前は登録済みのエージェントの名前の規則に縛られない。前の形では、
// agent が `x/../home/disable?` の帯のボタンが登録済みの home を無効にし、`x/../../rules/r_b/delete?`
// の帯のボタンが別のルール r_b を消した。
// 変異の確認:rules.gohtml の帯の送信先の PathSeg を外すと、home が無効になり r_b が消えて落ちる。
func TestOrphanBandButtonStaysOnItsAgent(t *testing.T) {
	srv, st, changes := newOddIDTestServer(t, "r_a")
	orphans := map[string]string{"r_o1": "x/../home/disable?", "r_o2": "x/../../rules/r_b/delete?"}
	if _, err := st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		port := uint16(9001)
		for _, id := range []string{"r_o1", "r_o2"} {
			rules = append(rules, proto.Rule{ID: id, Agent: orphans[id], Proto: proto.TCP, ListenPort: proto.PortRange{Lo: port, Hi: port},
				Target: "192.168.1.20:80", VPSMode: proto.ModeKernel, Enabled: true})
			port++
		}
		return rules, nil
	}); err != nil {
		t.Fatal(err)
	}
	base, _ := url.Parse(srv.URL + "/ui/rules")
	// 帯を 1 本押すとルール集合のハッシュが変わるので、押すたびにページを読み直し、まだ押していない帯を押す
	pressed := map[string]bool{}
	for range orphans {
		var band []string
		for _, m := range formRe.FindAllStringSubmatch(getPage(t, base.String()), -1) {
			if strings.Contains(m[2], `name="rules_digest"`) && !pressed[m[1]] {
				band = m
				break
			}
		}
		if band == nil {
			t.Fatal("no orphan band left to press")
		}
		pressed[band[1]] = true
		ref, err := url.Parse(html.UnescapeString(band[1]))
		if err != nil {
			t.Fatal(err)
		}
		form := url.Values{}
		for _, h := range hiddenRe.FindAllStringSubmatch(band[2], -1) {
			form.Set(h[1], html.UnescapeString(h[2]))
		}
		resp, err := http.PostForm(base.ResolveReference(ref).String(), form)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if len(*changes) != 0 {
		t.Errorf("an orphan band's button changed an agent: %v", *changes)
	}
	rules, err := st.Rules()
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range rules {
		ids = append(ids, r.ID)
	}
	if got := strings.Join(ids, ","); got != "r_a,r_b" {
		t.Errorf("rules after pressing both orphan bands = %s, want r_a,r_b: each band deletes only its own agent's rules", got)
	}
}

// TestPathSegment は、`/`、`?`、`#` と、区切り全体が `.` か `..` の ID を % の形にすることを確かめる。
// `.` と `..` の %2E の形は Go のクライアントとサーバの間でだけ効く。ブラウザはこの形も区切りと見なす
// ので、この 2 つの ID は Rule.Validate が拒む(設計文書 10.2 節)。
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
