package admin

import (
	"bytes"
	"encoding/json"
	"html"
	"io"
	"mime/multipart"
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

// newImportTestServer は 2 件のルール(r_keep, r_gone)を持つ管理 API サーバーを立てる。
// 書き出し・読み込みのテスト(仕様 10.1 節)で使う。
func newImportTestServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return append(rules,
			proto.Rule{ID: "r_keep", Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 443, Hi: 443}, Target: "192.168.1.30:443", VPSMode: proto.ModeKernel, Enabled: true},
			proto.Rule{ID: "r_gone", Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 27015, Hi: 27015}, Target: "192.168.1.30:27015", VPSMode: proto.ModeKernel, Enabled: true},
		), nil
	}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(st, &fakeBackend{st: st}))
	t.Cleanup(srv.Close)
	return srv, st
}

func multipartUpload(t *testing.T, target, filename string, content []byte) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", target, &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

var hiddenFieldRe = regexp.MustCompile(`(?s)name="(content|generation|digest)" value="(.*?)"`)

// extractHiddenFields は確認ページから apply フォームの 3 つの hidden 欄を取り出す。
// html/template が属性値の中の引用符をエンティティにするため、html.UnescapeString で
// 元の文字列に戻す(ブラウザの送信と同じ形にする)。
func extractHiddenFields(t *testing.T, page string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, m := range hiddenFieldRe.FindAllStringSubmatch(page, -1) {
		out[m[1]] = html.UnescapeString(m[2])
	}
	if len(out) != 3 {
		t.Fatalf("expected content/generation/digest hidden fields in the confirm page, got %v:\n%s", out, page)
	}
	return out
}

// TestRulesExport は書き出しが `rule ls --json` の `.rules` と同じ形の JSON 配列を、
// ダウンロード用のヘッダ付きで返すこと、その配列を読み込むと差分が「変わらない」だけに
// なることを確かめる(仕様 10.1 節)。
func TestRulesExport(t *testing.T) {
	srv, st := newImportTestServer(t)

	resp, err := http.Get(srv.URL + "/ui/rules/export")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "rules.json") {
		t.Errorf("Content-Disposition = %q, missing rules.json", cd)
	}
	body, _ := io.ReadAll(resp.Body)
	var exported []proto.Rule
	if err := json.Unmarshal(body, &exported); err != nil {
		t.Fatalf("export body is not a JSON array of rules: %v", err)
	}
	current, _ := st.Rules()
	if len(exported) != len(current) {
		t.Fatalf("exported %d rules, want %d", len(exported), len(current))
	}

	confirm := multipartUpload(t, srv.URL+"/ui/rules/import?lang=en", "rules.json", body)
	defer confirm.Body.Close()
	page, _ := io.ReadAll(confirm.Body)
	if !strings.Contains(string(page), "Unchanged 2") || strings.Contains(string(page), "Added 1") {
		t.Errorf("re-importing the export unchanged must show everything as unchanged: %s", page)
	}
}

// TestImportConfirmShowsDiff は追加・変更・削除が確認ページに出て、削除には
// data-confirm が付くことを確かめる(仕様 10.1 節)。
func TestImportConfirmShowsDiff(t *testing.T) {
	srv, _ := newImportTestServer(t)
	desired := []proto.Rule{
		{ID: "r_keep", Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 443, Hi: 443}, Target: "192.168.1.31:443", VPSMode: proto.ModeKernel, Enabled: true},
		{Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 25565, Hi: 25565}, Target: "192.168.1.30:25565", VPSMode: proto.ModeKernel, Enabled: true},
	}
	body, err := json.Marshal(desired)
	if err != nil {
		t.Fatal(err)
	}

	resp := multipartUpload(t, srv.URL+"/ui/rules/import?lang=en", "rules.json", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	page, _ := io.ReadAll(resp.Body)
	s := string(page)
	for _, want := range []string{
		"Added 1", "Changed 1", "Deleted 1", "Unchanged 0",
		"destination", "192.168.1.30:443", "192.168.1.31:443",
		"This rule will be removed",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("confirm page missing %q: %s", want, s)
		}
	}
	if !strings.Contains(s, `data-confirm="This includes deletions. Apply?"`) {
		t.Errorf("confirm form must carry data-confirm because of the deletion: %s", s)
	}
	if strings.Contains(s, `type="submit" disabled`) {
		t.Errorf("a diff with no issues must not withhold the apply button: %s", s)
	}
}

// TestImportConfirmShowsSourceSetContent は、拒否リストの CIDR を同じ件数のまま別のものへ
// 差し替えた読み込みが、確認ページに実際の CIDR の増減("+198.51.100.0/24 -203.0.113.0/24"
// のような形)を出すことを確かめる(仕様 10.1 節)。件数だけを見ていた頃は、件数が変わらない
// ためこの変更が unchanged と誤って表示されていた。
func TestImportConfirmShowsSourceSetContent(t *testing.T) {
	srv, st := newImportTestServer(t)
	if _, err := st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		for i := range rules {
			if rules[i].ID == "r_keep" {
				rules[i].SourceDeny = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
			}
		}
		return rules, nil
	}); err != nil {
		t.Fatal(err)
	}

	desired := []proto.Rule{
		{ID: "r_keep", Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 443, Hi: 443}, Target: "192.168.1.30:443", VPSMode: proto.ModeKernel, Enabled: true,
			SourceDeny: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}},
		{ID: "r_gone", Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 27015, Hi: 27015}, Target: "192.168.1.30:27015", VPSMode: proto.ModeKernel, Enabled: true},
	}
	body, err := json.Marshal(desired)
	if err != nil {
		t.Fatal(err)
	}

	resp := multipartUpload(t, srv.URL+"/ui/rules/import?lang=en", "rules.json", body)
	defer resp.Body.Close()
	page, _ := io.ReadAll(resp.Body)
	s := html.UnescapeString(string(page))
	if !strings.Contains(s, "Changed 1") || strings.Contains(s, "Unchanged 2") {
		t.Errorf("a same-count deny-list replacement must show as changed, not unchanged: %s", s)
	}
	if !strings.Contains(s, "+198.51.100.0/24") || !strings.Contains(s, "-203.0.113.0/24") {
		t.Errorf("confirm page must show the added/removed CIDRs, not just a count: %s", s)
	}
}

// TestImportConfirmWithholdsApplyOnIssues は、未登録のエージェントを指すルールが確認
// ページに出て、適用ボタンが無効になることを確かめる(仕様 10.1 節)。
func TestImportConfirmWithholdsApplyOnIssues(t *testing.T) {
	srv, _ := newImportTestServer(t)
	desired := []proto.Rule{
		{ID: "r_bad", Agent: "unknown-agent", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 8080, Hi: 8080}, Target: "192.168.1.40:8080", VPSMode: proto.ModeKernel, Enabled: true},
	}
	body, err := json.Marshal(desired)
	if err != nil {
		t.Fatal(err)
	}

	resp := multipartUpload(t, srv.URL+"/ui/rules/import?lang=en", "rules.json", body)
	defer resp.Body.Close()
	page, _ := io.ReadAll(resp.Body)
	s := string(page)
	if !strings.Contains(s, "Cannot apply") || !strings.Contains(s, "unknown-agent") || !strings.Contains(s, "is not registered") {
		t.Errorf("expected an unregistered-agent issue to be listed: %s", s)
	}
	if !strings.Contains(s, `type="submit" disabled`) {
		t.Errorf("the apply button must be disabled when issues are present: %s", s)
	}
}

// TestImportApplyAndStaleRefusal は、確認ページを描いた後にルール集合が変わると適用を
// 拒むこと、変わらないまま出せば適用が通ることを確かめる(仕様 10.1 節)。
// group/note/接続元制限/レートだけの変更は世代を上げない(5.3 節)ので、ここでは世代を
// 動かさない追加でハッシュだけがずれる状況を作る。
func TestImportApplyAndStaleRefusal(t *testing.T) {
	srv, st := newImportTestServer(t)
	desired := []proto.Rule{
		{ID: "r_keep", Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 443, Hi: 443}, Target: "192.168.1.31:443", VPSMode: proto.ModeKernel, Enabled: true},
	}
	body, err := json.Marshal(desired)
	if err != nil {
		t.Fatal(err)
	}

	confirm := multipartUpload(t, srv.URL+"/ui/rules/import?lang=en", "rules.json", body)
	defer confirm.Body.Close()
	page, _ := io.ReadAll(confirm.Body)
	fields := extractHiddenFields(t, string(page))

	// 確認ページを描いた後に、別経路(CLI 相当)でルール集合を変える。
	if _, err := st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return append(rules, proto.Rule{ID: "r_extra", Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 9999, Hi: 9999}, Target: "192.168.1.40:9999", VPSMode: proto.ModeKernel, Enabled: true}), nil
	}); err != nil {
		t.Fatal(err)
	}

	staleResp, err := http.PostForm(srv.URL+"/ui/rules/import/apply?lang=en", url.Values{
		"content": {fields["content"]}, "generation": {fields["generation"]}, "digest": {fields["digest"]},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer staleResp.Body.Close()
	stalePage, _ := io.ReadAll(staleResp.Body)
	if !strings.Contains(string(stalePage), "changed after this confirmation") {
		t.Errorf("a stale apply must explain the mismatch and not apply: %s", stalePage)
	}
	if r := findRuleT(t, st, "r_keep"); r.Target != "192.168.1.30:443" {
		t.Errorf("a refused apply must not change anything: target = %q", r.Target)
	}

	// 今の状態に対して確認をやり直し、そのまま適用すれば通る。
	confirm2 := multipartUpload(t, srv.URL+"/ui/rules/import", "rules.json", body)
	defer confirm2.Body.Close()
	page2, _ := io.ReadAll(confirm2.Body)
	fields2 := extractHiddenFields(t, string(page2))

	applyResp, err := http.PostForm(srv.URL+"/ui/rules/import/apply", url.Values{
		"content": {fields2["content"]}, "generation": {fields2["generation"]}, "digest": {fields2["digest"]},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer applyResp.Body.Close()
	if req := applyResp.Request; req == nil || req.URL.Path != "/" {
		t.Errorf("a successful apply must redirect to the dashboard, got %v", req)
	}
	after, err := st.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 || after[0].ID != "r_keep" || after[0].Target != "192.168.1.31:443" {
		t.Errorf("apply did not replace the rule set with the uploaded content: %+v", after)
	}
}

// TestImportConfirmLocales は確認ページが ja/en 両方で実行時エラーなく描画され、
// 言語に応じた件数の文言が出ることを確かめる。
func TestImportConfirmLocales(t *testing.T) {
	srv, _ := newImportTestServer(t)
	desired := []proto.Rule{
		{ID: "r_keep", Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 443, Hi: 443}, Target: "192.168.1.31:443", VPSMode: proto.ModeKernel, Enabled: true},
	}
	body, err := json.Marshal(desired)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ lang, want string }{{"ja", "変更 1"}, {"en", "Changed 1"}} {
		resp := multipartUpload(t, srv.URL+"/ui/rules/import?lang="+tc.lang, "rules.json", body)
		page, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", tc.lang, resp.StatusCode)
		}
		if !strings.Contains(string(page), tc.want) {
			t.Errorf("%s: missing %q: %s", tc.lang, tc.want, page)
		}
	}
}
