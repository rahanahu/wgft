package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	srv := httptest.NewServer(New(&fakeBackend{st: st}))
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

// conflictOnceBackend は fakeBackend を包み、ExpectedDigest 付きの最初の Batch 呼び出しだけを
// ErrBatchConflict で拒む。確認ページの事前照合(世代とハッシュの一致)を通り抜けた後、
// Batch を呼ぶまでのわずかな競合可能期間に別経路の書き込みが割り込んだ場合を模す
// (webui_import.go の uiImportApply のコメント、仕様 10.1 節)。
type conflictOnceBackend struct {
	*fakeBackend
	tripped bool
}

func (b *conflictOnceBackend) Batch(req BatchRequest) (*store.BatchResult, error) {
	if !b.tripped && req.ExpectedDigest != "" {
		b.tripped = true
		return nil, ErrBatchConflict
	}
	return b.fakeBackend.Batch(req)
}

// TestImportApplyMapsBatchConflictToStalePage は、事前照合を通り抜けた後に Batch 自身が
// ExpectedDigest の不一致(ErrBatchConflict)で拒む場合も、事前照合が拒んだときと同じ
// 「確認ページを表示した後に変わった」再アップロードの案内になることを確かめる。
// この経路は、事前照合と Batch 呼び出しの間の競合可能期間を、BatchRequest.ExpectedDigest が
// 実際に塞いでいることの確認である。
func TestImportApplyMapsBatchConflictToStalePage(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return append(rules, proto.Rule{ID: "r_keep", Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 443, Hi: 443}, Target: "192.168.1.30:443", VPSMode: proto.ModeKernel, Enabled: true}), nil
	}); err != nil {
		t.Fatal(err)
	}
	backend := &conflictOnceBackend{fakeBackend: &fakeBackend{st: st}}
	srv := httptest.NewServer(New(backend))
	t.Cleanup(srv.Close)

	desired := []proto.Rule{
		{ID: "r_keep", Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 443, Hi: 443}, Target: "192.168.1.31:443", VPSMode: proto.ModeKernel, Enabled: true},
	}
	body, err := json.Marshal(desired)
	if err != nil {
		t.Fatal(err)
	}
	confirm := multipartUpload(t, srv.URL+"/ui/rules/import?lang=en", "rules.json", body)
	page, _ := io.ReadAll(confirm.Body)
	confirm.Body.Close()
	fields := extractHiddenFields(t, string(page))

	applyResp, err := http.PostForm(srv.URL+"/ui/rules/import/apply?lang=en", url.Values{
		"content": {fields["content"]}, "generation": {fields["generation"]}, "digest": {fields["digest"]},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer applyResp.Body.Close()
	applyPage, _ := io.ReadAll(applyResp.Body)
	if !strings.Contains(string(applyPage), "changed after this confirmation") {
		t.Errorf("a Batch-level ErrBatchConflict must render the same re-upload page as the handler's own pre-check: %s", applyPage)
	}
	if r := findRuleT(t, st, "r_keep"); r.Target != "192.168.1.30:443" {
		t.Errorf("a refused apply must not change anything: target = %q", r.Target)
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

// manyRulesJSON marshals n distinct, valid kernel-mode UDP rules on agent "home" (registered
// by fakeBackend's default) starting at port lo. It is used to build a rule set whose raw JSON
// stays under importMaxBytes but whose application/x-www-form-urlencoded encoding (as sent by
// the confirm page's hidden "content" field) does not, because JSON's own punctuation ("{}:,)
// percent-encodes to 3 bytes each.
func manyRulesJSON(t *testing.T, n int, lo uint16) []byte {
	t.Helper()
	rules := make([]proto.Rule, n)
	for i := 0; i < n; i++ {
		port := lo + uint16(i)
		rules[i] = proto.Rule{
			ID: fmt.Sprintf("r_%05d", i), Agent: "home", Proto: proto.UDP,
			ListenPort: proto.PortRange{Lo: port, Hi: port}, Target: fmt.Sprintf("192.168.1.20:%d", port),
			VPSMode: proto.ModeKernel, Enabled: true,
		}
	}
	b, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestImportApplyBodyLimitSurvivesURLEncoding は、確認ページのアップロード自体は
// importMaxBytes(1 MiB)未満でも、適用時に hidden の "content" フィールドを
// application/x-www-form-urlencoded で送ると JSON の punctuation が %XX に膨れて 1 MiB を
// 超えうることの再現である(レビューの指摘)。修正前は適用の MaxBytesReader が upload と同じ
// importMaxBytes だったため、この POST は "http: request body too large" で失敗した。
func TestImportApplyBodyLimitSurvivesURLEncoding(t *testing.T) {
	srv, st := newImportTestServer(t)

	body := manyRulesJSON(t, 3000, 20000) // raw ~837 KB (< importMaxBytes)、url エンコードで ~1.31 MB (> importMaxBytes)
	if len(body) >= importMaxBytes {
		t.Fatalf("fixture raw JSON is %d bytes, want it under importMaxBytes (%d) to fit the initial upload", len(body), importMaxBytes)
	}

	confirm := multipartUpload(t, srv.URL+"/ui/rules/import?lang=en", "rules.json", body)
	page, _ := io.ReadAll(confirm.Body)
	confirm.Body.Close()
	if confirm.StatusCode != http.StatusOK {
		t.Fatalf("confirm status = %d, want 200: %s", confirm.StatusCode, page)
	}
	fields := extractHiddenFields(t, string(page))

	form := url.Values{"content": {fields["content"]}, "generation": {fields["generation"]}, "digest": {fields["digest"]}}
	if encoded := len(form.Encode()); encoded <= importMaxBytes {
		t.Fatalf("fixture's url-encoded form is %d bytes, want it over importMaxBytes (%d) to reproduce the finding", encoded, importMaxBytes)
	} else if encoded >= importApplyMaxBytes {
		t.Fatalf("fixture's url-encoded form is %d bytes, want it under importApplyMaxBytes (%d)", encoded, importApplyMaxBytes)
	}

	resp, err := http.PostForm(srv.URL+"/ui/rules/import/apply?lang=en", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if req := resp.Request; req == nil || req.URL.Path != "/" {
		t.Fatalf("apply must succeed and redirect to the dashboard, got %v (body: %s)", req, respBody)
	}
	after, err := st.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 3000 {
		t.Errorf("apply did not replace the rule set with the uploaded 3000 rules: got %d", len(after))
	}
}

// TestImportApplyRejectsOversizedContent は、適用の本体上限を url エンコードの膨張分だけ
// 広げても、デコード後の content 自身は importMaxBytes に収まらなければならないことを
// 確かめる(レビューの指摘)。content がそれ単体で 1 MiB を超える場合は、他の hidden
// フィールドの分の余裕があっても明確な誤りとして拒む。
func TestImportApplyRejectsOversizedContent(t *testing.T) {
	srv, _ := newImportTestServer(t)

	// 単純な英数字は url エンコードでほぼ膨らまないので、importMaxBytes 超えを content 自身の
	// 大きさだけで起こす(importApplyMaxBytes の余裕には収まる)。
	oversized := strings.Repeat("a", importMaxBytes+1024)
	form := url.Values{"content": {oversized}, "generation": {"0"}, "digest": {""}}
	if encoded := len(form.Encode()); encoded >= importApplyMaxBytes {
		t.Fatalf("fixture is %d bytes, want it under importApplyMaxBytes (%d) so the MaxBytesReader isn't what rejects it", encoded, importApplyMaxBytes)
	}

	resp, err := http.PostForm(srv.URL+"/ui/rules/import/apply?lang=en", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d (import content exceeds the 1 MiB limit): %s", resp.StatusCode, http.StatusRequestEntityTooLarge, respBody)
	}
}

// TestImportIssuesGrandfathersUnchangedLegacyRow は、後から増えた検査(proxy の範囲の拒否)に
// 落ちる古い行があっても、その行を変えない読み込みは確認画面で止めず、その行を変える
// 読み込みだけを止めることを確かめる。適用時のバッチ(proto.ValidateUpsert)と同じ規則である。
func TestImportIssuesGrandfathersUnchangedLegacyRow(t *testing.T) {
	legacy := proto.Rule{ID: "r_legacy", Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 443, Hi: 444},
		Target: "192.168.1.30:443", VPSMode: proto.ModeProxy, Enabled: true}
	other := proto.Rule{ID: "r_other", Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2456, Hi: 2456},
		Target: "192.168.1.20:2456", VPSMode: proto.ModeKernel, Enabled: true}
	if legacy.Validate() == nil {
		t.Fatal("test premise: a proxy range must fail Rule.Validate")
	}
	current := []proto.Rule{legacy, other}
	agents := map[string]bool{"home": true}

	otherNoted := other
	otherNoted.Note = "only the note changes"
	if got := importIssues([]proto.Rule{legacy, otherNoted}, current, agents, nil); len(got) != 0 {
		t.Errorf("import that leaves the legacy row alone is withheld: %v", got)
	}

	legacyNoted := legacy
	legacyNoted.Note = "touching the legacy row"
	got := importIssues([]proto.Rule{legacyNoted, other}, current, agents, nil)
	if len(got) != 1 || !strings.Contains(got[0], "r_legacy") {
		t.Errorf("import that changes the legacy row should report it once, got %v", got)
	}
}

// reservedPortsLikeVPSD builds the proto.Reserved set a real Batch would refuse a listen_port
// for, the same way reservedBackend's Batch below needs it. It is written independently of
// ReservedFromServerInfo (admin.go) instead of a call to that function: a test that renders the
// confirm page (which calls ReservedFromServerInfo through importIssues) and then also runs a
// real Batch against the same fixture only actually cross-checks ReservedFromServerInfo against
// an independent copy when the two are implemented separately. Calling ReservedFromServerInfo
// here would make such a test pass even if ReservedFromServerInfo's rule silently drifted, since
// both sides would then apply the same (wrong) rule.
//
// Despite the name, this is a copy of ReservedFromServerInfo, not of internal/vpsd/vpsd.go's
// construction of Daemon.reserved: that one takes Options (WGPort/AdminAddr/AgentAPIAddr) and
// splits AgentAPIAddr's port itself with net.SplitHostPort, whereas this one, like
// ReservedFromServerInfo, takes ServerInfo and uses AgentAPIPort, which its producers already
// return net.SplitHostPort'd. vpsd.go's own construction (reservedPorts) is pinned directly by
// internal/vpsd's TestReservedPorts; ReservedFromServerInfo's rule is pinned directly by
// TestReservedFromServerInfo (reserved_test.go, this package). cmd/wgft/rule_test.go's own
// reservedPortsLikeVPSD makes the same choice, with the same naming quirk, for the CLI's
// --dry-run tests.
func reservedPortsLikeVPSD(info ServerInfo) proto.Reserved {
	reserved := proto.Reserved{uint16(info.WGPort): "WireGuard"}
	if ap, err := netip.ParseAddrPort(info.AdminAddr); err == nil {
		reserved[ap.Port()] = "admin API"
	}
	if ap, err := netip.ParseAddrPort("0.0.0.0:" + info.AgentAPIPort); err == nil {
		reserved[ap.Port()] = "agent API"
	}
	return reserved
}

// reservedBackend wraps fakeBackend to report a fixed ServerInfo and to make Batch honor the
// same reserved-port set a real Daemon.Batch would (fakeBackend.Batch itself passes nil, which
// is fine for tests that don't care about reserved ports, but would hide the exact defect the
// tests below exist to catch: the confirm page and the real Batch disagreeing about a reserved
// port).
type reservedBackend struct {
	*fakeBackend
	info ServerInfo
}

func (b *reservedBackend) ServerInfo() (ServerInfo, error) { return b.info, nil }

func (b *reservedBackend) Batch(req BatchRequest) (*store.BatchResult, error) {
	return b.st.ApplyBatch(reservedPortsLikeVPSD(b.info), func(rules []proto.Rule) ([]proto.Rule, error) {
		return ApplyBatchToRules(rules, req)
	})
}

// TestImportConfirmRejectsReservedPortOverlap is the fix for the defect an independent review
// found: importIssues passed nil as proto.ValidateUpsert's reserved argument, so a read-import
// that overlapped the VPS's own WireGuard, admin API, or agent API port showed as accepted on
// the confirm page even though the real Daemon.Batch (internal/vpsd/admin_backend.go, via
// internal/vpsd/store/rules.go's ApplyBatch) would refuse it. For each of the three ports, this
// confirms both that the confirm page withholds the apply button and that a real Batch against
// the same fixture also refuses it, so the two judgments cannot drift apart the way they did
// before this fix.
func TestImportConfirmRejectsReservedPortOverlap(t *testing.T) {
	cases := []struct {
		name string
		info ServerInfo
		port uint16
	}{
		{"WireGuard", ServerInfo{WGPort: 51820}, 51820},
		{"admin API", ServerInfo{WGPort: 51821, AdminAddr: "127.0.0.1:8686"}, 8686},
		{"agent API", ServerInfo{WGPort: 51821, AgentAPIPort: "8687"}, 8687},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { st.Close() })
			backend := &reservedBackend{fakeBackend: &fakeBackend{st: st}, info: tc.info}
			srv := httptest.NewServer(New(backend))
			t.Cleanup(srv.Close)

			desired := []proto.Rule{
				{ID: "r_new", Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: tc.port, Hi: tc.port},
					Target: "192.168.1.30:9", VPSMode: proto.ModeKernel, Enabled: true},
			}
			body, err := json.Marshal(desired)
			if err != nil {
				t.Fatal(err)
			}

			confirm := multipartUpload(t, srv.URL+"/ui/rules/import?lang=en", "rules.json", body)
			defer confirm.Body.Close()
			if confirm.StatusCode != http.StatusOK {
				t.Fatalf("confirm status = %d, want 200", confirm.StatusCode)
			}
			page, _ := io.ReadAll(confirm.Body)
			s := string(page)
			if !strings.Contains(s, "Cannot apply") {
				t.Errorf("confirm page must withhold apply for a rule overlapping the reserved %s port: %s", tc.name, s)
			}
			if !strings.Contains(s, `type="submit" disabled`) {
				t.Errorf("apply button must be disabled: %s", s)
			}
			// The listed reason must actually name the reserved-port collision (proto/rule.go's
			// "includes %s port %d", from validateRuleSet), not just any issue. Checking only
			// "Cannot apply" above would stay green even if importIssues refused this rule for an
			// unrelated reason, such as wrongly treating every row as pointing at an unregistered
			// agent.
			wantReason := fmt.Sprintf("includes %s port %d", tc.name, tc.port)
			if !strings.Contains(s, wantReason) {
				t.Errorf("confirm page must list the reserved-port collision (%q), got: %s", wantReason, s)
			}
			fields := extractHiddenFields(t, s)

			// The confirm page's judgment must agree with what a real Batch does: applying the
			// same fixture through the actual apply handler must also be refused, not silently
			// accepted, and nothing must be saved.
			applyResp, err := http.PostForm(srv.URL+"/ui/rules/import/apply?lang=en", url.Values{
				"content": {fields["content"]}, "generation": {fields["generation"]}, "digest": {fields["digest"]},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer applyResp.Body.Close()
			applyBody, _ := io.ReadAll(applyResp.Body)
			if applyResp.StatusCode != http.StatusUnprocessableEntity {
				t.Errorf("apply of a %s-port-overlapping import must fail (422), got %d: %s", tc.name, applyResp.StatusCode, applyBody)
			}
			after, err := st.Rules()
			if err != nil {
				t.Fatal(err)
			}
			if len(after) != 0 {
				t.Errorf("a refused apply must not save anything: %+v", after)
			}
		})
	}
}

// TestImportConfirmAcceptsNonOverlappingUnixSocketAdminAddr is a control for
// TestImportConfirmRejectsReservedPortOverlap: an AdminAddr that is a Unix socket path (not
// host:port, e.g. the default "unix:///run/wgft/admin.sock") must not reserve any port, so a
// read-import that does not otherwise conflict must still be accepted. This guards against an
// overly broad fix that reserves something for every AdminAddr regardless of shape.
func TestImportConfirmAcceptsNonOverlappingUnixSocketAdminAddr(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	info := ServerInfo{WGPort: 51821, AdminAddr: "unix:///run/wgft/admin.sock", AgentAPIPort: "8687"}
	backend := &reservedBackend{fakeBackend: &fakeBackend{st: st}, info: info}
	srv := httptest.NewServer(New(backend))
	t.Cleanup(srv.Close)

	desired := []proto.Rule{
		{ID: "r_new", Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 8080, Hi: 8080},
			Target: "192.168.1.30:8080", VPSMode: proto.ModeKernel, Enabled: true},
	}
	body, err := json.Marshal(desired)
	if err != nil {
		t.Fatal(err)
	}
	confirm := multipartUpload(t, srv.URL+"/ui/rules/import?lang=en", "rules.json", body)
	defer confirm.Body.Close()
	page, _ := io.ReadAll(confirm.Body)
	s := string(page)
	if strings.Contains(s, "Cannot apply") {
		t.Errorf("a Unix socket admin_addr must not reserve a port: %s", s)
	}
	if strings.Contains(s, `type="submit" disabled`) {
		t.Errorf("apply button must not be disabled: %s", s)
	}
}

// A ServerInfo() failure -- the case that matters most, since falling back to reserved == nil
// would make a read-import that overlaps a reserved port show as accepted -- is covered by the
// "server info" case TestImportConfirmReadFailureIsNotSilentZero (webui_readfail_test.go) adds,
// alongside its existing generation/agents cases, via errServerInfoBackend.
